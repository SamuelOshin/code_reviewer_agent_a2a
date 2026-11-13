# app/services/github_mcp.py

"""GitHub Service

Direct GitHub API integration using PyGithub for fetching PR data, diffs, and files.
Uses async context manager pattern for proper resource management.
"""

import asyncio
import logging
import os
import re
import threading
from functools import partial
from typing import Any

from github import Auth, Github, GithubException
from github.GithubRetry import GithubRetry

from app.core.config import settings
from app.core.errors import new_error_id
from app.core.exceptions import GitHubMCPError
from app.models.github import PullRequest, PullRequestDiff, PullRequestFile

logger = logging.getLogger(__name__)

# Socket timeout, retry budget and rate-limit wait cap for PyGithub (P1-18). An executor
# thread cannot be killed, so when a review times out the call already running keeps
# going until it returns. These bound that call:
# - GITHUB_REQUEST_TIMEOUT applies per socket operation (connect or read), not per call;
#   15 s is also PyGithub's default, kept here so the value is explicit.
# - failed requests are retried at most GITHUB_RETRY_TOTAL times (PyGithub's default is 10).
# - a rate-limit backoff longer than GITHUB_RATE_LIMIT_MAX_WAIT raises instead of sleeping.
#   Without the cap, GithubRetry sleeps until X-RateLimit-Reset (up to an hour). Secondary
#   limits ask for 60 s, so with a 30 s cap they raise at once.
GITHUB_REQUEST_TIMEOUT = 15
GITHUB_RETRY_TOTAL = 3
GITHUB_RATE_LIMIT_MAX_WAIT = 30


class GitHubMCPService:
    """GitHub API Integration Service"""
    
    def __init__(self):
        self.token = settings.GITHUB_TOKEN
        self._client: Github | None = None
        self._closed = False
    
    async def __aenter__(self):
        """Context manager entry - initializes GitHub client"""
        try:
            logger.info("Creating GitHub client with token...")
            # Presence only: the token length narrows a brute-force search
            logger.info(f"Token present: {bool(self.token)}")
            
            self._client = Github(
                auth=Auth.Token(self.token),
                timeout=GITHUB_REQUEST_TIMEOUT,
                retry=GithubRetry(
                    total=GITHUB_RETRY_TOTAL, max_rate_limit_wait=GITHUB_RATE_LIMIT_MAX_WAIT
                ),
            )
            logger.info("GitHub client object created, testing connection...")
            
            # Test the connection - run blocking call in thread pool WITH TIMEOUT
            loop = asyncio.get_event_loop()
            
            # Add timeout to prevent hanging on slow networks (e.g., Leapcell)
            # Skip connection test if SKIP_GITHUB_CONNECTION_TEST env var is set
            skip_test = os.getenv("SKIP_GITHUB_CONNECTION_TEST", "false").lower() == "true"
            
            if skip_test:
                logger.info("⚡ Skipping GitHub connection test (SKIP_GITHUB_CONNECTION_TEST=true)")
                logger.info("✅ GitHub API client initialized (connection not tested)")
                return self
            
            try:
                user = await asyncio.wait_for(
                    loop.run_in_executor(None, self._client.get_user),
                    timeout=10.0  # 10 second timeout for connection test
                )
                login = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: user.login),
                    timeout=5.0  # 5 second timeout for getting login
                )
                
                logger.info(f"✅ GitHub API client initialized successfully (user: {login})")
            except TimeoutError:
                logger.error("⏱️ GitHub connection test timed out after 15s")
                logger.warning("💡 Tip: Set SKIP_GITHUB_CONNECTION_TEST=true to skip this check on slow networks")
                raise GitHubMCPError("GitHub API connection timed out - network may be slow or blocked") from None
            
            return self
        except GithubException as e:
            # str(e) includes the GitHub response body; keep the status only (P1-06 S1)
            logger.error(f"GitHub API error: status={e.status}")
            raise GitHubMCPError(
                f"GitHub API initialization failed (status={e.status})"
            ) from None
        except GitHubMCPError:
            raise  # Re-raise our custom errors
        except Exception as e:
            error_id = new_error_id()
            logger.error(
                f"Failed to initialize GitHub client [error_id={error_id}]: {type(e).__name__}"
            )
            raise GitHubMCPError(
                f"GitHub API initialization failed ({type(e).__name__}, error id: {error_id})"
            ) from None
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup"""
        self._closed = True
        if self._client:
            try:
                self._client.close()
                logger.info("GitHub client closed successfully")
            except Exception as e:
                logger.warning(f"Error closing GitHub client: {type(e).__name__}")
    
    def parse_pr_url(self, pr_url: str) -> tuple[str, str, int]:
        """
        Parse GitHub PR URL into owner, repo, pr_number
        
        Args:
            pr_url: Full PR URL (e.g., https://github.com/owner/repo/pull/123)
        
        Returns:
            Tuple of (owner, repo, pr_number)
        
        Raises:
            GitHubMCPError: If URL format is invalid
        """
        # [0-9], not \d: \d also matches non-ASCII digits (P1-15). The number must end
        # at the end of the string, "/", "?" or "#", so "pull/12abc" is rejected (P1-18).
        # Capped at 10 digits: a longer number is not a real PR, and int() on thousands
        # of digits raises ValueError (P1-20)
        pattern = r"https://github\.com/([^/]+)/([^/]+)/pull/([0-9]{1,10})(?=\Z|[/?#])"
        match = re.match(pattern, pr_url)
        
        if not match:
            raise GitHubMCPError(f"Invalid GitHub PR URL format: {pr_url}")
        
        owner, repo, pr_number = match.groups()
        return owner, repo, int(pr_number)
    
    async def _run_sync(self, func, *args, **kwargs):
        """
        Run a synchronous function in a thread pool to avoid blocking the event loop
        
        Args:
            func: Synchronous function to run
            *args, **kwargs: Arguments to pass to the function
        
        Returns:
            Result of the function
        """
        if self._closed:
            raise GitHubMCPError("GitHub client is closed")
        loop = asyncio.get_running_loop()
        stop = threading.Event()
        call = partial(func, *args, **kwargs) if (args or kwargs) else func

        def guarded():
            # A call queued behind a busy pool may start only after the caller gave up
            # (timeout or cancel). Skip it so no new GitHub request is made.
            if stop.is_set():
                return None
            return call()

        # Known limit (P1-18): a call that has already started cannot be stopped. It runs
        # until it returns, bounded by the socket timeout, a small retry budget and the
        # rate-limit wait cap (see GITHUB_RATE_LIMIT_MAX_WAIT). Its result is discarded.
        try:
            return await loop.run_in_executor(None, guarded)
        except asyncio.CancelledError:
            stop.set()
            raise

    async def post_pr_comment(self, owner: str, repo: str, pr_number: int, body: str) -> None:
        """
        Post one comment on a pull request (PR comments are issue comments)

        Raises:
            GitHubMCPError: If posting fails. The message never includes the token.
        """
        if not self._client:
            raise GitHubMCPError("GitHub client not initialized. Use context manager.")

        try:
            repository = await self._run_sync(self._client.get_repo, f"{owner}/{repo}")
            issue = await self._run_sync(repository.get_issue, pr_number)
            await self._run_sync(issue.create_comment, body)
            logger.info(f"Posted comment on {owner}/{repo}#{pr_number}")
        except GithubException as e:
            logger.error(f"Failed to post comment on {owner}/{repo}#{pr_number}: status={e.status}")
            raise GitHubMCPError(f"Failed to post PR comment (status {e.status})") from None
        except Exception as e:
            logger.error(f"Failed to post comment on {owner}/{repo}#{pr_number}: {type(e).__name__}")
            raise GitHubMCPError(f"Failed to post PR comment: {type(e).__name__}") from None

    async def get_pull_request(
        self, 
        owner: str, 
        repo: str, 
        pr_number: int
    ) -> PullRequest:
        """
        Fetch PR details using GitHub API
        
        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: PR number
        
        Returns:
            PullRequest model
        
        Raises:
            GitHubMCPError: If fetching fails
        """
        if not self._client:
            raise GitHubMCPError("GitHub client not initialized. Use context manager.")
        
        try:
            logger.info(f"Fetching PR {owner}/{repo}#{pr_number}")
            
            # Run blocking GitHub API calls in thread pool
            repository = await self._run_sync(self._client.get_repo, f"{owner}/{repo}")
            pr = await self._run_sync(repository.get_pull, pr_number)
            
            # Access attributes in thread pool too (they might make API calls)
            def _extract_pr_data():
                from app.models.github import GitHubUser
                return {
                    "id": pr.id,
                    "number": pr.number,
                    "title": pr.title,
                    "body": pr.body or "",
                    "state": pr.state,
                    "user": GitHubUser(
                        login=pr.user.login,
                        id=pr.user.id,
                        avatar_url=pr.user.avatar_url,
                        html_url=pr.user.html_url,
                        type=pr.user.type,
                        site_admin=pr.user.site_admin
                    ),
                    "created_at": pr.created_at,
                    "updated_at": pr.updated_at,
                    "merged_at": pr.merged_at,
                    "closed_at": pr.closed_at,
                    "html_url": pr.html_url,
                    "diff_url": pr.diff_url,
                    "patch_url": pr.patch_url,
                    "head": {
                        "ref": pr.head.ref,
                        "sha": pr.head.sha,
                        "label": pr.head.label,
                        "repo": pr.head.repo.full_name if pr.head.repo else None
                    },
                    "base": {
                        "ref": pr.base.ref,
                        "sha": pr.base.sha,
                        "label": pr.base.label,
                        "repo": pr.base.repo.full_name if pr.base.repo else None
                    },
                    "additions": pr.additions,
                    "deletions": pr.deletions,
                    "changed_files": pr.changed_files,
                    "commits": pr.commits,
                    "mergeable": pr.mergeable,
                    "mergeable_state": pr.mergeable_state,
                    "merged": pr.merged,
                    "draft": pr.draft
                }
            
            pr_data = await self._run_sync(_extract_pr_data)
            
            # Convert PyGithub PR to our PullRequest model
            return PullRequest(**pr_data)
        except GithubException as e:
            # Status only: str(e) carries the GitHub response body (P1-17)
            logger.error(f"Failed to fetch PR {owner}/{repo}#{pr_number}: status={e.status}")
            raise GitHubMCPError(f"Failed to fetch PR (status {e.status})") from None
        except Exception as e:
            error_id = new_error_id()
            logger.error(f"Failed to fetch PR {owner}/{repo}#{pr_number} [error_id={error_id}]: {type(e).__name__}")
            raise GitHubMCPError(f"Failed to fetch PR (error id: {error_id})") from None
    
    async def get_pr_diff(
        self, 
        owner: str, 
        repo: str, 
        pr_number: int
    ) -> str:
        """
        Fetch PR diff using GitHub API
        
        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: PR number
        
        Returns:
            Diff content as string
        """
        if not self._client:
            raise GitHubMCPError("GitHub client not initialized. Use context manager.")
        
        try:
            logger.info(f"Fetching diff for PR {owner}/{repo}#{pr_number}")
            
            # Run blocking calls in thread pool
            repository = await self._run_sync(self._client.get_repo, f"{owner}/{repo}")
            pr = await self._run_sync(repository.get_pull, pr_number)
            
            # Get diff by fetching files and aggregating patches
            files = await self._run_sync(lambda: list(pr.get_files()))
            diff_parts = []
            
            for file in files:
                if file.patch:
                    # Construct unified diff header
                    diff_parts.append(f"diff --git a/{file.filename} b/{file.filename}")
                    diff_parts.append(f"--- a/{file.filename}")
                    diff_parts.append(f"+++ b/{file.filename}")
                    diff_parts.append(file.patch)
            
            diff = "\n".join(diff_parts)
            logger.info(f"Fetched diff ({len(diff)} chars) for PR {owner}/{repo}#{pr_number}")
            return diff
        except GithubException as e:
            # Status only: str(e) carries the GitHub response body (P1-17)
            logger.error(f"Failed to fetch PR diff: status={e.status}")
            raise GitHubMCPError(f"Failed to fetch PR diff (status {e.status})") from None
        except Exception as e:
            error_id = new_error_id()
            logger.error(f"Failed to fetch PR diff [error_id={error_id}]: {type(e).__name__}")
            raise GitHubMCPError(f"Failed to fetch PR diff (error id: {error_id})") from None
    
    async def list_pr_files(
        self, 
        owner: str, 
        repo: str, 
        pr_number: int
    ) -> list[PullRequestFile]:
        """
        List changed files in PR using GitHub API
        
        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: PR number
        
        Returns:
            List of PullRequestFile models
        """
        if not self._client:
            raise GitHubMCPError("GitHub client not initialized. Use context manager.")
        
        try:
            logger.info(f"Fetching files for PR {owner}/{repo}#{pr_number}")
            
            # Run blocking calls in thread pool
            repository = await self._run_sync(self._client.get_repo, f"{owner}/{repo}")
            pr = await self._run_sync(repository.get_pull, pr_number)
            files = await self._run_sync(lambda: list(pr.get_files()))
            
            # Convert PyGithub files to our PullRequestFile models
            pr_files = []
            for file in files:
                pr_files.append(PullRequestFile(
                    filename=file.filename,
                    status=file.status,
                    additions=file.additions,
                    deletions=file.deletions,
                    changes=file.changes,
                    patch=file.patch or ""
                ))
            
            logger.info(f"Fetched {len(pr_files)} files for PR {owner}/{repo}#{pr_number}")
            return pr_files
        except GithubException as e:
            # Status only: str(e) carries the GitHub response body (P1-17)
            logger.error(f"Failed to fetch PR files: status={e.status}")
            raise GitHubMCPError(f"Failed to fetch PR files (status {e.status})") from None
        except Exception as e:
            error_id = new_error_id()
            logger.error(f"Failed to fetch PR files [error_id={error_id}]: {type(e).__name__}")
            raise GitHubMCPError(f"Failed to fetch PR files (error id: {error_id})") from None
    
    async def get_pr_reviews(
        self, 
        owner: str, 
        repo: str, 
        pr_number: int
    ) -> list[dict[str, Any]]:
        """
        Get PR reviews using GitHub API
        
        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: PR number
        
        Returns:
            List of review data
        """
        if not self._client:
            raise GitHubMCPError("GitHub client not initialized. Use context manager.")
        
        try:
            logger.info(f"Fetching reviews for PR {owner}/{repo}#{pr_number}")
            repository = self._client.get_repo(f"{owner}/{repo}")
            pr = repository.get_pull(pr_number)
            
            reviews = []
            for review in pr.get_reviews():
                reviews.append({
                    "id": review.id,
                    "user": review.user.login if review.user else None,
                    "state": review.state,
                    "body": review.body or "",
                    "submitted_at": review.submitted_at.isoformat() if review.submitted_at else None
                })
            
            logger.info(f"Fetched {len(reviews)} reviews for PR {owner}/{repo}#{pr_number}")
            return reviews
        except GithubException as e:
            logger.warning(f"Failed to fetch PR reviews: status={e.status}")
            return []  # Reviews are optional
        except Exception as e:
            logger.warning(f"Failed to fetch PR reviews: {type(e).__name__}")
            return []  # Reviews are optional
    
    async def get_file_content(
        self, 
        owner: str, 
        repo: str, 
        path: str, 
        ref: str | None = None
    ) -> str:
        """
        Get file content using GitHub API
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: File path
            ref: Git ref (branch, tag, commit SHA)
        
        Returns:
            File content as string
        """
        if not self._client:
            raise GitHubMCPError("GitHub client not initialized. Use context manager.")
        
        try:
            logger.debug(f"Fetching file content: {owner}/{repo}/{path} (ref={ref})")
            repository = self._client.get_repo(f"{owner}/{repo}")
            
            # Get file contents with optional ref
            contents = repository.get_contents(path, ref=ref) if ref else repository.get_contents(path)
            
            # Decode base64 content
            if hasattr(contents, 'decoded_content'):
                return contents.decoded_content.decode('utf-8')
            else:
                return ""
        except GithubException as e:
            # Status only: str(e) carries the GitHub response body (P1-17)
            logger.error(f"Failed to fetch file content: status={e.status}")
            raise GitHubMCPError(f"Failed to fetch file content (status {e.status})") from None
        except Exception as e:
            error_id = new_error_id()
            logger.error(f"Failed to fetch file content [error_id={error_id}]: {type(e).__name__}")
            raise GitHubMCPError(f"Failed to fetch file content (error id: {error_id})") from None
    
    async def get_pr_with_diff(
        self,
        owner: str,
        repo: str,
        pr_number: int
    ) -> tuple[PullRequest, PullRequestDiff]:
        """
        Fetch both PR details and diff in one call
        
        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: PR number
        
        Returns:
            Tuple of (PullRequest, PullRequestDiff)
        """
        pr = await self.get_pull_request(owner, repo, pr_number)
        files = await self.list_pr_files(owner, repo, pr_number)
        diff_content = await self.get_pr_diff(owner, repo, pr_number)
        
        diff = PullRequestDiff(
            pr_number=pr_number,
            total_additions=pr.additions,
            total_deletions=pr.deletions,
            total_changes=pr.additions + pr.deletions,
            files=files,
            raw_diff=diff_content
        )
        
        return pr, diff
