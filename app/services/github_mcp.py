# app/services/github_mcp.py

"""GitHub Service

Direct GitHub API integration using PyGithub for fetching PR data, diffs, and files.
Uses async context manager pattern for proper resource management.
"""

from typing import Optional, List, Dict, Any
import re
import base64
import asyncio
from functools import partial
from github import Github, GithubException
from app.core.config import settings
from app.core.exceptions import GitHubMCPError
from app.models.github import PullRequest, PullRequestFile, PullRequestDiff
import logging

logger = logging.getLogger(__name__)


class GitHubMCPService:
    """GitHub API Integration Service"""
    
    def __init__(self):
        self.token = settings.GITHUB_TOKEN
        self._client: Optional[Github] = None
    
    async def __aenter__(self):
        """Context manager entry - initializes GitHub client"""
        try:
            logger.info("Creating GitHub client with token...")
            logger.info(f"Token present: {bool(self.token)}, Length: {len(self.token) if self.token else 0}")
            
            self._client = Github(self.token)
            logger.info("GitHub client object created, testing connection...")
            
            # Test the connection - run blocking call in thread pool
            loop = asyncio.get_event_loop()
            user = await loop.run_in_executor(None, self._client.get_user)
            login = await loop.run_in_executor(None, lambda: user.login)
            
            logger.info(f"GitHub API client initialized successfully (user: {login})")
            return self
        except GithubException as e:
            logger.error(f"GitHub API error: {e.status}, {e.data}")
            raise GitHubMCPError(f"GitHub API initialization failed: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to initialize GitHub client: {type(e).__name__}: {e}", exc_info=True)
            raise GitHubMCPError(f"GitHub API initialization failed: {str(e)}")
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup"""
        if self._client:
            try:
                self._client.close()
                logger.info("GitHub client closed successfully")
            except Exception as e:
                logger.warning(f"Error closing GitHub client: {e}")
    
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
        pattern = r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)"
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
        loop = asyncio.get_event_loop()
        if args or kwargs:
            return await loop.run_in_executor(None, partial(func, *args, **kwargs))
        return await loop.run_in_executor(None, func)
    
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
            logger.error(f"Failed to fetch PR {owner}/{repo}#{pr_number}: {e}")
            raise GitHubMCPError(f"Failed to fetch PR: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to fetch PR {owner}/{repo}#{pr_number}: {e}")
            raise GitHubMCPError(f"Failed to fetch PR: {str(e)}")
    
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
            logger.error(f"Failed to fetch PR diff: {e}")
            raise GitHubMCPError(f"Failed to fetch PR diff: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to fetch PR diff: {e}")
            raise GitHubMCPError(f"Failed to fetch PR diff: {str(e)}")
    
    async def list_pr_files(
        self, 
        owner: str, 
        repo: str, 
        pr_number: int
    ) -> List[PullRequestFile]:
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
            logger.error(f"Failed to fetch PR files: {e}")
            raise GitHubMCPError(f"Failed to fetch PR files: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to fetch PR files: {e}")
            raise GitHubMCPError(f"Failed to fetch PR files: {str(e)}")
    
    async def get_pr_reviews(
        self, 
        owner: str, 
        repo: str, 
        pr_number: int
    ) -> List[Dict[str, Any]]:
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
            logger.warning(f"Failed to fetch PR reviews: {e}")
            return []  # Reviews are optional
        except Exception as e:
            logger.warning(f"Failed to fetch PR reviews: {e}")
            return []  # Reviews are optional
    
    async def get_file_content(
        self, 
        owner: str, 
        repo: str, 
        path: str, 
        ref: Optional[str] = None
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
            logger.error(f"Failed to fetch file content: {e}")
            raise GitHubMCPError(f"Failed to fetch file content: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to fetch file content: {e}")
            raise GitHubMCPError(f"Failed to fetch file content: {str(e)}")
    
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
