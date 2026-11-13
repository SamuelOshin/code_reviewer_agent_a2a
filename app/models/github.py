# app/models/github.py

"""GitHub Data Models

Pydantic models for GitHub entities (PRs, Users, Repositories, etc.)
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class GitHubUser(BaseModel):
    """GitHub user model"""
    login: str
    id: int
    avatar_url: str | None = None
    html_url: str | None = None
    type: str | None = None
    site_admin: bool | None = False


class GitHubRepository(BaseModel):
    """GitHub repository model"""
    id: int
    name: str
    full_name: str
    owner: GitHubUser
    private: bool = False
    html_url: str | None = None
    description: str | None = None
    fork: bool | None = False
    default_branch: str | None = "main"


class PullRequestFile(BaseModel):
    """Pull Request file change"""
    filename: str
    status: str  # added, removed, modified, renamed
    additions: int = 0
    deletions: int = 0
    changes: int = 0
    blob_url: str | None = None
    raw_url: str | None = None
    contents_url: str | None = None
    patch: str | None = None


class PullRequestLabel(BaseModel):
    """PR label"""
    id: int
    name: str
    color: str
    description: str | None = None


class PullRequest(BaseModel):
    """GitHub Pull Request model"""
    id: int
    number: int
    state: str  # open, closed
    title: str
    body: str | None = None
    user: GitHubUser
    created_at: datetime
    updated_at: datetime
    merged_at: datetime | None = None
    closed_at: datetime | None = None
    
    # PR details
    html_url: str
    diff_url: str | None = None
    patch_url: str | None = None
    
    # Branch info
    head: dict[str, Any]
    base: dict[str, Any]
    
    # Stats
    additions: int = 0
    deletions: int = 0
    changed_files: int = 0
    commits: int = 0
    
    # Status
    mergeable: bool | None = None
    mergeable_state: str | None = None
    merged: bool = False
    
    # Metadata
    labels: list[PullRequestLabel] = []
    requested_reviewers: list[GitHubUser] = []
    draft: bool = False


class PullRequestDiff(BaseModel):
    """Pull Request diff information"""
    pr_number: int
    total_additions: int = 0
    total_deletions: int = 0
    total_changes: int = 0
    files: list[PullRequestFile] = []
    raw_diff: str | None = None


class GitHubCommit(BaseModel):
    """GitHub commit model"""
    sha: str
    message: str
    author: dict[str, Any] | None = None
    committer: dict[str, Any] | None = None
    url: str | None = None


class GitHubComment(BaseModel):
    """GitHub PR comment model"""
    id: int
    user: GitHubUser
    body: str
    created_at: datetime
    updated_at: datetime
    html_url: str | None = None
    path: str | None = None  # For review comments
    line: int | None = None  # For review comments
