# app/models/github.py

"""GitHub Data Models

Pydantic models for GitHub entities (PRs, Users, Repositories, etc.)
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime


class GitHubUser(BaseModel):
    """GitHub user model"""
    login: str
    id: int
    avatar_url: Optional[str] = None
    html_url: Optional[str] = None
    type: Optional[str] = None
    site_admin: Optional[bool] = False


class GitHubRepository(BaseModel):
    """GitHub repository model"""
    id: int
    name: str
    full_name: str
    owner: GitHubUser
    private: bool = False
    html_url: Optional[str] = None
    description: Optional[str] = None
    fork: Optional[bool] = False
    default_branch: Optional[str] = "main"


class PullRequestFile(BaseModel):
    """Pull Request file change"""
    filename: str
    status: str  # added, removed, modified, renamed
    additions: int = 0
    deletions: int = 0
    changes: int = 0
    blob_url: Optional[str] = None
    raw_url: Optional[str] = None
    contents_url: Optional[str] = None
    patch: Optional[str] = None


class PullRequestLabel(BaseModel):
    """PR label"""
    id: int
    name: str
    color: str
    description: Optional[str] = None


class PullRequest(BaseModel):
    """GitHub Pull Request model"""
    id: int
    number: int
    state: str  # open, closed
    title: str
    body: Optional[str] = None
    user: GitHubUser
    created_at: datetime
    updated_at: datetime
    merged_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    
    # PR details
    html_url: str
    diff_url: Optional[str] = None
    patch_url: Optional[str] = None
    
    # Branch info
    head: Dict[str, Any]
    base: Dict[str, Any]
    
    # Stats
    additions: int = 0
    deletions: int = 0
    changed_files: int = 0
    commits: int = 0
    
    # Status
    mergeable: Optional[bool] = None
    mergeable_state: Optional[str] = None
    merged: bool = False
    
    # Metadata
    labels: List[PullRequestLabel] = []
    requested_reviewers: List[GitHubUser] = []
    draft: bool = False


class PullRequestDiff(BaseModel):
    """Pull Request diff information"""
    pr_number: int
    total_additions: int = 0
    total_deletions: int = 0
    total_changes: int = 0
    files: List[PullRequestFile] = []
    raw_diff: Optional[str] = None


class GitHubCommit(BaseModel):
    """GitHub commit model"""
    sha: str
    message: str
    author: Optional[Dict[str, Any]] = None
    committer: Optional[Dict[str, Any]] = None
    url: Optional[str] = None


class GitHubComment(BaseModel):
    """GitHub PR comment model"""
    id: int
    user: GitHubUser
    body: str
    created_at: datetime
    updated_at: datetime
    html_url: Optional[str] = None
    path: Optional[str] = None  # For review comments
    line: Optional[int] = None  # For review comments
