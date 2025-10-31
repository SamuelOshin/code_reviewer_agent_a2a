# app/schemas/webhook.py

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

class GitHubUser(BaseModel):
    login: str
    id: int
    avatar_url: str
    html_url: str

class GitHubRepository(BaseModel):
    id: int
    name: str
    full_name: str
    owner: GitHubUser
    html_url: str
    description: Optional[str] = None
    private: bool

class GitHubPullRequest(BaseModel):
    id: int
    number: int
    state: str
    title: str
    body: Optional[str] = None
    user: GitHubUser
    html_url: str
    diff_url: str
    patch_url: str
    created_at: datetime
    updated_at: datetime
    head: Dict[str, Any]
    base: Dict[str, Any]
    draft: bool = False
    additions: int = 0
    deletions: int = 0
    changed_files: int = 0

class GitHubWebhookPayload(BaseModel):
    action: str
    number: int
    pull_request: GitHubPullRequest
    repository: GitHubRepository
    sender: GitHubUser