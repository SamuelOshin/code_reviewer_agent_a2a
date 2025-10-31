# app/models/a2a.py

"""A2A Protocol Models

These models define the structure for Agent-to-Agent (A2A) protocol communication.
Based on python-a2a library patterns from simple_server.py example.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class TaskState(str, Enum):
    """Task execution states"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskStatus(BaseModel):
    """Task status information"""
    state: TaskState
    message: Optional[str] = None
    progress: Optional[float] = Field(None, ge=0.0, le=1.0)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class A2AMessage(BaseModel):
    """A2A Protocol Message"""
    role: str  # "user" or "agent"
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ArtifactPart(BaseModel):
    """Part of an artifact - matches python-a2a structure"""
    type: str  # text, json, markdown, code, image
    text: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    mime_type: Optional[str] = None


class A2AArtifact(BaseModel):
    """A2A Protocol Artifact - matches python-a2a structure with parts array"""
    parts: List[ArtifactPart]
    type: Optional[str] = None  # Legacy field for compatibility
    title: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class A2ATaskRequest(BaseModel):
    """A2A Task Request"""
    task_id: str
    skill: str
    parameters: Dict[str, Any]
    context: Optional[List[A2AMessage]] = []
    message: Optional[Dict[str, Any]] = None  # Used by python-a2a


class A2ATaskResponse(BaseModel):
    """A2A Task Response"""
    task_id: str
    status: str  # "completed", "failed", "in_progress"
    messages: List[A2AMessage]
    artifacts: List[A2AArtifact] = []
    error: Optional[str] = None


class AgentSkill(BaseModel):
    """Agent skill definition for agent card"""
    name: str = Field(..., description="Skill name")
    description: str = Field(..., description="What this skill does")
    parameters: Optional[Dict[str, Any]] = Field(None, description="Skill parameters schema")
    examples: Optional[List[str]] = None


class AgentCard(BaseModel):
    """Agent Card for A2A discovery"""
    schema_version: str = "1.0"
    name: str
    description: str
    version: str
    capabilities: List[str]
    skills: List[AgentSkill]
    endpoints: Dict[str, str]
    authentication: Optional[Dict[str, Any]] = None
    modalities: List[str] = ["text"]
    streaming: bool = False
