# app/models/a2a.py

"""A2A Protocol Models

These models define the structure for Agent-to-Agent (A2A) protocol communication.
Based on python-a2a library patterns from simple_server.py example.
"""

from typing import List, Optional, Dict, Any, TYPE_CHECKING
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

if TYPE_CHECKING:
    from typing import ForwardRef


class TaskState(str, Enum):
    """Task execution states"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class MessagePart(BaseModel):
    """Part of a message - matches Telex A2A structure"""
    kind: str  # "text", "image", "file", "data"
    text: Optional[str] = None
    file_url: Optional[str] = None
    mime_type: Optional[str] = None
    data: Optional[List[Dict[str, Any]]] = None  # For conversation history (kind="data")


class A2AMessage(BaseModel):
    """A2A Protocol Message - matches Telex structure"""
    messageId: str
    role: str  # "user" or "agent"
    parts: List[MessagePart]
    kind: str = "message"
    taskId: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class TaskStatus(BaseModel):
    """Task status information - matches Telex A2A structure"""
    state: str  # "pending", "in_progress", "completed", "failed", "input-required"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    message: Optional[A2AMessage] = None  # Nested message in status
    progress: Optional[float] = Field(None, ge=0.0, le=1.0)


class ArtifactPart(BaseModel):
    """Part of an artifact - matches Telex A2A structure"""
    kind: str  # "text", "json", "markdown", "code", "image", "file"
    text: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    file_url: Optional[str] = None  # For file artifacts
    mime_type: Optional[str] = None


class A2AArtifact(BaseModel):
    """A2A Protocol Artifact - matches Telex structure"""
    artifactId: str
    name: str  # Artifact name/title
    parts: List[ArtifactPart]
    metadata: Optional[Dict[str, Any]] = None


class A2ATaskRequest(BaseModel):
    """A2A Task Request - from Telex webhook"""
    task_id: str
    skill: str
    parameters: Dict[str, Any]
    context: Optional[List[A2AMessage]] = []
    message: Optional[Dict[str, Any]] = None  # Used by python-a2a
    callback_url: Optional[str] = None  # Telex callback URL for async results


class TaskAcceptedResponse(BaseModel):
    """Quick acknowledgment response for webhook requests"""
    task_id: str
    status: str = "accepted"
    message: str = "Task accepted and processing"


class A2ATask(BaseModel):
    """A2A Task - matches Telex structure"""
    id: str  # task ID
    contextId: str  # context/session ID
    status: TaskStatus
    artifacts: List[A2AArtifact] = []
    history: List[A2AMessage] = []
    kind: str = "task"


class A2ATaskResponse(BaseModel):
    """A2A Task Response wrapped in JSON-RPC 2.0 - matches Telex structure"""
    jsonrpc: str = "2.0"
    id: str  # Request ID
    result: A2ATask
    error: Optional[Dict[str, Any]] = None


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
