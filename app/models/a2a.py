# app/models/a2a.py

"""A2A Protocol Models

These models define the structure for Agent-to-Agent (A2A) protocol communication.

"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    pass


class MessagePart(BaseModel):
    """Part of a message"""
    kind: str  # "text", "image", "file", "data"
    text: str | None = None
    file_url: str | None = None
    mime_type: str | None = None
    data: list[dict[str, Any]] | None = None  # For conversation history (kind="data")


class A2AMessage(BaseModel):
    """A2A Protocol Message"""
    messageId: str
    role: str  # "user" or "agent"
    parts: list[MessagePart]
    kind: str = "message"
    taskId: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TaskStatus(BaseModel):
    """Task status information"""
    state: str  # "pending", "in_progress", "completed", "failed", "input-required"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    message: A2AMessage | None = None  # Nested message in status
    progress: float | None = Field(None, ge=0.0, le=1.0)


class ArtifactPart(BaseModel):
    """Part of an artifact"""
    kind: str  # "text", "json", "markdown", "code", "image", "file"
    text: str | None = None
    data: dict[str, Any] | None = None
    file_url: str | None = None  # For file artifacts
    mime_type: str | None = None


class A2AArtifact(BaseModel):
    """A2A Protocol Artifact"""
    artifactId: str
    name: str  # Artifact name/title
    parts: list[ArtifactPart]
    metadata: dict[str, Any] | None = None


class A2ATask(BaseModel):
    """A2A Task"""
    id: str  # task ID
    contextId: str  # context/session ID
    status: TaskStatus
    artifacts: list[A2AArtifact] = []
    history: list[A2AMessage] = []
    kind: str = "task"


class AgentSkill(BaseModel):
    """Agent skill definition for agent card"""
    name: str = Field(..., description="Skill name")
    description: str = Field(..., description="What this skill does")
    parameters: dict[str, Any] | None = Field(None, description="Skill parameters schema")
    examples: list[str] | None = None


class AgentCard(BaseModel):
    """Agent Card for A2A discovery"""
    schema_version: str = "1.0"
    name: str
    description: str
    version: str
    capabilities: list[str]
    skills: list[AgentSkill]
    endpoints: dict[str, str]
    authentication: dict[str, Any] | None = None
    modalities: list[str] = ["text"]
    streaming: bool = False
