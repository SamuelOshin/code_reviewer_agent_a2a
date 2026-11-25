# app/models/a2a.py

"""A2A Protocol Models and v1.0 SDK Conversions.

Provides both the legacy v0.3 Pydantic models used internally and converters to the
official `a2a-sdk` Protocol Buffer models for A2A v1.0 endpoints (`AgentCard`,
`SendMessageResponse`, `Task`, `Message`, `Artifact`, `Part`, `TaskState`, `Role`).
"""

from datetime import UTC, datetime
from typing import Any

import a2a.types as a2a_types
from google.protobuf.json_format import MessageToDict, ParseDict
from google.protobuf.struct_pb2 import Struct, Value
from google.protobuf.timestamp_pb2 import Timestamp
from pydantic import BaseModel, Field

__all__ = [
    "A2AArtifact",
    "A2AMessage",
    "A2ATask",
    "AgentCard",
    "AgentSkill",
    "ArtifactPart",
    "MessagePart",
    "TaskStatus",
    "a2a_types",
    "build_v03_agent_card",
    "build_v1_agent_card",
    "task_dict_to_v1_response",
]


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
    contextId: str | None = None
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
    metadata: dict[str, Any] | None = None


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


_TASK_STATE_MAP: dict[str, a2a_types.TaskState] = {
    "submitted": a2a_types.TaskState.TASK_STATE_SUBMITTED,
    "working": a2a_types.TaskState.TASK_STATE_WORKING,
    "completed": a2a_types.TaskState.TASK_STATE_COMPLETED,
    "failed": a2a_types.TaskState.TASK_STATE_FAILED,
    "canceled": a2a_types.TaskState.TASK_STATE_CANCELED,
    "cancelled": a2a_types.TaskState.TASK_STATE_CANCELED,
    "input-required": a2a_types.TaskState.TASK_STATE_INPUT_REQUIRED,
    "input_required": a2a_types.TaskState.TASK_STATE_INPUT_REQUIRED,
    "rejected": a2a_types.TaskState.TASK_STATE_REJECTED,
    "auth-required": a2a_types.TaskState.TASK_STATE_AUTH_REQUIRED,
    "auth_required": a2a_types.TaskState.TASK_STATE_AUTH_REQUIRED,
}

_ROLE_MAP: dict[str, a2a_types.Role] = {
    "user": a2a_types.Role.ROLE_USER,
    "ROLE_USER": a2a_types.Role.ROLE_USER,
    "agent": a2a_types.Role.ROLE_AGENT,
    "ROLE_AGENT": a2a_types.Role.ROLE_AGENT,
}


def _to_timestamp(raw: Any) -> Timestamp:
    ts = Timestamp()
    if isinstance(raw, datetime):
        dt = raw if raw.tzinfo is not None else raw.replace(tzinfo=UTC)
        ts.FromDatetime(dt)
        return ts
    if isinstance(raw, str) and raw:
        try:
            ts.FromJsonString(raw)
            return ts
        except ValueError:
            pass
    ts.GetCurrentTime()
    return ts


def _dict_part_to_sdk_part(part: dict[str, Any]) -> a2a_types.Part:
    kwargs: dict[str, Any] = {}
    if part.get("mime_type"):
        kwargs["media_type"] = str(part["mime_type"])
    elif part.get("mediaType"):
        kwargs["media_type"] = str(part["mediaType"])

    if "text" in part and part["text"] is not None:
        kwargs["text"] = str(part["text"])
    elif "data" in part and part["data"] is not None:
        val = Value()
        ParseDict(part["data"], val)
        kwargs["data"] = val
    elif part.get("file_url"):
        kwargs["url"] = str(part["file_url"])
    elif part.get("url"):
        kwargs["url"] = str(part["url"])
    else:
        kwargs["text"] = ""
    return a2a_types.Part(**kwargs)


def _dict_message_to_sdk_message(msg: dict[str, Any], default_context_id: str | None = None) -> a2a_types.Message:
    kwargs: dict[str, Any] = {
        "message_id": str(msg.get("messageId") or msg.get("message_id") or ""),
        "role": _ROLE_MAP.get(str(msg.get("role", "agent")), a2a_types.Role.ROLE_AGENT),
        "parts": [_dict_part_to_sdk_part(p) for p in msg.get("parts", []) if isinstance(p, dict)],
    }
    task_id = msg.get("taskId") or msg.get("task_id")
    if isinstance(task_id, str) and task_id:
        kwargs["task_id"] = task_id
    context_id = msg.get("contextId") or msg.get("context_id") or default_context_id
    if isinstance(context_id, str) and context_id:
        kwargs["context_id"] = context_id
    return a2a_types.Message(**kwargs)


def _dict_to_struct(data: dict[str, Any]) -> Struct:
    struct = Struct()
    ParseDict(data, struct)
    return struct


def build_v1_agent_card(raw_card: dict[str, Any], base_url: str | None = None) -> dict[str, Any]:
    """Validate an agent card JSON object strictly against `a2a.types.AgentCard`.

    When `base_url` is given, updates the first JSONRPC interface URL to point at
    `<base_url>/a2a/tasks`. Emits strict A2A v1.0 ProtoJSON (no extra v0.3 fields).
    """
    card = ParseDict(raw_card, a2a_types.AgentCard(), ignore_unknown_fields=False)
    if base_url:
        interface_url = f"{base_url.rstrip('/')}/a2a/tasks"
        if card.supported_interfaces:
            card.supported_interfaces[0].url = interface_url
        else:
            card.supported_interfaces.append(
                a2a_types.AgentInterface(
                    url=interface_url,
                    protocol_binding="JSONRPC",
                    protocol_version="1.0",
                )
            )

    return MessageToDict(card, preserving_proto_field_name=False)


def build_v03_agent_card(raw_card: dict[str, Any], base_url: str | None = None) -> dict[str, Any]:
    """Build a v0.3-compatible agent card for `/.well-known/agent.json`.

    Starts from the strictly validated v1.0 card so discovery via `A2ACardResolver`
    still succeeds, while formatting top-level `url`, `capabilities`, `securitySchemes`
    (`type: "http", scheme: "bearer"`), and `security` to satisfy A2A v0.3 Pydantic
    clients without misclassifying `bearerAuth` as `mutualTLS`.
    """
    card_dict = build_v1_agent_card(raw_card, base_url=base_url)
    interfaces = card_dict.get("supportedInterfaces") or []
    iface_url = interfaces[0].get("url", "") if interfaces else ""

    v03_card = dict(card_dict)
    v03_card["url"] = iface_url
    v03_card["preferredTransport"] = "JSONRPC"
    v03_card["protocolVersion"] = "0.3.0"
    v03_card["supportsAuthenticatedExtendedCard"] = bool(
        card_dict.get("capabilities", {}).get("extendedAgentCard", False)
    )
    caps = dict(card_dict.get("capabilities") or {})
    caps.pop("extendedAgentCard", None)
    v03_card["capabilities"] = caps

    v03_schemes: dict[str, Any] = {}
    for name, scheme in (card_dict.get("securitySchemes") or {}).items():
        if isinstance(scheme, dict) and "httpAuthSecurityScheme" in scheme:
            http_scheme = dict(scheme["httpAuthSecurityScheme"])
            http_scheme["type"] = "http"
            v03_schemes[name] = http_scheme
        else:
            v03_schemes[name] = scheme
    if v03_schemes:
        v03_card["securitySchemes"] = v03_schemes

    v1_reqs = v03_card.pop("securityRequirements", None)
    if isinstance(v1_reqs, list):
        v03_card["security"] = [
            {
                scheme_name: (
                    scope_val.get("list", []) if isinstance(scope_val, dict) else []
                )
                for scheme_name, scope_val in (req.get("schemes") or {}).items()
            }
            for req in v1_reqs
            if isinstance(req, dict)
        ]

    return v03_card


def task_dict_to_v1_response(result: dict[str, Any]) -> dict[str, Any]:
    """Convert an internal task or message dict into an A2A v1.0 `SendMessageResponse` dict."""
    if result.get("kind") == "message":
        sdk_msg = _dict_message_to_sdk_message(result)
        resp = a2a_types.SendMessageResponse(message=sdk_msg)
        return MessageToDict(resp, preserving_proto_field_name=False)

    context_id = str(result.get("contextId") or result.get("context_id") or "")
    raw_status = result.get("status")
    status_raw: dict[str, Any] = raw_status if isinstance(raw_status, dict) else {}
    state_str = str(status_raw.get("state", "completed")).lower()
    sdk_state = _TASK_STATE_MAP.get(state_str, a2a_types.TaskState.TASK_STATE_UNSPECIFIED)

    status_kwargs: dict[str, Any] = {
        "state": sdk_state,
        "timestamp": _to_timestamp(status_raw.get("timestamp")),
    }
    if isinstance(status_raw.get("message"), dict):
        status_kwargs["message"] = _dict_message_to_sdk_message(
            status_raw["message"], default_context_id=context_id
        )

    sdk_artifacts: list[a2a_types.Artifact] = []
    for art in result.get("artifacts", []):
        if not isinstance(art, dict):
            continue
        art_kwargs: dict[str, Any] = {
            "artifact_id": str(art.get("artifactId") or art.get("artifact_id") or ""),
            "name": str(art.get("name") or ""),
            "parts": [_dict_part_to_sdk_part(p) for p in art.get("parts", []) if isinstance(p, dict)],
        }
        if isinstance(art.get("metadata"), dict) and art["metadata"]:
            art_kwargs["metadata"] = _dict_to_struct(art["metadata"])
        sdk_artifacts.append(a2a_types.Artifact(**art_kwargs))

    sdk_history = [
        _dict_message_to_sdk_message(m, default_context_id=context_id)
        for m in result.get("history", [])
        if isinstance(m, dict)
    ]

    task_kwargs: dict[str, Any] = {
        "id": str(result.get("id") or ""),
        "status": a2a_types.TaskStatus(**status_kwargs),
        "artifacts": sdk_artifacts,
        "history": sdk_history,
    }
    if context_id:
        task_kwargs["context_id"] = context_id
    if isinstance(result.get("metadata"), dict) and result["metadata"]:
        task_kwargs["metadata"] = _dict_to_struct(result["metadata"])

    resp = a2a_types.SendMessageResponse(task=a2a_types.Task(**task_kwargs))
    return MessageToDict(resp, preserving_proto_field_name=False)
