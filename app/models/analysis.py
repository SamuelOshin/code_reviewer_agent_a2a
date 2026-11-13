# app/models/analysis.py

"""Code Analysis Result Models

Pydantic models for code analysis results including security, performance,
and best practice findings.
"""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Issue severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(StrEnum):
    """Overall risk assessment"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class ApprovalRecommendation(StrEnum):
    """PR approval recommendations"""
    APPROVE = "approve"
    APPROVE_WITH_SUGGESTIONS = "approve_with_suggestions"
    REQUEST_CHANGES = "request_changes"
    REJECT = "reject"
    # The review did not finish (an LLM step failed or saw only part of the diff),
    # so it cannot vouch for the PR. Never shown as an approval (P1-06).
    INCOMPLETE = "incomplete"


class AnalysisStatus(StrEnum):
    """Whether every part of the review ran on the whole diff (P1-06)"""
    COMPLETE = "complete"
    # Some LLM steps failed or saw a truncated diff; rule findings are still reported
    INCOMPLETE = "incomplete"
    # No LLM findings step succeeded; only rule-based findings are reported
    FAILED = "failed"


class SecurityIssue(BaseModel):
    """Security vulnerability found in code"""
    severity: Severity
    title: str
    description: str
    file: str
    line_number: int | None = None
    code_snippet: str | None = None
    recommendation: str
    cwe_id: str | None = None  # Common Weakness Enumeration ID
    references: list[str] = []


class PerformanceIssue(BaseModel):
    """Performance issue found in code"""
    severity: Severity
    title: str
    description: str
    file: str
    line_number: int | None = None
    code_snippet: str | None = None
    impact: str  # Free-text description of the effect. Risk is driven by `severity`, not this field.
    recommendation: str
    estimated_impact: str | None = None  # e.g., "50% slower", "2x memory usage"


class BestPracticeIssue(BaseModel):
    """Best practice violation"""
    category: str  # code_quality, maintainability, readability, testing
    severity: Severity
    title: str
    description: str
    file: str
    line_number: int | None = None
    code_snippet: str | None = None
    recommendation: str
    references: list[str] = []


class CodeAnalysisResult(BaseModel):
    """Complete code analysis result for a Pull Request"""
    
    # PR Identification
    pr_number: int
    pr_title: str
    author: str
    repository: str
    
    # Executive Summary
    executive_summary: str
    risk_level: RiskLevel
    
    # Findings
    security_findings: list[SecurityIssue] = []
    performance_findings: list[PerformanceIssue] = []
    best_practice_findings: list[BestPracticeIssue] = []
    
    # Metrics
    files_changed: int
    lines_added: int
    lines_deleted: int
    
    # Recommendations
    approval_recommendation: ApprovalRecommendation
    # Fail-closed reporting (P1-06). `incomplete_reasons` says what did not run, in
    # words safe to post publicly (no model output, no PR code).
    status: AnalysisStatus = AnalysisStatus.COMPLETE
    incomplete_reasons: list[str] = []
    diff_truncated: bool = False
    diff_chars_total: int | None = None
    diff_chars_reviewed_by_llm: int | None = None
    key_concerns: list[str] = []
    positive_aspects: list[str] = []
    suggested_reviewers: list[str] = []
    
    # Metadata
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    analysis_duration_seconds: float
    llm_provider: str | None = None
    llm_model: str | None = None
    
    model_config = ConfigDict(json_schema_extra={
            "example": {
                "pr_number": 123,
                "pr_title": "Add new authentication system",
                "author": "john_doe",
                "repository": "owner/repo",
                "executive_summary": "This PR introduces a new authentication system with JWT tokens. Overall implementation is solid, but there are some security concerns that should be addressed.",
                "risk_level": "medium",
                "security_findings": [
                    {
                        "severity": "high",
                        "title": "Hardcoded secret key",
                        "description": "Secret key is hardcoded in config.py",
                        "file": "app/config.py",
                        "line_number": 15,
                        "recommendation": "Move secret key to environment variables"
                    }
                ],
                "files_changed": 8,
                "lines_added": 245,
                "lines_deleted": 32,
                "approval_recommendation": "request_changes",
                "key_concerns": ["Hardcoded secrets", "Missing input validation"],
                "positive_aspects": ["Well structured", "Good test coverage"],
                "analyzed_at": "2024-01-15T10:30:00Z",
                "analysis_duration_seconds": 12.5
            }
        }
    )
