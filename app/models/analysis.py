# app/models/analysis.py

"""Code Analysis Result Models

Pydantic models for code analysis results including security, performance,
and best practice findings.
"""

from typing import Optional, List
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Issue severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(str, Enum):
    """Overall risk assessment"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class ApprovalRecommendation(str, Enum):
    """PR approval recommendations"""
    APPROVE = "approve"
    APPROVE_WITH_SUGGESTIONS = "approve_with_suggestions"
    REQUEST_CHANGES = "request_changes"
    REJECT = "reject"


class SecurityIssue(BaseModel):
    """Security vulnerability found in code"""
    severity: Severity
    title: str
    description: str
    file: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    references: List[str] = []


class PerformanceIssue(BaseModel):
    """Performance issue found in code"""
    severity: Severity
    title: str
    description: str
    file: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    impact: str
    recommendation: str
    estimated_impact: Optional[str] = None  # e.g., "50% slower", "2x memory usage"


class BestPracticeIssue(BaseModel):
    """Best practice violation"""
    category: str  # code_quality, maintainability, readability, testing
    severity: Severity
    title: str
    description: str
    file: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str
    references: List[str] = []


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
    security_findings: List[SecurityIssue] = []
    performance_findings: List[PerformanceIssue] = []
    best_practice_findings: List[BestPracticeIssue] = []
    
    # Metrics
    files_changed: int
    lines_added: int
    lines_deleted: int
    
    # Recommendations
    approval_recommendation: ApprovalRecommendation
    key_concerns: List[str] = []
    positive_aspects: List[str] = []
    suggested_reviewers: List[str] = []
    
    # Metadata
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    analysis_duration_seconds: float
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    
    class Config:
        json_schema_extra = {
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
