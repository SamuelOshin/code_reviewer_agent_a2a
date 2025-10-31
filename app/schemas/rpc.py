# app/schemas/rpc.py

"""JSON-RPC Method Schemas

Pydantic schemas for JSON-RPC method requests and responses.
These are used for validation and documentation of the RPC interface.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, HttpUrl

from app.models.analysis import (
    SecurityIssue,
    PerformanceIssue,
    BestPracticeIssue,
    RiskLevel,
    ApprovalRecommendation
)


# ============================================================================
# analyze_pr Method
# ============================================================================

class AnalyzePRRequest(BaseModel):
    """Request schema for analyze_pr method"""
    
    pr_url: HttpUrl = Field(
        ...,
        description="GitHub PR URL (e.g., https://github.com/owner/repo/pull/123)"
    )
    send_to_telex: bool = Field(
        default=True,
        description="Whether to send results to Telex"
    )
    focus_areas: Optional[List[str]] = Field(
        default=None,
        description="Specific areas to focus on (security, performance, best_practices)"
    )


class AnalyzePRResponse(BaseModel):
    """Response schema for analyze_pr method"""
    
    analysis_id: str = Field(..., description="Unique analysis ID")
    pr_number: int = Field(..., description="Pull request number")
    pr_url: str = Field(..., description="Pull request URL")
    pr_title: str = Field(..., description="Pull request title")
    pr_author: str = Field(..., description="Pull request author")
    executive_summary: str = Field(..., description="Executive summary of findings")
    risk_level: RiskLevel = Field(..., description="Overall risk level")
    approval_recommendation: ApprovalRecommendation = Field(..., description="Approval recommendation")
    
    security_issues_count: int = Field(..., description="Total security issues found")
    performance_issues_count: int = Field(..., description="Total performance issues found")
    best_practice_issues_count: int = Field(..., description="Total best practice issues found")
    
    metrics: Dict[str, Any] = Field(..., description="Analysis metrics")
    recommendations: List[str] = Field(..., description="Top recommendations")
    
    analyzed_at: datetime = Field(..., description="Analysis timestamp")
    analysis_duration_seconds: float = Field(..., description="Analysis duration")
    
    telex_sent: bool = Field(default=False, description="Whether results were sent to Telex")


# ============================================================================
# get_analysis_status Method
# ============================================================================

class GetAnalysisStatusRequest(BaseModel):
    """Request schema for get_analysis_status method"""
    
    analysis_id: str = Field(..., description="Analysis ID to check")


class GetAnalysisStatusResponse(BaseModel):
    """Response schema for get_analysis_status method"""
    
    analysis_id: str = Field(..., description="Analysis ID")
    status: str = Field(..., description="Analysis status (pending, running, completed, failed)")
    pr_url: Optional[str] = Field(None, description="PR URL if available")
    started_at: Optional[datetime] = Field(None, description="Start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    error: Optional[str] = Field(None, description="Error message if failed")


# ============================================================================
# list_analyses Method
# ============================================================================

class ListAnalysesRequest(BaseModel):
    """Request schema for list_analyses method"""
    
    limit: int = Field(default=10, ge=1, le=100, description="Max results to return")
    offset: int = Field(default=0, ge=0, description="Pagination offset")
    status_filter: Optional[str] = Field(None, description="Filter by status")


class AnalysisSummary(BaseModel):
    """Summary of a single analysis"""
    
    analysis_id: str
    pr_number: int
    pr_url: str
    pr_title: str
    risk_level: RiskLevel
    approval_recommendation: ApprovalRecommendation
    analyzed_at: datetime
    total_issues: int


class ListAnalysesResponse(BaseModel):
    """Response schema for list_analyses method"""
    
    analyses: List[AnalysisSummary] = Field(..., description="List of analyses")
    total: int = Field(..., description="Total count")
    limit: int = Field(..., description="Limit applied")
    offset: int = Field(..., description="Offset applied")


# ============================================================================
# get_analysis_details Method
# ============================================================================

class GetAnalysisDetailsRequest(BaseModel):
    """Request schema for get_analysis_details method"""
    
    analysis_id: str = Field(..., description="Analysis ID")


class GetAnalysisDetailsResponse(BaseModel):
    """Response schema for get_analysis_details method"""
    
    analysis_id: str
    pr_number: int
    pr_url: str
    pr_title: str
    pr_author: str
    pr_state: str
    executive_summary: str
    risk_level: RiskLevel
    approval_recommendation: ApprovalRecommendation
    
    security_issues: List[SecurityIssue]
    performance_issues: List[PerformanceIssue]
    best_practice_issues: List[BestPracticeIssue]
    
    recommendations: List[str]
    metrics: Dict[str, Any]
    
    analyzed_at: datetime
    analysis_duration_seconds: float
    llm_provider: str
    llm_model: str


# ============================================================================
# Introspection Methods
# ============================================================================

class IntrospectRequest(BaseModel):
    """Request schema for introspect method"""
    pass


class IntrospectResponse(BaseModel):
    """Response schema for introspect method"""
    
    methods: List[str] = Field(..., description="Available JSON-RPC methods")
    count: int = Field(..., description="Number of methods")
    version: str = Field(..., description="JSON-RPC version")
    agent_name: str = Field(default="Code Review Agent", description="Agent name")
    agent_version: str = Field(default="1.0.0", description="Agent version")
