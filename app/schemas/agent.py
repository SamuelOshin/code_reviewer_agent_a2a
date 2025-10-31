# app/schemas/agent.py

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class AnalysisRequest(BaseModel):
    """Request schema for PR analysis"""
    pr_url: str = Field(..., description="Full GitHub PR URL")
    focus_areas: List[str] = Field(
        default=["security", "performance", "best_practices"],
        description="Areas to focus analysis on"
    )
    include_suggestions: bool = Field(
        default=True,
        description="Include improvement suggestions"
    )

class SecurityFinding(BaseModel):
    """Security issue found in code"""
    severity: str  # critical, high, medium, low
    title: str
    description: str
    file: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str

class PerformanceFinding(BaseModel):
    """Performance issue found in code"""
    severity: str  # critical, high, medium, low
    title: str
    description: str
    file: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    impact: str
    recommendation: str

class BestPracticeFinding(BaseModel):
    """Best practice violation"""
    category: str  # code_quality, maintainability, readability
    title: str
    description: str
    file: str
    line_number: Optional[int] = None
    recommendation: str

class AnalysisResponse(BaseModel):
    """Complete analysis response"""
    pr_number: int
    pr_title: str
    author: str
    repository: str
    
    # Summary
    executive_summary: str
    risk_level: str  # low, medium, high, critical
    
    # Findings
    security_findings: List[SecurityFinding] = []
    performance_findings: List[PerformanceFinding] = []
    best_practice_findings: List[BestPracticeFinding] = []
    
    # Metrics
    files_changed: int
    lines_added: int
    lines_deleted: int
    
    # Recommendations
    approval_recommendation: str  # approve, approve_with_suggestions, request_changes
    key_concerns: List[str] = []
    positive_aspects: List[str] = []
    
    # Metadata
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    analysis_duration_seconds: float