# app/utils/formatters.py

"""Output Formatters

Format code analysis results for different outputs including
Telex messages, GitHub comments, and terminal display.
"""

from typing import List, Dict, Any
from datetime import datetime
import logging

from app.models.analysis import (
    CodeAnalysisResult,
    SecurityIssue,
    PerformanceIssue,
    BestPracticeIssue,
    Severity,
    RiskLevel,
    ApprovalRecommendation
)

logger = logging.getLogger(__name__)


class SummaryFormatter:
    """Format code analysis summaries for various platforms"""
    
    # Emoji mapping for visual indicators
    SEVERITY_EMOJI = {
        Severity.CRITICAL: "🚨",
        Severity.HIGH: "⚠️",
        Severity.MEDIUM: "⚡",
        Severity.LOW: "ℹ️",
        Severity.INFO: "💡"
    }
    
    RISK_EMOJI = {
        RiskLevel.CRITICAL: "🔴",
        RiskLevel.HIGH: "🟠",
        RiskLevel.MEDIUM: "🟡",
        RiskLevel.LOW: "🟢",
        RiskLevel.MINIMAL: "✅"
    }
    
    APPROVAL_EMOJI = {
        ApprovalRecommendation.APPROVE: "✅",
        ApprovalRecommendation.APPROVE_WITH_SUGGESTIONS: "👍",
        ApprovalRecommendation.REQUEST_CHANGES: "🔄",
        ApprovalRecommendation.REJECT: "❌"
    }
    
    @classmethod
    def format_for_telex(cls, analysis: CodeAnalysisResult) -> str:
        """
        Format analysis result as markdown for Telex A2A messages
        
        Args:
            analysis: Complete code analysis result
            
        Returns:
            Formatted markdown string
        """
        sections = []
        
        # Header with PR info
        sections.append(f"# 📋 Code Review Summary - PR #{analysis.pr_number}")
        sections.append("")
        
        # Risk Level Banner
        risk_emoji = cls.RISK_EMOJI.get(analysis.risk_level, "❔")
        sections.append(f"## {risk_emoji} Overall Risk Level: **{analysis.risk_level.value.upper()}**")
        sections.append("")
        
        # Executive Summary
        if analysis.executive_summary:
            sections.append("## 📝 Executive Summary")
            sections.append(analysis.executive_summary)
            sections.append("")
        
        # Metrics Overview
        sections.append("## 📊 Analysis Metrics")
        sections.append(f"- **Files Changed**: {analysis.files_changed}")
        sections.append(f"- **Lines Added**: +{analysis.lines_added}")
        sections.append(f"- **Lines Deleted**: -{analysis.lines_deleted}")
        total_issues = len(analysis.security_findings) + len(analysis.performance_findings) + len(analysis.best_practice_findings)
        sections.append(f"- **Total Issues Found**: {total_issues}")
        sections.append("")
        
        # Security Issues
        if analysis.security_findings:
            sections.append("## 🔒 Security Issues")
            sections.append(cls._format_security_issues(analysis.security_findings))
            sections.append("")
        
        # Performance Issues
        if analysis.performance_findings:
            sections.append("## ⚡ Performance Issues")
            sections.append(cls._format_performance_issues(analysis.performance_findings))
            sections.append("")
        
        # Best Practice Violations
        if analysis.best_practice_findings:
            sections.append("## 📐 Best Practice Issues")
            sections.append(cls._format_best_practice_issues(analysis.best_practice_findings))
            sections.append("")
        
        # Recommendations
        if analysis.key_concerns:
            sections.append("## 💡 Recommendations")
            for rec in analysis.key_concerns[:5]:  # Top 5
                sections.append(f"- {rec}")
            sections.append("")
        
        # Approval Recommendation
        approval_emoji = cls.APPROVAL_EMOJI.get(analysis.approval_recommendation, "❔")
        sections.append(f"## {approval_emoji} Recommendation: **{analysis.approval_recommendation.value.replace('_', ' ').upper()}**")
        sections.append("")
        
        
        # Footer
        sections.append("---")
        sections.append(f"*Analysis completed at {analysis.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}*")
        sections.append(f"*Duration: {analysis.analysis_duration_seconds:.2f}s | LLM: {analysis.llm_provider}/{analysis.llm_model}*")
        
        return "\n".join(sections)
    
    @classmethod
    def _format_security_issues(cls, issues: List[SecurityIssue]) -> str:
        """Format security issues as markdown list"""
        lines = []
        
        # Group by severity
        by_severity = {}
        for issue in issues:
            severity = issue.severity
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(issue)
        
        # Format by severity (critical first)
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if severity in by_severity:
                emoji = cls.SEVERITY_EMOJI.get(severity, "•")
                lines.append(f"\n### {emoji} {severity.value.upper()} ({len(by_severity[severity])} issues)")
                
                for issue in by_severity[severity][:3]:  # Top 3 per severity
                    lines.append(f"\n**{issue.title}**")
                    lines.append(f"- File: `{issue.file}:{issue.line_number or '?'}`")
                    lines.append(f"- {issue.description}")
                    if issue.code_snippet:
                        lines.append(f"```\n{issue.code_snippet[:150]}\n```")
                    lines.append(f"- 💡 {issue.recommendation}")
                    if issue.cwe_id:
                        lines.append(f"- � [{issue.cwe_id}](https://cwe.mitre.org/data/definitions/{issue.cwe_id.replace('CWE-', '')}.html)")
                
                if len(by_severity[severity]) > 3:
                    lines.append(f"\n*...and {len(by_severity[severity]) - 3} more {severity.value} issues*")
        
        return "\n".join(lines)
    
    @classmethod
    def _format_performance_issues(cls, issues: List[PerformanceIssue]) -> str:
        """Format performance issues as markdown list"""
        lines = []
        
        # Group by impact
        by_impact = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for issue in issues:
            impact = issue.impact.upper()
            if impact in by_impact:
                by_impact[impact].append(issue)
        
        # Format by impact
        for impact in ["HIGH", "MEDIUM", "LOW"]:
            if by_impact[impact]:
                emoji = "🔥" if impact == "HIGH" else "⚡" if impact == "MEDIUM" else "💡"
                lines.append(f"\n### {emoji} {impact} IMPACT ({len(by_impact[impact])} issues)")
                
                for issue in by_impact[impact][:3]:  # Top 3 per impact
                    lines.append(f"\n**{issue.title}**")
                    lines.append(f"- File: `{issue.file}:{issue.line_number or '?'}`")
                    lines.append(f"- {issue.description}")
                    if issue.estimated_impact:
                        lines.append(f"- 📈 Impact: {issue.estimated_impact}")
                    if issue.code_snippet:
                        lines.append(f"```\n{issue.code_snippet[:150]}\n```")
                    lines.append(f"- 💡 {issue.recommendation}")
                
                if len(by_impact[impact]) > 3:
                    lines.append(f"\n*...and {len(by_impact[impact]) - 3} more {impact.lower()} impact issues*")
        
        return "\n".join(lines)
    
    @classmethod
    def _format_best_practice_issues(cls, issues: List[BestPracticeIssue]) -> str:
        """Format best practice issues as markdown list"""
        lines = []
        
        # Group by category
        by_category = {}
        for issue in issues:
            category = issue.category or "general"
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(issue)
        
        # Format by category
        for category, cat_issues in by_category.items():
            lines.append(f"\n### 📐 {category.replace('_', ' ').title()} ({len(cat_issues)} issues)")
            
            for issue in cat_issues[:3]:  # Top 3 per category
                emoji = cls.SEVERITY_EMOJI.get(issue.severity, "•")
                lines.append(f"\n{emoji} **{issue.title}**")
                lines.append(f"- File: `{issue.file}:{issue.line_number or '?'}`")
                lines.append(f"- {issue.description}")
                if issue.code_snippet:
                    lines.append(f"```\n{issue.code_snippet[:150]}\n```")
                lines.append(f"- 💡 {issue.recommendation}")
            
            if len(cat_issues) > 3:
                lines.append(f"\n*...and {len(cat_issues) - 3} more {category} issues*")
        
        return "\n".join(lines)
    
    @classmethod
    def format_for_github_comment(cls, analysis: CodeAnalysisResult) -> str:
        """
        Format analysis result for GitHub PR comments
        
        Args:
            analysis: Complete code analysis result
            
        Returns:
            Formatted markdown for GitHub
        """
        # Similar to Telex format but with GitHub-specific adjustments
        return cls.format_for_telex(analysis)
    
    @classmethod
    def format_summary_table(cls, analysis: CodeAnalysisResult) -> str:
        """
        Format a compact summary table
        
        Args:
            analysis: Complete code analysis result
            
        Returns:
            Markdown table
        """
        lines = []
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Risk Level | {cls.RISK_EMOJI.get(analysis.risk_level, '')} {analysis.risk_level.value.upper()} |")
        lines.append(f"| Security Issues | {len(analysis.security_findings)} |")
        lines.append(f"| Performance Issues | {len(analysis.performance_findings)} |")
        lines.append(f"| Best Practice Issues | {len(analysis.best_practice_findings)} |")
        lines.append(f"| Recommendation | {cls.APPROVAL_EMOJI.get(analysis.approval_recommendation, '')} {analysis.approval_recommendation.value.replace('_', ' ')} |")
        
        return "\n".join(lines)
    
    @classmethod
    def format_plain_text(cls, analysis: CodeAnalysisResult) -> str:
        """
        Format as plain text (no markdown)
        
        Args:
            analysis: Complete code analysis result
            
        Returns:
            Plain text summary
        """
        lines = []
        lines.append(f"Code Review Summary - PR #{analysis.pr_number}")
        lines.append("=" * 60)
        lines.append(f"Risk Level: {analysis.risk_level.value.upper()}")
        lines.append(f"Security Issues: {len(analysis.security_findings)}")
        lines.append(f"Performance Issues: {len(analysis.performance_findings)}")
        lines.append(f"Best Practice Issues: {len(analysis.best_practice_findings)}")
        lines.append(f"Recommendation: {analysis.approval_recommendation.value.replace('_', ' ').upper()}")
        lines.append("")
        
        if analysis.executive_summary:
            lines.append("Executive Summary:")
            lines.append(analysis.executive_summary)
        
        return "\n".join(lines)