# app/services/code_analyzer.py

"""Code Analysis Orchestration Service

Main service that orchestrates the complete code review process:
1. Fetch PR data from GitHub via MCP
2. Parse diff content
3. Run rule-based checks (security, performance)
4. Run LLM-powered analysis
5. Generate executive summary
6. Build comprehensive CodeAnalysisResult
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import logging
import time

from app.core.config import settings
from app.core.exceptions import AnalysisError, GitHubMCPError, LLMError
from app.models.github import PullRequest, PullRequestFile
from app.models.analysis import (
    CodeAnalysisResult,
    SecurityIssue,
    PerformanceIssue,
    BestPracticeIssue,
    Severity,
    RiskLevel,
    ApprovalRecommendation
)
from app.services.github_mcp import GitHubMCPService
from app.services.llm_service import LLMService
from app.utils.diff_parser import DiffParser, FileDiff
from app.utils.security_rules import SecurityChecker
from app.utils.performance_rules import PerformanceChecker

logger = logging.getLogger(__name__)


class CodeAnalyzerService:
    """Main code analysis orchestration service"""
    
    def __init__(self):
        self.llm_service = LLMService()
        logger.info("CodeAnalyzerService initialized")
    
    async def analyze_pr(self, pr_url: str) -> CodeAnalysisResult:
        """
        Analyze a GitHub Pull Request
        
        Args:
            pr_url: Full GitHub PR URL (e.g., https://github.com/owner/repo/pull/123)
            
        Returns:
            Complete CodeAnalysisResult with all findings and recommendations
            
        Raises:
            AnalysisError: If analysis fails
            GitHubMCPError: If GitHub data fetch fails
            LLMError: If LLM analysis fails
        """
        start_time = time.time()
        
        try:
            logger.info(f"Starting analysis for PR: {pr_url}")
            
            # Step 1: Fetch PR data from GitHub
            logger.info("Step 1: Fetching PR data from GitHub...")
            pr_data, diff_content, files = await self._fetch_pr_data(pr_url)
            logger.info(f"PR data fetched successfully: PR#{pr_data.number}")
            
            # Step 2: Parse diff content
            logger.info("Step 2: Parsing diff content...")
            parsed_diffs = DiffParser.parse(diff_content)
            logger.info(f"Parsed {len(parsed_diffs)} file diffs")
            
            # Step 3: Prepare file changes for analysis
            logger.info("Step 3: Preparing file changes...")
            file_changes = self._prepare_file_changes(parsed_diffs)
            logger.info(f"Prepared {len(file_changes)} file changes")
            
            # Step 4: Run rule-based checks (fast, synchronous)
            logger.info("Step 4: Running rule-based checks...")
            rule_security_issues = SecurityChecker.check(file_changes)
            rule_performance_issues = PerformanceChecker.check(file_changes)
            
            logger.info(f"Rule-based checks: {len(rule_security_issues)} security, {len(rule_performance_issues)} performance issues")
            
            # Step 5: Run LLM-powered analysis (slower, comprehensive)
            llm_security_issues = await self.llm_service.analyze_security(diff_content, files)
            llm_performance_issues = await self.llm_service.analyze_performance(diff_content, files)
            llm_best_practice_issues = await self.llm_service.analyze_best_practices(diff_content, files)
            
            logger.info(f"LLM analysis: {len(llm_security_issues)} security, {len(llm_performance_issues)} performance, {len(llm_best_practice_issues)} best practice issues")
            
            # Step 6: Merge and deduplicate findings
            all_security_issues = self._merge_security_issues(rule_security_issues, llm_security_issues)
            all_performance_issues = self._merge_performance_issues(rule_performance_issues, llm_performance_issues)
            all_best_practice_issues = llm_best_practice_issues  # Only from LLM
            
            # Step 7: Calculate risk level
            risk_level = self._calculate_risk_level(all_security_issues, all_performance_issues)
            
            # Step 8: Generate executive summary
            executive_summary = await self.llm_service.generate_summary(
                pr_title=pr_data.title,
                pr_author=pr_data.user.login if pr_data.user else "unknown",
                pr_description=pr_data.body or "",
                security_issues=all_security_issues,
                performance_issues=all_performance_issues,
                best_practice_issues=all_best_practice_issues,
                total_additions=pr_data.additions,
                total_deletions=pr_data.deletions,
                changed_files=pr_data.changed_files
            )
            
            # Step 9: Generate recommendations
            recommendations = self._generate_recommendations(
                all_security_issues,
                all_performance_issues,
                all_best_practice_issues
            )
            
            # Step 10: Determine approval recommendation
            approval_recommendation = self._determine_approval(
                risk_level,
                all_security_issues,
                all_performance_issues
            )
            
            # Step 11: Build metrics
            metrics = {
                'files_changed': pr_data.changed_files,
                'lines_added': pr_data.additions,
                'lines_deleted': pr_data.deletions,
                'total_issues': len(all_security_issues) + len(all_performance_issues) + len(all_best_practice_issues),
                'critical_security_issues': len([s for s in all_security_issues if s.severity == Severity.CRITICAL]),
                'high_security_issues': len([s for s in all_security_issues if s.severity == Severity.HIGH]),
                'high_performance_issues': len([p for p in all_performance_issues if p.impact == "HIGH"]),
            }
            
            # Step 12: Build final result
            analysis_duration = time.time() - start_time
            
            # Extract repository from PR URL (format: https://github.com/owner/repo/pull/number)
            repo_parts = pr_data.html_url.split('/')
            repository = f"{repo_parts[3]}/{repo_parts[4]}" if len(repo_parts) > 4 else "unknown/unknown"
            
            result = CodeAnalysisResult(
                pr_number=pr_data.number,
                pr_title=pr_data.title,
                author=pr_data.user.login if pr_data.user else "unknown",
                repository=repository,
                executive_summary=executive_summary,
                risk_level=risk_level,
                security_findings=all_security_issues,
                performance_findings=all_performance_issues,
                best_practice_findings=all_best_practice_issues,
                files_changed=pr_data.changed_files,
                lines_added=pr_data.additions,
                lines_deleted=pr_data.deletions,
                approval_recommendation=approval_recommendation,
                key_concerns=recommendations,  # Map recommendations to key_concerns
                analyzed_at=datetime.now(timezone.utc),
                analysis_duration_seconds=analysis_duration,
                llm_provider=settings.LLM_PROVIDER,
                llm_model=settings.LLM_MODEL
            )
            
            logger.info(f"Analysis completed in {analysis_duration:.2f}s - Risk: {risk_level.value}, Recommendation: {approval_recommendation.value}")
            return result
            
        except GitHubMCPError as e:
            logger.error(f"GitHub MCP error during analysis: {e}")
            raise
        except LLMError as e:
            logger.error(f"LLM error during analysis: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during analysis: {e}")
            raise AnalysisError(f"Analysis failed: {str(e)}")
    
    async def _fetch_pr_data(self, pr_url: str) -> tuple[PullRequest, str, List[PullRequestFile]]:
        """
        Fetch PR data from GitHub via API
        
        Args:
            pr_url: GitHub PR URL
            
        Returns:
            Tuple of (PullRequest, diff_content, files)
        """
        try:
            logger.info("Entering GitHubMCPService context manager...")
            async with GitHubMCPService() as github_service:
                logger.info("GitHubMCPService initialized, parsing PR URL...")
                # Parse PR URL to extract owner, repo, and PR number
                owner, repo, pr_number = github_service.parse_pr_url(pr_url)
                logger.info(f"Parsed URL: {owner}/{repo}#{pr_number}")
                
                # Fetch PR and diff data
                logger.info("Fetching PR and diff data...")
                pr, pr_diff = await github_service.get_pr_with_diff(owner, repo, pr_number)
                logger.info(f"Successfully fetched PR and diff data")
                
                return pr, pr_diff.raw_diff, pr_diff.files
        except Exception as e:
            logger.error(f"Error in _fetch_pr_data: {type(e).__name__}: {e}", exc_info=True)
            raise
    
    def _prepare_file_changes(self, parsed_diffs: List[FileDiff]) -> List[Dict[str, Any]]:
        """
        Convert parsed diffs to format expected by rule checkers
        
        Args:
            parsed_diffs: List of FileDiff objects from DiffParser
            
        Returns:
            List of file change dictionaries
        """
        file_changes = []
        
        for diff in parsed_diffs:
            file_changes.append({
                'filename': diff.filename,
                'status': diff.status,
                'language': diff.language,
                'additions': diff.additions,
                'deletions': diff.deletions,
                'hunks': diff.hunks
            })
        
        return file_changes
    
    def _merge_security_issues(
        self,
        rule_issues: List[SecurityIssue],
        llm_issues: List[SecurityIssue]
    ) -> List[SecurityIssue]:
        """
        Merge and deduplicate security issues from rule-based and LLM analysis
        
        Args:
            rule_issues: Issues from rule-based checks
            llm_issues: Issues from LLM analysis
            
        Returns:
            Deduplicated list of security issues
        """
        merged = list(rule_issues)  # Start with all rule-based issues
        
        # Add LLM issues if not duplicates
        for llm_issue in llm_issues:
            is_duplicate = False
            
            for existing in merged:
                # Check if same file, line, and similar title
                if (existing.file == llm_issue.file and
                    existing.line_number == llm_issue.line_number and
                    self._titles_similar(existing.title, llm_issue.title)):
                    is_duplicate = True
                    # If LLM found higher severity, update
                    if self._severity_higher(llm_issue.severity, existing.severity):
                        existing.severity = llm_issue.severity
                        existing.recommendation = llm_issue.recommendation
                    break
            
            if not is_duplicate:
                merged.append(llm_issue)
        
        # Sort by severity (CRITICAL first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        merged.sort(key=lambda x: severity_order.get(x.severity, 999))
        
        return merged
    
    def _merge_performance_issues(
        self,
        rule_issues: List[PerformanceIssue],
        llm_issues: List[PerformanceIssue]
    ) -> List[PerformanceIssue]:
        """
        Merge and deduplicate performance issues
        
        Args:
            rule_issues: Issues from rule-based checks
            llm_issues: Issues from LLM analysis
            
        Returns:
            Deduplicated list of performance issues
        """
        merged = list(rule_issues)
        
        for llm_issue in llm_issues:
            is_duplicate = False
            
            for existing in merged:
                if (existing.file == llm_issue.file and
                    existing.line_number == llm_issue.line_number and
                    self._titles_similar(existing.title, llm_issue.title)):
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                merged.append(llm_issue)
        
        # Sort by impact (HIGH first)
        impact_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        merged.sort(key=lambda x: impact_order.get(x.impact, 999))
        
        return merged
    
    def _titles_similar(self, title1: str, title2: str) -> bool:
        """
        Check if two issue titles are similar (fuzzy matching)
        
        Args:
            title1: First title
            title2: Second title
            
        Returns:
            True if titles are similar
        """
        # Simple word overlap check
        words1 = set(title1.lower().split())
        words2 = set(title2.lower().split())
        
        if not words1 or not words2:
            return False
        
        overlap = len(words1 & words2)
        min_length = min(len(words1), len(words2))
        
        return overlap / min_length > 0.5  # 50% word overlap
    
    def _severity_higher(self, sev1: Severity, sev2: Severity) -> bool:
        """Check if sev1 is higher severity than sev2"""
        severity_rank = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
        return severity_rank.get(sev1, 0) > severity_rank.get(sev2, 0)
    
    def _calculate_risk_level(
        self,
        security_issues: List[SecurityIssue],
        performance_issues: List[PerformanceIssue]
    ) -> RiskLevel:
        """
        Calculate overall risk level based on findings
        
        Args:
            security_issues: All security issues
            performance_issues: All performance issues
            
        Returns:
            Overall risk level
        """
        critical_security = len([s for s in security_issues if s.severity == Severity.CRITICAL])
        high_security = len([s for s in security_issues if s.severity == Severity.HIGH])
        high_performance = len([p for p in performance_issues if p.impact == "HIGH"])
        
        # Risk calculation logic
        if critical_security > 0:
            return RiskLevel.CRITICAL
        
        if high_security >= 3 or (high_security >= 1 and high_performance >= 2):
            return RiskLevel.HIGH
        
        if high_security >= 1 or high_performance >= 1:
            return RiskLevel.MEDIUM
        
        if security_issues or performance_issues:
            return RiskLevel.LOW
        
        return RiskLevel.MINIMAL
    
    def _generate_recommendations(
        self,
        security_issues: List[SecurityIssue],
        performance_issues: List[PerformanceIssue],
        best_practice_issues: List[BestPracticeIssue]
    ) -> List[str]:
        """
        Generate prioritized list of recommendations
        
        Args:
            security_issues: All security issues
            performance_issues: All performance issues
            best_practice_issues: All best practice issues
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        # Critical security first
        critical_security = [s for s in security_issues if s.severity == Severity.CRITICAL]
        if critical_security:
            recommendations.append(f"🚨 CRITICAL: Address {len(critical_security)} critical security issue(s) immediately")
        
        # High severity security
        high_security = [s for s in security_issues if s.severity == Severity.HIGH]
        if high_security:
            recommendations.append(f"⚠️ HIGH: Fix {len(high_security)} high-severity security issue(s) before merging")
        
        # High impact performance
        high_performance = [p for p in performance_issues if p.impact == "HIGH"]
        if high_performance:
            recommendations.append(f"⚡ PERFORMANCE: Optimize {len(high_performance)} high-impact performance issue(s)")
        
        # Best practices
        if best_practice_issues:
            top_categories = {}
            for issue in best_practice_issues:
                top_categories[issue.category] = top_categories.get(issue.category, 0) + 1
            
            if top_categories:
                top_category = max(top_categories.items(), key=lambda x: x[1])
                recommendations.append(f"📐 BEST PRACTICES: Focus on {top_category[0]} ({top_category[1]} issue(s))")
        
        # Positive reinforcement if minimal issues
        total_issues = len(security_issues) + len(performance_issues) + len(best_practice_issues)
        if total_issues <= 2:
            recommendations.append("✅ Overall code quality is good with minimal issues")
        
        return recommendations[:5]  # Top 5 recommendations
    
    def _determine_approval(
        self,
        risk_level: RiskLevel,
        security_issues: List[SecurityIssue],
        performance_issues: List[PerformanceIssue]
    ) -> ApprovalRecommendation:
        """
        Determine approval recommendation based on risk and issues
        
        Args:
            risk_level: Overall risk level
            security_issues: All security issues
            performance_issues: All performance issues
            
        Returns:
            Approval recommendation
        """
        critical_security = len([s for s in security_issues if s.severity == Severity.CRITICAL])
        high_security = len([s for s in security_issues if s.severity == Severity.HIGH])
        
        # Critical security = REJECT
        if critical_security > 0:
            return ApprovalRecommendation.REJECT
        
        # HIGH risk or 2+ high security = REQUEST_CHANGES
        if risk_level == RiskLevel.HIGH or high_security >= 2:
            return ApprovalRecommendation.REQUEST_CHANGES
        
        # MEDIUM risk or 1 high security = APPROVE_WITH_SUGGESTIONS
        if risk_level == RiskLevel.MEDIUM or high_security >= 1:
            return ApprovalRecommendation.APPROVE_WITH_SUGGESTIONS
        
        # Everything else = APPROVE
        return ApprovalRecommendation.APPROVE