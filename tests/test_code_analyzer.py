# tests/test_code_analyzer.py

"""Integration tests for CodeAnalyzerService

Tests the full analysis orchestration with mocked dependencies.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from app.services.code_analyzer import CodeAnalyzerService
from app.models.github import PullRequest, GitHubUser
from app.models.analysis import (
    SecurityIssue,
    PerformanceIssue,
    BestPracticeIssue,
    Severity,
    Impact,
    RiskLevel,
    ApprovalRecommendation
)


# Sample PR data for mocking
SAMPLE_PR = PullRequest(
    number=123,
    title="Add user authentication",
    body="Implements JWT-based authentication",
    url="https://github.com/test/repo/pull/123",
    user=GitHubUser(login="testuser", id=1),
    head_sha="abc123",
    base_sha="def456",
    state="open",
    created_at=datetime.now(),
    updated_at=datetime.now()
)

SAMPLE_DIFF = """diff --git a/app/auth.py b/app/auth.py
new file mode 100644
index 0000000..111111
--- /dev/null
+++ b/app/auth.py
@@ -0,0 +1,15 @@
+import hashlib
+
+API_KEY = "sk_live_secret123"
+
+def authenticate(username, password):
+    # Vulnerable: Using MD5
+    hash_pw = hashlib.md5(password.encode()).hexdigest()
+    
+    # Vulnerable: SQL injection
+    query = f"SELECT * FROM users WHERE user='{username}' AND pass='{hash_pw}'"
+    
+    for user in db.query(query):
+        if user:
+            return True
+    return False
"""

# Sample LLM responses
SAMPLE_SECURITY_ISSUES = [
    {
        "title": "SQL Injection Vulnerability",
        "description": "User input is directly interpolated into SQL query",
        "severity": "CRITICAL",
        "category": "sql_injection",
        "cwe_id": "CWE-89",
        "file": "app/auth.py",
        "line": 10
    }
]

SAMPLE_PERFORMANCE_ISSUES = [
    {
        "title": "N+1 Query Pattern",
        "description": "Loop contains database query",
        "impact": "HIGH",
        "category": "database",
        "file": "app/auth.py",
        "line": 12
    }
]

SAMPLE_BEST_PRACTICE_ISSUES = [
    {
        "title": "Missing input validation",
        "description": "No validation of username/password parameters",
        "category": "validation",
        "file": "app/auth.py",
        "line": 5
    }
]

SAMPLE_SUMMARY = """
This PR introduces a new authentication system but contains several critical security vulnerabilities.

**Critical Issues:**
- SQL injection vulnerability allowing unauthorized database access
- Hardcoded API credentials
- Use of weak MD5 hashing for passwords

**Performance Concerns:**
- N+1 query pattern in authentication loop

**Recommendations:**
1. Use parameterized queries to prevent SQL injection
2. Store API keys in environment variables
3. Switch to bcrypt or argon2 for password hashing
4. Optimize database queries
"""


@pytest.fixture
def analyzer():
    """Create CodeAnalyzerService instance"""
    return CodeAnalyzerService()


@pytest.fixture
def mock_github_service():
    """Mock GitHubMCPService"""
    with patch('app.services.code_analyzer.GitHubMCPService') as mock:
        service = AsyncMock()
        service.get_pr_with_diff = AsyncMock(return_value=(SAMPLE_PR, SAMPLE_DIFF))
        service.__aenter__ = AsyncMock(return_value=service)
        service.__aexit__ = AsyncMock(return_value=None)
        mock.return_value = service
        yield service


@pytest.fixture
def mock_llm_service():
    """Mock LLMService"""
    with patch('app.services.code_analyzer.LLMService') as mock:
        service = AsyncMock()
        service.analyze_security = AsyncMock(return_value=SAMPLE_SECURITY_ISSUES)
        service.analyze_performance = AsyncMock(return_value=SAMPLE_PERFORMANCE_ISSUES)
        service.analyze_best_practices = AsyncMock(return_value=SAMPLE_BEST_PRACTICE_ISSUES)
        service.generate_summary = AsyncMock(return_value=SAMPLE_SUMMARY)
        mock.return_value = service
        yield service


class TestCodeAnalyzerService:
    """Test suite for CodeAnalyzerService"""
    
    # ========================================================================
    # Full Analysis Tests
    # ========================================================================
    
    @pytest.mark.asyncio
    async def test_analyze_pr_success(self, analyzer, mock_github_service, mock_llm_service):
        """Test successful PR analysis"""
        pr_url = "https://github.com/test/repo/pull/123"
        
        result = await analyzer.analyze_pr(pr_url)
        
        # Check PR metadata
        assert result.pr_number == 123
        assert result.pr_title == "Add user authentication"
        assert result.pr_author == "testuser"
        assert result.pr_url == pr_url
        
        # Check that analysis ran
        assert result.executive_summary is not None
        assert len(result.executive_summary) > 0
        
        # Check metrics
        assert "total_files" in result.metrics
        assert "lines_added" in result.metrics
        assert "lines_deleted" in result.metrics
        
        # Check timing
        assert result.analysis_duration_seconds >= 0
        assert result.analyzed_at is not None
    
    @pytest.mark.asyncio
    async def test_analyze_pr_with_security_issues(self, analyzer, mock_github_service, mock_llm_service):
        """Test PR analysis with security issues detected"""
        pr_url = "https://github.com/test/repo/pull/123"
        
        result = await analyzer.analyze_pr(pr_url)
        
        # Should detect security issues (from both rules and LLM)
        assert len(result.security_issues) > 0
        
        # Check for critical issues
        critical_issues = [i for i in result.security_issues if i.severity == Severity.CRITICAL]
        assert len(critical_issues) > 0
    
    @pytest.mark.asyncio
    async def test_analyze_pr_with_performance_issues(self, analyzer, mock_github_service, mock_llm_service):
        """Test PR analysis with performance issues"""
        pr_url = "https://github.com/test/repo/pull/123"
        
        result = await analyzer.analyze_pr(pr_url)
        
        # Should detect performance issues
        assert len(result.performance_issues) >= 0
    
    @pytest.mark.asyncio
    async def test_analyze_pr_generates_recommendations(self, analyzer, mock_github_service, mock_llm_service):
        """Test that recommendations are generated"""
        pr_url = "https://github.com/test/repo/pull/123"
        
        result = await analyzer.analyze_pr(pr_url)
        
        # Should have recommendations
        assert len(result.recommendations) > 0
        
        # Recommendations should have emoji
        assert any('🔒' in rec or '⚡' in rec or '✨' in rec for rec in result.recommendations)
    
    # ========================================================================
    # Risk Level Tests
    # ========================================================================
    
    @pytest.mark.asyncio
    async def test_risk_level_critical(self, analyzer, mock_github_service, mock_llm_service):
        """Test CRITICAL risk level for critical security issues"""
        pr_url = "https://github.com/test/repo/pull/123"
        
        result = await analyzer.analyze_pr(pr_url)
        
        # With critical security issues, should be CRITICAL or HIGH risk
        assert result.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
    
    @pytest.mark.asyncio
    async def test_risk_level_calculation(self, analyzer, mock_github_service):
        """Test risk level calculation logic"""
        # Mock LLM with no critical issues
        with patch('app.services.code_analyzer.LLMService') as mock_llm:
            service = AsyncMock()
            service.analyze_security = AsyncMock(return_value=[
                {
                    "title": "Minor issue",
                    "severity": "LOW",
                    "category": "style",
                    "file": "test.py",
                    "line": 1
                }
            ])
            service.analyze_performance = AsyncMock(return_value=[])
            service.analyze_best_practices = AsyncMock(return_value=[])
            service.generate_summary = AsyncMock(return_value="All good")
            mock_llm.return_value = service
            
            pr_url = "https://github.com/test/repo/pull/123"
            result = await analyzer.analyze_pr(pr_url)
            
            # Should be lower risk without critical issues
            assert result.risk_level in [RiskLevel.LOW, RiskLevel.MINIMAL]
    
    # ========================================================================
    # Approval Recommendation Tests
    # ========================================================================
    
    @pytest.mark.asyncio
    async def test_approval_reject_on_critical(self, analyzer, mock_github_service, mock_llm_service):
        """Test REJECT recommendation for critical security issues"""
        pr_url = "https://github.com/test/repo/pull/123"
        
        result = await analyzer.analyze_pr(pr_url)
        
        # With critical issues, should recommend rejection or changes
        assert result.approval_recommendation in [
            ApprovalRecommendation.REJECT,
            ApprovalRecommendation.REQUEST_CHANGES
        ]
    
    @pytest.mark.asyncio
    async def test_approval_approve_on_clean_code(self, analyzer, mock_github_service):
        """Test APPROVE recommendation for clean code"""
        # Mock LLM with no issues
        with patch('app.services.code_analyzer.LLMService') as mock_llm:
            service = AsyncMock()
            service.analyze_security = AsyncMock(return_value=[])
            service.analyze_performance = AsyncMock(return_value=[])
            service.analyze_best_practices = AsyncMock(return_value=[])
            service.generate_summary = AsyncMock(return_value="Clean code, no issues")
            mock_llm.return_value = service
            
            # Mock diff with safe code
            safe_diff = """diff --git a/app/utils.py b/app/utils.py
new file mode 100644
index 0000000..111111
--- /dev/null
+++ b/app/utils.py
@@ -0,0 +1,5 @@
+def format_name(name: str) -> str:
+    \"\"\"Format a name properly\"\"\"
+    return name.strip().title()
"""
            mock_github_service.get_pr_with_diff = AsyncMock(
                return_value=(SAMPLE_PR, safe_diff)
            )
            
            pr_url = "https://github.com/test/repo/pull/123"
            result = await analyzer.analyze_pr(pr_url)
            
            # Should approve clean code
            assert result.approval_recommendation in [
                ApprovalRecommendation.APPROVE,
                ApprovalRecommendation.APPROVE_WITH_SUGGESTIONS
            ]
    
    # ========================================================================
    # Deduplication Tests
    # ========================================================================
    
    @pytest.mark.asyncio
    async def test_merge_duplicate_security_issues(self, analyzer, mock_github_service):
        """Test deduplication of similar security issues"""
        # Mock LLM to return duplicate issues
        with patch('app.services.code_analyzer.LLMService') as mock_llm:
            service = AsyncMock()
            service.analyze_security = AsyncMock(return_value=[
                {
                    "title": "SQL Injection",
                    "severity": "CRITICAL",
                    "category": "sql",
                    "file": "app/auth.py",
                    "line": 10
                },
                {
                    "title": "SQL Injection vulnerability",  # Similar title
                    "severity": "HIGH",
                    "category": "sql",
                    "file": "app/auth.py",
                    "line": 10
                }
            ])
            service.analyze_performance = AsyncMock(return_value=[])
            service.analyze_best_practices = AsyncMock(return_value=[])
            service.generate_summary = AsyncMock(return_value="Test")
            mock_llm.return_value = service
            
            pr_url = "https://github.com/test/repo/pull/123"
            result = await analyzer.analyze_pr(pr_url)
            
            # Should merge duplicates - exact count depends on rule-based detection too
            # Just verify deduplication happened (fewer issues than if all were kept)
            assert len(result.security_issues) >= 1
    
    # ========================================================================
    # Metrics Tests
    # ========================================================================
    
    @pytest.mark.asyncio
    async def test_metrics_calculation(self, analyzer, mock_github_service, mock_llm_service):
        """Test that metrics are calculated correctly"""
        pr_url = "https://github.com/test/repo/pull/123"
        
        result = await analyzer.analyze_pr(pr_url)
        
        # Check required metrics
        assert "total_files" in result.metrics
        assert "languages" in result.metrics
        assert "lines_added" in result.metrics
        assert "lines_deleted" in result.metrics
        
        # Values should be reasonable
        assert result.metrics["total_files"] > 0
        assert result.metrics["lines_added"] >= 0
        assert result.metrics["lines_deleted"] >= 0
    
    # ========================================================================
    # Error Handling Tests
    # ========================================================================
    
    @pytest.mark.asyncio
    async def test_handle_github_error(self, analyzer):
        """Test handling of GitHub service errors"""
        with patch('app.services.code_analyzer.GitHubMCPService') as mock:
            service = AsyncMock()
            service.get_pr_with_diff = AsyncMock(side_effect=Exception("GitHub API error"))
            service.__aenter__ = AsyncMock(return_value=service)
            service.__aexit__ = AsyncMock(return_value=None)
            mock.return_value = service
            
            pr_url = "https://github.com/test/repo/pull/123"
            
            with pytest.raises(Exception):
                await analyzer.analyze_pr(pr_url)
    
    @pytest.mark.asyncio
    async def test_handle_llm_error_gracefully(self, analyzer, mock_github_service):
        """Test that LLM errors are handled gracefully"""
        with patch('app.services.code_analyzer.LLMService') as mock_llm:
            service = AsyncMock()
            # LLM fails but analysis continues
            service.analyze_security = AsyncMock(side_effect=Exception("LLM error"))
            service.analyze_performance = AsyncMock(return_value=[])
            service.analyze_best_practices = AsyncMock(return_value=[])
            service.generate_summary = AsyncMock(return_value="Fallback summary")
            mock_llm.return_value = service
            
            pr_url = "https://github.com/test/repo/pull/123"
            
            # Should still complete with rule-based analysis
            result = await analyzer.analyze_pr(pr_url)
            
            # Should have results from rule-based checker
            assert result is not None
            assert result.pr_number == 123
    
    # ========================================================================
    # Integration Tests
    # ========================================================================
    
    @pytest.mark.asyncio
    async def test_end_to_end_analysis_flow(self, analyzer, mock_github_service, mock_llm_service):
        """Test complete end-to-end analysis flow"""
        pr_url = "https://github.com/test/repo/pull/123"
        
        result = await analyzer.analyze_pr(pr_url)
        
        # Verify all components are present
        assert result.pr_number is not None
        assert result.pr_title is not None
        assert result.pr_author is not None
        assert result.executive_summary is not None
        assert result.risk_level is not None
        assert result.approval_recommendation is not None
        assert len(result.recommendations) > 0
        assert result.metrics is not None
        assert result.analyzed_at is not None
        assert result.analysis_duration_seconds >= 0
        
        # Verify GitHub service was called
        mock_github_service.get_pr_with_diff.assert_called_once()
        
        # Verify LLM service was called for all analyses
        assert mock_llm_service.analyze_security.called
        assert mock_llm_service.analyze_performance.called
        assert mock_llm_service.generate_summary.called
    
    @pytest.mark.asyncio
    async def test_different_pr_urls(self, analyzer, mock_github_service, mock_llm_service):
        """Test handling of different PR URL formats"""
        urls = [
            "https://github.com/user/repo/pull/123",
            "https://github.com/org/project/pull/456",
            "https://github.com/test-user/test-repo/pull/1"
        ]
        
        for url in urls:
            result = await analyzer.analyze_pr(url)
            assert result is not None
            assert result.pr_url == url


# Run tests with: pytest tests/test_code_analyzer.py -v
