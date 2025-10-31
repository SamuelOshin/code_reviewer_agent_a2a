# app/services/a2a_service.py

from typing import Optional
from app.models.a2a import A2ATaskRequest, A2ATaskResponse, A2AMessage, A2AArtifact
from app.services.github_mcp import GitHubMCPService
from app.services.code_analyzer import CodeAnalyzerService
from app.utils.formatters import SummaryFormatter
import re

class A2AService:
    """A2A Protocol Service Implementation"""
    
    def __init__(
        self, 
        github_service: GitHubMCPService,
        analyzer_service: CodeAnalyzerService
    ):
        self.github = github_service
        self.analyzer = analyzer_service
        self.formatter = SummaryFormatter()
    
    async def handle_task(self, request: A2ATaskRequest) -> A2ATaskResponse:
        """
        Handle incoming A2A task request
        
        Processes task based on skill requested and returns formatted response
        """
        try:
            if request.skill == "analyze_pr":
                return await self._handle_analyze_pr(request)
            else:
                return A2ATaskResponse(
                    task_id=request.task_id,
                    status="failed",
                    messages=[
                        A2AMessage(
                            role="agent",
                            content=f"Unknown skill: {request.skill}"
                        )
                    ],
                    error=f"Skill '{request.skill}' not supported"
                )
        
        except Exception as e:
            return A2ATaskResponse(
                task_id=request.task_id,
                status="failed",
                messages=[
                    A2AMessage(
                        role="agent",
                        content=f"Error processing request: {str(e)}"
                    )
                ],
                error=str(e)
            )
    
    async def _handle_analyze_pr(
        self, 
        request: A2ATaskRequest
    ) -> A2ATaskResponse:
        """Handle PR analysis task"""
        
        # Extract parameters
        pr_url = request.parameters.get('pr_url')
        focus_areas = request.parameters.get('focus_areas', [
            'security', 'performance', 'best_practices'
        ])
        
        if not pr_url:
            return A2ATaskResponse(
                task_id=request.task_id,
                status="failed",
                messages=[
                    A2AMessage(
                        role="agent",
                        content="Missing required parameter: pr_url"
                    )
                ],
                error="pr_url is required"
            )
        
        # Parse GitHub URL
        owner, repo, pr_number = self._parse_pr_url(pr_url)
        
        # Fetch PR data using GitHub MCP
        async with self.github:
            pr_data = await self.github.get_pull_request(owner, repo, pr_number)
            diff = await self.github.get_pr_diff(owner, repo, pr_number)
            files = await self.github.list_pr_files(owner, repo, pr_number)
        
        # Analyze the code
        analysis = await self.analyzer.analyze_pr(
            pr_data=pr_data.dict(),
            diff_content=diff,
            files=[f.dict() for f in files],
            focus_areas=focus_areas
        )
        
        # Format response
        summary_text = self.formatter.format_for_telex(analysis)
        
        # Create artifacts
        artifacts = [
            A2AArtifact(
                type="code_review_summary",
                title=f"PR #{pr_number} Analysis",
                data=analysis.dict(),
                metadata={
                    "pr_url": pr_url,
                    "repository": f"{owner}/{repo}"
                }
            )
        ]
        
        return A2ATaskResponse(
            task_id=request.task_id,
            status="completed",
            messages=[
                A2AMessage(
                    role="agent",
                    content=summary_text
                )
            ],
            artifacts=artifacts
        )
    
    def _parse_pr_url(self, url: str) -> tuple[str, str, int]:
        """Parse GitHub PR URL into owner, repo, pr_number"""
        pattern = r'github\.com/([^/]+)/([^/]+)/pull/(\d+)'
        match = re.search(pattern, url)
        
        if not match:
            raise ValueError(f"Invalid GitHub PR URL: {url}")
        
        owner, repo, pr_number = match.groups()
        return owner, repo, int(pr_number)