# app/services/telex_service.py

import httpx
from app.core.config import settings
from app.models.a2a import A2ATaskResponse
from app.utils.formatters import SummaryFormatter
from app.schemas.agent import AnalysisResponse
from typing import Optional

class TelexService:
    """Telex Integration Service"""
    
    def __init__(self):
        self.webhook_url = settings.TELEX_WEBHOOK_URL
        self.api_key = settings.TELEX_API_KEY
        self.channel = settings.TELEX_CHANNEL
        self.formatter = SummaryFormatter()
    
    async def post_summary(self, response: A2ATaskResponse) -> bool:
        """
        Post analysis summary to Telex channel
        
        Args:
            response: A2A task response with analysis results
        
        Returns:
            True if posted successfully, False otherwise
        """
        if not self.webhook_url:
            print("Telex webhook URL not configured")
            return False
        
        try:
            # Extract analysis from artifacts
            if not response.artifacts:
                return False
            
            artifact = response.artifacts[0]
            analysis = AnalysisResponse(**artifact.data)
            
            # Format message for Telex
            message_content = self.formatter.format_for_telex(analysis)
            
            # Prepare Telex payload
            payload = {
                "channel": self.channel,
                "text": message_content,
                "username": "Code Review Bot",
                "icon_emoji": ":robot_face:",
                "attachments": [
                    {
                        "color": self._get_color_for_risk(analysis.risk_level),
                        "title": f"PR #{analysis.pr_number}: {analysis.pr_title}",
                        "title_link": f"https://github.com/{analysis.repository}/pull/{analysis.pr_number}",
                        "fields": [
                            {
                                "title": "Risk Level",
                                "value": analysis.risk_level.upper(),
                                "short": True
                            },
                            {
                                "title": "Recommendation",
                                "value": analysis.approval_recommendation.replace('_', ' ').title(),
                                "short": True
                            }
                        ]
                    }
                ]
            }
            
            # Send to Telex
            async with httpx.AsyncClient() as client:
                headers = {}
                if self.api_key:
                    headers['Authorization'] = f"Bearer {self.api_key}"
                
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    headers=headers,
                    timeout=30.0
                )
                
                return response.status_code == 200
        
        except Exception as e:
            print(f"Error posting to Telex: {e}")
            return False
    
    def _get_color_for_risk(self, risk_level: str) -> str:
        """Map risk level to Telex color"""
        colors = {
            'low': '#36a64f',      # Green
            'medium': '#ff9900',   # Orange
            'high': '#ff6600',     # Dark Orange
            'critical': '#ff0000'  # Red
        }
        return colors.get(risk_level, '#808080')  # Gray default