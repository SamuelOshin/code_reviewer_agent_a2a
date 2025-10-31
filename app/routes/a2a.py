# app/routes/a2a.py

from fastapi import APIRouter, Response
from app.core.config import settings
import json

router = APIRouter()

@router.get('/.well-known/agent.json')
async def get_agent_card():
    """
    A2A Agent Card Endpoint
    
    Returns agent capabilities and endpoint information
    """
    with open('config/agent_card.json', 'r') as f:
        agent_card = json.load(f)
    
    return agent_card

@router.get('/health')
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "agent": "code-review-summarizer"
    }