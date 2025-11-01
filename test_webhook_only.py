"""
Test just the Telex webhook push without running full analysis
"""
import asyncio
import httpx
from datetime import datetime, timezone

async def test_webhook():
    # Real Telex webhook from your logs
    webhook_url = "https://ping.telex.im/v1/a2a/webhooks/e94d7c27-bb8e-4586-b247-0e763c1eb3e8"
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMTlhNDAzOS03ZTMxLTcwYWQtODM4My00YjA2ZTg0OTkyMDYiLCJpYXQiOjE3NjIwMjY0NDcsImV4cCI6MTc2MjExMjg0N30.8_igt3_vzU4DaVkLYfKlqBdM-RsbhzvPiMjhKvIqmLs"
    
    # Simple test payload (JSON-RPC message/send request, not result)
    test_payload = {
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": {
            "message": {
                "messageId": "msg-webhook-test",
                "role": "agent",
                "parts": [
                    {
                        "kind": "text",
                        "text": "🧪 This is a webhook test message from PRRover!",
                        "file_url": None,
                        "mime_type": None,
                        "data": None
                    }
                ],
                "kind": "message",
                "taskId": "task-webhook-test",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        },
        "id": "test-webhook-001"
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    
    print("=" * 80)
    print("🧪 WEBHOOK PUSH TEST")
    print("=" * 80)
    print(f"URL: {webhook_url}")
    print(f"Token: {token[:50]}...")
    print("=" * 80)
    print()
    
    # Test with different timeouts
    timeouts = [
        ("Short (10s)", httpx.Timeout(10.0)),
        ("Medium (30s)", httpx.Timeout(30.0)),
        ("Long (60s)", httpx.Timeout(10.0, read=60.0)),
    ]
    
    for timeout_name, timeout_config in timeouts:
        print(f"Testing with {timeout_name} timeout...")
        start_time = asyncio.get_event_loop().time()
        
        try:
            async with httpx.AsyncClient(timeout=timeout_config) as client:
                response = await client.post(
                    webhook_url,
                    json=test_payload,
                    headers=headers
                )
                elapsed = asyncio.get_event_loop().time() - start_time
                
                print(f"  ✅ SUCCESS!")
                print(f"  Status: {response.status_code}")
                print(f"  Time: {elapsed:.2f}s")
                print(f"  Response: {response.text[:200]}")
                print()
                return  # Success, no need to try other timeouts
                
        except httpx.TimeoutException as e:
            elapsed = asyncio.get_event_loop().time() - start_time
            print(f"  ⏱️  TIMEOUT after {elapsed:.2f}s")
            print(f"  Error: {e}")
            print()
            
        except httpx.HTTPStatusError as e:
            elapsed = asyncio.get_event_loop().time() - start_time
            print(f"  ❌ HTTP ERROR after {elapsed:.2f}s")
            print(f"  Status: {e.response.status_code}")
            print(f"  Response: {e.response.text}")
            print()
            return  # Don't retry on HTTP errors
            
        except Exception as e:
            elapsed = asyncio.get_event_loop().time() - start_time
            print(f"  ❌ ERROR after {elapsed:.2f}s")
            print(f"  Error: {type(e).__name__}: {e}")
            print()
            return
    
    print("=" * 80)
    print("All timeout attempts exhausted. Webhook appears to be very slow or unresponsive.")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(test_webhook())
