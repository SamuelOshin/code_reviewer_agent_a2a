# Code Review Agent 🤖

AI-powered code review agent for GitHub Pull Requests using Agent-to-Agent (A2A) protocol and Google Gemini AI. Features comprehensive security analysis, performance optimization detection, and best practice recommendations with webhook-based delivery for seamless integration.

## 🌟 Features

- **🔒 Security Analysis**: Detects 10+ vulnerability types (SQL injection, XSS, hardcoded secrets, etc.) with CWE references
- **⚡ Performance Analysis**: Identifies performance bottlenecks (N+1 queries, nested loops, blocking I/O, etc.)
- **✨ Best Practices**: LLM-powered code quality recommendations
- **🤝 A2A Protocol**: Full Agent-to-Agent protocol compliance with proper Message/Task handling
- **🔗 GitHub Integration**: Uses GitHub MCP (Model Context Protocol) for seamless PR access
- **🧠 Multi-LLM Support**: Google Gemini (default), OpenAI GPT-4, Anthropic Claude
- **📊 Risk Assessment**: Automated risk level calculation and approval recommendations
- **🚀 JSON-RPC 2.0**: Standard RPC interface for programmatic access
- **🎯 GitHub Webhooks**: Automatic analysis on PR events with webhook push notifications
- **🔄 Non-blocking Mode**: Immediate response with background processing and webhook delivery
- **📏 Payload Optimization**: Automatic artifact truncation to prevent HTTP 413 errors
- **🛡️ Error Handling**: Comprehensive error handling with proper webhook error reporting

## 📋 Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Docker Deployment](#docker-deployment)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Recent Updates](#recent-updates)

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Code Review Agent                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   FastAPI    │───>│  JSON-RPC    │───>│    Routes    │  │
│  │  Main App    │    │   Handler    │    │  (webhooks)  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                                         │         │
│         v                                         v         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           MessageHandlerService                      │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐      │  │
│  │  │  GitHub    │ │    LLM     │ │   Telex    │      │  │
│  │  │    MCP     │ │  Service   │ │   Client   │      │  │
│  │  └────────────┘ └────────────┘ └────────────┘      │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐      │  │
│  │  │  Security  │ │Performance │ │  Formatters│      │  │
│  │  │  Checker   │ │  Checker   │ │            │      │  │
│  │  └────────────┘ └────────────┘ └────────────┘      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              A2A Protocol Compliance                  │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐      │  │
│  │  │  Immediate │ │ Background │ │   Webhook  │      │  │
│  │  │  Response  │ │ Processing │ │   Push     │      │  │
│  │  │  (Message) │ │   (Task)   │ │  (Result)  │      │  │
│  │  └────────────┘ └────────────┘ └────────────┘      │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
         │                  │                   │
         v                  v                   v
    ┌─────────┐      ┌──────────┐      ┌──────────┐
    │ GitHub  │      │   LLM    │      │  Telex   │
    │   API   │      │Providers │      │   A2A    │
    └─────────┘      └──────────┘      └──────────┘
```

## 📦 Prerequisites

- **Python 3.11+**
- **Node.js 20+** (required by python-a2a for GitHub MCP)
- **Git**
- **GitHub Personal Access Token** (with repo access)
- **LLM API Key** (Google, OpenAI, or Anthropic)

## 🚀 Installation

### Local Development (PowerShell)

```powershell
# Clone the repository
git clone https://github.com/yourusername/code_reviewer_agent_a2a.git
cd code_reviewer_agent_a2a

# Create virtual environment
python -m venv venv

# Activate virtual environment (PowerShell)
& .\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Edit .env with your credentials (use your preferred editor)
notepad .env
```

### POSIX (macOS/Linux/WSL)

```bash
# Clone the repository
git clone https://github.com/yourusername/code_reviewer_agent_a2a.git
cd code_reviewer_agent_a2a

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Edit .env with your credentials
nano .env
```

## ⚙️ Configuration

Create a `.env` file with the following variables:

```env
# Environment
ENVIRONMENT=development
LOG_LEVEL=INFO

# GitHub Configuration
GITHUB_TOKEN=ghp_your_github_token_here
GITHUB_WEBHOOK_SECRET=your_webhook_secret

# LLM Configuration: <provider>:<model-id>
# Providers: google, openai, anthropic, openai-compatible
LLM_MODEL=google:gemini-3.8-flash
GOOGLE_API_KEY=your_google_api_key

# Switching provider is a config change only, for example:
# LLM_MODEL=openai:gpt-6.1-sol
# OPENAI_API_KEY=sk-your-openai-key
# LLM_MODEL=anthropic:claude-sonnet-5-5
# ANTHROPIC_API_KEY=sk-ant-your-anthropic-key

# Optional: per-role models, fallback models, and OpenAI-compatible servers
# LLM_MODEL_SECURITY=anthropic:claude-sonnet-5-5
# LLM_MODEL_SUMMARY=google:gemini-3.5-flash-lite
# LLM_FALLBACK_MODELS=openai:gpt-6.1-sol
# OPENAI_COMPATIBLE_BASE_URL=http://localhost:11434/v1

# Telex Configuration (Optional)
TELEX_WEBHOOK_URL=https://telex.example.com
TELEX_API_KEY=your_telex_api_key
```

### Getting API Keys

1. **GitHub Token**: https://github.com/settings/tokens
   - Select scopes: `repo`, `read:org`

2. **Google Gemini API**: https://ai.google.dev/gemini-api/docs/api-key

3. **OpenAI**: https://platform.openai.com/api-keys

4. **Anthropic**: https://console.anthropic.com/

You only need a key for the providers your configured models use. Model IDs in
these examples were checked against the vendors' docs on 2026-11-12; see
`.env.example` for every LLM setting. The old `LLM_PROVIDER` setting is no longer
read, and a model without a provider prefix (such as `gemini-1.5-flash`) stops
startup with an error that explains the format.

## 🎯 Usage

### Running the Server

**PowerShell:**
```powershell
# Activate virtual environment
& .\venv\Scripts\Activate.ps1

# Run development server with auto-reload
uvicorn app.main:app --reload --port 8000
```

**POSIX:**
```bash
# Activate virtual environment
source venv/bin/activate

# Run development server
uvicorn app.main:app --reload --port 8000
```

The server will be available at `http://localhost:8000`

### Setting Up GitHub Webhooks

1. Go to your GitHub repository → Settings → Webhooks
2. Click "Add webhook"
3. Configure:
   - **Payload URL**: `https://your-domain.com/webhooks/github`
   - **Content type**: `application/json`
   - **Secret**: (same as `GITHUB_WEBHOOK_SECRET` in `.env`)
   - **Events**: Select "Pull requests"
4. Click "Add webhook"

### Testing Locally with ngrok

```powershell
# Install ngrok
# https://ngrok.com/download

# Expose local server
ngrok http 8000

# Use the HTTPS URL in GitHub webhook settings
```

## 📚 API Documentation

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information |
| `/.well-known/agent.json` | GET | A2A agent card |
| `/rpc` | POST | JSON-RPC 2.0 endpoint |
| `/webhooks/github` | POST | GitHub webhook handler |
| `/health` | GET | Health check (comprehensive) |
| `/ready` | GET | Readiness probe (K8s) |
| `/live` | GET | Liveness probe (K8s) |
| `/docs` | GET | Interactive API docs (dev only) |

### A2A Protocol Implementation

The agent implements the Agent-to-Agent (A2A) protocol with proper handling of:

#### Immediate Response (Message Object)
When a request is received, the agent immediately returns a `Message` object:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "messageId": "uuid",
    "role": "agent",
    "parts": [{"kind": "text", "text": "🔄 PR analysis started!"}],
    "kind": "message",
    "taskId": "task-uuid",
    "timestamp": "2025-11-04T..."
  },
  "id": "request-id"
}
```

#### Background Processing & Webhook Push (Task Object)
Analysis runs asynchronously and results are pushed via webhook as a `Task` object:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "id": "task-uuid",
    "contextId": "context-uuid",
    "status": {
      "state": "completed",
      "timestamp": "2025-11-04T...",
      "message": {...},
      "progress": 1.0
    },
    "artifacts": [
      {
        "artifactId": "artifact-uuid",
        "name": "PR Analysis",
        "parts": [{"kind": "text", "text": "# Analysis Report..."}]
      }
    ],
    "history": [...],
    "kind": "task"
  },
  "id": "webhook-id"
}
```

### JSON-RPC Methods

#### `message/send`

Handles incoming messages from Telex via A2A protocol.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "message/send",
  "params": {
    "message": {
      "messageId": "uuid",
      "role": "user",
      "parts": [{"kind": "text", "text": "Analyze PR: https://github.com/user/repo/pull/123"}],
      "contextId": "context-uuid",
      "timestamp": "2025-11-04T..."
    },
    "configuration": {
      "pushNotificationConfig": {
        "url": "https://telex.example.com/webhook",
        "token": "bearer-token",
        "authentication": {
          "schemes": ["Bearer"]
        }
      }
    }
  },
  "id": 1
}
```

**Immediate Response (Message):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "messageId": "response-uuid",
    "role": "agent",
    "parts": [{"kind": "text", "text": "🔄 PR analysis started!"}],
    "kind": "message",
    "taskId": "task-uuid",
    "timestamp": "2025-11-04T..."
  },
  "id": 1
}
```

**Webhook Push (Task - sent asynchronously):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "id": "task-uuid",
    "contextId": "context-uuid",
    "status": {
      "state": "completed",
      "timestamp": "2025-11-04T...",
      "message": {...},
      "progress": 1.0
    },
    "artifacts": [...],
    "history": [...],
    "kind": "task"
  },
  "id": "webhook-uuid"
}
```

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)

```powershell
# Build and run
docker-compose up --build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f app

# Stop
docker-compose down
```

### Using Docker CLI

```powershell
# Build image
docker build -t code-review-agent .

# Run container
docker run -d `
  --name code-review-agent `
  -p 8000:8000 `
  --env-file .env `
  code-review-agent

# View logs
docker logs -f code-review-agent

# Stop container
docker stop code-review-agent
```

## 🧪 Testing

### Run All Tests

**PowerShell:**
```powershell
& .\venv\Scripts\Activate.ps1
pytest -v
```

**POSIX:**
```bash
source venv/bin/activate
pytest -v
```

### Run Specific Test Files

```powershell
# Test diff parser
pytest tests/test_diff_parser.py -v

# Test security rules
pytest tests/test_security_rules.py -v

# Test code analyzer
pytest tests/test_code_analyzer.py -v
```

### Run with Coverage

```powershell
pytest --cov=app --cov-report=html
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Node.js Not Found

**Error**: `Node.js not found` when running python-a2a

**Solution (PowerShell)**:
```powershell
# Install Node.js 20+
winget install OpenJS.NodeJS.LTS

# Verify installation
node --version
```

#### 2. GitHub MCP Connection Errors

**Error**: `Failed to connect to GitHub MCP`

**Solutions**:
- Verify `GITHUB_TOKEN` in `.env`
- Check token has `repo` scope
- Ensure Node.js 20+ is installed

#### 3. LLM API Errors

**Error**: `LLM provider error`

**Solutions**:
- Verify API key in `.env`
- Check API quota/rate limits
- Try switching to alternative provider

#### 4. Import Errors

**Error**: `ModuleNotFoundError`

**Solution**:
```powershell
# Ensure virtual environment is activated
& .\venv\Scripts\Activate.ps1

# Reinstall dependencies
pip install -r requirements.txt
```

#### 5. A2A Protocol Validation Errors

**Error**: `state: 'accepted' invalid` or `wrong object type`

**Solution**: This was a protocol compliance issue. The agent now:
- Returns `Message` object immediately (not `Task`)
- Uses valid task states: `submitted`, `working`, `completed`, `failed`, etc.
- Sends `Task` objects via webhook push (not in immediate response)

#### 6. HTTP 413 Payload Too Large

**Error**: `413 Payload Too Large` on webhook push

**Solution**: The agent now automatically truncates artifacts to 50KB max to prevent webhook payload size issues.

#### 7. Webhook Format Errors

**Error**: Telex rejects webhook payload format

**Solution**: Webhook pushes now use correct JSON-RPC response format:
```json
{
  "jsonrpc": "2.0",
  "result": { /* Task object */ },
  "id": "webhook-id"
}
```
Instead of the incorrect request format with `method` and `params`.

### Debug Mode

Enable debug logging:

```env
LOG_LEVEL=DEBUG
```

### Testing Webhook Integration

Use the provided test scripts:

```powershell
# Test A2A endpoint
python scripts/test_a2a_endpoint.py

# Test webhook push
python scripts/test_webhook_push.py
```

## 📖 Project Structure

```
code_reviewer_agent_a2a/
├── app/
│   ├── core/              # Core configuration
│   │   ├── config.py      # Settings (Pydantic)
│   │   ├── logging.py     # Logging setup
│   │   └── exceptions.py  # Custom exceptions
│   ├── models/            # Data models
│   │   ├── jsonrpc.py     # JSON-RPC models
│   │   ├── a2a.py         # A2A protocol models
│   │   ├── github.py      # GitHub models
│   │   └── analysis.py    # Analysis models
│   ├── services/          # Business logic
│   │   ├── message_handler.py  # A2A message handling
│   │   ├── github_mcp.py  # GitHub MCP client
│   │   ├── llm_service.py # LLM integration
│   │   ├── code_analyzer.py # Main orchestrator
│   │   ├── telex_client.py  # Telex A2A client
│   │   └── jsonrpc_handler.py # RPC handler
│   ├── routes/            # API routes
│   │   ├── webhooks.py    # GitHub webhooks
│   │   ├── jsonrpc.py     # RPC endpoint
│   │   ├── a2a.py         # A2A protocol routes
│   │   └── health.py      # Health checks
│   ├── schemas/           # Request/Response schemas
│   │   ├── agent.py       # Agent schemas
│   │   ├── rpc.py         # RPC schemas
│   │   └── webhook.py     # Webhook schemas
│   ├── utils/             # Utilities
│   │   ├── diff_parser.py # Diff parsing
│   │   ├── security_rules.py # Security patterns
│   │   ├── performance_rules.py # Performance patterns
│   │   └── formatters.py  # Output formatting
│   └── main.py            # FastAPI app
├── config/
│   ├── agent_card.json    # A2A agent card
│   ├── agent_card_telex.json # Telex-specific agent card
│   └── prompts/           # LLM prompts
│       ├── security_analysis.txt
│       ├── performance_analysis.txt
│       ├── summary_generation.txt
│       └── telex_chat_system.txt
├── tests/                 # Test suite
│   ├── conftest.py        # Test configuration
│   ├── test_a2a_protocol.py # A2A protocol tests
│   ├── test_code_analyzer.py # Analyzer tests
│   ├── test_diff_parser.py # Diff parser tests
│   ├── test_github_mcp.py  # GitHub MCP tests
│   ├── test_jsonrpc.py     # JSON-RPC tests
│   ├── test_security_rules.py # Security tests
│   └── test_webhooks.py    # Webhook tests
├── scripts/               # Utility scripts
│   ├── setup_github_webhook.py # Webhook setup
│   ├── test_a2a_endpoint.py    # A2A testing
│   └── deploy.sh              # Deployment script
├── docker-compose.yml     # Docker composition
├── Dockerfile            # Container definition
├── requirements.txt      # Python dependencies
├── pyproject.toml        # Project metadata
├── .env.example          # Environment template
├── QUICK_START.md        # Quick start guide
├── QUICK_START_TELEX.md  # Telex integration guide
└── README.md
```

## 🤝 Contributing

Contributions welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- **python-a2a**: Agent-to-Agent protocol implementation
- **FastAPI**: Modern Python web framework
- **Google Gemini**: AI language model
- **GitHub**: MCP integration

## 📞 Support

- **Issues**: https://github.com/yourusername/code_reviewer_agent_a2a/issues
- **Discussions**: https://github.com/yourusername/code_reviewer_agent_a2a/discussions
- **Documentation**: See `code_reviewer_implementation.md` and `get_started_plan.md`

## 🆕 Recent Updates

### v1.1.0 - A2A Protocol Compliance & Webhook Fixes

**Key Improvements:**
- ✅ **A2A Protocol Compliance**: Fixed immediate response to return `Message` objects instead of `Task` objects
- ✅ **Webhook Format**: Corrected webhook push to use JSON-RPC response format (`result`) instead of request format (`method`/`params`)
- ✅ **Payload Optimization**: Added automatic artifact truncation (50KB max) to prevent HTTP 413 errors
- ✅ **Code Cleanup**: Removed duplicate functions, mock code, and invalid task states
- ✅ **Error Handling**: Improved webhook error reporting with proper `Task` objects for failed states

**Breaking Changes:**
- Webhook payload format changed from request-style to response-style JSON-RPC
- Immediate responses now return `Message` objects (not `Task`)
- Invalid task state `"accepted"` removed (now uses valid A2A states)

**Migration Guide:**
If you have existing webhook integrations, update your webhook handlers to expect:
```json
{
  "jsonrpc": "2.0",
  "result": { /* Task object */ },
  "id": "..."
}
```

---

Built with ❤️ using Python, FastAPI, and Google Gemini AI
