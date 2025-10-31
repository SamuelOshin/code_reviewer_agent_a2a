# Code Review Agent 🤖

AI-powered code review agent for GitHub Pull Requests using Agent-to-Agent (A2A) protocol and Google Gemini AI.

## 🌟 Features

- **🔒 Security Analysis**: Detects 10+ vulnerability types (SQL injection, XSS, hardcoded secrets, etc.) with CWE references
- **⚡ Performance Analysis**: Identifies performance bottlenecks (N+1 queries, nested loops, blocking I/O, etc.)
- **✨ Best Practices**: LLM-powered code quality recommendations
- **🤝 A2A Protocol**: Full Agent-to-Agent protocol compliance for integration with Telex
- **🔗 GitHub Integration**: Uses GitHub MCP (Model Context Protocol) for seamless PR access
- **🧠 Multi-LLM Support**: Google Gemini (default), OpenAI GPT-4, Anthropic Claude
- **📊 Risk Assessment**: Automated risk level calculation and approval recommendations
- **🚀 JSON-RPC 2.0**: Standard RPC interface for programmatic access
- **🎯 GitHub Webhooks**: Automatic analysis on PR events

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
- [Contributing](#contributing)

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
│  │           CodeAnalyzerService                        │  │
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

# LLM Configuration (Google Gemini - Default)
LLM_PROVIDER=google
LLM_MODEL=gemini-1.5-flash
GOOGLE_API_KEY=your_gemini_api_key

# Alternative: OpenAI
# LLM_PROVIDER=openai
# LLM_MODEL=gpt-4
# OPENAI_API_KEY=sk-your-openai-key

# Alternative: Anthropic
# LLM_PROVIDER=anthropic
# LLM_MODEL=claude-3-sonnet-20240229
# ANTHROPIC_API_KEY=sk-ant-your-anthropic-key

# Telex Configuration (Optional)
TELEX_URL=https://telex.example.com
TELEX_API_KEY=your_telex_api_key
```

### Getting API Keys

1. **GitHub Token**: https://github.com/settings/tokens
   - Select scopes: `repo`, `read:org`

2. **Google AI Studio**: https://makersuite.google.com/app/apikey
   - Free tier available

3. **OpenAI**: https://platform.openai.com/api-keys
   - Paid service

4. **Anthropic**: https://console.anthropic.com/
   - Paid service

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

### JSON-RPC Methods

#### `analyze_pr`

Analyzes a GitHub Pull Request.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "analyze_pr",
  "params": {
    "pr_url": "https://github.com/user/repo/pull/123",
    "send_to_telex": true,
    "focus_areas": ["security", "performance"]
  },
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "analysis_id": "analysis-123-1698765432",
    "pr_number": 123,
    "pr_url": "https://github.com/user/repo/pull/123",
    "pr_title": "Add authentication",
    "pr_author": "testuser",
    "executive_summary": "This PR introduces authentication...",
    "risk_level": "HIGH",
    "approval_recommendation": "REQUEST_CHANGES",
    "security_issues_count": 3,
    "performance_issues_count": 1,
    "best_practice_issues_count": 2,
    "metrics": {
      "total_files": 5,
      "lines_added": 200,
      "lines_deleted": 50
    },
    "recommendations": [
      "🔒 Fix SQL injection vulnerability",
      "⚡ Optimize database queries"
    ],
    "analyzed_at": "2024-10-30T12:00:00Z",
    "analysis_duration_seconds": 15.3,
    "telex_sent": true
  },
  "id": 1
}
```

#### `introspect`

Lists available methods.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "introspect",
  "id": 2
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

### Debug Mode

Enable debug logging:

```env
LOG_LEVEL=DEBUG
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
│   │   ├── github_mcp.py  # GitHub MCP client
│   │   ├── llm_service.py # LLM integration
│   │   ├── code_analyzer.py # Main orchestrator
│   │   ├── telex_client.py  # Telex A2A client
│   │   └── jsonrpc_handler.py # RPC handler
│   ├── routes/            # API routes
│   │   ├── webhooks.py    # GitHub webhooks
│   │   ├── jsonrpc.py     # RPC endpoint
│   │   └── health.py      # Health checks
│   ├── schemas/           # Request/Response schemas
│   │   └── rpc.py         # RPC schemas
│   ├── utils/             # Utilities
│   │   ├── diff_parser.py # Diff parsing
│   │   ├── security_rules.py # Security patterns
│   │   ├── performance_rules.py # Performance patterns
│   │   └── formatters.py  # Output formatting
│   └── main.py            # FastAPI app
├── config/
│   ├── agent_card.json    # A2A agent card
│   └── prompts/           # LLM prompts
│       ├── security_analysis.txt
│       ├── performance_analysis.txt
│       └── summary_generation.txt
├── tests/                 # Test suite
│   ├── test_diff_parser.py
│   ├── test_security_rules.py
│   └── test_code_analyzer.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
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

---

Built with ❤️ using Python, FastAPI, and Google Gemini AI
