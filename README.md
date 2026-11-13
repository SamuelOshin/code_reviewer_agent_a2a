# PRRover

An AI code review agent for GitHub Pull Requests. It combines regex rules with LLM
analysis to report security, performance and best-practice findings, and it fails
closed: a review that did not fully run never says "approve".

It is a FastAPI service with a JSON-RPC 2.0 endpoint, a simple A2A-style task endpoint
and a GitHub webhook. The LLM layer is provider agnostic: provider and model are
configuration, not code.

> **Status:** this project is being rebuilt as an AI engineering portfolio piece. The
> [project tracker](docs/PROJECT_TRACKER.md) holds the plan and what is verified.
> No real LLM or GitHub call has been run end to end yet; the test suite mocks them.

## What it does

| Feature | Where |
|---|---|
| Parses PR diffs per file and hunk | `app/utils/diff_parser.py`, `tests/test_diff_parser.py` |
| Rule-based security checks (SQL injection, hardcoded secrets, unsafe deserialization, command injection, XSS, path traversal, weak crypto, insecure random, missing auth check, debug mode), with CWE ids | `app/utils/security_rules.py`, `tests/test_security_rules.py` |
| Rule-based performance checks (N+1 queries, nested loops, blocking I/O, string concatenation, missing index, and others) | `app/utils/performance_rules.py`, `tests/test_performance_rules.py` |
| LLM analysis in four roles: security, performance, best practices, summary | `app/services/llm_service.py`, `app/llm/types.py`, `tests/test_llm_summary.py` |
| Provider-agnostic model layer on Pydantic AI: Google, OpenAI, Anthropic and any OpenAI-compatible server; per-role models; ordered fallback models | `app/llm/`, `tests/test_llm_contract.py` |
| Risk level and approval recommendation | `app/services/code_analyzer.py`, `tests/test_code_analyzer.py` |
| Fail-closed results (see below) | `tests/test_fail_closed.py` |
| JSON-RPC 2.0 at `/rpc` with `analyze_pr`, `message/send`, `introspect`, batch support | `app/main.py`, `app/routes/jsonrpc.py`, `tests/test_jsonrpc.py` |
| `POST /a2a/tasks`: JSON-RPC `message/send`, or `{"message": "<text containing a PR URL>"}` | `app/routes/a2a_tasks.py`, `tests/test_a2a_protocol.py` |
| GitHub webhook: HMAC-verified `pull_request` events (opened, synchronize, reopened) get one summary comment on the PR, capped at 60,000 characters | `app/routes/webhooks.py`, `tests/test_webhooks.py` |
| Optional push of the result to a caller-supplied URL (allowlisted, https, public addresses only) | `app/core/push_url.py`, `tests/test_security_p107.py` |
| Safe errors: clients get a generic message plus an error id; raw model output is never logged. Some log lines still include raw exception text, such as GitHub error details (`P1-17`) | `app/core/errors.py`, `tests/test_safe_logging.py` |

## Fail-closed reviews

Every result carries a `status`:

- `complete`: every step ran on the whole diff.
- `incomplete`: an LLM step failed, returned unusable output, or saw only part of the diff.
- `failed`: no LLM findings step succeeded; only rule-based findings are reported.

An `incomplete` or `failed` review gets the recommendation `incomplete` and **never
approves**. Rule findings are kept when an LLM call fails. The LLM sees only the first
8,000 characters of the diff; when the diff is longer the result sets `diff_truncated`
and reports how many characters were reviewed (the rules still cover the whole diff).
Malformed or truncated model output is never read as "no issues". Raw model output is
never logged. Tests: `tests/test_fail_closed.py`.

The status and reasons appear in the PR comment (`app/utils/formatters.py`) and in the
A2A report text. The `analyze_pr` RPC result carries them as `analysis_status` and
`incomplete_reasons`, plus `llm_models_by_role` (the model configured for each role).
Tests: `tests/test_p115_followups.py`.

## Quick start

Needs Python 3.11+, [uv](https://docs.astral.sh/uv/), a GitHub token with read access
to the PRs you review, and a key for one LLM provider.

```bash
git clone https://github.com/SamuelOshin/code_reviewer_agent_a2a.git
cd code_reviewer_agent_a2a
uv sync
cp .env.example .env     # then edit .env (see Configuration)
uv run uvicorn app.main:app --reload --port 8000
```

Startup refuses to run without valid `GITHUB_TOKEN`, `GITHUB_WEBHOOK_SECRET` and
`API_KEY`, so edit `.env` first. Generate values with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"   # API_KEY
python -c "import secrets; print(secrets.token_hex(32))"       # GITHUB_WEBHOOK_SECRET
```

### Docker

```bash
cp .env.example .env     # edit it first
docker compose up --build
```

The image installs from `uv.lock`, runs as a non-root user, and has a healthcheck on
`/health`. Set `HOST_PORT` in `.env` if port 8000 is taken.

## Configuration

All settings are environment variables (or `.env`). [`.env.example`](.env.example) and
[`app/core/config.py`](app/core/config.py) are the source of truth.

| Variable | Required | Meaning |
|---|---|---|
| `GITHUB_TOKEN` | yes | Token used to read PRs and post comments |
| `GITHUB_WEBHOOK_SECRET` | yes | HMAC secret for `/webhooks/github`. At least 32 characters; startup fails if shorter, empty or still the `.env.example` placeholder |
| `API_KEY` | yes | Bearer key for `/rpc` and `/a2a/*`. At least 32 characters; startup fails if shorter or still the placeholder |
| `LLM_MODEL` | yes in practice | `<provider>:<model-id>`; providers `google`, `openai`, `anthropic`, `openai-compatible`. A value without a provider prefix is rejected with an explanatory error |
| `LLM_MODEL_SECURITY`, `_PERFORMANCE`, `_BEST_PRACTICES`, `_SUMMARY` | no | Per-role model; empty uses `LLM_MODEL` |
| `LLM_FALLBACK_MODELS` | no | Comma-separated models tried in order when a call fails |
| `LLM_STRUCTURED_OUTPUT_MODE` | no | `auto` (default), `native`, `tool` or `prompted` |
| `LLM_TEMPERATURE`, `LLM_MAX_TOKENS`, `LLM_MAX_RETRIES`, `LLM_TIMEOUT_SECONDS` | no | Defaults 0.3, 4000, 2, 120 |
| `GOOGLE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` | per provider | Only for the providers your models use |
| `OPENAI_COMPATIBLE_BASE_URL`, `OPENAI_COMPATIBLE_API_KEY` | for `openai-compatible` | Local models or gateways |
| `PUSH_URL_ALLOWED_HOSTS` | no | Comma-separated bare hostnames allowed to receive push notifications. Empty (default) disables them |
| `PUSH_URL_ALLOWED_PORTS` | no | Extra ports push URLs may use, comma-separated. Empty (default) allows only 443 |
| `A2A_BLOCKING_TIMEOUT_SECONDS` | no | Longest a blocking `message/send` may run, default 300, max 3600. On timeout it returns JSON-RPC error `-32004` |
| `CORS_ALLOWED_ORIGINS` | no | Comma-separated `scheme://host[:port]`, lowercased. Empty sends no CORS headers; `*` is refused |
| `JSONRPC_MAX_BATCH_SIZE` | no | Most calls per JSON-RPC batch, 1-100, default 10 |
| `ENVIRONMENT`, `PORT`, `LOG_LEVEL`, `LOG_FORMAT`, `HOST_PORT` | no | See `.env.example` |

Switching provider is a configuration change only, for example
`LLM_MODEL=anthropic:claude-sonnet-5-5` plus `ANTHROPIC_API_KEY`. The model IDs in
`.env.example` are examples; the default there is provisional.

## API

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/rpc` | POST | Bearer `API_KEY` | JSON-RPC 2.0: `analyze_pr`, `message/send`, `introspect` |
| `/a2a/tasks` | POST | Bearer `API_KEY` | `message/send` task endpoint |
| `/webhooks/github` | POST | HMAC signature | GitHub `pull_request` events |
| `/.well-known/agent.json` | GET | none | Agent card |
| `/health`, `/ready`, `/live` | GET | none | Health, readiness, liveness |
| `/docs` | GET | none | Interactive docs, `ENVIRONMENT=development` only |

Without `Authorization: Bearer $API_KEY`, `/rpc` and `/a2a/*` return 401. A batch larger
than `JSONRPC_MAX_BATCH_SIZE`, or an empty batch, is rejected with "Invalid Request".

```bash
export API_KEY=...   # the value from your .env

curl -X POST http://localhost:8000/rpc \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"analyze_pr","params":{"pr_url":"https://github.com/OWNER/REPO/pull/1"}}'

curl -X POST http://localhost:8000/a2a/tasks \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"message":"Review https://github.com/OWNER/REPO/pull/1"}'
```

`message/send` without a push configuration returns a finished task (blocking is the
default). With `"blocking": false` and a `pushNotificationConfig.url`, it returns at
once and pushes the result to that URL. The URL must be `https`, its host must be in
`PUSH_URL_ALLOWED_HOSTS`, its port 443 or one in `PUSH_URL_ALLOWED_PORTS`, and it must
resolve to public addresses only. A blocking call that runs longer than
`A2A_BLOCKING_TIMEOUT_SECONDS` returns error `-32004`.

### GitHub webhook

In the repository's Settings, Webhooks: payload URL `https://<your-host>/webhooks/github`,
content type `application/json`, the secret equal to `GITHUB_WEBHOOK_SECRET`, event
"Pull requests". Requests without a valid `X-Hub-Signature-256` are rejected, and a
malformed `X-GitHub-Delivery` header (not 1 to 64 of letters, digits, `.`, `_`, `-`) gets
400. A delivery is ignored if its delivery id or the SHA-256 of its signed body was seen
in the last hour (in memory, per process, bounded in size), so GitHub redeliveries and a
captured body resent with a new id do not post twice. If the review fails (the analysis
raises, returns a failed or incomplete result, or the comment cannot be posted), the id
and body are forgotten, so a manual "Redeliver" runs it again; a review that completed
and was posted stays claimed.

## Security notes

- `/rpc` and `/a2a/*` use a constant-time Bearer check (`app/core/auth.py`).
- The webhook secret is mandatory; unsigned events cannot make the bot comment.
- Push URLs are allowlisted and checked against private addresses, including IPv4
  addresses embedded in IPv6 (mapped, compatible and NAT64) forms (SSRF guard). A known
  limit: DNS can change between the check and the connection; the allowlist is the main
  control.
- Webhook replay protection keys on both the delivery id and the signed body's hash, so
  a captured body resent with a new id is also ignored. It is in memory and per process:
  a restart, or a second replica, forgets it, and a replay after the one-hour window
  is processed again.
- This repo is public. Put secrets only in `.env`, which is not committed.

## Development

```bash
uv run pytest                          # tests (LLM, GitHub and push calls are mocked)
uv run pytest --cov=app                # with coverage
uv run ruff check .                    # lint
```

CI (`.github/workflows/ci.yml`) runs ruff, pytest with coverage and `pip-audit`.

```
app/
  core/       settings, auth, push URL guard, safe errors, logging
  llm/        provider-agnostic model layer (the only place provider SDKs are used)
  models/     JSON-RPC, A2A, GitHub and analysis models
  routes/     rpc, a2a tasks, webhooks, health
  services/   analyzer, GitHub client, LLM prompts and parsing, message handler
  utils/      diff parser, security and performance rules, formatters
config/       agent card and LLM prompts
tests/
```

## Known gaps and planned work

Not built yet; see the [tracker](docs/PROJECT_TRACKER.md):

- Inline PR review comments (planned, `P2-03`); today the webhook posts one summary comment.
- Migration to the official A2A SDK. The current A2A support is hand-written, and the
  agent card (`config/agent_card.json`) still points at an old, no-longer-running hosting URL and a skill id that
  does not match the RPC method name (`P2-02`).
- Chunking large diffs so the LLM reviews the whole PR (`P2-07`).
- Prompt-injection defences (`P2-06`).
- Evals with published precision and recall, an MCP server, tracing and cost metrics,
  persisted runs and model routing (Phase 3).
- Not tested yet: a real review against a live provider, and the push-notification path
  against a real receiver.

## License

No license file is present in the repository yet.
