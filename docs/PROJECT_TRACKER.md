# Project Tracker

The single source of truth for this project: what we are building, how, what is
done, what is left, and where to resume. Any person or agent should be able to
read this file alone and continue the work.

**Last updated:** 2026-11-12

---

## 1. Resume here

| | |
|---|---|
| **Current phase** | Phase 1: make it honest and working (planning complete) |
| **Active task** | None. Done: `P1-01` to `P1-04`, `P1-06` to `P1-21`. Open: `P1-05` (needs one real review on two providers), `P1-22` |
| **Next action** | Owner sets a random `API_KEY` and a random `GITHUB_WEBHOOK_SECRET` (both at least 32 characters) in `.env`, then runs one real review on two providers (closes `P1-05`). Owner picks a license (the old README claimed MIT; no LICENSE file exists). Then `P1-22` |
| **Working branch** | `main`. Start each new task on its own branch from `main`. `P1-21` on `chore/p1-21` for one PR |
| **Blockers** | None. Owner approved running repo code on 2026-11-12. Use `uv` for everything (`uv sync`, `uv run`). If an install fails on a Windows cache file lock, retry or set a different `UV_CACHE_DIR` |
| **Working rule** | Parallel agents don't edit this file. The coordinating session records their results |

---

## 2. How to use this file

**Starting a session**

1. Read this file from top to bottom, then `AGENTS.md`.
2. Run `git status` and `git log --oneline -5`, and compare them with section 1.
   If they disagree, trust git and correct this file.
3. Pick up the active task. If there is none, take the first `todo` task whose
   dependencies are `done`.

**While working**

- Work on one task at a time, and set it to `doing` when you start.
- A task is `done` only when every acceptance check has been run and passed.
  If a check could not be run, the task stays `doing` and section 8 says why.
- Record any real design choice in section 5.
- New work found along the way goes in section 7 as a new task. Don't widen the
  current task.

**Ending a session, or before context runs out**

1. Update section 1 so the next action is specific enough to start cold.
2. Update task statuses in section 7.
3. Add an entry to section 9: what changed, what was verified, what was not.

**Status values:** `todo` · `doing` · `blocked` · `done` · `dropped`

**This repo is public.** Never put tokens, keys, webhook IDs or private URLs here.

---

## 3. Goal and scope

**Owner:** Samuel Oshin

**Goal:** turn this project into a current, working AI engineering portfolio piece
that recruiters can see running and can verify. The agent reviews GitHub Pull
Requests for security, performance and code quality problems.

**Why now:** the project was built for Telex, which is no longer active, and has
had no commits since November 2025. Its default model has been shut down.

**What good looks like**

- A recruiter can see the agent review a real PR, with comments on the PR itself.
- Review quality is measured, with published precision and recall.
- Every claim in the README is true and can be checked in the code.
- It runs from a clean clone by following the README.
- Switching LLM provider or model is a configuration change, with no code edits.

**In scope**

- Removing Telex and all code built only for it
- Modern LLM integration, A2A, and real MCP support
- Evals, tracing, tests and CI
- Security fixes for anything publicly reachable

**Out of scope**

- Becoming a commercial product (billing, multi-tenant accounts, dashboards)
- Supporting Git hosts other than GitHub
- Keeping backward compatibility with Telex or the legacy task format

---

## 4. Current state and target

**Today:** FastAPI app, about 6.5k lines of Python. A PR URL arrives by webhook or
RPC, PyGithub fetches the diff, regex rules and three LLM calls produce findings,
then a risk score and summary are built. Results can only reach Telex.

**Keep:** diff parser, the hybrid design (rules plus LLM), risk scoring logic,
webhook HMAC verification.

**Target (approved, see `D-05`):**

```
GitHub PR event / A2A client / MCP client / CLI
                    |
           Authenticated entry points
                    |
              Review pipeline
   fetch PR once -> rules -> specialist agents (parallel, with
   tools to read surrounding code) -> verifier -> risk scoring
                    |
    Structured findings, fail closed on any error
                    |
   GitHub inline review / A2A task result / MCP result
                    |
       Stored runs, tracing, token and cost metrics

Eval harness: seeded-bug and clean PRs -> precision/recall in CI
```

### Provider-agnostic model layer (`D-06`)

Every LLM call goes through one internal interface. The rest of the app never
knows which provider is running.

**Rules**

- Provider SDKs are imported only inside the model layer (proposed: `app/llm/`).
- The pipeline asks for typed results, such as a list of findings, and never handles
  provider request or response formats.
- Provider and model come from configuration, for example
  `LLM_MODEL=<provider>:<model-id>`. No model ID is hardcoded in application code.
- Separate roles can use separate models, for example a cheaper model for summaries
  and a stronger one for security review.
- OpenAI-compatible endpoints work through a configurable base URL, which covers
  local models and gateways.

**The interface must cover**

| Capability | Behaviour |
|---|---|
| Structured output | Native schema support where the provider has it. Otherwise validate the JSON and retry once. If that still fails, the review fails closed |
| Tool calling | Needed by specialist agents in `P3-03` |
| Usage reporting | Tokens, cost and latency returned in one format for every provider |
| Errors | Rate limit, timeout, auth and context-length errors mapped to shared types, with retries in one place |
| Capabilities | Each model declares what it supports, so a missing feature fails clearly at startup |
| Fallback | Optional ordered list of models for when one is unavailable |

**Proof:** a contract test suite runs the same checks against every adapter, and the
eval harness can compare any configured models.

### Routing strategy (`D-14`)

Routing decides which model reviews each part of a PR, so simple changes stay cheap
and risky changes get the strongest model. It sits above the model layer and picks
from configured model tiers. Build it in this order:

1. **Role routing:** each role has a configured model. This comes with `P1-05`.
2. **Rule routing:** deterministic signals pick a tier, such as file path, language,
   diff size and rule hits. This is the default and needs no external service.
3. **Classifier routing (optional, `D-15`):** a fast classifier scores each file for
   difficulty and risk, and returns a tier with a confidence score.

**Safety rules**

- A missed bug costs far more than an extra model call, so uncertainty always routes
  up to the stronger tier.
- Hard floors cannot be overridden by a classifier. Rule hits, and paths touching
  auth, crypto, secrets, payments or CI, always use the top tier.
- If the router fails or times out, use the top tier and record that it happened.
- Every review records its route, reason, confidence and cost, so results can be
  replayed and audited.

**Proof:** evals compare routed review against always-strong and always-cheap
baselines. Routing ships only if it cuts cost without a meaningful drop in recall.

---

## 5. Decisions

### Made

| ID | Decision | Why | Date |
|---|---|---|---|
| D-01 | Remove Telex entirely | Platform is inactive, per the owner | 2026-11-04 |
| D-02 | Project lives at `Documents\code_reviewer_agent_a2a`, cloned from `SamuelOshin/code_reviewer_agent_a2a` | Owner's request | 2026-11-05 |
| D-03 | This file is the shared tracker, with `AGENTS.md` as the entry point | Any agent can resume work | 2026-11-05 |
| D-04 | No AI attribution in commits or PRs | Owner's global rule | 2026-11-05 |
| D-05 | Adopt the target architecture in section 4, and the three-phase plan in section 7 | Owner accepted the recommendation | 2026-11-12 |
| D-06 | The LLM layer is provider agnostic, and provider and model are configuration | Owner's request. Avoids lock-in, survives model retirements, and lets evals compare models | 2026-11-05 |
| D-07 | Ship as a GitHub Action first. Add a GitHub App later only if a live demo needs it | Owner accepted the recommendation. An Action needs no hosting | 2026-11-12 |
| D-09 | Keep the name PRRover and use it consistently | Owner accepted the recommendation | 2026-11-12 |
| D-10 | Don't rewrite git history. Deleting `test_webhook_only.py` in `P1-02` is enough | Owner accepted the recommendation. The token expired in November 2025 and Telex is gone | 2026-11-12 |
| D-11 | The old Render deployment is not running, so the public tracker exposes no live endpoint. Don't redeploy until `P1-07` lands | Confirmed by the owner | 2026-11-12 |
| D-12 | Keep our own small model interface and implement it with Pydantic AI, so the library stays replaceable. Confirm Pydantic AI covers section 4 at the start of `P1-05`, and write our own adapters if it doesn't | Owner accepted the recommendation | 2026-11-12 |
| D-13 | Choose the example config's default model from eval results in `P3-01`. Until then, use any current model that passes the contract tests | Owner accepted the recommendation | 2026-11-12 |
| D-14 | Add a model routing strategy | Owner's request. Controls cost while keeping risky code on strong models | 2026-11-05 |
| D-15 | Jev is an optional, replaceable routing classifier, kept only if evals justify it. Call the decision API directly and don't use `typesafe/jev-router` | Owner's choice. Keeps the design provider agnostic and model selection auditable | 2026-11-05 |
| D-16 | Send only metadata to a third-party classifier by default (paths, sizes, languages, rule hits). Sending diff text is opt-in, and never for private repos without the repo owner's consent | Owner accepted the recommendation | 2026-11-12 |

### Proposed: need the owner's answer

| ID | Question | Recommendation |
|---|---|---|
| D-08 | Where will the demo be hosted? | Deferred. Decide during Phase 3 |

---

## 6. Findings from the 2026-11-04 scan

Priority = (Impact + Risk) x (6 - Effort). Line numbers are from commit `a086632`
and will drift.

Evidence: **Read** = confirmed by reading the code. **Probe** = confirmed by a
standalone script that did not import repo code. **Audit** = reported by a tool.
**Design** = a risk that has not been demonstrated.

| ID | Score | Finding | Location | Evidence | Task |
|---|---|---|---|---|---|
| F-01 | 50 | Default model `gemini-1.5-flash` is shut down, and `google-generativeai` is deprecated | `app/core/config.py`, `app/services/llm_service.py:37` | Read + vendor notes | P1-05 |
| F-02 | 45 | README claims GitHub MCP and `python-a2a`, and says Node.js is needed. None is true | `README.md:11,80,615`, `Dockerfile` | Read | P1-13 |
| F-03 | 40 | Unparseable LLM output becomes `[]`, which reads as "no issues" and can approve. The LLM only sees the first 8,000 diff characters | `app/services/llm_service.py:172-188,210` | Read + Probe | P1-06 |
| F-04 | 36 | Unauthenticated endpoints post results to caller-supplied URLs, so private PRs readable by `GITHUB_TOKEN` can be exfiltrated | `app/routes/a2a_tasks.py`, `app/services/message_handler.py:584` | Read | P1-07 |
| F-05 | 35 | Push token and full payloads are logged. An expired JWT and a real webhook ID are committed | `app/services/message_handler.py:62`, `test_webhook_only.py` | Read | P1-02, P1-08 |
| F-06 | 30 | `"CRITICAL"` is compared with the value `"critical"`, and `impact == "HIGH"` misses free-text LLM impact | `app/services/llm_service.py:368-370`, `app/services/code_analyzer.py` | Read + Probe | P1-09 |
| F-07 | 30 | `docker compose up` should crash: required `SECRET_KEY` is not passed. Compose also sets the wrong `TELEX_URL` name | `docker-compose.yml` | Read + Run (config import fails without `SECRET_KEY`; compose itself not run) | P1-11 |
| F-08 | 28 | Rule false positives: `model.eval()`, `regex.exec(x)` and `open(config_path)` are CRITICAL, which forces REJECT. Performance findings repeat on every added line | `app/utils/security_rules.py`, `app/utils/performance_rules.py:161` | Read + Probe | P1-10 |
| F-09 | 27 | `TelexClient` uses fields that don't exist, so it always fails. `message/send` without Telex push config returns an error | `app/services/telex_client.py:128,144`, `app/services/message_handler.py:165-181` | Read + Run (blocking `message/send` returns "Unable to process PR review") | P1-03, P1-04 |
| F-10 | 25 | Dead modules, unused dependencies, empty files, unreachable code. Empty files include `app/middleware/auth.py`, `error_handler.py`, `request_logger.py` and `app/schemas/telex.py` | Across the repo | Read + vulture + coverage | P1-02, P1-03 |
| F-11 | 24 | Four empty test files and an empty `conftest.py`. `test_code_analyzer.py` imports a missing `Impact`. Coverage is 21% | `tests/` | Run | P1-12 |
| F-12 | 21 | A2A is hand-rolled to Telex's format. Agent card says `analyze_github_pr`, code routes `analyze_pr` | `app/models/a2a.py`, `config/agent_card.json` | Read | P2-02 |
| F-13 | 20 | Error-task block repeated nine times, 48 `except Exception` blocks, `focus_areas` ignored | `app/routes/a2a_tasks.py` | Read | P2-05 |
| F-14 | 20 | Three LLM calls run in sequence, and the PR is refetched three times | `app/services/code_analyzer.py:90`, `app/services/github_mcp.py` | Read | P2-04 |
| F-15 | n/a | Known vulnerabilities in pinned `starlette`, `urllib3`, `werkzeug`. The list is partial and severity is unchecked | `requirements.txt` | Audit | P1-01 |
| F-16 | n/a | Diffs and PR descriptions go into prompts with no injection protection | `app/services/llm_service.py:210,377` | Design | P2-06 |

---

## 7. Work plan

Phases approved under `D-05`.

### Phase 1: make it honest and working

Exit: clean clone installs and starts, a PR can be reviewed end to end, tests pass
in CI, and the README is accurate.

| ID | Status | Task | Depends on | Acceptance checks |
|---|---|---|---|---|
| P1-01 | done | Move to `pyproject.toml` with `uv` and a lockfile, keeping only dependencies the code imports. Record a test baseline first | Owner OK to run tests | Baseline recorded in section 9. `uv sync` works. Full `pip-audit` output reviewed, with nothing high or critical left unexplained |
| P1-02 | done | Delete `test_webhook_only.py` and other Telex fixtures | D-10 | No `eyJ`-style token in tracked files |
| P1-03 | done | Remove Telex and dead code: `telex_client.py`, `telex_service.py`, `a2a_service.py`, `routes/a2a.py`, `config/agent_card_telex.json`, `telex_workflow.json`, `/a2a/webhooks/{hook_id}`, legacy task format, placeholder RPC handlers, unused `public/fonts`, empty `scripts/*`, unreachable code in `performance_rules.py`, debug prints | P1-01 | `grep -ri telex app config` returns nothing. App starts. Tests no worse than baseline |
| P1-04 | done | Add a working result path: `message/send` returns a completed task without push config, and GitHub webhook runs have an output. Webhook runs post one summary comment (capped at 60,000 characters), but only when `GITHUB_WEBHOOK_SECRET` is set, so a forged event can't make the bot comment | P1-03 | A test proves a request with no push config returns a completed task |
| P1-05 | doing | Build the provider-agnostic model layer from section 4, replacing the `llm_service.py` provider classes and deprecated `google-generativeai`. Check vendor docs for current model IDs | P1-01, D-12 | Provider SDKs imported only in the model layer. Contract tests pass for every adapter. One real review succeeds on at least two providers using configuration changes only. No model ID in application code |
| P1-06 | done | Fail closed: a parse failure or partial analysis gives a `failed` or `incomplete` result and never `approve`. Report any truncated diff. Keep rule findings when an LLM call fails. Stop logging raw LLM output (`llm_service.py` logs the first 200 characters of an unparseable response, which can echo PR code) | P1-05 | Tests: malformed, truncated and nested-array LLM output never yields approve. The strict xfail `test_llm_error_falls_back_to_rule_results` (F-03) passes and its marker is removed |
| P1-07 | done | Add auth to `/rpc` and `/a2a/*`, make the webhook secret mandatory, block caller-supplied URLs unless allowlisted, restrict CORS, and limit batch size | P1-03 | Tests: unauthenticated call is rejected, disallowed URL is rejected, missing secret stops startup |
| P1-08 | done | Stop logging tokens and payloads, and return safe error messages. Clients now get a generic message plus an error id, and the full error is logged server-side under that id | P1-03 | No token or payload in logs, proven by a test using a sentinel value |
| P1-09 | done | Use the `Severity` enum throughout and add a structured impact level | P1-03 | Test: critical findings are counted correctly in the summary |
| P1-10 | done | Tune rules: fix `eval`, `exec`, `open` and concatenation patterns, and report each performance match once on its real line | P1-03 | Regression tests cover the `F-08` examples |
| P1-11 | done | Fix Docker: remove unused `SECRET_KEY` and Node.js, correct env vars, make the healthcheck fail on bad status. The image installs from `uv.lock`, `requirements.txt` is deleted, compose uses `env_file`, and the host port is configurable with `HOST_PORT` | P1-03 | `docker compose up` reaches healthy from a clean clone |
| P1-12 | done | Done: empty test files filled, ruff and mypy config, ruff findings fixed, and `.github/workflows/ci.yml` (ruff, pytest with coverage, `pip-audit`). CI went green on PR #1 on 2026-11-13. Coverage 82%. mypy is out of CI because of 55 errors, moved to `P2-09` | P1-03 | CI green on a PR. Coverage figure recorded |
| P1-13 | done | Rewrite the README so every claim is true. It still describes Telex, MCP, `python-a2a`, Node.js and `pip install -r requirements.txt` (deleted), documents removed RPC methods and settings, it must document `API_KEY` (its `/rpc` examples now return 401 without it), and its Docker section should be `cp .env.example .env` then `docker compose up --build` | All above | Every feature listed maps to code or a test |
| P1-15 | done | Review follow-ups from `P1-04` and `P1-05`: dedupe replayed webhook deliveries by `X-GitHub-Delivery`; add a timeout to blocking `message/send`; use `[0-9]` instead of `\d` in `parse_pr_url`; map a Google 404 to `LLMConfigurationError` like the other providers; record the model each role used in the result, not just the default. From the PR #2 review: show the P1-06 status and incomplete reasons in the A2A report and the `analyze_pr` RPC result; reject `::7f00:1` and NAT64 push URL addresses and restrict the port; set a minimum length for the webhook secret; reject or normalize mixed-case CORS origins; return an error for an empty JSON-RPC batch | P1-04, P1-05, P1-06, P1-07 | Tests: a replayed delivery posts once, a non-ASCII-digit PR URL is rejected, a Google 404 raises a configuration error |
| P1-16 | done | Close the webhook replay gap: the `X-GitHub-Delivery` id is not covered by the signature, so a captured body resent with a new id is processed again. Also dedupe on a hash of the signed body, and let a failed review be redelivered manually instead of blocking its id for an hour. From the PR #3 review: strip whitespace before the webhook secret length check, and cap the delivery id's length and format | P1-15 | Tests: the same signed body with a new delivery id posts once; a delivery whose analysis failed can be redelivered |
| P1-17 | done | Remove raw exception text from the remaining log lines and error messages (about 20, e.g. `app/services/github_mcp.py`, `app/routes/webhooks.py`, `app/routes/jsonrpc.py`, `app/main.py`): log the type and an error id, and raise without the original text. Then restore the README's broader safe-logging claim | P1-08 | A sentinel test covers each path: nothing from the exception reaches the logs or the client |
| P1-18 | done | Smaller follow-ups from the PR #3 review: a JSON-RPC batch of blocking `message/send` calls runs sequentially (up to 100 times the timeout), so cap or parallelise it; on timeout, an in-flight GitHub call keeps running in its executor thread; `fec0::1` passes the push URL guard; `parse_pr_url` is unanchored, so `pull/12abc` parses as PR 12 | P1-15 | Tests for each case |
| P1-19 | done | Webhook follow-ups from the `P1-16` to `P1-18` review: a delivery whose analysis keeps failing before any comment is posted is released each time, so it can be resent without limit (each resend re-runs the analysis and GitHub calls, no comment); add a per-body retry budget, e.g. at most 3 releases an hour. The replay cache drops its oldest entries early once 2048 arrive within the hour. PyGithub's own `github` logger prints rate-limit response text at DEBUG; pin it to INFO or higher | P1-16 | Tests: a body whose analysis always raises runs at most N times an hour; the `github` logger stays at INFO under `LOG_LEVEL=DEBUG` |
| P1-20 | done | Parsing and batching follow-ups from the same review: a PR number thousands of digits long raises `ValueError` instead of `GitHubMCPError` (use `[0-9]{1,10}`); the A2A PR URL extractor has no left boundary, so `evilgithub.com/o/r/pull/1` becomes a github.com URL, and it accepts `pull/12-x` where `parse_pr_url` rejects it; batch concurrency is 5 per batch, not per process (4 batches reached 20 calls at once); `_push_error` sorts errors by substrings of the message, so an error id containing `404` or `429` gets the wrong category | P1-18 | Tests for each case |
| P1-21 | done | Follow-ups from the `P1-19` and `P1-20` review: `_push_error` categories almost never fire, because `_analyze_and_return` turns LLM and GitHub errors into a failed task, and a 429 from the client's own webhook is pushed back as "I've hit my API rate limit"; waiting for a batch slot has no limit and does not count against `A2A_BLOCKING_TIMEOUT_SECONDS`, and single requests are not limited at all; the A2A extractor accepts `http://`, `GitHub.com` and `HTTPS://GITHUB.COM`, which `parse_pr_url` then rejects (the last becomes `https://HTTPS://...`); `pull/0` is accepted; optionally pin google-auth's `google` logger to INFO like the others | P1-19, P1-20 | Tests: a webhook 429 gets its own message; a batch call waiting for a slot times out with `-32004`; the extractor and `parse_pr_url` agree on scheme and host case |
| P1-22 | todo | Follow-ups from the `P1-21` review: the A2A extractor matches `/PULL/` and `/Pull/` (IGNORECASE) and `parse_pr_url` then rejects them, so lowercase the path segment or match it case-sensitively; when a client webhook stores the result but answers 5xx or 3xx, the extra error post marks the same task `failed`, so send it only for 413 and 429 or mark it as a delivery failure; a model rate limit never gets the friendly message, because `CodeAnalyzerService` turns model errors into a failed step (decide whether a review whose steps all failed on rate limits should say so); JSON-RPC responses with no readable id leave out `id` instead of sending `"id": null` (the route already sends null); on a batch slot timeout an id of `1.0` loses its id while the normal path coerces it to `1` | P1-21 | Tests: `/PULL/1` is extracted and parsed (or rejected by both); a webhook 500 after storing the result does not mark the task failed; every error response carries `"id": null` when the id is unreadable |
| P1-14 | done | Repo hygiene: add `.gitattributes` to normalise line endings, ignore `.claude/worktrees/` and tool caches, replace deprecated `datetime.utcnow` everywhere in `app/`, and use PyGithub's `Auth.Token` | P1-03 | `git add --renormalize .` leaves a clean diff. No `utcnow` in `app/` |

### Phase 2: modernize the core

| ID | Status | Task | Depends on | Acceptance checks |
|---|---|---|---|---|
| P2-01 | todo | Use schema-enforced structured output through the model layer, with the validated fallback for models without native support, and remove regex JSON extraction | Phase 1 | `_extract_json_from_response` is gone. Invalid output follows the fail-closed path |
| P2-02 | todo | Migrate to the official `a2a-sdk` and A2A v1.0, with a correct agent card and auth scheme | Phase 1 | An independent A2A client can discover the agent and complete a review |
| P2-03 | todo | Post inline PR review comments through a GitHub Action or App | D-07 | A real PR shows inline comments on the right lines |
| P2-04 | todo | Fetch PR data once, run LLM calls concurrently, keep references to background tasks | Phase 1 | One fetch per review. Timing before and after recorded |
| P2-05 | todo | Remove remaining duplication, narrow exception handling, implement or remove `focus_areas`. Also remove the unused `metrics` dict in `analyze_pr`, the dead `AgentCard` and `AgentSkill` models, and stop deriving severity from `impact` text in `PerformanceChecker.check_file_content` | P2-02 | No repeated task-building blocks. Broad catches only at boundaries |
| P2-06 | todo | Defend against prompt injection: isolate untrusted content, keep the model's tools read-only, and make verdicts depend on validated findings | P2-01 | Eval cases with injected instructions cannot change the verdict |
| P2-07 | todo | Review whole PRs by chunking large diffs per file, and state any coverage limit in the result | P2-01 | Test: a bug past the old 8,000-character limit is reviewed |
| P2-08 | todo | Tune the remaining noisy performance rules (`inefficient_list_operations`, `synchronous_in_async`, `loading_all_records`) | P3-01 | Eval shows fewer false positives without lower recall |
| P2-09 | todo | Fix the 55 mypy errors (mostly in `message_handler.py`, `performance_rules.py`, `health.py` and `security_rules.py`), add mypy to CI, and add `ruff format --check` once the code is formatted | Phase 1 | CI runs mypy and the format check, both green |

### Phase 3: the portfolio piece

| ID | Status | Task | Depends on | Acceptance checks |
|---|---|---|---|---|
| P3-01 | todo | Build an eval harness with seeded-bug and clean PRs, measuring precision, recall and false-positive rate for any configured model | P2-01 | One command gives a report. Baseline saved. At least two models compared on quality, cost and latency |
| P3-02 | todo | Run evals in CI and fail on regressions | P3-01 | A deliberate regression fails CI |
| P3-03 | todo | Add specialist agents with read-only code tools, plus a verifier for findings | P3-01 | Eval shows measured improvement, or the change is reverted |
| P3-04 | todo | Add a real MCP server exposing the review tools | Phase 2 | Works from an MCP client |
| P3-05 | todo | Add tracing plus token and cost metrics per review, and use prompt caching | Phase 2 | A review shows its trace, tokens and cost |
| P3-06 | todo | Persist runs and task state | Phase 2 | Task status survives a restart |
| P3-08 | todo | Add the router interface and rule routing from section 4, with hard floors and fail-to-top-tier behaviour | P3-01 | Tests prove hard floors and failure behaviour. Each review records route, reason and cost. Evals compare routed, always-strong and always-cheap runs |
| P3-09 | todo | Add classifier routing with Jev as an optional, replaceable implementation | P3-08, D-15, D-16 | Runs and falls back with Jev disabled or down. Evals show lower cost without a meaningful recall drop, or the feature stays off |
| P3-07 | todo | Publish the demo and a final README with architecture, eval results and trade-offs | All above, D-08 | A stranger can see it working from the README alone |

---

## 8. Verification status

Keep this honest. It records what has actually been proven.

| Check | State | Notes |
|---|---|---|
| Test suite | Passing 2026-11-13 | After merging `P1-21`: **745 passed, 0 xfail**. Coverage **90%**. LLM, GitHub and push calls are mocked; no real provider was called |
| App startup | Starts in-process | `/`, `/health` (`healthy`), `/ready` and the agent card return 200, with or without `SECRET_KEY`. Real LLM and GitHub calls not tested |
| Docker | Passing 2026-11-12 | From `.env.example` copied to `.env`, `docker compose up --build` reached `healthy` (Docker 29.8). `/health` returned 200 from this app. The container runs as `appuser` with no Node.js. Tested on host port 8010, because another local service holds 8000 |
| CI | Passing 2026-11-13 | Green on GitHub for PR #2 at `549f481` (ruff, pytest with coverage, `pip-audit`). GitGuardian also passed |
| Radon, vulture | Done | Highest complexity: `DiffParser._parse_file_diff` at 30 and `_parse_hunk` at 22 |
| Ruff | Passing | `ruff check .` is clean with the rules in `pyproject.toml`. `ruff format` is not enforced yet (`P2-09`) |
| mypy | 55 errors | Lenient config in `pyproject.toml`, not in CI (`P2-09`) |
| Bandit | **Not run** | Never installed successfully |
| `pip-audit` | Done 2026-11-12 | Full audit of every locked package, dev included: no known vulnerabilities. `F-15` is resolved by the dependency refresh |
| Secret scan | Partial | Pattern scan of history found one JWT, which expired 2025-11-02. Use a dedicated scanner in CI |
| Telex and Render reachability | **Inconclusive** | Hosts did not resolve from the agent's environment, which may be a network limit |
| Findings | Static only | Treat "Read" findings as strong, but confirm each with a test when fixing it |

---

## 9. Session log

Newest first. Keep entries short.

### 2026-11-13: `P1-21` built, reviewed and fixed

- **Done:** one Sonnet side session built it from `main`. Auto mode blocked its later
  commits, so the coordinating session read the diff and committed the rest on the
  owner's go-ahead. On `chore/p1-21`: 745 passed, 90% coverage, ruff clean,
  `pip-audit` clean.
  - Push failures: an `httpx` error from posting to the client's webhook gets its own
    "Could Not Deliver the Result" message. One short extra post is made only when the
    webhook answered with an error status; an unreachable webhook is not posted to again.
    The second post is re-checked by the push URL guard.
  - GitHub access failures reach the client as fixed text plus an error id. Model
    failures, rate limits included, show as a failed analysis step, not a failed task.
    The rate-limit text no longer names a provider.
  - A batch call waits at most `A2A_BLOCKING_TIMEOUT_SECONDS` for a slot, else `-32004`
    without running, so a batch finishes within about twice the timeout. Single requests
    are not queued behind the limit (explained in a code comment).
  - The extractor rewrites `http://`, mixed-case and upper-case GitHub URLs to
    `https://github.com/...`; both parsers reject PR number 0. The `google` logger stays
    at INFO or higher under `LOG_LEVEL=DEBUG`.
- **Review:** Bobby Review gave "ready with follow-ups" with three should-fix items: the
  README promised a rate-limit message the analyzer can never produce; the README and a
  comment still said a batch takes ceil(n/5) times the timeout; a malformed id on a call
  that timed out waiting for a slot failed the whole batch. All fixed; the re-review gave
  "ready". The rest is `P1-22`.
- **Not verified:** no real webhook, GitHub, model or multi-worker run; Python 3.11 only.

### 2026-11-13: `P1-19` and `P1-20` built, reviewed and fixed

- **Done:** two Sonnet side sessions built them in parallel from `main`. Merged on
  `chore/p1-19-p1-20`: 716 passed, 90% coverage, ruff clean, `pip-audit` clean.
  - **P1-19:** a body whose analysis keeps failing before a comment is posted runs at
    most 3 times within an hour of its first failure (`MAX_RUNS_PER_BODY`), then gets
    "duplicate". The window is fixed, not sliding. A 400 releases without spending runs.
    The replay cache holds 8192 entries per store; past that, the oldest is dropped
    early (replayable, or a fresh budget). `github`, `urllib3`, `anthropic` and
    `google_genai` loggers stay at INFO or higher under `LOG_LEVEL=DEBUG`.
  - **P1-20:** PR numbers are capped at 10 digits in both parsers; the extractor
    rejects hosts like `evilgithub.com` and `x.github.com` and agrees with
    `parse_pr_url` on the right boundary; the batch limit of 5 is shared by the
    process (one semaphore per event loop); `_push_error` classifies by exception type
    and HTTP status, never text.
- **Review:** Bobby Review gave "ready with follow-ups" and one should-fix: the new
  extractor boundary rejected backticks, bold, `PR:` and `>` quotes that `main`
  accepted. Also fixed before the PR: the retry budget was reordered on update, so an
  expired count could hide behind a newer one and a body got fewer retries; a 400 spent
  the budget; the Anthropic SDK printed the prompt at DEBUG. The re-review gave "ready
  with follow-ups"; the rest is `P1-21`.
- **Not verified:** no real GitHub, model or multi-worker run; google-auth's DEBUG
  logging was read in the code, not run.

### 2026-11-13: `P1-16` to `P1-18` built, reviewed and fixed

- **Done:** three Sonnet side sessions built them in parallel from `main`. Merged on
  `chore/p1-16-p1-18`: 662 passed, 89% coverage, ruff clean, `pip-audit` clean.
  - **P1-16:** replay is caught by the delivery id or the SHA-256 of the signed body.
    A delivery is released only when no comment was posted, so "Redeliver" works after
    a crash or a failed post; a posted failed or incomplete review stays claimed for up
    to an hour. The delivery id must be 1 to 64 of `[A-Za-z0-9._-]`. The webhook secret
    is stripped before the length check, and the stripped value is the HMAC key.
  - **P1-17:** logs and raised errors carry the exception type (or GitHub status) and
    an error id, never exception text; the LLM layer raises `from None`. Two lines
    keep text on purpose: `LLMError` (already a safe message) and `ClientInputError`
    (written for the caller). The remaining `from e` lines in `push_url.py` and
    `webhooks.py` chain generic messages that are not logged with a traceback.
  - **P1-18:** batch calls run 5 at a time; `fec0::/10` and Teredo are rejected and
    6to4 is judged by its IPv4; `parse_pr_url` and the A2A extractor reject
    `pull/12abc`; PyGithub has a 15 s socket timeout, 3 retries and a 30 s cap on
    rate-limit waits (needs `pygithub>=2.10`); queued GitHub calls are skipped after a
    timeout, but one already running finishes in its thread.
- **Review:** Bobby Review first gave "changes needed": a posted fail-closed review
  was released, so a captured body for a large PR could re-run the model and comment
  without limit. Also a missed raw-text log line on push timeouts, an uncapped
  PyGithub rate-limit sleep (up to an hour), and a stale README clause. All fixed; the
  re-review gave "ready with follow-ups" and re-ran the probes. Follow-ups are `P1-19`
  and `P1-20`.
- **Not verified:** no real GitHub, model, rate-limit or multi-worker run. Whether
  PyGithub 2.9 already had `max_rate_limit_wait` is unknown (2.8.1 does not).

### 2026-11-13: `P1-13` and `P1-15` built

- **Done:** two Sonnet side sessions built them in parallel from `main`, in separate
  files. The coordinating session checked authorship, scope and overlap, ran the
  merged result (575 passed, 88% coverage, ruff clean, `pip-audit` clean), read the
  webhook, push URL and config changes, then updated the README for `P1-15`.
  - **P1-13:** README rewritten; each feature maps to a file or test. Planned work is
    labelled as planned.
  - **P1-15:** replayed delivery ids are ignored for an hour (in memory, per process);
    blocking `message/send` times out (`A2A_BLOCKING_TIMEOUT_SECONDS`, error
    `-32004`); `[0-9]` in PR URLs; any 404 maps to `LLMConfigurationError`; the
    result records the configured model per role; status and reasons appear in the
    A2A report and the `analyze_pr` result (`analysis_status`); embedded IPv4 in
    IPv6 and NAT64 is judged by the IPv4; push ports limited to 443 plus
    `PUSH_URL_ALLOWED_PORTS`; webhook secret at least 32 characters; CORS origins
    lowercased; an empty batch is "Invalid Request".
- **Not done:** no real GitHub, model or Docker run, and the replay cache is not
  shared across workers. The replay gap on the unsigned delivery id is `P1-16`. No
  LICENSE file; the owner decides.
- **Review:** Bobby Review rated PR #3 ready with follow-ups, with no blockers. Its two
  should-fix items were README wording, fixed before merge. The rest are `P1-16` to `P1-18`.

### 2026-11-13: PR #2 reviewed, fixed and merged

- **Review:** Bobby Review gave "changes needed". `P1-07` held every probe (auth
  header variants, route bypass, push URL tricks, batch, CORS, config, webhook).
- **Fixed (`549f481`):** B1, a truncated reply with an inner `[]` parsed as "no
  issues" and approved. Prose `[]` no longer counts, a broken object array raises,
  and deep nesting fails cleanly. S1, raw exception text reached the logs from
  `code_analyzer.py` and `github_mcp.py`; now only the type and an error id.
  516 passed, ruff clean, CI green. The fix was not re-reviewed by a separate pass.
- **Behaviour change:** prose such as "No issues found: []" now gives `incomplete`.
- **Follow-ups:** added to `P1-15` (and the README `API_KEY` gap to `P1-13`). Webhook
  replay was already in `P1-15`.

### 2026-11-13: `P1-06` and `P1-07` merged

- **Done:** two side sessions built `P1-06` and `P1-07` in parallel from `main`, in
  separate files. The coordinating session read the key code, reran everything per
  branch and merged, then merged both. Result: 490 passed, 0 xfail, 86% coverage,
  ruff clean, `pip-audit` clean.
  - **P1-06:** results carry a status (complete, incomplete or failed). An
    unfinished review becomes `INCOMPLETE` and never approves. Rule findings
    survive LLM failures. Truncated diffs are reported with character counts.
    Raw model output is never logged.
  - **P1-07:** `/rpc` and `/a2a/*` need `Authorization: Bearer <API_KEY>`
    (at least 32 characters, constant-time check). The webhook secret is
    required. Startup refuses the `.env.example` placeholder secrets. Push URLs
    must be https, on `PUSH_URL_ALLOWED_HOSTS`, and resolve to public addresses.
    CORS allows only configured origins, and JSON-RPC batches are capped.
- **Not done:** no real LLM, GitHub or push call, and Docker was not rerun. A known
  limit: DNS rebinding between the push URL check and the connect. The allowlist
  is the primary control. The README does not yet describe the new settings
  (`P1-13`).

### 2026-11-13: `P1-04` and `P1-05` merged

- **Done:** two side sessions built `P1-04` (result path) and `P1-05` (model layer on
  Pydantic AI, per `D-12`) in parallel. Bobby Review rated both "Ready with
  follow-ups". The same sessions then fixed the should-fix items:
  - **P1-04:** no PR comment for unsigned webhooks, a neutral footer, and a cap on
    comment size.
  - **P1-05:** provider error bodies stay out of errors and logs (proven with a
    sentinel test on every adapter), old `LLM_MODEL` values fail with a clear
    message, numeric settings are validated, `httpx2` is declared, and the README's
    LLM section is updated.

  The coordinating session reran everything and merged both. Result: 320 passed, 1
  strict xfail, 82% coverage, ruff clean, `pip-audit` clean.
- **Not done:** no real LLM or GitHub call has run, so `P1-05` stays `doing`. CI has
  not run on the merged result. The rest of the README is still stale (`P1-13`).
- **New follow-ups:** `P1-15`.

### 2026-11-12: Docker verified, `P1-11` done

- **Done:** with Docker Desktop running, built the image and ran the stack. It
  reached `healthy` and `/health` returned 200. Port 8000 was taken by another
  local service, so the compose host port is now `${HOST_PORT:-8000}`, documented
  in `.env.example`.
- **Not done:** the container used placeholder keys, so no real review ran.

### 2026-11-12: second parallel batch merged

- **Done:** three Bobby Build agents (Sonnet) finished `P1-08`, `P1-11` and most of
  `P1-12` from `e95fb24`. The coordinating session checked each branch, reran the
  tests, confirmed the new log-safety tests fail on the old code, and merged all
  three. It then did `P1-14` and the ruff pass itself, because those touch nearly
  every file: `.gitattributes`, timezone-aware datetimes, PyGithub `Auth.Token`,
  and fixes for all 359 ruff findings (exception chaining, `StrEnum`, dead code).
  Result: 215 passed, 1 strict xfail, 73% coverage, ruff clean, `pip-audit` clean.
- **Behaviour changes:** JSON-RPC errors no longer include exception text, only a
  generic message and an error id. `SECRET_KEY` and other unused settings are
  gone. `requirements.txt` is deleted, and Docker installs from `uv.lock`. The
  severity, risk and approval enums are now `StrEnum`.
- **Not verified:** the Docker image was never built, and CI has never run on
  GitHub. Real LLM and GitHub calls are still untested.

### 2026-11-12: first parallel batch merged

- **Done:** three Bobby Build agents (Sonnet), each in its own worktree from
  `660b989`, finished `P1-02` + `P1-03`, `P1-09` and `P1-10`. The coordinating
  session checked each branch (author, no AI attribution, files in scope), reran
  the tests, confirmed the new tests fail on the old code, then merged all three
  into `chore/p1-01-pyproject`. Combined result: 109 passed, 1 strict xfail,
  coverage 37%, no Telex references in `app/`, `config/` or `tests/`, and no
  committed token. About 11,000 lines of dead code removed.
- **Behaviour changes:** `analyze_pr` no longer accepts `send_to_telex`. The RPC
  methods `get_analysis_status`, `list_analyses` and `get_analysis_details` are
  gone. `POST /a2a/tasks` returns 422 for the old `task_id`/`skill` format, and
  `/a2a/webhooks/{hook_id}` returns 404. `format_for_telex` is now `format_short`.
- **Rule trade-off:** the command-injection `open(variable)` rule was removed.
  Path traversal still flags `open(filename)`, `open(file_path)` and `open(path)`,
  but other variable names passed to `open()` are no longer flagged.
- **Known gaps:** commits `deae76c` and `5cbf909` are not bootable on their own,
  only the branch tip is. The README still mentions Telex. The background push path
  and the GitHub webhook analysis were not run end to end.
- **New follow-ups:** `P1-14`, `P2-08`, and extra scope on `P1-06`, `P1-08`,
  `P1-12`, `P1-13` and `P2-05`.

### 2026-11-12: `P1-01` done

- **Done:** `pyproject.toml` lists only the 9 packages the code imports, plus a dev
  group. `uv.lock` resolves 66 packages, and `.python-version` is 3.11.
  `requirements.txt` is now generated by `uv export` for the Dockerfile. `uv sync`
  works. Tests match the baseline (63 passed, same collection error, 21%), the app
  starts, and a full `pip-audit` finds no known vulnerabilities.
- **Note:** major upgrades (FastAPI 0.162, Starlette 1.10, OpenAI 3.50, Anthropic
  2.8) pass the mocked tests, but real provider calls were not run. `P1-05` covers
  that.
- **Not done:** ruff and bandit still not run, which falls under `P1-12`.

### 2026-11-12: test baseline (`P1-01`)

- **Done:** with the owner's OK, installed pinned `requirements.txt` into a local
  `.venv` (Python 3.11) and ran the suite: 63 passed, 1 collection error, 21%
  coverage. Started the app in-process and confirmed `F-07`, `F-09` and `F-11` by
  running code. Found four more empty files under `F-10`.
- **How to reproduce:** set dummy `GITHUB_TOKEN`, `GITHUB_WEBHOOK_SECRET`,
  `SECRET_KEY` and `GOOGLE_API_KEY`, then run
  `.venv/Scripts/python -m pytest tests --continue-on-collection-errors --cov=app`.
- **Not done:** dependency move, full `pip-audit`, ruff and bandit. Docker Compose
  and real LLM or GitHub calls were not run.

### 2026-11-12: decisions settled

- **Done:** owner confirmed `D-11` and accepted the recommendations for `D-05`,
  `D-07`, `D-09`, `D-10`, `D-12`, `D-13` and `D-16`. `D-08` is deferred to Phase 3.
  Branch pushed to `origin`.
- **Not done:** Phase 1 has not started. Pydantic AI has not been checked against
  section 4 yet.
- **Next:** owner OKs running repo code, then `P1-01`.

### 2026-11-05: routing strategy added

- **Done:** recorded `D-14` and `D-15`, added the routing design to section 4, added
  `P3-08` and `P3-09`, and opened `D-16`.
- **Not done:** Jev has not been tried. Its speed, cost and benchmark figures are
  vendor or third-party claims.

### 2026-11-05: provider-agnostic requirement added

- **Done:** recorded `D-06`, added the model layer design to section 4, updated
  `P1-05`, `P2-01` and `P3-01`, and opened `D-12` and `D-13`.
- **Not done:** Pydantic AI has not been evaluated against section 4 yet.

### 2026-11-05: tracker created

- **Done:** moved the project to `Documents\code_reviewer_agent_a2a`, restored full
  git history from GitHub, and created this tracker with `AGENTS.md` and `CLAUDE.md`
  on branch `docs/project-tracker`.
- **Not done:** nothing committed. No application code changed.
- **Next:** owner answers section 5.

### 2026-11-04: refactoring scan

- **Done:** cloned the repo, read the core code, ran radon and vulture, probed the
  regexes, ran a partial `pip-audit`, and researched the current stack.
- **Not done:** tests and app were not run, and ruff and bandit failed to install.

---

## 10. Reference

Versions change quickly, so check before relying on them.

| Item | Value | Checked |
|---|---|---|
| `a2a-sdk` (PyPI) | 1.3.0 | 2026-11-04 |
| `google-genai` (PyPI) | 2.34.0 | 2026-11-04 |
| `anthropic` (PyPI) | 2.4.0 | 2026-11-04 |
| `mcp` (PyPI) | 2.3.0 | 2026-11-04 |
| A2A specification | v1.0 stable since March 2026, per secondary sources | 2026-11-04 |
| Gemini 1.5 models | Shut down per Gemini API release notes | 2026-11-04 |
| Jev (TypeSafe) | Decision-only model, early access since 2026-09-15. Listed as `typesafe/jev-1.13` on OpenRouter at $0.042 per million input tokens, output free. Vendor quotes 70-500ms. Single provider, and data retention is unconfirmed | 2026-11-05 |
| `typesafe/jev-router` | Separate product: a Chat Completions router on OpenRouter, billed at the routed model's price. Not used in this plan (see `D-15`) | 2026-11-05 |

- A2A protocol: <https://a2a-protocol.org>
- Gemini models: <https://ai.google.dev/gemini-api/docs/models>
- Gemini release notes: <https://ai.google.dev/gemini-api/docs/changelog>
- Jev: <https://typesafe.ai/> and <https://openrouter.ai/docs/guides/community/jev>
- Jev limits paper: <https://arxiv.org/pdf/2609.26758>
