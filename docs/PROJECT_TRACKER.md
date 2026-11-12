# Project Tracker

The single source of truth for this project: what we are building, how, what is
done, what is left, and where to resume. Any person or agent should be able to
read this file alone and continue the work.

**Last updated:** 2026-11-05

---

## 1. Resume here

| | |
|---|---|
| **Current phase** | Phase 0: planning |
| **Active task** | None. Waiting for the owner to approve Phase 1 |
| **Next action** | Owner answers the open decisions in section 5, then start `P1-01` |
| **Working branch** | `docs/project-tracker` (tracker committed, not pushed) |
| **Blockers** | `P1-01` needs the owner's explicit OK to run repo code (see section 8) |

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

**Target (proposed, see `D-05`):**

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
| D-06 | The LLM layer is provider agnostic, and provider and model are configuration | Owner's request. Avoids lock-in, survives model retirements, and lets evals compare models | 2026-11-05 |
| D-14 | Add a model routing strategy | Owner's request. Controls cost while keeping risky code on strong models | 2026-11-05 |
| D-15 | Jev is an optional, replaceable routing classifier, kept only if evals justify it. Call the decision API directly and don't use `typesafe/jev-router` | Owner's choice. Keeps the design provider agnostic and model selection auditable | 2026-11-05 |

### Proposed: need the owner's answer

| ID | Question | Recommendation |
|---|---|---|
| D-05 | Approve the target architecture in section 4? | Yes |
| D-12 | Build the model layer on a library or write our own adapters? | Keep our own small interface and implement it with Pydantic AI, so the library stays replaceable. Confirm it covers section 4 before adopting it |
| D-13 | Which model should the example config default to? | Choose from eval results in `P3-01`. Until then, any current model that passes the contract tests |
| D-16 | What may be sent to a third-party classifier? | Metadata only by default (paths, sizes, languages, rule hits). Sending diff text is opt-in, and never for private repos without the repo owner's consent |
| D-07 | GitHub App, GitHub Action, or both? | Action first (no hosting needed), App later if a live demo needs it |
| D-08 | Where will the demo be hosted? | Decide in Phase 3 |
| D-09 | Keep the name "PRRover" (used in `config/agent_card.json`) or rename? | Keep it, and use it consistently |
| D-10 | Rewrite git history to remove the committed token (`P1-02`)? | Not needed if Telex is gone, since the token expired in November 2025. Deleting the file is enough |
| D-11 | Is the old Render deployment still running? If so, shut it down | Shut it down until `P1-07` lands. Owner to check |

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
| F-07 | 30 | `docker compose up` should crash: required `SECRET_KEY` is not passed. Compose also sets the wrong `TELEX_URL` name | `docker-compose.yml` | Read | P1-11 |
| F-08 | 28 | Rule false positives: `model.eval()`, `regex.exec(x)` and `open(config_path)` are CRITICAL, which forces REJECT. Performance findings repeat on every added line | `app/utils/security_rules.py`, `app/utils/performance_rules.py:161` | Read + Probe | P1-10 |
| F-09 | 27 | `TelexClient` uses fields that don't exist, so it always fails. `message/send` without Telex push config returns an error | `app/services/telex_client.py:128,144`, `app/services/message_handler.py:165-181` | Read | P1-03, P1-04 |
| F-10 | 25 | Dead modules, unused dependencies, empty files, unreachable code | Across the repo | Read + vulture | P1-02, P1-03 |
| F-11 | 24 | Four empty test files and an empty `conftest.py`. `test_code_analyzer.py` imports a missing `Impact` | `tests/` | Read | P1-12 |
| F-12 | 21 | A2A is hand-rolled to Telex's format. Agent card says `analyze_github_pr`, code routes `analyze_pr` | `app/models/a2a.py`, `config/agent_card.json` | Read | P2-02 |
| F-13 | 20 | Error-task block repeated nine times, 48 `except Exception` blocks, `focus_areas` ignored | `app/routes/a2a_tasks.py` | Read | P2-05 |
| F-14 | 20 | Three LLM calls run in sequence, and the PR is refetched three times | `app/services/code_analyzer.py:90`, `app/services/github_mcp.py` | Read | P2-04 |
| F-15 | n/a | Known vulnerabilities in pinned `starlette`, `urllib3`, `werkzeug`. The list is partial and severity is unchecked | `requirements.txt` | Audit | P1-01 |
| F-16 | n/a | Diffs and PR descriptions go into prompts with no injection protection | `app/services/llm_service.py:210,377` | Design | P2-06 |

---

## 7. Work plan

Phases are proposed until `D-05` is answered.

### Phase 1: make it honest and working

Exit: clean clone installs and starts, a PR can be reviewed end to end, tests pass
in CI, and the README is accurate.

| ID | Status | Task | Depends on | Acceptance checks |
|---|---|---|---|---|
| P1-01 | todo | Move to `pyproject.toml` with `uv` and a lockfile, keeping only dependencies the code imports. Record a test baseline first | Owner OK to run tests | Baseline recorded in section 9. `uv sync` works. Full `pip-audit` output reviewed, with nothing high or critical left unexplained |
| P1-02 | todo | Delete `test_webhook_only.py` and other Telex fixtures | D-10 | No `eyJ`-style token in tracked files |
| P1-03 | todo | Remove Telex and dead code: `telex_client.py`, `telex_service.py`, `a2a_service.py`, `routes/a2a.py`, `config/agent_card_telex.json`, `telex_workflow.json`, `/a2a/webhooks/{hook_id}`, legacy task format, placeholder RPC handlers, unused `public/fonts`, empty `scripts/*`, unreachable code in `performance_rules.py`, debug prints | P1-01 | `grep -ri telex app config` returns nothing. App starts. Tests no worse than baseline |
| P1-04 | todo | Add a working result path: `message/send` returns a completed task without push config, and GitHub webhook runs have an output | P1-03 | A test proves a request with no push config returns a completed task |
| P1-05 | todo | Build the provider-agnostic model layer from section 4, replacing the `llm_service.py` provider classes and deprecated `google-generativeai`. Check vendor docs for current model IDs | P1-01, D-12 | Provider SDKs imported only in the model layer. Contract tests pass for every adapter. One real review succeeds on at least two providers using configuration changes only. No model ID in application code |
| P1-06 | todo | Fail closed: a parse failure or partial analysis gives a `failed` or `incomplete` result and never `approve`. Report any truncated diff | P1-05 | Tests: malformed, truncated and nested-array LLM output never yields approve |
| P1-07 | todo | Add auth to `/rpc` and `/a2a/*`, make the webhook secret mandatory, block caller-supplied URLs unless allowlisted, restrict CORS, and limit batch size | P1-03 | Tests: unauthenticated call is rejected, disallowed URL is rejected, missing secret stops startup |
| P1-08 | todo | Stop logging tokens and payloads, and return safe error messages | P1-03 | No token or payload in logs, proven by a test using a sentinel value |
| P1-09 | todo | Use the `Severity` enum throughout and add a structured impact level | P1-03 | Test: critical findings are counted correctly in the summary |
| P1-10 | todo | Tune rules: fix `eval`, `exec`, `open` and concatenation patterns, and report each performance match once on its real line | P1-03 | Regression tests cover the `F-08` examples |
| P1-11 | todo | Fix Docker: remove unused `SECRET_KEY` and Node.js, correct env vars, make the healthcheck fail on bad status | P1-03 | `docker compose up` reaches healthy from a clean clone |
| P1-12 | todo | Repair `test_code_analyzer.py`, fill or delete empty test files, and add CI for lint, types, tests and `pip-audit` | P1-03 | CI green on a PR. Coverage figure recorded |
| P1-13 | todo | Rewrite the README so every claim is true | All above | Every feature listed maps to code or a test |

### Phase 2: modernize the core

| ID | Status | Task | Depends on | Acceptance checks |
|---|---|---|---|---|
| P2-01 | todo | Use schema-enforced structured output through the model layer, with the validated fallback for models without native support, and remove regex JSON extraction | Phase 1 | `_extract_json_from_response` is gone. Invalid output follows the fail-closed path |
| P2-02 | todo | Migrate to the official `a2a-sdk` and A2A v1.0, with a correct agent card and auth scheme | Phase 1 | An independent A2A client can discover the agent and complete a review |
| P2-03 | todo | Post inline PR review comments through a GitHub Action or App | D-07 | A real PR shows inline comments on the right lines |
| P2-04 | todo | Fetch PR data once, run LLM calls concurrently, keep references to background tasks | Phase 1 | One fetch per review. Timing before and after recorded |
| P2-05 | todo | Remove remaining duplication, narrow exception handling, implement or remove `focus_areas` | P2-02 | No repeated task-building blocks. Broad catches only at boundaries |
| P2-06 | todo | Defend against prompt injection: isolate untrusted content, keep the model's tools read-only, and make verdicts depend on validated findings | P2-01 | Eval cases with injected instructions cannot change the verdict |
| P2-07 | todo | Review whole PRs by chunking large diffs per file, and state any coverage limit in the result | P2-01 | Test: a bug past the old 8,000-character limit is reviewed |

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
| Test suite | **Not run** | Auto mode blocked running repo code on 2026-11-04. 60 tests are defined, and 14 of them should fail at import |
| App startup | **Not run** | Same reason |
| Radon, vulture | Done | Highest complexity: `DiffParser._parse_file_diff` at 30 and `_parse_hunk` at 22 |
| Ruff, bandit | **Failed** | Could not install because of a Windows file lock on the uv cache |
| `pip-audit` | **Partial** | Only the last 25 lines were kept. Rerun in `P1-01` |
| Secret scan | Partial | Pattern scan of history found one JWT, which expired 2025-11-02. Use a dedicated scanner in CI |
| Telex and Render reachability | **Inconclusive** | Hosts did not resolve from the agent's environment, which may be a network limit |
| Findings | Static only | Treat "Read" findings as strong, but confirm each with a test when fixing it |

---

## 9. Session log

Newest first. Keep entries short.

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
