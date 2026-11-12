# Agent Guide

AI code review agent for GitHub Pull Requests, being rebuilt as an AI engineering
portfolio project.

**Before doing anything, read [docs/PROJECT_TRACKER.md](docs/PROJECT_TRACKER.md).**
It holds the scope, decisions, task list, and where to resume. Follow its session
rules, and update it before you stop.

## Rules

- Work on the tracker's active task. Add new work to the tracker instead of widening
  the task.
- Don't mark a task `done` until its acceptance checks have actually passed.
- Record what was not verified. Never imply a check ran when it didn't.
- Decisions listed as proposed belong to the owner. Ask before acting on them.
- Keep the README truthful. Don't claim a feature the code doesn't have.
- Stay provider agnostic: import LLM SDKs only in the model layer, and never hardcode
  a provider or model ID in application code.
- This repo is public: no tokens, keys, webhook IDs or private URLs in any file.

## Git

- Never commit to `main` directly. Use a branch.
- Commit or push only when the owner asks.
- Commits and PRs are authored solely by the owner. No `Co-Authored-By` trailers and
  no "Generated with" lines. Never list an AI assistant as a contributor.
