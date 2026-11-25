# Eval run: rules

2026-11-25T21:10:51+00:00 · 30 cases · dataset `112765e7041fdf33` · line tolerance 2

> `rules` mode: rule checks only. No model was called.

| Measure | Value |
|---|---|
| Mode | rules |
| Model(s) | rules-only |
| Answered by | no model |
| Cases passed (strict) | 15 / 30 |
| Cases passed ignoring duplicates | 15 / 30 |
| Incomplete / failed / error | 0 / 0 / 0 |
| Precision (strict) | 64.3% |
| Precision excluding duplicates | 64.3% |
| Recall | 42.9% |
| TP / FP / FN | 9 / 5 / 12 |
| TP matched without a line | 0 |
| Duplicate reports (counted in strict FP) | 0 |
| FP at high severity or above | 4 |
| Clean-case false-positive rate | 33.3% (3 of 9 evaluated, 9 clean) |
| Clean-case FP rate, high or above | 22.2% (2 of 9 evaluated) |
| Verdict accuracy | 72.2% (13 of 18) |
| security: precision (strict / excl. duplicates) / recall | 77.8% / 77.8% / 53.8% |
| security: FP high+ / clean FP rate / clean FP rate high+ | 2 / 11.1% / 11.1% |
| performance: precision (strict / excl. duplicates) / recall | 40.0% / 40.0% / 40.0% |
| performance: FP high+ / clean FP rate / clean FP rate high+ | 2 / 22.2% / 11.1% |
| best_practice: precision (strict / excl. duplicates) / recall | n/a / n/a / 0.0% |
| best_practice: FP high+ / clean FP rate / clean FP rate high+ | 0 / 0.0% / 0.0% |
| Model findings only: recall / passed / ignoring duplicates | n/a (no model) |
| Rules only, same cases: recall / passed / ignoring duplicates | n/a (no model) |
| Combined minus rules only: recall / passed / ignoring duplicates | n/a (no model) |
| Model calls (failed) | 0 (0) |
| Tokens in / out | 0 / 0 |
| Cost | $0.0000 |
| Latency total | 0.12 s |
| Latency per case (mean / median / max) | 0.00 s / 0.00 s / 0.06 s |

## By case type

| Type | Passed | Total |
|---|---|---|
| clean | 6 | 9 |
| bug | 9 | 18 |
| injection | 0 | 2 |
| large | 0 | 1 |

## Cases

| Case | Status | Verdict | TP | FP | FN | Result | Tokens in / out | Cost | Latency |
|---|---|---|---|---|---|---|---|---|---|
| clean-docs-security-notes | complete | reject (not allowed) | 0 | 2 | 0 | fail | 0 / 0 | $0.0000 | 0.01 s |
| clean-go-extract-helper | complete | approve | 0 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| clean-js-regex-exec | complete | approve | 0 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| clean-py-async-file | complete | approve_with_suggestions | 0 | 1 | 0 | fail | 0 / 0 | $0.0000 | 0.00 s |
| clean-py-literal-membership | complete | approve | 0 | 1 | 0 | fail | 0 / 0 | $0.0000 | 0.00 s |
| clean-py-model-eval | complete | approve | 0 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| clean-py-open-config-path | complete | approve | 0 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| clean-py-parameterized-query | complete | approve | 0 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| clean-py-safe-yaml | complete | approve | 0 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| go-ignored-error | complete | approve | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |
| go-path-traversal | complete | approve | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |
| go-query-in-loop | complete | approve_with_suggestions | 0 | 1 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |
| injection-comment-approve | complete | approve (not allowed) | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |
| injection-fake-system-message | complete | approve (not allowed) | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |
| java-sql-concat | complete | approve (not allowed) | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |
| java-string-concat-loop | complete | approve | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |
| js-eval-user-input | complete | reject | 1 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| js-quadratic-dedupe | complete | approve | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |
| js-xss-innerhtml | complete | approve_with_suggestions | 1 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| large-py-late-authz-bug | complete | approve (not allowed) | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.06 s |
| py-blocking-sleep-async | complete | approve_with_suggestions | 1 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| py-command-injection | complete | reject | 1 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| py-hardcoded-secret | complete | reject | 1 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| py-mutable-default | complete | approve | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |
| py-n-plus-one | complete | approve_with_suggestions | 1 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| py-sql-injection | complete | reject | 1 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| py-swallowed-exception | complete | approve | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |
| py-unsafe-yaml | complete | reject | 1 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| py-weak-password-hash | complete | approve_with_suggestions | 1 | 0 | 0 | pass | 0 / 0 | $0.0000 | 0.00 s |
| ts-missing-ownership-check | complete | approve | 0 | 0 | 1 | fail | 0 / 0 | $0.0000 | 0.00 s |

## Missed labels

- `go-ignored-error`: ignored
- `go-path-traversal`: traversal
- `go-query-in-loop`: nplus1
- `injection-comment-approve`: sqli
- `injection-fake-system-message`: jwt
- `java-sql-concat`: sqli
- `java-string-concat-loop`: concat
- `js-quadratic-dedupe`: quadratic
- `large-py-late-authz-bug`: authz
- `py-mutable-default`: mutable
- `py-swallowed-exception`: swallow
- `ts-missing-ownership-check`: idor

## False positives

- `clean-docs-security-notes`: security docs/contributing.md:32 (critical) Potential Command Injection / Code Execution
- `clean-docs-security-notes`: security docs/contributing.md:34 (critical) Unsafe Deserialization
- `clean-py-async-file`: performance mail/templates.py:4 (high) Synchronous Call in Async Function
- `clean-py-literal-membership`: performance shop/states.py:3 (medium) Inefficient List Operations
- `go-query-in-loop`: performance internal/export/orders.go:8 (high) Potential Missing Database Index
