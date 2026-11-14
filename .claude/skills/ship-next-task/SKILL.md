---
name: ship-next-task
description: Ship one tracker task end to end. Build it in a side session, verify, review with Bobby Review, fix and re-review until Ready, update the tracker, open a PR, merge on green CI, clean up. Use when the owner says "ship the next task", "ship P1-NN", or runs a /goal that loops over tracker tasks.
argument-hint: "[task id, e.g. P1-22; default: next todo task]"
---

# Ship the next tracker task

Run from the coordinating session in the main checkout. This session is the only one
that edits `docs/PROJECT_TRACKER.md`. Follow `AGENTS.md` and the owner's global rules
at every step.

## Hard rules

- **No AI attribution anywhere.** No `Co-Authored-By` trailers and no "Generated with"
  lines in commits or PR bodies. Commits are authored by the owner's git identity.
- **Never commit to `main`.** Work on `claude/...` side branches and a `chore/<task>` PR
  branch.
- **Pushing, opening PRs and merging need the owner's approval.** A `/goal` whose text
  says the owner authorizes pushing, opening PRs and merging counts as that approval for
  the tasks it names. Without it, stop and ask before each push and each merge.
- **Never work around a blocked permission.** If a commit, push or merge is denied, or a
  side session reports one, stop and ask the owner. Don't redo it from another session.
- **No secrets, keys, webhook ids or private URLs** in any file, commit, PR or brief.
- **Report results faithfully.** Say what ran, with the exact counts, and what did not run.

## Stop and ask the owner when

- The task needs an owner decision or secrets, such as a real provider run, a license,
  a decision marked "proposed", or `.env` values.
- Review is not "Ready" (no blocking or should-fix items left) after 3 fix rounds.
- CI fails twice on the same PR, or GitHub reports a merge conflict you can't resolve
  cleanly.
- A permission prompt or denial blocks a step.
- A side session waits on the user, or its report doesn't match the diff.

When you stop, print `STOPPED: <task id> - <reason>` so a `/goal` evaluator can see it.

## Steps

Print a short proof line after each step, for example `P1-22 step 4: review Ready`.
A `/goal` evaluator only reads the transcript.

1. **Pick the task.** Use `$ARGUMENTS` if given. Otherwise take the first `todo` row in
   the current phase of `docs/PROJECT_TRACKER.md`, skipping owner items. Read its scope
   and acceptance checks. Check that `main` is clean and up to date
   (`git pull --ff-only`). If the task is too big for one PR, split it in the tracker
   first and ship the first part.

2. **Build it in a side session.** Use `start_session` with `initiation: "user_asked"`
   (the goal or the owner's request counts as asking), a Sonnet model, `context: "fresh"`
   and `use_worktree: true`. The brief must give:
   - the tracker row and the files involved;
   - the acceptance checks as tests;
   - "do not edit the tracker";
   - the commands: `uv sync --frozen`, `ruff check .`, `pytest -q --cov=app`, and the
     CI-style audit (`uv export --frozen --no-hashes --no-emit-project` to a temp file,
     then `pip-audit -r <file> --no-deps --disable-pip`);
   - "commit on your branch, subjects carry the task id, no AI attribution";
   - "don't push, open a PR, merge or touch `main`";
   - "if a commit is blocked, stop and list what is uncommitted".

   If two tasks touch different files, they may run as parallel sessions.

3. **Verify the session's work yourself.** Don't trust its report.
   - Commit author: `git log --format='%h %an <%ae> %s' main..<branch>`.
   - No attribution: grep the commit messages for `co-authored|generated with|claude`.
     A library name like `anthropic` is fine.
   - Scope: `git diff --stat main...<branch>`.
   - Conflicts with other open branches: `git merge-tree --write-tree`.
   - Read the code diff.
   - Run the suite on the branch, or on a detached scratch worktree if several branches
     are combined. Remove the scratch worktree afterwards.

4. **Review.** Run the `bobby-review` agent in the background on the local branch, or
   on the merged branches. Give it:
   - the commits and what each one changes;
   - the acceptance checks;
   - your own concerns, to confirm or refute;
   - concrete adversarial probes.

   It must not post, push or commit. Spot-check its key findings against the code
   before you relay them.

5. **Fix and re-review.**
   - Fix blocking and should-fix items yourself in the task's worktree, with a
     regression test for each.
   - Confirm each new test fails on the old code and passes on the new.
   - Commit with the task id in the subject.
   - Send the new commits back to the same reviewer agent for a re-review.
   - Repeat until the verdict has no blocking or should-fix items, for at most 3 rounds.
   - Follow-ups go to the tracker, not into this PR.

6. **Prepare the PR branch.**
   - Create `chore/<task>` from `main`, then `git merge --no-ff` the task branch or
     branches.
   - Update the tracker:
     - mark the task `done`;
     - set the test row to the new counts;
     - point "Resume here" at the next task;
     - add a newest-first session log entry: what was done, the review outcome, what
       was not verified;
     - triage the review follow-ups by the convergence rule below;
     - record the review's findings count by severity in the session log entry, e.g.
       `findings: 0 blocking, 1 should-fix, 3 follow-up`.
   - Run ruff, the full suite and the CI-style audit. Then commit the tracker.

7. **Open the PR.**
   - Push with `-u`, retrying once on a network error.
   - Run `gh pr create` with a body covering: what changed, the review rounds, the exact
     verification counts, and what was not verified. No "Generated with" line.
   - Bind it with the PR tools (`get_status`).
   - Don't poll CI in a loop. If Auto-fix is on, wait for its events. Otherwise check
     `gh pr view <n> --json statusCheckRollup,mergeStateStatus` when it's time to merge.

8. **Merge.** Do this only with the owner's approval or the goal's authorization, and
   only when all checks pass and `mergeStateStatus` is `CLEAN`. Then:
   - Run `gh pr merge <n> --merge --match-head-commit <reviewed head sha>`.
   - Switch to `main` and `git pull --ff-only`.
   - Print `MERGED: <task id> PR #<n> at <merge sha>`.

9. **Clean up.**
   - Archive the side sessions with `archive_session`. If a hook rewrites the input,
     resend exactly the input it gives.
   - Check each worktree has no changes and each branch is merged into `main`
     (`git merge-base --is-ancestor`).
   - Remove the worktrees and delete the local branches with `git branch -d`.
   - Delete the remote PR branch and run `git fetch --prune`.
   - Print `CLEAN: <task id>` with `git worktree list` and `git branch -a`.

10. **Next.** If this runs under a `/goal`, go back to step 1 for the next task. Print
    `DONE: no shippable todo tasks left in <phase>` when only owner items remain.

## Convergence rule

Each review spins off follow-ups. If every follow-up becomes the next task, the loop
never ends. Triage them when you update the tracker:

- **Next task in the current phase:** only follow-ups that the reviewer would rank
  should-fix or worse. These are a wrong result, a security or data-safety gap, a
  README claim the code breaks, or a crash on reachable input. Put them in one new
  `todo` row.
- **Backlog, not a new current-phase task:** nits, optional items, refactors with no
  behaviour change, missing tests for already-correct code, and anything the reviewer
  marked low priority or pre-existing and harmless. Append them to a single backlog row
  in the next phase (create it once, then keep adding to it), and name the source task.
- **No qualifying follow-ups:** add no new row. Print
  `CONVERGED: <task id> - follow-ups moved to <backlog row>`.

Stop the loop when:

- a task's review finds no blocking or should-fix items (print `CONVERGED:` and then
  `DONE:`), or
- the last 2 tasks each produced only backlog follow-ups, or
- the goal's task or turn budget is reached (print `STOPPED: budget`).

When unsure whether a follow-up qualifies, put it in the backlog and say so in the
session log. The owner can promote it.
