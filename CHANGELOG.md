# Changelog

## 0.4.0

- Read committed Git blobs without executable checkout filters. Verify offline LFS objects and support hydrated worktrees.
- Add Windows subprocess-tree supervision, portable fixtures, and Windows/Linux CI for Python 3.10 through 3.13.
- Run approved Python counterexamples against baseline and candidate, and replay the same case after a proposed repair.
- Support authenticated negative verdicts in v2 evidence with explicit PASS enforcement for consumers.
- Keep verification artifacts outside the candidate in protected CI. Add a GitHub App check publisher and a VS Code diagnostic extension.

## 0.3.1 — Security Hardening

### P0-01 — MCP trust boundary
- **New `trustdiff_evidence.EvidenceValidator`**: reading a report is now separate from trusting it. Statuses: `VERIFIED`, `UNVERIFIED`, `STALE_REPORT`, `INVALID_EVIDENCE`, `NOT_RUN`.
- `VERIFIED` (and `verdict: "PASS"`) requires a signed proof bundle checked against trust anchors provisioned outside the repository (`TRUSTDIFF_ALLOWED_SIGNERS`, `TRUSTDIFF_PRINCIPAL`, optional `TRUSTDIFF_EXPECTED_POLICY_SHA256`), bound to the current `HEAD`, and identical to `latest.json`.
- Unsigned reports remain viewable but are labelled `UNVERIFIED`, shown under `claimed*` keys, sanitised (control/bidi characters stripped, strings and lists bounded) and flagged `untrusted_content`.
- The `READY` default was removed. `trustdiff_proof.bundle_errors()` is now the single verification routine used by `verify-proof` and the validator; it fails closed on malformed input instead of raising (previously `verify-proof` could crash with `AttributeError` on hostile bundles).
- `verify_ledger(state=None)` accepts an explicit state directory (default unchanged).
- **Compatibility:** `trustdiff_verdict` keeps `status`, `overall_verdict`, `target_commit`, `integrity`, `policy_source`, `limitations`, but `overall_verdict` is `PASS` only when verified (otherwise `UNKNOWN`), `status` no longer returns `READY`, and the last three fields move under `claimed` unless verified. `trustdiff_evidence_gaps` / `trustdiff_counterexamples` now return an object with `items` instead of a bare list (an empty list was indistinguishable from "no risk"). Report and proof file formats are unchanged. See `docs/reports/P0-01.md`.

### P0-02 — Verifier independent of the repository under test
- Gate is `pull_request_target` + reusable `trustdiff-verify.yml`; verifier = base commit code that must hash to the externally approved `TRUSTDIFF_VERIFIER_SHA256` (computed by inline workflow code, not by the verifier itself); candidate checked out as data, never executed on the host; digest-pinned runner image required (`check --require-pinned-image`).
- Signing isolated in an `attest` job bound to a protected environment; `verify` job has no secrets. All actions pinned to full SHAs (`docs/CI_PINS.md`), explicit permissions, Dependabot cooldown, real-Docker CI job.
- New `trustdiff_supply.py` (`verifier-digest`). Repositories whose git config can execute commands are refused (an agent could previously make the verifier run its command via `core.fsmonitor`/`diff.external`/`filter.*`).
- Fixed: uploaded evidence used hidden paths without `include-hidden-files`.

### P0-03 — Execution isolation
- Containers see a clean read-only export of the target commit only (no `.git`, `.trustdiff`, untracked files); per-job name/label/workspace; container killed by name on timeout/overflow and verified gone; bounded output (was unbounded in memory); pids/memory/cpu/fsize/ipc limits; Docker socket, devices, host namespaces and extra mounts refused by construction; challenge script copied before mounting.
- `check --runtime runsc|kata…`: stronger isolation (gVisor / Kata microVM) through the same constrained flags; fails closed if the runtime is not registered; recorded as `runner.runtime/isolation`.
- Real-Docker integration tests added (run by the `docker-integration` job).

### P0-04 — Evidence chain
- Proof bundle v2 (signed attestation: principal, key id, signing time, verifier digest, commit, baseline, policy digest, runner/isolation, environment). v1 still verifies (flagged legacy); `--require-v2` available.
- Trust store v2 with key ids, validity windows, `rotate-key`, `revoke-key` (absolute). `verify-proof` re-verifies without running tests (`--print-scope`, `--expected-verifier-sha256`).
- `approve-policy` / `verify-approval` signed policy-approval records. `publish-evidence` / `verify-evidence-store` write-once, hash-chained store. `verify-ledger` now states it is tamper-evident only.

### P0-05 — Untrusted input hardening
- New `trustdiff_safe.py`. Fixed: quadratic-backtracking regex in the JS import scanner; `RecursionError` crash on nested Python source; quoted/ambiguous file names (NUL-delimited paths, per-file literal diffs); unbounded diff/command output; unvalidated contract fields; regex backtracking in `deny_pattern` (isolated, 5 s limit); crashes on malformed reports/claims/bundles/trust stores; CLI tracebacks (`ERROR:` exit 2).
- New report fields `git_config_audit`, `unusual_paths`; `analysis_incomplete` gap when content analysis is truncated.
- 167 tests (was 16): regression, seeded fuzzing, signed-bundle mutation property, mutation-tested.

### Compatibility summary
See `docs/MIGRATION_0.3.0_to_0.3.1.md`. File formats are unchanged; deliberate behavioural breaks: MCP view shapes (P0-01), tests run on the target commit rather than the working tree, contract schema validation, mandatory gate configuration variables.

## 0.3.0 — Focused verification gate prototype

- Baseline-controlled contracts, drift protection, strict critical-risk coverage and clean-tree gates.
- Source-content risk heuristics, static Python/JS/TS dependency impact and test weakening warnings.
- Narrow executable admin-role counterexamples and explicit unexecuted challenge recipes.
- Restricted Docker command runner and evidence recording by execution mode/image digest.
- Ed25519 signed portable in-toto v1 Statements with external allowed signers and expected subject/policy checks.
- GitHub Gate PR workflow, package artifact attestation workflow, optional MCP read-only bridge, contributor guidance, SARIF/Markdown outputs.
- Expanded attack-oriented test suite; retained original authorization demonstration.

## 0.1.0 — Supplied alpha baseline

- Local-first CLI, Git input snapshots, policy and test contracts, claim accounting and chained local evidence ledger. The original historical artifacts are not cryptographic trust anchors.
