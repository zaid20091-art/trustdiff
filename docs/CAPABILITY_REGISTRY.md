# TrustDiff 0.4.0 capability registry

Status is based on local tests; not every operational environment has been tested. "Implemented" does not mean secure against all adversaries.

| Capability | Status | Evidence / limitation |
|---|---|---|
| Contracts loaded from approved Git baseline | **Implemented; tested** | `tests/test_beta_features.py`: rejected test-policy weakening. Requires trustworthy base SHA. |
| Restricted Docker contract runner | **Implemented; host side tested with a fake docker; real-Docker tests written but NOT run in the delivery environment** | `trustdiff_runner.py`, `tests/test_runner_hardening.py` (`RealDockerTests` need Docker + `TRUSTDIFF_TEST_IMAGE`). Shares host kernel. |
| Basic static contract `deny_pattern` | **Implemented; tested** | Checks added patch lines; bypassable heuristic, not semantic proof. |
| Independent claim accounting | **Implemented; tested** | `tests/test_claims.py`, `tests/test_alpha_gates.py`; waived ≠ proven. |
| Risk classification + coverage gap gate | **Implemented; tested** | Sensitive filenames/changed lines and explicit `covers`; false positives and missed dynamic risk possible. |
| Python/JS/TS import impact graph | **Implemented; Python path tested** | AST + relative import regex; no dynamic/service graphs. |
| Test weakening signals | **Implemented; heuristic** | Removed test files / assertion-count loss; does not prove regression. |
| Counterexample recipes | **Implemented; advisory** | Auth/money/DB/workflow/dependencies; not executed as evidence. |
| Executable adversarial admin-role generator | **Implemented; tested on fixture** | Exact three Python function names/one-argument `role`, generated negative cases. Narrow assumptions. |
| Approved counterexamples | **Implemented for Python call sequences** | Four domains exercised by local fixtures. External services and autonomous oracle generation remain open. |
| Reproduction and repair verification | **Implemented; fixture tests** | Requires pinned inputs and a descendant repair. Live Docker replay remains open. |
| Versioned JSON/HTML/Markdown/SARIF | **Implemented; tested** | SARIF generation tested; GitHub Code Scanning upload not enabled. |
| Archived report/linked local ledger | **Implemented; tested** | Detects local tamper, not remote full rewrite. |
| Ed25519 verifier proof + offline validation | **Implemented; tested** | Signed with external key in tests; tests cover tamper/replay/wrong principal. Real independent key custody not provided. |
| GitHub PR gate and artifact uploads | **Workflow and exact-head publisher provided** | Local policy tests and simulated Checks API. Live GitHub validation remains open. |
| GitHub tag release provenance | **Workflow provided; not executed** | GitHub `actions/attest@v4` signs wheel provenance, not code correctness. |
| Development tool integration | **CLI diagnostics, MCP and VS Code extension source** | Committed workflow events and optional editor save events trigger diagnostics independently of how edits were made. |
| GitLab | **Example only** | Fails closed, requires protected verifier integration. |
| Generic AI counterexample generation | **Not implemented** | Suggested recipes only; avoid unsupported claims. |
| External policy service, transparency, managed signing | **Not implemented** | Roadmap phase 2+. |
| Multi-repository benchmark/false-positive metrics | **Synthetic fixtures only** | Four control/mutant pairs. Real-repository detection metrics remain open. |
| EvidenceValidator / MCP trust states | **Implemented; tested** | `trustdiff_evidence.py`, `tests/test_evidence_validator.py`. PASS only when VERIFIED. Real MCP stdio transport not exercised (stub). |
| Verifier digest pinning + protected gate workflows | **Implemented; statically + scenario tested; NOT run on GitHub** | `trustdiff_supply.py`, `tests/test_workflow_policy.py`, `tests/test_fork_pr_scenarios.py`. |
| Stronger isolation runtime (`--runtime runsc/kata`) | **Implemented; fail-closed logic tested with fake docker; never run against gVisor/Kata** | `trustdiff_runner.py`. |
| Proof bundle v2, key rotation/revocation, signed policy approvals | **Implemented; tested** | Completed failure verdicts can be signed. Enforcing signed approvals remains separate. |
| Write-once evidence store | **Implemented; tamper-evident on ordinary storage** | `trustdiff_store.py`. Immutability needs external WORM storage. |
| Untrusted-input hardening, fuzz/property tests | **Implemented; tested** | `trustdiff_safe.py`, `tests/test_input_hardening.py`. Seeded fuzzing, not coverage-guided. |
