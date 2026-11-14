# Delivery notes

The current release is TrustDiff 0.4.0. See the [release audit](docs/reports/0.4.0-AUDIT.md), [integrations](docs/INTEGRATIONS.md), and [evidence protocol](docs/EVIDENCE_PROTOCOL.md). The extracted source tree includes dotfiles and workflows. Commit that tree to a Git repository to configure GitHub checks.

## Historical delivery notes for 0.3.0

This package upgrades the supplied TrustDiff 0.1 alpha code into a focused, test-backed verification-gate prototype. It keeps the original CLI concepts (`init`, `check`, `report`, `verify-ledger`) but extends the implementation into modules with trusted baseline policy, critical-risk coverage gate, Docker execution profile, impact analysis, generated negative authorization tests, in-toto-style portable statement with Ed25519 proof, SARIF/Markdown/HTML reports, and integration templates for GitHub and coding agents.

## Completed verification in the delivery environment

- 16 Python unit/integration tests passed, including tamper detection, commit-replay mismatch, policy drift, evidence gaps, generated authorization counterexample, ledger validation and SARIF generation.
- Authorization regression fixture demonstrates: weak agent-only tests PASS; independently authored negative-role contract FAIL; TrustDiff-generated boundary challenge FAIL; overall gate FAIL.
- Build wheel from source and install it into a separate virtualenv without external downloads using a locally built wheel; CLI entrypoint was verified.
- Docker daemon was not available: Docker security *arguments* were tested using a subprocess mock; there is **no claim** of live container execution or CI validation on GitHub.
- GitHub Workflows are supplied but have not yet run on an actual GitHub-hosted runner.

## Bootstrap and GitHub limitations

This ZIP is a **source tree snapshot**, not a `.git` repository. Extract it, run `git init -b main`, `git add .`, `git commit`, configure a remote and push. GitHub must be configured manually to enforce the `TrustDiff Gate / verify` status check. Existing historical alpha Git bundle and `.trustdiff/` runtime output from the user-uploaded alpha delivery are **not republished**: they are not revised proofs and would add misleading, potentially private artifacts to the GitHub source tree. The original upload remains the source for that legacy history.

`trustdiff check` without Docker is deliberately nonzero for test contracts. The first repository commit establishes the reviewed policy baseline. If a candidate PR changes policy, the gate refuses to silently accept it; a reviewer must update trusted contracts in an approved change. A signed proof is not independent without external key control and a protected verifier.

## Suggested next high-value milestone

Use a protected, separately distributed verifier workflow and VM isolation, run the included Docker workflow on real fork PRs, then publish a small dataset of real authorization failures and false-positive measurements. See `docs/ROADMAP.md`.
