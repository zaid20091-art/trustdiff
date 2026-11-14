# Pinned GitHub Actions

All `uses:` references are pinned to full commit SHAs (enforced by `tests/test_workflow_policy.py`).
Verify a pin yourself before release: `gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha` (dereference annotated tags).

| Action | Tag | Commit | Verification in this delivery |
|---|---|---|---|
| actions/checkout | v4.2.2 | `11bd71901bbe5b1630ceea73d27597364c9af683` | [Upstream commit exists](https://github.com/actions/checkout/commit/11bd71901bbe5b1630ceea73d27597364c9af683) |
| actions/setup-python | v5.6.0 | `a26af69be951a213d495a4c3e4e4022e16d87065` | [Upstream commit exists](https://github.com/actions/setup-python/commit/a26af69be951a213d495a4c3e4e4022e16d87065) |
| actions/upload-artifact | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` | [Upstream commit exists](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02) |
| actions/download-artifact | v4.3.0 | `d3f86a106a0bac45b974a628896c90dbdf5c8093` | [Upstream commit exists](https://github.com/actions/download-artifact/commit/d3f86a106a0bac45b974a628896c90dbdf5c8093) |
| actions/attest-build-provenance | v4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` | [Upstream commit exists](https://github.com/actions/attest-build-provenance/commit/4d101475d8b20a2381f78447822ac1eab6504dd8). Confirm tag and nested action pins before changing the trusted workflow. |

The listed upstream commits exist. Live workflow execution and transitive action review remain separate checks.

## Required repository/organisation configuration (not files in a branch)

| Name | Kind | Purpose |
|---|---|---|
| `TRUSTDIFF_VERIFIER_SHA256` | variable | approved verifier digest: run `trustdiff verifier-digest` on a reviewed commit |
| `TRUSTDIFF_RUNNER_IMAGE` | variable | `image@sha256:<digest>` with the project's test dependencies baked in |
| `TRUSTDIFF_SIGNING_ENABLED`, `TRUSTDIFF_PRINCIPAL` | variables | enable signing and set the signer identity |
| `trustdiff-signing` | environment | holds `TRUSTDIFF_SIGNING_KEY`; require reviewers |
| `requirements-signing.lock` | file in the trusted base | `pip-compile --generate-hashes` output for `cryptography` (not shipped: hashes must be generated against your index) |

Protect `.github/` and the verifier modules with repository ownership rules. Require the installation's exact-head App check and review changes to `trustdiff.contracts.json` through the approved policy process.
