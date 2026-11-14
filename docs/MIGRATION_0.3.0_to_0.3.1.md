# Migrating from 0.3.0 to 0.3.1

## Nothing to do
* `trustdiff.contracts.json`, `latest.json`, archived evidence, the ledger and v1 proof bundles keep their formats. Old reports still render and old bundles still verify (flagged `legacy`).
* `keygen`, `bundle`, `attest --key`, `verify-proof` keep working; `attest` without `--principal` still emits a v1 bundle (with a warning).

## Behaviour changes you may notice
| Change | Why | Action |
|---|---|---|
| MCP `trustdiff_verdict`: `status` is no longer `READY`; `overall_verdict` is `PASS` only when `VERIFIED`, else `UNKNOWN`; other fields move under `claimed` unless verified | a local JSON file is not proof | set `TRUSTDIFF_ALLOWED_SIGNERS` and `TRUSTDIFF_PRINCIPAL` in the MCP server env |
| MCP `trustdiff_evidence_gaps` / `trustdiff_counterexamples` return `{status, items, note, ...}` instead of a list | an empty list read as "no risk" | read `items` |
| Tests run against a clean export of the **target commit**, not the working directory | removes `.git`, state and untracked secrets from the container | commit what tests need; untracked files are not visible |
| Contracts are schema-validated (ids, `timeout_seconds` 1-600, command <= 64 strings, ...) | untrusted policy | fix rejected contracts; the error names the field |
| `deny_pattern` regexes run in an isolated child with a 5 s limit; timeout is `ERROR` | catastrophic backtracking | simplify the pattern |
| Repositories whose git config can execute commands are refused | an agent can edit `.git/config` | verify a fresh clone, or `TRUSTDIFF_TRUST_GIT_CONFIG=1` for a repo you control (recorded in the report as `git_config_audit: overridden`) |
| `worktree_sha256` is computed over per-file digests instead of raw bytes | no unbounded reads / special files | none (value changes; it was never a stable interface) |
| `trustdiff.contracts.json` `command`/`timeout_seconds` limits | see above | none for valid contracts |
| New report fields `git_config_audit`, `unusual_paths` | transparency | none |
| Gate workflow is `pull_request_target` + reusable workflow | PR could edit the old gate | configure the variables in `docs/CI_PINS.md` |

## New optional features
`attest --principal` (v2 bundles), `rotate-key`, `revoke-key`, `approve-policy`/`verify-approval`, `verifier-digest`, `publish-evidence`/`verify-evidence-store`, `check --require-pinned-image`.

## Schema versioning
Proof bundles carry `bundle_version` (1 or 2). Verifiers must reject unknown versions (0.3.1 does). Approval records carry `approval_version: 1`. Trust stores: v1 (`{principal: [base64 keys]}`) is still read; `rotate-key` rewrites it as v2. Downgrading a v2 trust store to a 0.3.0 verifier is not supported.
