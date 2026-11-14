# TrustDiff

**Do not trust AI-generated changes. Verify their claims and record what remains unknown.**

[العربية](README.ar.md) · [Threat model](docs/THREAT_MODEL.md) · [Architecture](docs/ARCHITECTURE.md) · [Capability registry](docs/CAPABILITY_REGISTRY.md) · [Roadmap](docs/ROADMAP.md)

TrustDiff is a **developer-first, evidence-carrying code-review gate**. It checks a change against baseline-controlled contracts, highlights risks missing evidence, creates narrowly scoped counterexample tests, and can issue an independently signed verification bundle. Its core makes deterministic decisions; agent output is never a substitute for independent test evidence.

**Status: 0.4.0 alpha.** See the [release audit](docs/reports/0.4.0-AUDIT.md) for test results and deployment gaps.

## Why this is different

- **Protected acceptance policy:** on PRs, contracts are loaded from the *trusted base commit*; changing or deleting policy inside a candidate PR makes the gate fail, rather than quietly weakening the test suite.
- **Risk-to-evidence mapping:** sensitive authorization, money, CI/secrets, database and dependency edits are classified. Critical risks without an explicitly covered **passing** contract block acceptance. Coverage declarations remain reviewer-owned, and weak contracts are still possible.
- **Impact-aware review:** static Python/JS/TS import graph identifies affected files/tests, while test deletion and assertion reduction are reported as review signals (not proven bugs).
- **Counterexamples:** reviewer-approved Python call sequences capture authorization boundaries, idempotency, migration behavior and API compatibility. The verifier validates the expected observations on the baseline before comparing the candidate. Named admin functions also yield a limited heuristic probe.
- **Fail-closed constrained execution:** Docker runs commands as a non-root user with no network, a read-only source mount, dropped Linux capabilities, limited resources and restricted writable temporary storage. Without explicit permission the checker refuses to execute. Docker is not a substitute for a hardened VM.
- **Portable proof:** JSON report, per-obligation evidence, append-only local hash ledger, SARIF/HTML/Markdown outputs, in-toto v1 statement and optional Ed25519 signing with a separately controlled key. Verification binds the signature, expected Git commit, and (optionally) the approved policy hash.
- **Integrations:** CLI diagnostics, a protected GitHub verification workflow, a Checks API publisher for a GitHub App, a VS Code extension and a read-only MCP bridge.

## Fast start: new GitHub repository

Extract this distribution ZIP into a directory, then initialize a Git repository if you did not download it using `git clone`:

```bash
git init -b main
git add .
git commit -m "Initial TrustDiff 0.4.0 source"
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
python3 fixtures/security-regression/run_demo.py
```

`trustdiff check` intentionally refuses to run test contracts on the host unless explicitly opted in. With a trusted Docker daemon:

```bash
docker pull python:3.11-slim
IMAGE="$(docker image inspect python:3.11-slim --format '{{index .RepoDigests 0}}')"
trustdiff check --baseline HEAD --runner docker --image "$IMAGE" --challenge-mode run
trustdiff report --format html --output .trustdiff/report.html
trustdiff report --format sarif --output .trustdiff/findings.sarif
trustdiff verify-ledger
```

On a PR, supply the approved base commit. The included protected workflow produces artifacts from the reviewer-controlled verifier. Use the authenticated GitHub App check on the exact head SHA for merge enforcement. [GitHub setup](docs/INTEGRATIONS.md)

## Portable signed evidence

Core uses only the Python standard library. Signature issuance/validation is an optional extra:

```bash
python3 -m pip install -e '.[crypto]'
# For a local *demo only*: production keys belong to an independent verifier.
trustdiff keygen --private "$HOME/trustdiff-verifier.pem" --allowed-signers "$HOME/trustdiff-trusted.json" --principal independent-ci
# After a clean, passing check with committed trusted policy and digest-pinned runner:
trustdiff attest --key "$HOME/trustdiff-verifier.pem" --output .trustdiff/proof.json
trustdiff verify-proof --bundle .trustdiff/proof.json \
  --allowed-signers "$HOME/trustdiff-trusted.json" --principal independent-ci \
  --expected-commit "$(git rev-parse HEAD)" --require-pass
```

Add `--expected-policy-sha256 <approved-digest>` in a real release gate. **Never let the coding agent own the signing key, approved policy or allowed-signers file**. A local self-signature is technically verifiable but does not establish independent trust. `trustdiff bundle` can create an **unsigned** portable evidence file; `verify-proof` correctly rejects it as unauthenticated. GitHub `actions/attest@v4` in the tag workflow signs **wheel build provenance**, which is distinct from the TrustDiff code-verification verdict.

## Commands

| Command | Purpose |
|---|---|
| `trustdiff init` | Initialize ignored local state |
| `trustdiff plan --working-tree` | Show path risk diagnostics for tracked and untracked local changes |
| `trustdiff check --baseline SHA --runner docker --image IMAGE` | Policy-controlled check, risk/impact analysis, evidence report, optional challenges |
| `trustdiff report --format json\|html\|markdown\|sarif` | Human/machine-readable report |
| `trustdiff verify-ledger` | Check local hash links and archived report digests |
| `trustdiff bundle` | Create portable **unsigned** evidence, only after passing gate |
| `trustdiff attest --key KEY` | Sign a verified, clean, approved run using an external Ed25519 private key |
| `trustdiff reproduce --help` | Replay an approved case and optionally verify a descendant repair |
| `trustdiff verify-proof --bundle FILE --allowed-signers FILE --principal NAME --expected-commit SHA` | Verify signature and its accepted subject and verdict |

## Adoption model

TrustDiff intentionally starts with **one painful decision**: *can this particular AI-authored change be accepted based on verifiable obligations, and what high-risk behavior was left unchecked?* Use agent suggestions to propose tests, but let reviewer-owned contracts and a separate execution/signing environment make the decision. See [`docs/PRODUCT_BET.md`](docs/PRODUCT_BET.md) for the focus and honest success measures.

Read the [counterexample and reproduction guide](docs/COUNTEREXAMPLES.md) and the [evidence protocol](docs/EVIDENCE_PROTOCOL.md). Source is distributed under the [MIT License](LICENSE).
