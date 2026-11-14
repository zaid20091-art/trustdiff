# TrustDiff threat model, alpha 0.4.0

## Adversary

A coding agent or contributor can edit candidate source, tests, dependency manifests, change descriptions and most files of the candidate branch, including its copy of TrustDiff and its future report outputs. It can attempt to remove tests, switch role comparisons, forge JSON, make tests pass for a partial input, change a workflow, alter dependency resolution, or replace an entire local ledger.

## Defenses implemented

- **Baseline policy pinning:** `check --baseline SHA` runs the mandatory contract set from that Git commit, not candidate replacements. Contract-file drift is flagged as a gate error. The SHA must refer to a legitimately approved base. A self-selected baseline does not provide an independent authority.
- **Bounded test execution:** requires explicit Docker runner with network disabled, read-only source, unprivileged user, dropped capabilities and limits. No shell wrapping is used for contract commands. This is a *hardening profile*, not a VM-grade containment guarantee.
- **Fail-closed unknowns:** missing policy, non-passing required checks, broken integrity, unsigned proof, mismatched expected commit or bad signer cause a nonzero result. Critical risk coverage failures block merge when the GitHub job is protected and required.
- **Signed report binding:** `attest` requires clean Git state, a passing report, an intact local archive/ledger and a baseline-anchored policy. The verifier checks Ed25519 signature authorization from a JSON trust store and exact target SHA, plus optional approved policy digest. Key control is external to the agent.
- **Counterexamples:** approved Python sequences check observed values on the baseline and candidate. Generated name-based authorization probes supply narrower diagnostic evidence. Arbitrary Python can influence its own observation process.

## Explicitly NOT guaranteed

- No proof of absence of every bug or bypass; AI semantic inference is not performed.
- No complete call graph, API/service-to-service dependency graph or database reachability. Reflection, dynamic import, side effects, ignored files, runtime services, external APIs and nondeterministic scheduling are not modeled.
- The runtime profile does not establish that the host or daemon actually provides VM-grade isolation. Host, daemon, runner, shared-cache and protected-maintainer compromise remain outside the current guarantees.
- No protection against malicious or incorrect trusted policies. `covers` declares reviewer intent; only independent contract quality and adversarial benchmarking justify confidence.
- No remote timestamp/append-only transparency server. An attacker can rebuild a local SHA-256 ledger; third parties must trust an **external** key and policy commitment.
- No automatic approval workflow or tamper-resistant hardware-backed key custody; signature generation helper is demonstration-only and must not be used in the agent workspace for production.
- No protection if repository administrators disable GitHub required checks, forge an approved baseline, modify a workflow in a protected branch or grant the agent access to CI signing credentials.

## Residual / next-hardening decisions

Move the verifier into a separate protected distribution or reusable workflow pinned by SHA; use VM-level execution and ephemeral identities; add externally recorded signed policy decisions; introduce evidence transparency and immutable attestations; pin GitHub actions by full hash; fuzz report and ledger parser inputs; test the actual configured CI environment including fork PRs.
