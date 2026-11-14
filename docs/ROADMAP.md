# Focused roadmap: verified changes, not feature count

## Shipped in alpha 0.3

Deterministic gate, trusted baseline contract selection, rudimentary static impact graph, declared risk coverage, static weakening alerts, a narrowly executable admin-role counterexample, restricted Docker runner, signed Ed25519 verification bundle, read-only MCP bridge and GitHub workflow scaffolding. Implementation has unit/integration coverage but still needs trusted infrastructure review and real-container exercises.

## Next: production hardening (highest priority)

- Separate signed/pinned verifier releases from candidate repositories and run checks in a separately managed GitHub reusable workflow or dedicated verification service.
- VM-grade job isolation with ephemeral identity and no ambient host authority; configuration-free runner bootstrap and immutable, audited container images.
- Cryptographically signed policy/approval records with externally anchored append-only storage and key rotation, compromise/revocation support, trusted timestamping.
- Replay commands and full environment/dependency material for isolated reproducibility; integration tests on real GitHub fork PRs and VM hosts.

## Then: prove superiority on real errors

- Mutation campaign covering authorization boundaries, idempotency/financial invariants, schema compatibility and async race conditions with real open-source projects.
- AST/dataflow/impact graph expansion with language plugins and uncertainty estimates. Ingestion of declared API/schema edges without running untrusted generators.
- Safer counterexample generation from approved contracts and formalized pre/postconditions; use an AI assistant *only* to draft tests, never to assign final verdicts.
- Tune false positives, cost and PR-time budgets using published per-project measurements.

## Adoption without trust compromise

- Stable CLI and structured API contract for agent ecosystems; separate public MCP tool for **reading** evidence and a protected verifier control-plane for accepting submissions.
- GitLab CI plugin that fetches trusted checker from protected registry and a status-check integration with permitted credentials.
- Check-action/reusable-workflow template, branch-protection setup docs, signed proof verification in release pipelines.

## Defer deliberately

- Autonomous "all bugs found" claims, every-language compatibility claims, self-approval agents, blockchain marketing and badges without independently audited metrics.

**Success definition:** identify and reproduce additional high-impact regressions missed by ordinary agent tests, while keeping reviewer alerts and gate time low, and making each acceptance decision independently auditable. Timing and product adoption are unvalidated research assumptions, not promises.
