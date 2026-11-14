# The product bet: Proof-Carrying Pull Requests

## The painful decision

A reviewer often sees a green AI-generated PR and cannot tell whether the AI wrote tests that only validate its favorite case. TrustDiff attempts to answer: "What exactly was checked by an entity that did not write this code? What important behavior is still untested? Should merge proceed?"

## The concentrated wedge

The first excellent workflow is **authorization regressions**: changed access checks automatically trigger a risk/coverage gap, a proposed negative-role test, and (for one narrow explicit interface) an executable counterexample that can fail a green PR. This is stronger than claiming to understand every vulnerability.

Build the market narrative around one repeatable demonstration: ordinary unit tests pass; a scoped independent challenge finds an actual permissions regression; code review receives a report, clear unknowns and an artifact tied to the commit. Earn confidence by repeated, independently measured comparisons. Generalize to financial idempotency and data migration only after each domain has a credible oracle and fixtures.

## Technical differentiation

- Trust policy anchored to the reviewer branch, not agent output.
- Deterministic check and traceable report, with a public signature verification protocol.
- Cost-aware planning: classify critical change surfaces and avoid running expensive optional challenge suites on doc edits; mandatory baseline contracts still run.
- Integration by **status check and artifact**, not a new editor or giant autonomous agent.

## Red lines

No unqualified "secure" sticker; no signed proof from a compromised/shared agent environment; no passing a critical risk based solely on AI reasoning or `covers` metadata; no lying that a proposed counterexample actually ran. Availability of a signed bundle alone is not independence: key, policy, workflow and host custody are separate controls.
