# External specifications and ecosystem research (reviewed November 2026)

Design choices were checked against:

- [in-toto Attestation Framework, Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) — subject digest and custom predicate structure; TrustDiff intentionally uses a custom predicate rather than claiming official SLSA compliance.
- [SLSA provenance specification](https://slsa.dev/spec/v1.0/provenance) — provenance is not a blanket proof of correctness.
- [pyca/cryptography Ed25519 primitives](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) — signature and verification semantics.
- [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/) — network/read-only/dropped capabilities/security options. Isolation remains defense in depth.
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) and [actions/attest](https://github.com/actions/attest) — released wheel provenance, not the code-review verdict.
- [GitHub's warning on `pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target) — avoid running untrusted PR code in privileged CI contexts.
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/) for the read-only evidence interface.
- [OpenSSF Scorecard](https://scorecard.dev/) — external checks worth adding to verifier repository governance.

These sources inform technical choices, but reading their documentation alone does not validate the security of TrustDiff's implementation.
