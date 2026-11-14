# Security policy

TrustDiff is an **alpha-quality security-sensitive project**. Treat the verifier, its plugins, CI configuration and signing environment as security-critical code. Do not rely on it as a complete security assessment or assume Docker provides VM-grade isolation.

Please report potential bypasses responsibly through a private GitHub security advisory in the repository where this software is published (if that feature is enabled). Avoid public exploit demonstrations against other users. No security response SLA is promised.

Threat model and trust assumptions: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Self-signed proof does not establish independence. The agent that writes candidate code must never have access to an attestation private key or control of the approved trust store.
