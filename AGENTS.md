# TrustDiff contributor working agreement

- Read `README.md`, `docs/THREAT_MODEL.md`, and `trustdiff.contracts.json` before modifying security-relevant code.
- Never edit the baseline verifier, stored reports or approved contracts to obtain a passing verdict; a PR may propose policy changes, but they require independent review.
- Keep generated tests separate from the verifier-owned mandatory contracts. Treat semantic hypotheses and challenge recipes as suggestions until executed.
- After a change, run `python -m unittest discover -s tests -v` and `python fixtures/security-regression/run_demo.py`. If Docker is available, run the documented `trustdiff check --baseline BASE_SHA --runner docker --image DIGEST --challenge-mode run`.
- Never claim a verification **PASS** when the command fails, the runner is unavailable, the policy drifted or the key/trust anchor belongs to the coding agent.
- Signing private keys, allowed-signer trust stores and release credentials must remain entirely outside this repository and outside agent access.
- The independent GitHub PR gate, not these instructions, decides merge eligibility.
