# Contributing to TrustDiff

TrustDiff prioritizes evidence precision over accumulating tests. A new feature needs: a known failure mode, a conservative unknown-state policy, threat-model updates, reproducible tests, and an explanation of what the feature does *not* prove.

```sh
python -m unittest discover -s tests -v
python fixtures/security-regression/run_demo.py
```

A PR that changes verifier logic, workflows or policy is high risk by design. Have it reviewed independently, update a trusted baseline before requiring a new policy contract, and do not weaken the merge gate merely to make a PR pass. Do not commit `.trustdiff/`, credentials, private signer keys, or verification output presented as an external trust anchor.
