# Validation and benchmark honesty

The repository contains a reproducible security regression fixture at `fixtures/security-regression/run_demo.py`. It alters an admin check from `role == 'admin'` to `role != 'guest'`. A weak test that checks only the admin case passes, while an independent negative-role check rejects access for a non-admin. The fixture demonstrates the product wedge **in one deliberately constructed case only**, not measured detection performance.

Run:

```bash
python3 -m unittest discover -s tests -v
python3 fixtures/security-regression/run_demo.py
python3 fixtures/security-regression/benchmark.py
python3 -m pip install -e .
```

The delivery tests cover policy drift, critical evidence gaps, attacker-generated test changes, generated counterexample failure, local ledger corruption, Ed25519 tampering/identity/commit replay, Docker security flag construction, fail-closed unknowns and output format. Docker was **not** available in the delivery runtime; there is no claimed live container test.

The synthetic benchmark runs a positive-path smoke check and an expanded boundary check on one control and one deliberately planted mutant in each of the four domains. It emits per-case decisions and wall-clock timings as JSON. The fixture construction favors the boundary check by design. These results measure the fixtures and local execution overhead only.

## What must be measured next

- Mutant recall on real fixes from independent repositories and language ecosystems, especially missed authorization and payment failures.
- False-positive rate of risk classification and test-drift signals, with manual review effort per alert.
- Median/P95 gating latency and CPU/memory cost on cold/warm containers.
- Percentage of critical changes lacking mandatory contract coverage and time-to-close each gap.
- Reproducibility across host architectures, locked dependencies and pinned container digests.
- Adoption: branch-protection retention, PR reviewer actions, effective security regressions blocked.

No fabricated percentages, SLSA grades, recall score or production security guarantee are offered. Benchmarks should record a baseline against existing CI tests/linters and publish raw failing examples.
