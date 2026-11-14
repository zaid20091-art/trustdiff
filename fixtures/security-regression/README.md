# A green agent test is not enough

Run `python3 fixtures/security-regression/run_demo.py`. The fixture creates a temporary Git repo, commits an independent negative-authorization test and approved contract into a trusted base, and then commits an agent's buggy implementation (`role != 'guest'`). The agent's weak admin-positive test passes. The baseline-owned verifier fails on a `user` role, and TrustDiff's narrow generated counterexample also fails. The actual target repo is not modified.

**Only this fixture** uses `--allow-host-execution` for portability in local/CI unit tests. The result is intentionally not attestable as independent evidence. Normal use requires a pinned Docker image, a trusted baseline and externally managed signing keys/verification workflow. This is one constructed regression, not a population-scale benchmark.
