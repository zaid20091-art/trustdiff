# TrustDiff 0.4.0 security model

TrustDiff is a *verifier*. Its results are only as trustworthy as the separation between **who verifies** and **what is verified**.

## Roles and what each may control

| Party | May control | Must NOT control |
|---|---|---|
| Candidate (human or coding agent) | the branch: source, tests, `.git/config` of its own checkout, file names/types/sizes, workflow files in its branch | the verifier code, the approved verifier digest, acceptance policy, signing keys, trust stores, runner image, evidence store |
| Verifier (CI job / service) | executes the pinned verifier on candidate **data** | secrets (except the separate `attest` job), network inside test containers |
| Approver / org admin | repository variables, protected environment, trust store, policy approvals | – |

## Controls (0.4.0)

1. **Reading is not trusting.** `EvidenceValidator` (`trustdiff_evidence.py`) is the only path from `.trustdiff/latest.json` to a verdict. `VERIFIED` requires a signed proof, an authorised and currently valid signer, trust anchors outside the repository, the current `HEAD` and a clean worktree.
2. **Verifier independence.** The gate is `pull_request_target` (loaded from the base branch). The verifier is the base commit's code and must hash to `TRUSTDIFF_VERIFIER_SHA256`, a repository/organisation variable. The digest is computed by inline workflow code, not by the code being checked. The candidate is checked out as data and never executed on the host.
3. **Privilege split.** The `verify` job has no secrets and no environment. Signing is a separate `attest` job bound to the protected environment `trustdiff-signing`, running only the approved verifier, installing its dependency from a hash-locked file in the trusted base.
4. **Pinned supply chain.** Every `uses:` is a full commit SHA (policy-tested); Dependabot waits 7 days before proposing new releases; the runner image must be `@sha256:` (`--require-pinned-image`); the test container has no network so dependencies must be baked into that image.
5. **Execution isolation (Docker, defence in depth).** Clean read-only export of the target commit (no `.git`, `.trustdiff`, untracked files, secrets), no network, all capabilities dropped, no-new-privileges, pids/memory/cpu/file-size limits, private IPC, unprivileged user, per-job name and label, container killed by name on timeout/overflow, bounded output, workspace deleted in `finally`. The Docker socket, devices, host namespaces and extra mounts are refused by construction (`build_argv`).
6. **Git is untrusted input.** The verifier audits execution-capable Git configuration and disables hooks, external diffs, text conversion, lazy fetching and LFS filters. Snapshot export reads committed blobs directly. Optional LFS hydration uses an external cache with size and SHA-256 verification.
7. **Evidence.** v2 bundles bind signer (`principal`, `key_id`, `signed_at`), verifier code digest, commit, baseline, policy digest and runner. Trust stores support rotation (`not_before/not_after`) and hard revocation. Signed policy-approval records exist for policy changes. A write-once content-addressed store with a hash-chained log can be pointed at storage the candidate cannot write.
8. **Bounded everything.** Untrusted JSON, source files, diffs, output and regular expressions have size/time limits; overflow is an ERROR, never a pass.

## What is NOT covered (read this before relying on it)

* **GitHub-hosted behaviour was not exercised in this delivery.** The workflows are validated statically (`tests/test_workflow_policy.py`) and the PR scenarios are replayed with real git and the real verifier (`tests/test_fork_pr_scenarios.py`), but nothing was run on GitHub Actions itself. Run the workflows on a private fork first.
* Plain Docker shares the host kernel. Registered gVisor and Kata runtimes can be selected explicitly. Their setup and isolation require acceptance testing on the deployed worker.
* The tests marked `RealDockerTests` only run where Docker and `TRUSTDIFF_TEST_IMAGE` exist (the `docker-integration` CI job). They were skipped in the delivery environment.
* A local hash chain proves nothing about authorship. Only signatures verified against externally held anchors do.
* A v2 proof can authenticate PASS or FAIL. Merge consumers must require an authenticated PASS.
* Signed approvals are verifiable (`verify-proof --approval`) but the gate does not yet *require* them.
* A signed bundle binds tested obligations and results to the commit. Python candidate code shares a process with the observation worker, so use a stronger black-box boundary for hostile implementations.
