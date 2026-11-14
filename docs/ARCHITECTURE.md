# TrustDiff 0.4.0 architecture

## The trust decision

```text
Candidate PR/agent commit (untrusted)
                 |
                 v
        Git change + snapshots ------------------+
                 |                               |
                 v                               v
   Reviewer-owned contracts in BASE_SHA      Static risk/impact/test-drift analysis
                 |                               |
                 v                               v
   Constrained runner / static policy         Coverage obligations and challenge recipes
                 |                               |
                 +-------------+-----------------+
                               v
                       Evidence + verdict
                               |
             +-----------------+------------------+
             |                                    |
    Local chained archive                 Optional in-toto Statement
 (not external trust anchor)                    + Ed25519 signature
                                                  |
                                         Independent expected SHA,
                                         trusted signer and policy
```

The CLI applies acceptance policy. The impact analyzer classifies changes. The counterexample engine checks approved observations against both commits. The runner builds a committed snapshot, optionally hydrates verified LFS objects, and launches the chosen isolation profile. The repair command replays the original and repaired commits. Ed25519 signing and MCP are optional extras.

### Verdict logic

A check is `PASS` only if at least one **required** contract exists, every loaded contract returns technical `PASS`, every supplied agent claim is technically supported, input fingerprints remain stable, policy source is committed, no policy drift is detected and no critical risk remains without explicitly covered passing obligations. A waiver never creates proof. Unimplemented contract types result in `UNKNOWN` and a nonzero gate.

`coverage_gaps` records missing technical evidence; a zero-length gaps array is *not* an assertion that all hazards have been found. The conservative classifier detects sensitive path names and lines of changed Python/JS/TS code. Dynamic and transitive issues not inferable from imports can be missed.

### Change model

Inputs: base SHA, target `HEAD`, tracked/untracked snapshot and approved baseline contracts. Only **committed** changes are compared. If there are uncommitted or untracked candidate inputs, the check can still produce a diagnostic report, but `attest` refuses to sign it. Signed results are bound to the committed target and an immutable policy fingerprint. For cleaner reproducibility use a standalone/clean checkout and `--baseline BASE_SHA`.

### Isolation

`--runner docker` sets `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, non-root UID, resource limits, a read-only worktree and limited `/tmp`. `--pull=never` prevents the runner silently refreshing the image during verification. Always fetch/approve the container image first and pass an immutable `@sha256` digest. A Docker daemon is still privileged infrastructure; use disposable VMs and minimal host credentials for truly adversarial repositories. `--allow-host-execution` exists only for local demos, and results from it cannot be independently signed.

### Policy authority

The GitHub example extracts the verifier implementation from the PR's **base commit** before it evaluates candidate changes. Policies are also read from that base. Workflow and protected-branch permissions, however, are external trust assumptions, and the developer must not be able to modify the independent signing service. A controlled external verifier repository is the recommended next production step. When the baseline has no contracts, bootstrap must be handled in an independently reviewed commit.
