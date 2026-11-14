# Approved counterexamples and reproduction

Define deterministic Python call sequences in the trusted policy. Each sequence runs in one process so later calls can observe state changes. The verifier keeps the expected JSON outside that process and checks it against the approved baseline first.

```json
{
  "id": "IDEMPOTENCY-01",
  "type": "counterexample",
  "domain": "money",
  "path": "billing.py",
  "calls": [
    {"function": "capture", "args": ["payment-1"]},
    {"function": "capture", "args": ["payment-1"]}
  ],
  "expected": [{"charged": true}, {"charged": false}],
  "covers": ["money"],
  "timeout_seconds": 15
}
```

The other domain labels are `authorization`, `database` and `api`. Use positive and negative authorization cases, data-preservation checks around a migration, or old client inputs as appropriate. Domains describe the contract; each project supplies its own fixtures and expected behavior. Access to external services is blocked in the Docker profile.

Baseline mismatch yields `UNKNOWN`, worker or snapshot errors yield `ERROR`, and a validated baseline followed by a candidate mismatch yields `FAIL`. A baseline passing a proposed case is necessary for a regression assertion and does not establish that the expected behavior is correct. Add cases and their coverage via a separately reviewed baseline policy update.

Use `trusted_script` on a `test` contract to mount a verifier-owned Python script read from the baseline. It runs with the committed snapshot as its working directory and Python isolated mode enabled. Add the working directory to the import path explicitly inside the trusted driver only if the test intentionally imports candidate code. Existing command-based contracts execute against candidate-owned files. For hostile code, the in-process Python observation worker can be manipulated by code it imports. Use an independently controlled black-box driver and separate service process for higher-assurance behavior checks.

## Replay and repair

Run the command below in the candidate repository from the independently provisioned verifier. Use the same pinned image, approved objects and runtime as the original check.

```bash
export TRUSTDIFF_STATE_DIR=/secure/trustdiff-run-state
trustdiff reproduce --case IDEMPOTENCY-01 --baseline "$BASE_SHA" --target "$ORIGINAL_SHA" \
  --policy-sha256 "$POLICY_SHA256" --verifier-sha256 "$VERIFIER_SHA256" --image "$RUNNER_IMAGE"
```

The JSON includes the tested source path, inputs, expected and observed JSON, revisions and runner profile. Share it with any repair tool or developer. Exit 0 means the failure was reproduced. Exit 1 means the run did not reproduce that assertion. Supply `--repair REPAIR_SHA` from a clean checkout of the descendant repair to require the original failure, a passing replay against the repair, and a passing full gate. This path makes no edits and grants no merge authority.

## Git LFS and snapshot limits

Verification disables Git's executable LFS filters. For container tests, approve and populate a cache separately, outside the candidate checkout. Pass `--lfs-cache /approved/lfs/objects` to read objects arranged as `OID[:2]/OID[2:4]/OID`. TrustDiff checks the committed pointer's SHA-256 and size before use. A missing, corrupt or unsupported object stops execution. The runner does not fetch object URLs or use candidate LFS config.

Snapshots cap total materialized content at 512 MiB and regular Git blobs at 32 MiB. The runner refuses tracked symlinks, submodules, reserved state directories and names that cannot be represented safely across Windows and POSIX. Static diagnostics can still report unusual Git names.
