# Integrations

## GitHub verification workflow

1. Commit the extracted source tree, including `.github/` and `.gitattributes`. Protect the base branch and restrict edits to the workflows, policy and verifier modules.
2. From the approved release checkout, run `trustdiff verifier-digest` and set `TRUSTDIFF_VERIFIER_SHA256` in protected repository or organization settings. Set `TRUSTDIFF_RUNNER_IMAGE` to an approved digest-pinned Linux image. Optionally set `TRUSTDIFF_RUNNER_RUNTIME` to a registered runtime such as `runsc` or `io.containerd.kata.v2`.
3. The example runs on `pull_request_target` with read-only contents access. It checks the expected head, verifies the base verifier before use, keeps evidence outside the candidate directory and executes candidate tests through the configured runner. Keep package installs, build steps and candidate-controlled executable files out of this workflow's host steps. [GitHub security guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
4. To enable signing, provision a separate protected `trustdiff-signing` environment, its `TRUSTDIFF_SIGNING_KEY` secret, the `TRUSTDIFF_PRINCIPAL` and `TRUSTDIFF_SIGNING_ENABLED=true` variables, and a reviewed `requirements-signing.lock` with hashes for the exact runner. The verify job has no signing secret. The signing job consumes that run's artifact and binds the expected base, head and verifier. A failed completed gate can produce signed failure evidence.
5. The workflow's own check may bind to the base event context. Use the exact-head app check below if configuring a required check. Validate the ruleset with a fork containing a known failure. [Required checks troubleshooting](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)

### Publish the exact-head result

Create and install a GitHub App with **Checks: write** for the target repository. On a protected publisher, obtain a short-lived installation token and inject it as `TRUSTDIFF_GITHUB_INSTALLATION_TOKEN`. Provide the independently expected PR metadata and digests, and use a trust store controlled by the publisher. The publisher requires the signed report's repository binding, which the workflow supplies with `check --repository OWNER/REPO`.

```bash
python integrations/github/publish_check.py --repository OWNER/REPO \
  --bundle proof.json --principal independent-ci --signers /secure/signers.json \
  --commit "$PR_HEAD" --baseline "$PR_BASE" --policy "$POLICY_SHA" --verifier "$VERIFIER_SHA"
```

Choose **TrustDiff Independent Verification** in the branch ruleset and select the registered app as the expected source. The publisher creates a completed check run after v2 evidence authenticates. Repeated publish calls can create repeated checks. App registration, token minting, webhook delivery, deduplication and fork/merge-queue acceptance tests are deployment work. [Check runs API](https://docs.github.com/en/rest/checks/runs#create-a-check-run)

## VS Code

The extension in `integrations/vscode` uses a TrustDiff CLI installed outside the workspace. Set `trustdiff.executable` to its absolute path in user settings. Run **TrustDiff: Review Changes**. Opt into `trustdiff.watchOnSave` to refresh path risks after saves. Workspace Trust gates these commands. Reports appear in the TrustDiff output channel and carry diagnostic status. Follow the [extension README](../integrations/vscode/README.md) to package or run it. [VS Code Workspace Trust](https://code.visualstudio.com/api/extension-guides/workspace-trust)

## Development tools and MCP

Any tool can call `trustdiff plan --working-tree` for bounded local path diagnostics, invoke `reproduce` on an independent verifier, or use the read-only MCP bridge to inspect an authenticated verdict. The bridge exposes `trustdiff_verdict`, `trustdiff_evidence_gaps`, and `trustdiff_counterexamples`. Configure its external trust anchors in the process environment.

```json
{"TRUSTDIFF_ALLOWED_SIGNERS": "/secure/signers.json", "TRUSTDIFF_PRINCIPAL": "independent-ci"}
```

Install the optional SDK with `python -m pip install ".[mcp]"` and launch `python -m trustdiff_mcp`. [Client configuration example](../integrations/mcp.example.json)

## Other CI

The GitLab example requires provisioning an independent worker and supplying the merge-request baseline. The package-provenance workflow emits separate wheel-build provenance on version tags.
