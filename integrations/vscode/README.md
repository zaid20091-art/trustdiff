# TrustDiff for VS Code

Install the TrustDiff CLI outside the open workspace and set the application-level `trustdiff.executable` setting to its absolute path. Run **TrustDiff: Review Changes** from a trusted local workspace. Set `trustdiff.watchOnSave` to `true` for automatic diagnostics after saves.

To try the extension from source, open this directory in VS Code and launch an Extension Development Host, or run `code --extensionDevelopmentPath=ABSOLUTE_PATH_TO_THIS_DIRECTORY`. To package it, copy the repository's MIT `LICENSE` into this directory and run `vsce package` with the VS Code extension packaging tool installed. Install the resulting VSIX using **Extensions: Install from VSIX**.

Run `node --test extension.test.js` for executable path and diagnostic rendering tests. Local diagnostics flag sensitive paths using tracked and untracked changes.
