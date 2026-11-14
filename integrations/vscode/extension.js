"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { execFile } = require("node:child_process");

function trustedExecutable(configured, roots) {
  if (!configured || !path.isAbsolute(configured)) {
    throw new Error("Set an absolute TrustDiff executable path in user settings.");
  }
  const binary = fs.realpathSync(configured);
  if (!fs.statSync(binary).isFile() || (process.platform === "win32" && !/\.exe$/i.test(binary))) {
    throw new Error("Use the installed TrustDiff executable.");
  }
  for (const root of roots) {
    const relative = path.relative(fs.realpathSync(root), binary);
    if (!relative || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(".." + path.sep))) {
      throw new Error("Install TrustDiff outside the open workspace.");
    }
  }
  return binary;
}

function describe(raw) {
  const plan = JSON.parse(raw);
  if (plan.protocol !== "trustdiff.plan/v1" || plan.kind !== "diagnostic" || !Array.isArray(plan.risk_topics)) {
    throw new Error("Unexpected TrustDiff diagnostic output.");
  }
  const safe = (value) => String(value).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "?");
  return [
    `Path-based risks (${safe(plan.risk_count)} total). Diagnostic only.`,
    ...plan.risk_topics.map((risk) => `${safe(risk.level)} ${safe(risk.topic)} — ${safe(risk.path)}`),
  ].join("\n");
}

function activate(context) {
  const vscode = require("vscode");
  const output = vscode.window.createOutputChannel("TrustDiff");
  let timer;
  let child;
  let pending;
  function review(folder, reveal) {
    if (!vscode.workspace.isTrusted || !folder || folder.uri.scheme !== "file") return;
    if (child) {
      pending = {folder, reveal: reveal || pending?.reveal};
      return;
    }
    const config = vscode.workspace.getConfiguration("trustdiff");
    const roots = (vscode.workspace.workspaceFolders || []).filter((item) => item.uri.scheme === "file").map((item) => item.uri.fsPath);
    try {
      const exe = trustedExecutable(config.get("executable"), roots);
      child = execFile(exe, ["plan", "--working-tree"], {
        cwd: folder.uri.fsPath, timeout: 30_000, maxBuffer: 512 * 1024, windowsHide: true,
      }, (error, stdout) => {
        child = undefined;
        try {
          output.clear();
          output.appendLine(error ? "TrustDiff diagnostic failed. Check the selected repository and local installation." : describe(stdout));
        } catch (err) {
          output.appendLine(err.message);
        }
        if (reveal) output.show(true);
        if (pending) {
          const next = pending;
          pending = undefined;
          review(next.folder, next.reveal);
        }
      });
    } catch (err) {
      output.appendLine(err.message);
      if (reveal) output.show(true);
    }
  }
  context.subscriptions.push(output, vscode.commands.registerCommand("trustdiff.review", async () => {
    const editor = vscode.window.activeTextEditor;
    const active = editor && vscode.workspace.getWorkspaceFolder(editor.document.uri);
    const choices = vscode.workspace.workspaceFolders || [];
    const folder = active || (choices.length === 1 ? choices[0] : await vscode.window.showWorkspaceFolderPick());
    review(folder, true);
  }), vscode.workspace.onDidSaveTextDocument((document) => {
    if (!vscode.workspace.isTrusted || !vscode.workspace.getConfiguration("trustdiff").get("watchOnSave")) return;
    const folder = vscode.workspace.getWorkspaceFolder(document.uri);
    clearTimeout(timer);
    timer = setTimeout(() => review(folder, false), 600);
  }), { dispose() { clearTimeout(timer); pending = undefined; child?.kill(); } });
}

module.exports = { activate, describe, trustedExecutable };
