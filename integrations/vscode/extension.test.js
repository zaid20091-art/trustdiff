"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { describe, trustedExecutable } = require("./extension");

test("rejects relative and workspace-owned executables", () => {
  assert.throws(() => trustedExecutable("./bin/trustdiff", []), /absolute/);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "trustdiff-editor-"));
  try {
    const binary = path.join(directory, "trustdiff.exe");
    fs.writeFileSync(binary, "");
    assert.throws(() => trustedExecutable(binary, [directory]), /outside/);
    assert.equal(trustedExecutable(binary, []), fs.realpathSync(binary));
  } finally {
    fs.rmSync(directory, {recursive: true});
  }
});

test("renders diagnostics without granting a verdict", () => {
  const plan = {protocol: "trustdiff.plan/v1", kind: "diagnostic", risk_count: 1,
    risk_topics: [{level: "critical", topic: "authorization", path: "new\nfile"}]};
  assert.match(describe(JSON.stringify(plan)), /Diagnostic only/);
  assert.match(describe(JSON.stringify(plan)), /new\?file/);
  assert.throws(() => describe('{"overall_verdict":"PASS"}'), /Unexpected/);
});
