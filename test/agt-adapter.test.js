import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { adaptAgtAuditCloudEvent, inspectAgtSidecarDecision } from "../src/index.js";

const example = async (name) => JSON.parse(await readFile(new URL(`../examples/${name}`, import.meta.url), "utf8"));

test("converts a complete AGT audit CloudEvent into an authorization envelope", async () => {
  const result = adaptAgtAuditCloudEvent(
    await example("agt-audit-cloudevent.json"),
    await example("agt-adapter-context.json")
  );
  assert.equal(result.verifiable, true);
  assert.equal(result.disposition, "authorized");
  assert.equal(result.authorization.agentId, "agent:soc-remediator");
  assert.equal(result.authorization.toolCallId, "call-remediate-1042");
  assert.equal(result.authorization.policyGeneration, "42");
  assert.equal(result.authorization.argumentsDigest, "sha256:c97812e4d275135bfad98e0720d2310c85c0aa7f02ef8b933893d699c0cffe1f");
});

test("does not misrepresent an AGT session id as a native tool-call id", async () => {
  const event = await example("agt-audit-cloudevent.json");
  const context = await example("agt-adapter-context.json");
  delete context.nativeToolCallId;
  const result = adaptAgtAuditCloudEvent(event, context);
  assert.equal(result.verifiable, false);
  assert.equal(result.authorization, null);
  assert.equal(result.captureGaps.some((item) => item.code === "missing_native_tool_call_id"), true);
});

test("reports current AGT sidecar response capture gaps", () => {
  const result = inspectAgtSidecarDecision(
    { decision: "allow", matched_rule: "allow-case-evidence", reason: "approved", policy_name: "soc-remediation" },
    { agent_did: "agent:soc-remediator", action: "file.open", resource: "/evidence/case-1042.json" },
    { workloadId: "k8s:security/soc-remediator-0", effect: "read" }
  );
  assert.equal(result.disposition, "capture_incomplete");
  assert.equal(result.verifiable, false);
  assert.deepEqual(result.captureGaps.map((item) => item.field), [
    "decisionId", "principal", "toolCallId", "argumentsDigest", "policyGeneration",
    "policyDigest", "policyComplete", "issuedAt", "expiresAt", "nonce"
  ]);
});

test("does not turn an AGT deny into an authorization", async () => {
  const event = await example("agt-audit-cloudevent.json");
  event.data.policy_decision = "deny";
  const result = adaptAgtAuditCloudEvent(event, await example("agt-adapter-context.json"));
  assert.equal(result.disposition, "not_authorized");
  assert.equal(result.authorization, null);
});
