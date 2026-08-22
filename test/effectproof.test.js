import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  authorizationEnvelope,
  createEvidenceBundle,
  createWorkloadBinding,
  bindingTrustAnchor,
  digestArguments,
  generateAttestor,
  normalizeTetragonEvent,
  parseTetragonJsonLines,
  reconcile,
  trustAnchor,
  verifyEvidenceBundle,
  verdict
} from "../src/index.js";

const example = (name) => new URL(`../examples/${name}`, import.meta.url);

async function fixtures() {
  const authorization = authorizationEnvelope(JSON.parse(await readFile(example("authorization.json"), "utf8")));
  const events = JSON.parse(await readFile(example("tetragon-events.json"), "utf8"));
  return { authorization, events };
}

function identityFor(authorization, overrides = {}) {
  const issuer = generateAttestor("cluster-workload-identity");
  const binding = createWorkloadBinding({
    bindingId: "binding-1",
    agentId: authorization.agentId,
    workloadId: authorization.workloadId,
    podUid: "pod-uid-1042",
    cgroupId: "cgroup:77881",
    validFrom: "2026-08-22T11:59:00.000Z",
    validUntil: "2026-08-22T12:02:00.000Z",
    ...overrides
  }, issuer);
  return { issuer, binding, identity: { binding, trustAnchor: bindingTrustAnchor(issuer) } };
}

function normalize(event, overrides = {}) {
  return normalizeTetragonEvent(event, {
    operation: "file.open",
    effect: "read",
    arguments: { flags: "O_RDONLY" },
    argumentsDigest: digestArguments({ flags: "O_RDONLY" }),
    ...overrides
  });
}

test("matches the authorized effect and detects an extra kernel-observed effect", async () => {
  const { authorization, events } = await fixtures();
  const { identity } = identityFor(authorization);
  const findings = reconcile(authorization, events.map((event) => normalize(event)), identity);
  assert.deepEqual(findings.map((item) => item.classification), ["authorized_observed", "unauthorized_observed"]);
  assert.equal(verdict(findings), "violation");
});

test("fails loud when Tetragon process attribution is degraded", async () => {
  const { authorization, events } = await fixtures();
  const observation = normalize(events[0], { sensorHealth: "degraded" });
  const { identity } = identityFor(authorization);
  const findings = reconcile(authorization, [observation], identity);
  assert.deepEqual(findings.map((item) => item.classification), ["unverifiable", "authorized_not_observed"]);
  assert.equal(verdict(findings), "unverifiable");
});

test("fails loud when the policy generation was incomplete", async () => {
  const { authorization, events } = await fixtures();
  const incomplete = authorizationEnvelope({ ...authorization, policyComplete: false });
  const findings = reconcile(incomplete, [normalize(events[0])]);
  assert.deepEqual(findings.map((item) => item.classification), ["unverifiable"]);
});

test("creates independently verifiable Ed25519 evidence and rejects tampering", async () => {
  const { authorization, events } = await fixtures();
  const observations = events.map((event) => normalize(event));
  const { binding, identity } = identityFor(authorization);
  const findings = reconcile(authorization, observations, identity);
  const attestor = generateAttestor("kernel-attestor");
  const bundle = createEvidenceBundle({
    authorization,
    workloadBinding: binding,
    observations,
    findings,
    attestor,
    generatedAt: "2026-08-22T12:00:03.000Z"
  });
  assert.equal(verifyEvidenceBundle(bundle, trustAnchor(attestor)), true);
  assert.equal(verifyEvidenceBundle(bundle, trustAnchor(generateAttestor("kernel-attestor"))), false);
  const tampered = structuredClone(bundle);
  tampered.payload.verdict = "verified";
  assert.equal(verifyEvidenceBundle(tampered, trustAnchor(attestor)), false);
});

test("refuses an attestor claiming the acting agent identity", async () => {
  const { authorization, events } = await fixtures();
  const observations = [normalize(events[0])];
  const { binding, identity } = identityFor(authorization);
  assert.throws(() => createEvidenceBundle({
    authorization,
    workloadBinding: binding,
    observations,
    findings: reconcile(authorization, observations, identity),
    attestor: generateAttestor(authorization.agentId)
  }), /independent/);
});

test("rejects an untrusted or stale workload binding", async () => {
  const { authorization, events } = await fixtures();
  const valid = identityFor(authorization);
  const wrongIssuer = generateAttestor("cluster-workload-identity");
  let findings = reconcile(authorization, [normalize(events[0])], {
    binding: valid.binding,
    trustAnchor: bindingTrustAnchor(wrongIssuer)
  });
  assert.equal(findings[0].classification, "unverifiable");

  const stale = identityFor(authorization, { validUntil: "2026-08-22T12:00:30.000Z" });
  findings = reconcile(authorization, [normalize(events[0])], stale.identity);
  assert.match(findings[0].rationale, /does not cover/);
});

test("parses Tetragon JSONL and reports the failing line", async () => {
  const jsonl = await readFile(example("tetragon-events.jsonl"), "utf8");
  assert.equal(parseTetragonJsonLines(jsonl, {
    operation: "file.open",
    effect: "read",
    argumentsDigest: digestArguments({ flags: "O_RDONLY" })
  }).length, 2);
  assert.throws(() => parseTetragonJsonLines(`${jsonl}not-json\n`), /line 3/);
});
