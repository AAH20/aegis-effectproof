#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { stdin } from "node:process";
import { adaptAgtAuditCloudEvent } from "./adapters/agt.js";
import { authorizationEnvelope, digestArguments } from "./contracts.js";
import { attestorFromPrivateKey, createEvidenceBundle, exportPrivateKey, generateAttestor, trustAnchor, verifyEvidenceBundle } from "./evidence.js";
import { bindingTrustAnchor, createWorkloadBinding } from "./identity.js";
import { reconcile } from "./reconcile.js";
import { normalizeTetragonEvent, parseTetragonJsonLines } from "./tetragon.js";

async function loadJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function options(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    if (!name?.startsWith("--") || args[index + 1] === undefined) throw new TypeError(`invalid option ${name ?? ""}`);
    parsed[name.slice(2)] = args[index + 1];
  }
  return parsed;
}

function requireOptions(value, names) {
  for (const name of names) if (!value[name]) throw new TypeError(`--${name} is required`);
}

async function readInput(path) {
  if (path !== "-") return readFile(path, "utf8");
  const chunks = [];
  for await (const chunk of stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function keygen(args) {
  const value = options(args);
  requireOptions(value, ["identity", "private-out", "trust-out"]);
  const attestor = generateAttestor(value.identity);
  await writeFile(value["private-out"], exportPrivateKey(attestor), { mode: 0o600 });
  await writeFile(value["trust-out"], `${JSON.stringify(trustAnchor(attestor), null, 2)}\n`, { mode: 0o644 });
}

async function bind(args) {
  const value = options(args);
  requireOptions(value, ["input", "issuer-id", "issuer-key", "out"]);
  const issuer = attestorFromPrivateKey(value["issuer-id"], await readFile(value["issuer-key"], "utf8"));
  const binding = createWorkloadBinding(await loadJson(value.input), issuer);
  await writeFile(value.out, `${JSON.stringify(binding, null, 2)}\n`, { mode: 0o644 });
}

async function attest(args) {
  const value = options(args);
  requireOptions(value, ["authorization", "binding", "binding-trust", "events", "attestor-id", "attestor-key", "out"]);
  const authorization = authorizationEnvelope(await loadJson(value.authorization));
  const binding = await loadJson(value.binding);
  const bindingTrust = await loadJson(value["binding-trust"]);
  const observations = parseTetragonJsonLines(await readInput(value.events), {
    operation: authorization.operation,
    effect: authorization.effect,
    argumentsDigest: authorization.argumentsDigest,
    sensorHealth: value["sensor-health"] ?? "ready"
  });
  const findings = reconcile(authorization, observations, { binding, trustAnchor: bindingTrust });
  const attestor = attestorFromPrivateKey(value["attestor-id"], await readFile(value["attestor-key"], "utf8"));
  const bundle = createEvidenceBundle({ authorization, workloadBinding: binding, observations, findings, attestor });
  await writeFile(value.out, `${JSON.stringify(bundle, null, 2)}\n`, { mode: 0o644 });
  console.log(JSON.stringify({ verdict: bundle.payload.verdict, findings: findings.length, output: value.out }));
}

async function verifyBundle(args) {
  const value = options(args);
  requireOptions(value, ["bundle", "trust"]);
  const valid = verifyEvidenceBundle(await loadJson(value.bundle), await loadJson(value.trust));
  console.log(JSON.stringify({ valid }));
  if (!valid) process.exitCode = 1;
}

async function agtAdapt(args) {
  const value = options(args);
  requireOptions(value, ["event", "context", "out"]);
  const result = adaptAgtAuditCloudEvent(await loadJson(value.event), await loadJson(value.context));
  await writeFile(value.out, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o644 });
  console.log(JSON.stringify({ disposition: result.disposition, verifiable: result.verifiable, captureGaps: result.captureGaps.length, output: value.out }));
  if (result.disposition === "capture_incomplete") process.exitCode = 3;
}

async function demo() {
  const authorization = authorizationEnvelope(await loadJson(new URL("../examples/authorization.json", import.meta.url)));
  const events = await loadJson(new URL("../examples/tetragon-events.json", import.meta.url));
  const identityIssuer = generateAttestor("cluster-workload-identity");
  const binding = createWorkloadBinding({
    bindingId: "binding-security-remediator-0", agentId: authorization.agentId, workloadId: authorization.workloadId,
    podUid: "pod-uid-1042", cgroupId: "cgroup:77881",
    validFrom: "2026-08-22T11:59:00.000Z", validUntil: "2026-08-22T12:02:00.000Z"
  }, identityIssuer);
  const observations = events.map((event) => normalizeTetragonEvent(event, {
    operation: "file.open", effect: "read", arguments: { flags: "O_RDONLY" }, sensorHealth: "ready",
    argumentsDigest: digestArguments({ flags: "O_RDONLY" })
  }));
  const findings = reconcile(authorization, observations, { binding, trustAnchor: bindingTrustAnchor(identityIssuer) });
  const attestor = generateAttestor("effectproof-kernel-attestor");
  const bundle = createEvidenceBundle({
    authorization, workloadBinding: binding, observations, findings, attestor,
    generatedAt: "2026-08-22T12:00:03.000Z"
  });
  console.log(JSON.stringify({ ...bundle, signatureValid: verifyEvidenceBundle(bundle, trustAnchor(attestor)) }, null, 2));
}

const [command, ...args] = process.argv.slice(2);
const commands = { demo, keygen, bind, attest, verify: verifyBundle, "agt-adapt": agtAdapt };
if (!commands[command]) {
  console.error("Usage: effectproof <demo|keygen|bind|attest|verify|agt-adapt> [options]");
  process.exitCode = 2;
} else {
  commands[command](args).catch((error) => {
    console.error(error.stack ?? error.message);
    process.exitCode = 1;
  });
}
