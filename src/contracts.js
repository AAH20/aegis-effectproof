import { digest } from "./canonical.js";

function requiredString(value, name) {
  if (typeof value !== "string" || value.trim() === "") throw new TypeError(`${name} must be a non-empty string`);
  return value;
}

function requiredTimestamp(value, name) {
  requiredString(value, name);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new TypeError(`${name} must be an RFC 3339 timestamp`);
  return timestamp;
}

export function authorizationEnvelope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("authorization must be an object");
  const envelope = {
    schemaVersion: value.schemaVersion ?? "effectproof.dev/authorization/v0.1",
    decisionId: requiredString(value.decisionId, "decisionId"),
    agentId: requiredString(value.agentId, "agentId"),
    principal: requiredString(value.principal, "principal"),
    workloadId: requiredString(value.workloadId, "workloadId"),
    toolCallId: requiredString(value.toolCallId, "toolCallId"),
    operation: requiredString(value.operation, "operation"),
    target: requiredString(value.target, "target"),
    effect: requiredString(value.effect, "effect"),
    argumentsDigest: requiredString(value.argumentsDigest, "argumentsDigest"),
    policyId: requiredString(value.policyId, "policyId"),
    policyGeneration: requiredString(value.policyGeneration, "policyGeneration"),
    policyDigest: requiredString(value.policyDigest, "policyDigest"),
    policyComplete: value.policyComplete === true,
    issuedAt: requiredString(value.issuedAt, "issuedAt"),
    expiresAt: requiredString(value.expiresAt, "expiresAt"),
    nonce: requiredString(value.nonce, "nonce")
  };
  const issued = requiredTimestamp(envelope.issuedAt, "issuedAt");
  const expires = requiredTimestamp(envelope.expiresAt, "expiresAt");
  if (expires <= issued) throw new TypeError("expiresAt must be after issuedAt");
  return Object.freeze(envelope);
}

export function observedEffect(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("observation must be an object");
  return Object.freeze({
    schemaVersion: value.schemaVersion ?? "effectproof.dev/observation/v0.1",
    eventId: requiredString(value.eventId, "eventId"),
    observedAt: requiredString(value.observedAt, "observedAt"),
    sensorId: requiredString(value.sensorId, "sensorId"),
    sensorHealth: requiredString(value.sensorHealth, "sensorHealth"),
    workloadId: value.workloadId ?? null,
    processExecId: value.processExecId ?? null,
    parentExecId: value.parentExecId ?? null,
    binary: value.binary ?? null,
    operation: requiredString(value.operation, "operation"),
    target: requiredString(value.target, "target"),
    effect: requiredString(value.effect, "effect"),
    argumentsDigest: requiredString(value.argumentsDigest, "argumentsDigest"),
    source: requiredString(value.source, "source"),
    sourceDigest: requiredString(value.sourceDigest, "sourceDigest")
  });
}

export function workloadBindingPayload(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("workload binding must be an object");
  const binding = {
    schemaVersion: value.schemaVersion ?? "effectproof.dev/workload-binding/v0.1",
    bindingId: requiredString(value.bindingId, "bindingId"),
    issuer: requiredString(value.issuer, "issuer"),
    agentId: requiredString(value.agentId, "agentId"),
    workloadId: requiredString(value.workloadId, "workloadId"),
    podUid: requiredString(value.podUid, "podUid"),
    cgroupId: requiredString(value.cgroupId, "cgroupId"),
    validFrom: requiredString(value.validFrom, "validFrom"),
    validUntil: requiredString(value.validUntil, "validUntil")
  };
  if (requiredTimestamp(binding.validUntil, "validUntil") <= requiredTimestamp(binding.validFrom, "validFrom")) {
    throw new TypeError("validUntil must be after validFrom");
  }
  return Object.freeze(binding);
}

export function digestArguments(value) {
  return digest(value);
}
