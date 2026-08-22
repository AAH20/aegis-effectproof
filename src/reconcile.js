import { digest } from "./canonical.js";
import { bindingCoversAuthorization, verifyWorkloadBinding } from "./identity.js";

function finding(classification, severity, rationale, authorization, observation = null) {
  return Object.freeze({
    findingId: digest({ classification, decisionId: authorization.decisionId, eventId: observation?.eventId ?? null }),
    classification,
    severity,
    rationale,
    decisionId: authorization.decisionId,
    eventId: observation?.eventId ?? null,
    processExecId: observation?.processExecId ?? null
  });
}

function isWithinWindow(authorization, observation) {
  const observed = Date.parse(observation.observedAt);
  return Number.isFinite(observed) && observed >= Date.parse(authorization.issuedAt) && observed <= Date.parse(authorization.expiresAt);
}

function attributionComplete(observation) {
  return observation.sensorHealth === "ready" && observation.workloadId && observation.processExecId && observation.binary;
}

export function reconcile(authorization, observations, identity = {}) {
  if (!Array.isArray(observations)) throw new TypeError("observations must be an array");
  if (!authorization.policyComplete) {
    return [finding("unverifiable", "critical", "authorization did not identify a complete policy generation", authorization)];
  }
  if (!verifyWorkloadBinding(identity.binding, identity.trustAnchor)) {
    return [finding("unverifiable", "critical", "workload-to-agent binding signature or issuer trust is invalid", authorization)];
  }
  if (!bindingCoversAuthorization(identity.binding, authorization)) {
    return [finding("unverifiable", "critical", "workload binding does not cover this agent, workload, or authorization window", authorization)];
  }

  const findings = [];
  let matched = false;
  for (const observation of observations) {
    if (!attributionComplete(observation)) {
      findings.push(finding("unverifiable", "critical", "kernel observation lacks healthy process attribution", authorization, observation));
      continue;
    }
    const sameWorkload = observation.workloadId === authorization.workloadId;
    const sameEffect = observation.operation === authorization.operation && observation.target === authorization.target
      && observation.effect === authorization.effect && observation.argumentsDigest === authorization.argumentsDigest;
    if (sameWorkload && sameEffect && isWithinWindow(authorization, observation) && !matched) {
      matched = true;
      findings.push(finding("authorized_observed", "info", "kernel-observed effect matches the authorized envelope", authorization, observation));
    } else {
      findings.push(finding("unauthorized_observed", "critical", sameWorkload
        ? "workload produced a kernel effect outside its authorized envelope"
        : "kernel effect originated from a workload not bound to this authorization", authorization, observation));
    }
  }
  if (!matched) findings.push(finding("authorized_not_observed", "high", "no attributable kernel effect matched the authorization", authorization));
  return findings;
}

export function verdict(findings) {
  if (findings.some((item) => item.classification === "unverifiable")) return "unverifiable";
  if (findings.some((item) => item.classification === "unauthorized_observed")) return "violation";
  if (findings.some((item) => item.classification === "authorized_not_observed")) return "incomplete";
  return "verified";
}
