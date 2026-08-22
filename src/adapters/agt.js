import { digest } from "../canonical.js";
import { authorizationEnvelope } from "../contracts.js";

function nonEmpty(value) {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function sha256(value) {
  const normalized = nonEmpty(value);
  if (!normalized) return null;
  return normalized.startsWith("sha256:") ? normalized : /^[0-9a-f]{64}$/.test(normalized) ? `sha256:${normalized}` : null;
}

function gap(field, code, source, detail) {
  return Object.freeze({ field, code, severity: "critical", source, detail });
}

function requireCapture(gaps, field, value, code, source, detail) {
  if (value === null || value === undefined || value === false) gaps.push(gap(field, code, source, detail));
  return value;
}

function result(source, authorization, gaps, disposition, sourceRecord) {
  return Object.freeze({
    source,
    disposition,
    authorization,
    captureGaps: Object.freeze(gaps),
    sourceDigest: digest(sourceRecord),
    verifiable: authorization !== null && gaps.length === 0
  });
}

export function adaptAgtAuditCloudEvent(event, context = {}) {
  if (!event || typeof event !== "object" || Array.isArray(event)) throw new TypeError("AGT audit CloudEvent must be an object");
  const source = "microsoft-agt:audit-cloudevent";
  const data = event.data && typeof event.data === "object" ? event.data : {};
  const decision = nonEmpty(data.policy_decision) ?? nonEmpty(data.outcome);
  if (!decision || !["allow", "allowed", "success", "warn", "log"].includes(decision)) {
    return result(source, null, [], "not_authorized", event);
  }

  const gaps = [];
  const decisionId = requireCapture(gaps, "decisionId", nonEmpty(event.id), "missing_decision_id", source, "CloudEvent id is absent");
  const agentId = requireCapture(gaps, "agentId", nonEmpty(event.source), "missing_agent_identity", source, "CloudEvent source is absent");
  const principal = requireCapture(gaps, "principal", nonEmpty(data.approver_did) ?? nonEmpty(context.principal), "missing_delegating_principal", source, "AGT event has no approver_did and no trusted deployment principal was supplied");
  const workloadId = requireCapture(gaps, "workloadId", nonEmpty(context.workloadId), "missing_workload_identity", source, "AGT audit events do not bind the decision to a workload incarnation");
  const toolCallId = requireCapture(gaps, "toolCallId", nonEmpty(context.nativeToolCallId), "missing_native_tool_call_id", source, "session_id is not accepted as a native framework tool-call ID");
  const operation = requireCapture(gaps, "operation", nonEmpty(data.action), "missing_action", source, "audit data.action is absent");
  const target = requireCapture(gaps, "target", nonEmpty(data.resource), "missing_resource", source, "audit data.resource is absent");
  const effect = requireCapture(gaps, "effect", nonEmpty(context.effect), "missing_effect_semantics", source, "AGT action names do not establish kernel-effect semantics");
  const argumentsDigest = requireCapture(gaps, "argumentsDigest", sha256(data.arguments_hash), "missing_or_invalid_arguments_digest", source, "audit arguments_hash is absent or is not SHA-256");
  const policyId = requireCapture(gaps, "policyId", nonEmpty(data.matched_rule) ?? nonEmpty(context.policyId), "missing_policy_identity", source, "matched_rule and trusted policy identity are absent");
  const policyGeneration = requireCapture(gaps, "policyGeneration", nonEmpty(data.policy_version), "missing_policy_generation", source, "audit policy_version is absent");
  const policyDigest = requireCapture(gaps, "policyDigest", sha256(context.policyDigest), "missing_policy_digest", source, "AGT audit events do not include a canonical policy-bundle digest");
  const policyComplete = requireCapture(gaps, "policyComplete", context.policyComplete === true, "policy_completeness_unproven", source, "AGT audit events do not prove that the policy generation loaded completely");
  const issuedAt = requireCapture(gaps, "issuedAt", nonEmpty(event.time), "missing_decision_time", source, "CloudEvent time is absent");
  const expiresAt = requireCapture(gaps, "expiresAt", nonEmpty(context.expiresAt), "missing_authorization_expiry", source, "AGT decision has no bounded execution expiry");
  const nonce = requireCapture(gaps, "nonce", nonEmpty(context.nonce), "missing_nonce", source, "AGT audit event has no authorization nonce");

  if (gaps.length > 0) return result(source, null, gaps, "capture_incomplete", event);
  const authorization = authorizationEnvelope({
    decisionId, agentId, principal, workloadId, toolCallId, operation, target, effect,
    argumentsDigest, policyId, policyGeneration, policyDigest, policyComplete,
    issuedAt, expiresAt, nonce
  });
  return result(source, authorization, gaps, "authorized", event);
}

export function inspectAgtSidecarDecision(response, request = {}, context = {}) {
  if (!response || typeof response !== "object" || Array.isArray(response)) throw new TypeError("AGT sidecar response must be an object");
  const source = "microsoft-agt:sidecar-evaluate-response";
  if (!["allow", "warn", "log"].includes(response.decision)) return result(source, null, [], "not_authorized", response);
  const gaps = [
    gap("decisionId", "missing_decision_id", source, "EvaluateResponse has no stable decision identifier"),
    gap("principal", "missing_delegating_principal", source, "EvaluateResponse has no authenticated principal"),
    gap("toolCallId", "missing_native_tool_call_id", source, "EvaluateResponse has no native tool-call identifier"),
    gap("argumentsDigest", "missing_arguments_digest", source, "EvaluateResponse does not commit to evaluated arguments"),
    gap("policyGeneration", "missing_policy_generation", source, "EvaluateResponse exposes policy_name but not generation"),
    gap("policyDigest", "missing_policy_digest", source, "EvaluateResponse has no canonical policy digest"),
    gap("policyComplete", "policy_completeness_unproven", source, "EvaluateResponse cannot prove complete policy loading"),
    gap("issuedAt", "missing_decision_time", source, "EvaluateResponse has no evaluation timestamp"),
    gap("expiresAt", "missing_authorization_expiry", source, "EvaluateResponse has no bounded execution expiry"),
    gap("nonce", "missing_nonce", source, "EvaluateResponse has no replay-resistant authorization nonce")
  ];
  if (!nonEmpty(request.agent_did)) gaps.push(gap("agentId", "missing_agent_identity", source, "request agent_did is absent"));
  if (!nonEmpty(request.action)) gaps.push(gap("operation", "missing_action", source, "request action is absent"));
  if (!nonEmpty(request.resource)) gaps.push(gap("target", "missing_resource", source, "request resource is absent"));
  if (!nonEmpty(context.workloadId)) gaps.push(gap("workloadId", "missing_workload_identity", source, "no trusted deployment workload identity was supplied"));
  if (!nonEmpty(context.effect)) gaps.push(gap("effect", "missing_effect_semantics", source, "no kernel-effect mapping was supplied"));
  return result(source, null, gaps, "capture_incomplete", { response, request });
}
