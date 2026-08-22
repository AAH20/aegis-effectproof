import { createPublicKey, sign, verify } from "node:crypto";
import { canonicalJson, digest } from "./canonical.js";
import { workloadBindingPayload } from "./contracts.js";

export function createWorkloadBinding(value, issuer) {
  if (!issuer?.identity || !issuer.privateKey || !issuer.publicKey) throw new TypeError("a workload identity issuer is required");
  const payload = workloadBindingPayload({ ...value, issuer: issuer.identity });
  if (payload.agentId === issuer.identity) throw new TypeError("workload binding issuer must be independent of the acting agent");
  const signature = sign(null, Buffer.from(canonicalJson(payload)), issuer.privateKey).toString("base64");
  return Object.freeze({ payload, signature });
}

export function verifyWorkloadBinding(binding, expectedIssuer) {
  if (!binding?.payload || typeof binding.signature !== "string") return false;
  if (!expectedIssuer?.identity || !expectedIssuer.keyId || !expectedIssuer.publicKey) return false;
  if (binding.payload.issuer !== expectedIssuer.identity) return false;
  try {
    const key = createPublicKey({ key: Buffer.from(expectedIssuer.publicKey, "base64"), type: "spki", format: "der" });
    return verify(null, Buffer.from(canonicalJson(binding.payload)), key, Buffer.from(binding.signature, "base64"));
  } catch {
    return false;
  }
}

export function bindingTrustAnchor(issuer) {
  if (!issuer?.identity || !issuer.publicKey) throw new TypeError("issuer identity and public key are required");
  const publicKey = issuer.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  return Object.freeze({ identity: issuer.identity, keyId: digest(publicKey), publicKey });
}

export function bindingCoversAuthorization(binding, authorization) {
  return binding.payload.agentId === authorization.agentId
    && binding.payload.workloadId === authorization.workloadId
    && Date.parse(binding.payload.validFrom) <= Date.parse(authorization.issuedAt)
    && Date.parse(binding.payload.validUntil) >= Date.parse(authorization.expiresAt);
}
