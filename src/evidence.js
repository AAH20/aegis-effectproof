import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { canonicalJson, digest } from "./canonical.js";
import { verdict } from "./reconcile.js";

export function generateAttestor(identity = "effectproof-attestor") {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { identity, privateKey, publicKey };
}

export function attestorFromPrivateKey(identity, privateKeyPem) {
  if (typeof identity !== "string" || identity.length === 0) throw new TypeError("attestor identity is required");
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new TypeError("attestor key must be Ed25519");
  return { identity, privateKey, publicKey: createPublicKey(privateKey) };
}

export function exportPrivateKey(attestor) {
  if (!attestor?.privateKey) throw new TypeError("attestor private key is required");
  return attestor.privateKey.export({ type: "pkcs8", format: "pem" });
}

export function trustAnchor(attestor) {
  if (!attestor?.identity || !attestor.publicKey) throw new TypeError("attestor identity and public key are required");
  const publicKey = attestor.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  return Object.freeze({ identity: attestor.identity, keyId: digest(publicKey), publicKey });
}

export function createEvidenceBundle({ authorization, workloadBinding, observations, findings, attestor, generatedAt = new Date().toISOString() }) {
  if (!attestor?.identity || !attestor.privateKey || !attestor.publicKey) throw new TypeError("an independent Ed25519 attestor is required");
  if (attestor.identity === authorization.agentId) throw new TypeError("attestor identity must be independent of the acting agent");
  if (!workloadBinding?.payload || !workloadBinding.signature) throw new TypeError("a signed workload binding is required");
  const anchor = trustAnchor(attestor);
  const payload = {
    schemaVersion: "effectproof.dev/evidence/v0.1",
    generatedAt,
    attestor: { ...anchor, algorithm: "Ed25519" },
    authorizationDigest: digest(authorization),
    workloadBindingDigest: digest(workloadBinding),
    observationDigests: observations.map(digest),
    findings,
    verdict: verdict(findings)
  };
  const signature = sign(null, Buffer.from(canonicalJson(payload)), attestor.privateKey).toString("base64");
  return Object.freeze({ payload, signature });
}

export function verifyEvidenceBundle(bundle, expectedAttestor) {
  if (!bundle?.payload?.attestor?.publicKey || typeof bundle.signature !== "string") return false;
  if (!expectedAttestor?.identity || !expectedAttestor.keyId || !expectedAttestor.publicKey) return false;
  if (bundle.payload.attestor.identity !== expectedAttestor.identity
    || bundle.payload.attestor.keyId !== expectedAttestor.keyId
    || bundle.payload.attestor.publicKey !== expectedAttestor.publicKey) return false;
  try {
    const key = createPublicKey({
      key: Buffer.from(bundle.payload.attestor.publicKey, "base64"),
      type: "spki",
      format: "der"
    });
    return verify(null, Buffer.from(canonicalJson(bundle.payload)), key, Buffer.from(bundle.signature, "base64"));
  } catch {
    return false;
  }
}
