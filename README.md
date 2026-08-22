# Aegis EffectProof

**Independent kernel verification of autonomous-agent effects.**

Agent governance systems can report what an agent requested and what a policy allowed. Those statements do not prove what the host executed. EffectProof correlates an authorization envelope with Tetragon kernel observations and produces an independently signed evidence bundle.

## Proof in 30 seconds

```bash
npm test
npm run demo
```

The demo authorizes one read of `/evidence/case-1042.json`. Its Tetragon fixture observes that read and an additional read of `/etc/shadow`. EffectProof returns:

```json
{
  "classifications": ["authorized_observed", "unauthorized_observed"],
  "verdict": "violation",
  "signatureValid": true
}
```

No LLM decides whether an effect matches. Reconciliation is deterministic and defaults to `unverifiable` when process attribution or policy-generation evidence is incomplete.

## Trust boundaries

```text
agent runtime / AGT             Linux kernel / Tetragon
authorization envelope         process + file + network effects
             \                 /
              EffectProof correlator
                       |
           independent Ed25519 attestor
                       |
              offline verification
```

The attestor identity must differ from the acting agent identity. Verification requires a pinned public-key trust anchor; an identity string alone is never accepted as trust. Production deployments must additionally isolate the private key and attestor workload.

## Verdicts

| Classification | Meaning |
| --- | --- |
| `authorized_observed` | A healthy kernel observation matches the authorized workload, operation, target, effect, arguments and time window. |
| `authorized_not_observed` | No attributable kernel effect matched the authorization. |
| `unauthorized_observed` | The sensor observed an effect outside the envelope or from another workload. |
| `unverifiable` | Sensor attribution or policy-generation evidence was incomplete. |

## Streaming CLI

Create separate workload-identity and evidence-attestor keys:

```bash
effectproof keygen --identity cluster-workload-identity \
  --private-out identity.pem --trust-out identity-trust.json
effectproof keygen --identity effectproof-kernel-attestor \
  --private-out attestor.pem --trust-out attestor-trust.json
```

Sign the workload-to-agent binding:

```bash
effectproof bind --input examples/workload-binding-input.json \
  --issuer-id cluster-workload-identity --issuer-key identity.pem \
  --out workload-binding.json
```

Consume a Tetragon JSONL file or replace the filename with `-` to read a live exporter stream from standard input:

```bash
effectproof attest --authorization examples/authorization.json \
  --binding workload-binding.json --binding-trust identity-trust.json \
  --events examples/tetragon-events.jsonl \
  --attestor-id effectproof-kernel-attestor --attestor-key attestor.pem \
  --out effectproof-bundle.json

effectproof verify --bundle effectproof-bundle.json --trust attestor-trust.json
```

Private keys are created with mode `0600`. The verifier requires the complete pinned trust anchor and exits non-zero for invalid evidence.

## Why this exists

The implementation is grounded in active upstream gaps:

- [Tetragon #4883](https://github.com/cilium/tetragon/issues/4883): process attribution can silently degrade while the agent appears healthy.
- [Tetragon #4999](https://github.com/cilium/tetragon/issues/4999): incorrect process ancestry can be reported.
- [Tetragon #5130](https://github.com/cilium/tetragon/issues/5130): causal runtime enforcement for autonomous workloads.
- [Microsoft Agent Governance Toolkit #3805](https://github.com/microsoft/agent-governance-toolkit/issues/3805): a compliance receipt may be self-signed by the acting agent.
- [Microsoft Agent Governance Toolkit #3562](https://github.com/microsoft/agent-governance-toolkit/issues/3562): decisions cannot identify a complete policy-load generation.
- [OpenTelemetry GenAI #309](https://github.com/open-telemetry/semantic-conventions-genai/issues/309): no standard causal link exists between inference and tool execution.

## Scope of v0.1

- Validated authorization envelopes with principal, workload, native tool-call and complete policy-generation identity.
- Normalization of `process_kprobe`, `process_tracepoint`, and `process_exec` JSON events.
- Exact deterministic reconciliation.
- Fail-loud handling of degraded attribution.
- Ed25519 evidence bundles and offline verification.

## Microsoft AGT adapter

`adaptAgtAuditCloudEvent()` converts AGT audit CloudEvents into authorization envelopes only when every trust-boundary field is capturable. It accepts AGT-native `agent_did`, action, resource, argument hash, approver and policy version, then requires trusted deployment evidence for workload identity, native tool-call identity, policy-bundle digest/completeness, expiry and nonce.

`inspectAgtSidecarDecision()` reports the gaps in the current AGT `EvaluateResponse`; it does not invent missing identifiers. In particular, AGT `session_id` is never treated as a native framework tool-call ID.

The reference fixtures are:

- `examples/agt-audit-cloudevent.json`
- `examples/agt-adapter-context.json`

```bash
effectproof agt-adapt --event examples/agt-audit-cloudevent.json \
  --context examples/agt-adapter-context.json --out authorization-result.json
```

This maps directly to AGT issues [#3562](https://github.com/microsoft/agent-governance-toolkit/issues/3562) and [#3613](https://github.com/microsoft/agent-governance-toolkit/issues/3613). The adapter remains external until AGT maintainers approve an integration location.

The repository does not claim that a Kubernetes pod name alone is a cryptographic workload identity. The next milestone binds short-lived workload identity to cgroup/process identity and verifies a real Tetragon stream on Linux.

## Related Aegis systems

- **Aegis Authority Mesh** determines whether an agent action has a governed authority path.
- **Verified Effects Runtime** handles retries, crash recovery, idempotency and ambiguous external outcomes.
- **EffectProof** independently verifies the kernel-visible execution boundary.

Apache-2.0
