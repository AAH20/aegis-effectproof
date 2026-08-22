# Threat model

## Security objective

Produce evidence that lets a verifier distinguish a matching authorized effect, an unmatched observed effect, a missing effect, and an unverifiable observation without trusting the acting agent's own report.

## Trusted components

- The configured authorization issuer and its policy-generation identity.
- The Tetragon deployment, kernel telemetry path and process attribution health signal.
- The isolated EffectProof attestor and its Ed25519 private key.
- Workload-to-agent bindings supplied by the deployment identity plane.

## Untrusted components

- Model output, prompts, tool arguments and agent self-reports.
- The tool process and its child processes.
- Unsigned correlation identifiers.
- Evidence bundles before signature verification.

## Fail-loud conditions

- Incomplete policy generation.
- Degraded sensor health.
- Missing workload, process or binary attribution.
- Effect outside the authorization window.
- Signature failure or unexpected attestor identity.

## Known v0.1 limitations

- The included Tetragon adapter consumes JSON exporter events rather than a live gRPC stream.
- Workload identity is a configured binding, not yet a SPIFFE-verifiable identity.
- Correlation is exact-envelope plus workload and time-window matching; causal propagation into kernel state is future work.
- Public-key inclusion proves bundle integrity, not trust in the signer. Verifiers must pin the expected attestor public key; EffectProof does not accept identity-only trust.
