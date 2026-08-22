# Ubuntu and Tetragon validation

Portable CI does not prove kernel attribution, cgroup binding, or Tetragon policy behavior. Run this procedure on the Ubuntu 26 test laptop.

## Prerequisites

- A supported Linux kernel and disposable Kubernetes cluster.
- Tetragon, `kubectl`, `tetra`, Node.js 22+, and this repository.
- The Tetragon branch `codex/procfs-attribution-health` when validating `tetragon_host_procfs_valid`.

Do not run the scenario against production. Use harmless decoy files rather than real secrets.

## Gate 1: sensor health

```bash
tetra status
kubectl -n kube-system logs -l app.kubernetes.io/name=tetragon --tail=500 \
  | grep -F "Process attribution prerequisite check failed"
```

The status command must succeed and the error search must return no matches. When the metrics endpoint is exposed, assert:

```text
tetragon_host_procfs_valid 1
```

Never interpret an absent metric as healthy.

## Gate 2: capture

Apply a narrow TracingPolicy for the chosen file-open hook, start a disposable workload, and capture JSONL:

```bash
tetra getevents -o json > tetragon-events.jsonl
```

Perform one authorized decoy-file read and one out-of-envelope decoy-file read. Stop capture after both events arrive.

## Gate 3: bind and attest

Create authorization and binding documents containing the actual pod UID, cgroup identity, timestamps and workload ID. Run the README workflow with the captured stream.

Expected summaries:

```json
{"verdict":"violation","findings":2}
{"valid":true}
```

The bundle must contain both `authorized_observed` and `unauthorized_observed`.

## Gate 4: negative controls

Repeat separately with:

1. A wrong workload-binding trust anchor.
2. An expired workload binding.
3. `--sensor-health degraded`.
4. A Tetragon event with empty `exec_id` or `binary`.
5. A modified evidence bundle after signing.

Every case must become `unverifiable` or fail signature verification. None may become `verified`.

## Evidence to preserve

- Ubuntu and kernel versions.
- Tetragon commit and configuration.
- Sanitized raw events.
- Authorization, signed binding and evidence bundle.
- Public trust anchors, never private keys.
- Exact commands and test output.
