import { digest } from "./canonical.js";
import { observedEffect } from "./contracts.js";

function get(value, path) {
  return path.split(".").reduce((current, key) => current?.[key], value);
}

function first(...values) {
  return values.find((value) => typeof value === "string" && value.length > 0) ?? null;
}

function eventBody(event) {
  for (const type of ["process_kprobe", "process_tracepoint", "process_exec"]) {
    if (event[type]) return { type, body: event[type] };
  }
  throw new TypeError("unsupported Tetragon event: expected process_kprobe, process_tracepoint, or process_exec");
}

function targetFromArguments(args = []) {
  for (const argument of args) {
    const target = first(
      get(argument, "file_arg.path"),
      get(argument, "path_arg.path"),
      get(argument, "sock_arg.saddr"),
      get(argument, "string_arg")
    );
    if (target) return target;
  }
  return null;
}

export function normalizeTetragonEvent(event, options = {}) {
  const { type, body } = eventBody(event);
  const process = body.process ?? {};
  const parent = body.parent ?? {};
  const pod = process.pod ?? {};
  const container = process.docker ?? process.container ?? {};
  const workloadId = first(
    options.workloadId,
    container.id,
    pod.container?.id,
    pod.namespace && pod.name ? `k8s:${pod.namespace}/${pod.name}` : null
  );
  const target = options.target ?? targetFromArguments(body.args) ?? process.binary;
  const operation = options.operation ?? body.function_name ?? type;
  const effect = options.effect ?? ({ process_exec: "execute", process_kprobe: "observe", process_tracepoint: "observe" })[type];
  const args = options.arguments ?? body.args ?? [];

  return observedEffect({
    eventId: options.eventId ?? digest(event),
    observedAt: options.observedAt ?? event.time ?? body.time,
    sensorId: options.sensorId ?? "tetragon",
    sensorHealth: options.sensorHealth ?? "ready",
    workloadId,
    processExecId: process.exec_id ?? null,
    parentExecId: parent.exec_id ?? null,
    binary: process.binary ?? null,
    operation,
    target,
    effect,
    argumentsDigest: options.argumentsDigest ?? digest(args),
    source: `tetragon:${type}`,
    sourceDigest: digest(event)
  });
}

export function parseTetragonJsonLines(input, options = {}) {
  if (typeof input !== "string") throw new TypeError("Tetragon JSONL input must be a string");
  return input.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line, index) => {
    try {
      return normalizeTetragonEvent(JSON.parse(line), options);
    } catch (error) {
      throw new TypeError(`invalid Tetragon JSONL at line ${index + 1}: ${error.message}`);
    }
  });
}
