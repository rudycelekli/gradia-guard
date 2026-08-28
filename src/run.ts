import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { digestCanonical, sha256 } from "./canonical.js";
import { processCoverage } from "./coverage.js";
import { FrameChain } from "./frames.js";
import { assertCommandSafe } from "./security.js";
import { EvidenceSpool, safeBundleName } from "./spool.js";
import type { CaptureMode } from "./types.js";

export interface RunOptions {
  command: readonly string[];
  outputRoot: string;
  captureMode: CaptureMode;
  encryptionKey?: Uint8Array;
  keyId?: string;
  cwd?: string;
  now?: () => Date;
  onBundle?: (directory: string) => void;
}

export interface RunResult {
  directory: string;
  exitCode: number;
  signal: string | null;
}

const PROCESS_POLICY = {
  schema_version: "gradia.guard.process-policy.v1",
  argv_secret_shapes: "refuse",
  private_reasoning: "never_capture",
  spool_default: "digest-only",
  assurance_ceiling: "process",
} as const;

export async function runGuardedProcess(options: RunOptions): Promise<RunResult> {
  return runGuardedProcessInternal(options, null);
}

/** @internal Used only by the parent-owned credentialless runtime composition. */
export async function runGuardedProcessWithExplicitEnvironment(
  options: RunOptions,
  environment: Readonly<Record<string, string>>,
): Promise<RunResult> {
  return runGuardedProcessInternal(options, environment);
}

async function runGuardedProcessInternal(
  options: RunOptions,
  explicitEnvironment: Readonly<Record<string, string>> | null,
): Promise<RunResult> {
  if (options.command.length === 0) throw new Error("guard_command_missing");
  assertCommandSafe(options.command);
  const command = options.command[0] as string;
  const args = options.command.slice(1);
  const chain = new FrameChain(options.now ? { now: options.now } : {});
  const environmentSha256 =
    explicitEnvironment === null ? null : explicitEnvironmentIdentity(explicitEnvironment);
  const commandIdentity =
    environmentSha256 === null
      ? digestCanonical({ executable: command, argv: args })
      : digestCanonical({
          executable: command,
          argv: args,
          environment_mode: "explicit",
          environment_sha256: environmentSha256,
        });
  mkdirSync(options.outputRoot, { recursive: true, mode: 0o700 });
  const directory = resolve(options.outputRoot, safeBundleName(command, chain.sessionId));
  const spool = new EvidenceSpool({
    directory,
    sessionId: chain.sessionId,
    commandIdentitySha256: commandIdentity,
    mode: options.captureMode,
    ...(options.encryptionKey ? { encryptionKey: options.encryptionKey } : {}),
    ...(options.keyId ? { keyId: options.keyId } : {}),
    ...(options.now ? { now: options.now } : {}),
  });
  options.onBundle?.(directory);
  const subject = { kind: "process" as const, identity_sha256: commandIdentity };
  const coverage = processCoverage();
  const policySha256 = digestCanonical(PROCESS_POLICY);
  spool.append(
    chain.decision({
      subject,
      coverage,
      inputs: [],
      outputs: [],
      authority_scope_ids: [],
      policy_sha256: policySha256,
      decision: {
        kind: "process_dispatch",
        verdict: "allowed",
        reason_codes: [
          "argv_secret_shape_absent",
          ...(environmentSha256 === null
            ? []
            : [
                "explicit_child_environment_enforced",
                `explicit_environment_sha256:${environmentSha256}`,
              ]),
          "process_wrapper_capture_ceiling_acknowledged",
        ],
      },
    }),
  );

  return await new Promise<RunResult>((resolvePromise) => {
    let child;
    try {
      child = spawn(command, args, {
        cwd: options.cwd,
        env: explicitEnvironment === null ? process.env : { ...explicitEnvironment },
        stdio: ["inherit", "pipe", "pipe"],
      });
    } catch (error) {
      const reference = spool.capture(Buffer.from(safeErrorCode(error)), "text/plain; role=wrapper-error");
      spool.append(
      chain.action({
          subject,
          coverage,
          inputs: [],
          outputs: [reference],
          authority_scope_ids: [],
          policy_sha256: policySha256,
          action: {
            kind: "wrapper_failure",
            disposition: "failed",
            exit_code: null,
            signal: null,
            reason_codes: ["process_spawn_threw"],
          },
        }),
      );
      spool.finalize("wrapper_failure");
      resolvePromise({ directory, exitCode: 125, signal: null });
      return;
    }

    spool.append(
      chain.action({
        subject,
        coverage,
        inputs: [],
        outputs: [],
        authority_scope_ids: [],
        policy_sha256: policySha256,
        action: {
          kind: "process_started",
          disposition: "running",
          exit_code: null,
          signal: null,
          reason_codes: ["child_process_spawned"],
        },
      }),
    );

    child.stdout.on("data", (chunk: Buffer) => {
      process.stdout.write(chunk);
      appendChunk("stdout_chunk", chunk, "application/octet-stream; channel=stdout");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      process.stderr.write(chunk);
      appendChunk("stderr_chunk", chunk, "application/octet-stream; channel=stderr");
    });
    let settled = false;
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      removeSignalHandlers();
      const reference = spool.capture(Buffer.from(safeErrorCode(error)), "text/plain; role=spawn-error-code");
      spool.append(
        chain.action({
          subject,
          coverage,
          inputs: [],
          outputs: [reference],
          authority_scope_ids: [],
          policy_sha256: policySha256,
          action: {
            kind: "wrapper_failure",
            disposition: "failed",
            exit_code: null,
            signal: null,
            reason_codes: ["child_process_error"],
          },
        }),
      );
      spool.finalize("wrapper_failure");
      resolvePromise({ directory, exitCode: 125, signal: null });
    });
    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      removeSignalHandlers();
      const disposition = signal ? "signaled" : code === 0 ? "completed" : "failed";
      spool.append(
        chain.action({
          subject,
          coverage,
          inputs: [],
          outputs: [],
          authority_scope_ids: [],
          policy_sha256: policySha256,
          action: {
            kind: "process_terminal",
            disposition,
            exit_code: code,
            signal,
            reason_codes: signal ? ["child_process_signaled"] : [code === 0 ? "child_process_completed" : "child_process_nonzero"],
          },
        }),
      );
      spool.finalize(signal ? "signaled" : code === 0 ? "completed" : "failed");
      resolvePromise({ directory, exitCode: code ?? 128, signal });
    });

    const forwardedSignals: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];
    const signalHandlers = new Map<NodeJS.Signals, () => void>();
    for (const signal of forwardedSignals) {
      const handler = (): void => {
        if (!child.killed) child.kill(signal);
      };
      signalHandlers.set(signal, handler);
      process.once(signal, handler);
    }

    function removeSignalHandlers(): void {
      for (const [signal, handler] of signalHandlers) process.removeListener(signal, handler);
    }

    function appendChunk(kind: "stdout_chunk" | "stderr_chunk", chunk: Buffer, mediaType: string): void {
      const reference = spool.capture(chunk, mediaType);
      spool.append(
        chain.action({
          subject,
          coverage,
          inputs: [],
          outputs: [reference],
          authority_scope_ids: [],
          policy_sha256: policySha256,
          action: {
            kind,
            disposition: "running",
            exit_code: null,
            signal: null,
            reason_codes: ["stream_chunk_observed"],
          },
        }),
      );
    }
  });
}

function explicitEnvironmentIdentity(environment: Readonly<Record<string, string>>): string {
  if (typeof environment !== "object" || environment === null || Array.isArray(environment)) {
    throw new Error("guard_process_environment_invalid");
  }
  const entries = Object.entries(environment)
    .map(([name, value]) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,199}$/.test(name)) {
        throw new Error("guard_process_environment_name_invalid");
      }
      if (typeof value !== "string" || value.includes("\u0000")) {
        throw new Error("guard_process_environment_value_invalid");
      }
      return { name, value_sha256: sha256(Buffer.from(value)) };
    })
    .sort((left, right) => left.name.localeCompare(right.name));
  return digestCanonical({ entries });
}

function safeErrorCode(error: unknown): string {
  if (error && typeof error === "object" && "code" in error && typeof error.code === "string") {
    return error.code;
  }
  return "process_spawn_failed";
}
