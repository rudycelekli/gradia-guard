import { createDecipheriv } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, isSha256, sha256 } from "./canonical.js";
import { coverageBlockers } from "./coverage.js";
import { contentReferenceBlockers, frameBlockers, recomputeFrameDigest } from "./frames.js";
import { assertStableId } from "./security.js";
import { verifyGatewayBundle } from "./gateway-verify.js";
import { verifySdkBundle } from "./sdk-verify.js";
import {
  BUNDLE_SCHEMA_VERSION,
  GENESIS_SHA256,
  type ContentReference,
  type EvidenceBundleManifest,
  type EvidenceFrame,
  type VerificationResult,
} from "./types.js";

export interface VerifyOptions {
  encryptionKey?: Uint8Array;
  expectedKeyId?: string;
}

export function verifyBundle(directory: string, options: VerifyOptions = {}): VerificationResult {
  const blockers: string[] = [];
  let manifest: EvidenceBundleManifest | null = null;
  try {
    manifest = JSON.parse(readFileSync(join(directory, "bundle.json"), "utf8")) as EvidenceBundleManifest;
  } catch {
    return result(["bundle_manifest_unreadable"], null, 0, null, 0, 0);
  }
  if ((manifest as { schema_version?: unknown }).schema_version === "gradia.guard.gateway-bundle.v1") {
    return verifyGatewayBundle(directory);
  }
  if ((manifest as { schema_version?: unknown }).schema_version === "gradia.guard.sdk-bundle.v1") {
    return verifySdkBundle(directory);
  }
  try {
    blockers.push(...manifestBlockers(manifest));
  } catch {
    blockers.push("bundle_manifest_shape_invalid");
  }
  let frames: EvidenceFrame[] = [];
  try {
    const text = readFileSync(join(directory, "frames.ndjson"), "utf8");
    if (text && !text.endsWith("\n")) blockers.push("frame_log_truncated");
    frames = text
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line, index) => {
        try {
          return JSON.parse(line) as EvidenceFrame;
        } catch {
          blockers.push(`frame_json_invalid:${index}`);
          return null;
        }
      })
      .filter((frame): frame is EvidenceFrame => frame !== null);
  } catch {
    blockers.push("frame_log_unreadable");
  }

  let head: string = GENESIS_SHA256;
  let payloadsChecked = 0;
  let payloadsUnavailable = 0;
  let terminalCount = 0;
  let lastObservedAt: string | null = null;
  frames.forEach((frame, index) => {
    try {
      blockers.push(...frameBlockers(frame).map((item) => `${item}:${index}`));
      if (frame.session_id !== manifest?.session_id) blockers.push(`frame_session_mismatch:${index}`);
      if (frame.subject.identity_sha256 !== manifest?.command_identity_sha256) {
        blockers.push(`frame_command_identity_mismatch:${index}`);
      }
      if (canonicalJson(frame.coverage) !== canonicalJson(manifest?.coverage)) {
        blockers.push(`frame_bundle_coverage_mismatch:${index}`);
      }
      if (frame.sequence !== index) blockers.push(`frame_sequence_gap:${index}`);
      if (frame.previous_frame_sha256 !== head) blockers.push(`frame_previous_hash_mismatch:${index}`);
      if (frame.frame_sha256 !== recomputeFrameDigest(frame)) blockers.push(`frame_digest_mismatch:${index}`);
      if (isSha256(frame.frame_sha256)) head = frame.frame_sha256;
      if (lastObservedAt !== null && frame.observed_at < lastObservedAt) {
        blockers.push(`frame_timestamp_regressed:${index}`);
      }
      lastObservedAt = frame.observed_at;
      if (
        frame.frame_kind === "action" &&
        ["process_terminal", "wrapper_failure"].includes(frame.action.kind)
      ) {
        terminalCount += 1;
        if (index !== frames.length - 1) blockers.push(`terminal_frame_not_last:${index}`);
      }
      for (const reference of [...frame.inputs, ...frame.outputs]) {
        const checked = verifyContent(directory, reference, options, blockers);
        if (checked) payloadsChecked += 1;
        else payloadsUnavailable += 1;
      }
    } catch {
      blockers.push(`frame_shape_unreadable:${index}`);
    }
  });
  if (manifest.frame_count !== frames.length) blockers.push("manifest_frame_count_mismatch");
  if (manifest.chain_head_sha256 !== head) blockers.push("manifest_chain_head_mismatch");
  if (manifest.status === "recording") blockers.push("bundle_not_finalized");
  if (manifest.status !== "recording" && terminalCount !== 1) blockers.push("terminal_frame_count_invalid");
  if (frames.length === 0) blockers.push("frame_log_empty");
  const terminal = frames.at(-1);
  if (terminal?.frame_kind === "action") {
    const expected =
      terminal.action.kind === "wrapper_failure"
        ? "wrapper_failure"
        : terminal.action.disposition === "signaled"
          ? "signaled"
          : terminal.action.disposition === "completed"
            ? "completed"
            : "failed";
    if (manifest.terminal_disposition !== expected) blockers.push("bundle_terminal_disposition_mismatch");
    if ((expected === "wrapper_failure") !== (manifest.status === "aborted")) {
      blockers.push("bundle_terminal_status_mismatch");
    }
  }
  const terminalObservedAt = frames.at(-1)?.observed_at;
  if (manifest.finalized_at && terminalObservedAt && manifest.finalized_at < terminalObservedAt) {
    blockers.push("bundle_finalized_before_terminal");
  }
  return result(
    blockers,
    manifest.session_id,
    frames.length,
    isSha256(head) ? head : null,
    payloadsChecked,
    payloadsUnavailable,
  );
}

function manifestBlockers(manifest: EvidenceBundleManifest): string[] {
  const blockers: string[] = [];
  const actualKeys = Object.keys(manifest).sort();
  const expectedKeys = [
    "capture_mode",
    "chain_head_sha256",
    "command_identity_sha256",
    "coverage",
    "created_at",
    "finalized_at",
    "frame_count",
    "guard_version",
    "schema_version",
    "session_id",
    "status",
    "terminal_disposition",
  ].sort();
  if (actualKeys.length !== expectedKeys.length || actualKeys.some((key, index) => key !== expectedKeys[index])) {
    blockers.push("bundle_fields_invalid");
  }
  if (manifest.schema_version !== BUNDLE_SCHEMA_VERSION) blockers.push("bundle_schema_invalid");
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.guard_version)) {
    blockers.push("bundle_guard_version_invalid");
  }
  try {
    assertStableId(manifest.session_id, "session_id");
  } catch {
    blockers.push("bundle_session_id_invalid");
  }
  if (!["digest-only", "encrypted"].includes(manifest.capture_mode)) blockers.push("bundle_capture_mode_invalid");
  if (!["recording", "finalized", "aborted"].includes(manifest.status)) blockers.push("bundle_status_invalid");
  if (!isSha256(manifest.command_identity_sha256)) blockers.push("bundle_command_digest_invalid");
  if (!isSha256(manifest.chain_head_sha256)) blockers.push("bundle_chain_head_invalid");
  if (!Number.isSafeInteger(manifest.frame_count) || manifest.frame_count < 0) blockers.push("bundle_frame_count_invalid");
  if (!Number.isFinite(Date.parse(manifest.created_at)) || new Date(manifest.created_at).toISOString() !== manifest.created_at) {
    blockers.push("bundle_created_at_invalid");
  }
  if (
    manifest.finalized_at !== null &&
    (!Number.isFinite(Date.parse(manifest.finalized_at)) ||
      new Date(manifest.finalized_at).toISOString() !== manifest.finalized_at ||
      manifest.finalized_at < manifest.created_at)
  ) {
    blockers.push("bundle_finalized_at_invalid");
  }
  blockers.push(...coverageBlockers(manifest.coverage));
  if (manifest.coverage.tier !== "process") blockers.push("bundle_wrapper_coverage_overclaim");
  if (manifest.status === "recording" && (manifest.finalized_at !== null || manifest.terminal_disposition !== null)) {
    blockers.push("bundle_recording_terminal_conflict");
  }
  if (manifest.status !== "recording" && (!manifest.finalized_at || !manifest.terminal_disposition)) {
    blockers.push("bundle_finalization_incomplete");
  }
  return blockers;
}

function verifyContent(
  directory: string,
  reference: ContentReference,
  options: VerifyOptions,
  blockers: string[],
): boolean {
  blockers.push(...contentReferenceBlockers(reference));
  if (reference.storage === "digest-only") return false;
  if (!reference.ciphertext_ref || !reference.ciphertext_sha256) return false;
  const path = join(directory, "payloads", reference.ciphertext_ref);
  if (!existsSync(path)) {
    blockers.push(`encrypted_payload_missing:${reference.ciphertext_ref}`);
    return false;
  }
  const envelope = readFileSync(path);
  if (sha256(envelope) !== reference.ciphertext_sha256) {
    blockers.push(`encrypted_payload_digest_mismatch:${reference.ciphertext_ref}`);
    return false;
  }
  if (!options.encryptionKey) return false;
  if (options.encryptionKey.byteLength !== 32) {
    blockers.push("verification_key_invalid");
    return false;
  }
  if (options.expectedKeyId && options.expectedKeyId !== reference.key_id) {
    blockers.push(`verification_key_id_mismatch:${reference.ciphertext_ref}`);
    return false;
  }
  if (envelope.byteLength < 29 || envelope[0] !== 1) {
    blockers.push(`encrypted_payload_envelope_invalid:${reference.ciphertext_ref}`);
    return false;
  }
  try {
    const nonce = envelope.subarray(1, 13);
    const tag = envelope.subarray(13, 29);
    const ciphertext = envelope.subarray(29);
    const decipher = createDecipheriv("aes-256-gcm", options.encryptionKey, nonce);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.byteLength !== reference.byte_length || sha256(plaintext) !== reference.plaintext_sha256) {
      blockers.push(`encrypted_payload_plaintext_mismatch:${reference.ciphertext_ref}`);
      return false;
    }
    return true;
  } catch {
    blockers.push(`encrypted_payload_decryption_failed:${reference.ciphertext_ref}`);
    return false;
  }
}

function result(
  blockers: readonly string[],
  sessionId: string | null,
  frameCount: number,
  chainHead: string | null,
  payloadsChecked: number,
  payloadsUnavailable: number,
): VerificationResult {
  return {
    ok: blockers.length === 0,
    blockers: [...new Set(blockers)].sort(),
    session_id: sessionId,
    frame_count: frameCount,
    chain_head_sha256: chainHead,
    payloads_checked: payloadsChecked,
    payloads_unavailable: payloadsUnavailable,
  };
}

export function canonicalVerificationResult(resultValue: VerificationResult): string {
  return `${canonicalJson(resultValue)}\n`;
}
