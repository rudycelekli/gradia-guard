import { createCipheriv, randomBytes } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { basename, join } from "node:path";
import { canonicalJson, sha256 } from "./canonical.js";
import { processCoverage } from "./coverage.js";
import { assertEnvironmentName, assertStableId } from "./security.js";
import {
  BUNDLE_SCHEMA_VERSION,
  GENESIS_SHA256,
  type CaptureMode,
  type ContentReference,
  type EvidenceBundleManifest,
  type EvidenceFrame,
} from "./types.js";

interface EvidenceSpoolOptions {
  directory: string;
  sessionId: string;
  commandIdentitySha256: string;
  mode: CaptureMode;
  encryptionKey?: Uint8Array;
  keyId?: string;
  now?: () => Date;
}

export class EvidenceSpool {
  readonly directory: string;
  readonly framesPath: string;
  readonly manifestPath: string;
  readonly mode: CaptureMode;
  private readonly key: Uint8Array | null;
  private readonly keyId: string | null;
  private readonly now: () => Date;
  private manifest: EvidenceBundleManifest;

  constructor(options: EvidenceSpoolOptions) {
    this.directory = options.directory;
    this.framesPath = join(options.directory, "frames.ndjson");
    this.manifestPath = join(options.directory, "bundle.json");
    this.mode = options.mode;
    this.now = options.now ?? (() => new Date());
    this.key = options.encryptionKey ?? null;
    this.keyId = options.keyId ?? null;
    if (this.mode === "encrypted") {
      if (!this.key || this.key.byteLength !== 32) throw new Error("encrypted_spool_key_must_be_32_bytes");
      if (!this.keyId) throw new Error("encrypted_spool_key_id_required");
      assertStableId(this.keyId, "key_id");
    } else if (this.key || this.keyId) throw new Error("digest_only_spool_rejects_encryption_fields");
    if (existsSync(this.directory)) throw new Error("evidence_bundle_directory_exists");
    mkdirSync(join(this.directory, "payloads"), { recursive: true, mode: 0o700 });
    writeFileSync(this.framesPath, "", { mode: 0o600, flag: "wx" });
    const createdAt = this.now().toISOString();
    this.manifest = {
      schema_version: BUNDLE_SCHEMA_VERSION,
      guard_version: "0.1.0",
      session_id: options.sessionId,
      created_at: createdAt,
      finalized_at: null,
      status: "recording",
      capture_mode: this.mode,
      coverage: processCoverage(),
      command_identity_sha256: options.commandIdentitySha256,
      frame_count: 0,
      chain_head_sha256: GENESIS_SHA256,
      terminal_disposition: null,
    };
    this.writeManifest();
  }

  append(frame: EvidenceFrame): void {
    if (this.manifest.status !== "recording") throw new Error("evidence_bundle_already_finalized");
    if (frame.session_id !== this.manifest.session_id) throw new Error("spool_session_mismatch");
    if (frame.sequence !== this.manifest.frame_count) throw new Error("spool_sequence_mismatch");
    if (frame.previous_frame_sha256 !== this.manifest.chain_head_sha256) {
      throw new Error("spool_previous_hash_mismatch");
    }
    appendFileSync(this.framesPath, `${canonicalJson(frame)}\n`, { encoding: "utf8", mode: 0o600 });
    this.manifest.frame_count += 1;
    this.manifest.chain_head_sha256 = frame.frame_sha256;
    this.writeManifest();
  }

  capture(content: Uint8Array, mediaType: string): ContentReference {
    const plaintextSha256 = sha256(content);
    if (this.mode === "digest-only") {
      return {
        schema_version: "gradia.guard.content-ref.v1",
        media_type: mediaType,
        byte_length: content.byteLength,
        plaintext_sha256: plaintextSha256,
        storage: "digest-only",
        ciphertext_ref: null,
        ciphertext_sha256: null,
        key_id: null,
      };
    }
    if (!this.key || !this.keyId) throw new Error("encrypted_spool_not_initialized");
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    const ciphertext = Buffer.concat([cipher.update(content), cipher.final()]);
    const tag = cipher.getAuthTag();
    const envelope = Buffer.concat([Buffer.from([1]), nonce, tag, ciphertext]);
    const ciphertextSha256 = sha256(envelope);
    const ciphertextRef = `${ciphertextSha256}.bin`;
    writeFileSync(join(this.directory, "payloads", ciphertextRef), envelope, {
      mode: 0o600,
      flag: "wx",
    });
    return {
      schema_version: "gradia.guard.content-ref.v1",
      media_type: mediaType,
      byte_length: content.byteLength,
      plaintext_sha256: plaintextSha256,
      storage: "aes-256-gcm",
      ciphertext_ref: ciphertextRef,
      ciphertext_sha256: ciphertextSha256,
      key_id: this.keyId,
    };
  }

  finalize(disposition: NonNullable<EvidenceBundleManifest["terminal_disposition"]>): void {
    if (this.manifest.status !== "recording") return;
    this.manifest.status = disposition === "wrapper_failure" ? "aborted" : "finalized";
    this.manifest.finalized_at = this.now().toISOString();
    this.manifest.terminal_disposition = disposition;
    this.writeManifest();
  }

  private writeManifest(): void {
    const temporary = `${this.manifestPath}.tmp`;
    writeFileSync(temporary, `${canonicalJson(this.manifest)}\n`, { encoding: "utf8", mode: 0o600 });
    renameSync(temporary, this.manifestPath);
  }
}

export function decodeKeyFromEnvironment(name: string): Uint8Array {
  assertEnvironmentName(name);
  const raw = process.env[name];
  if (!raw) throw new Error(`encrypted_spool_key_environment_missing:${name}`);
  const bytes = Buffer.from(raw, "base64");
  if (bytes.byteLength !== 32 || bytes.toString("base64").replace(/=+$/, "") !== raw.replace(/=+$/, "")) {
    throw new Error(`encrypted_spool_key_environment_invalid:${name}`);
  }
  return bytes;
}

export function loadManifest(directory: string): EvidenceBundleManifest {
  return JSON.parse(readFileSync(join(directory, "bundle.json"), "utf8")) as EvidenceBundleManifest;
}

export function safeBundleName(command: string, sessionId: string): string {
  const stem = basename(command).replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 40) || "process";
  return `${stem}-${sessionId}`;
}
