import { readFileSync } from "node:fs";
import { join } from "node:path";
import { digestCanonical } from "./canonical.js";
import {
  verifyGuardRemoteAnchor,
  type GuardRemoteAnchor,
  type GuardRemoteAnchorVerification,
} from "./remote-anchor.js";
import { assertEnvironmentName, assertStableId } from "./security.js";
import {
  verifyRuntimeEvidenceBundle,
  type RuntimeEvidenceBundle,
} from "./runtime-evidence.js";
import type {
  EvidenceBundleManifest,
  EvidenceFrame,
  GatewayEvidenceBundleManifest,
  GatewayEvidenceFrame,
  SdkEvidenceBundleManifest,
  SdkEvidenceFrame,
} from "./types.js";
import { verifyBundle } from "./verify.js";

export interface GuardRights {
  evaluation: boolean;
  redistribution: boolean;
  derived_publication: boolean;
  training: boolean;
  raw_trajectory: boolean;
}

export interface UploadOptions {
  apiBase: string;
  projectId: string;
  token: string;
  retentionPolicyId: string;
  rights: GuardRights;
  fetchImpl?: typeof fetch;
}

export interface UploadResult {
  guardEvidenceEditionId: string;
  bundleSha256: string;
  editionSha256: string;
  requestId: string;
  statusCode: 200 | 201;
  remoteAnchor: GuardRemoteAnchor;
  remoteAnchorVerification: GuardRemoteAnchorVerification;
}

interface StoredBundle {
  manifest: EvidenceBundleManifest | GatewayEvidenceBundleManifest | SdkEvidenceBundleManifest;
  frames: (EvidenceFrame | GatewayEvidenceFrame | SdkEvidenceFrame)[];
}

export async function uploadEvidenceBundle(
  directory: string,
  options: UploadOptions,
): Promise<UploadResult> {
  const local = verifyBundle(directory);
  if (!local.ok) throw new Error(`upload_bundle_unverified:${local.blockers.join(",")}`);
  const bundle = readStoredBundle(directory);
  return uploadCanonicalEvidence(bundle, bundle.manifest.session_id, options);
}

/** Upload a portable G3 bundle only after independent local replay succeeds. */
export async function uploadRuntimeEvidenceBundle(
  value: unknown,
  options: UploadOptions,
): Promise<UploadResult> {
  const verification = verifyRuntimeEvidenceBundle(value);
  if (!verification.ok || verification.session_id === null) {
    throw new Error(`upload_runtime_bundle_unverified:${verification.blockers.join(",")}`);
  }
  return uploadCanonicalEvidence(
    value as RuntimeEvidenceBundle,
    verification.session_id,
    options,
  );
}

async function uploadCanonicalEvidence(
  bundle: StoredBundle | RuntimeEvidenceBundle,
  sessionId: string,
  options: UploadOptions,
): Promise<UploadResult> {
  const bundleSha256 = digestCanonical(bundle);
  const endpoint = ingestionEndpoint(options.apiBase, options.projectId);
  if (!options.token.trim()) throw new Error("upload_token_missing");
  assertStableId(options.retentionPolicyId, "retention_policy_id");
  const uploadIntentSha256 = digestCanonical({
    schema_version: "gradia.guard.upload-intent.v1",
    project_id: options.projectId,
    bundle_sha256: bundleSha256,
    rights: options.rights,
    retention_policy_id: options.retentionPolicyId,
  });
  const requestId = `guard-upload-${uploadIntentSha256.slice(0, 32)}`;
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(endpoint, {
    method: "POST",
    headers: {
      accept: "application/json",
      authorization: `Bearer ${options.token}`,
      "content-type": "application/json",
      "idempotency-key": uploadIntentSha256,
      "x-request-id": requestId,
    },
    body: JSON.stringify({
      bundle,
      rights: options.rights,
      retention_policy_id: options.retentionPolicyId,
    }),
    redirect: "error",
  });
  const responseText = await response.text();
  if (responseText.length > 1_048_576) throw new Error("upload_response_too_large");
  let payload: unknown;
  try {
    payload = JSON.parse(responseText);
  } catch {
    throw new Error(`upload_response_invalid:${response.status}`);
  }
  if (response.status !== 200 && response.status !== 201) {
    throw new Error(`upload_refused:${response.status}:${problemCode(payload)}`);
  }
  const returnedRequestId = response.headers.get("x-request-id");
  if (returnedRequestId !== requestId) throw new Error("upload_request_id_mismatch");
  if (!isRecord(payload)) throw new Error("upload_response_shape_invalid");
  if (payload["bundle_sha256"] !== bundleSha256) throw new Error("upload_bundle_digest_mismatch");
  const editionId = payload["guard_evidence_edition_id"];
  if (typeof editionId !== "string") throw new Error("upload_edition_id_missing");
  assertStableId(editionId, "guard_evidence_edition_id");
  const createdBy = payload["created_by"];
  if (typeof createdBy !== "string") throw new Error("upload_collector_identity_missing");
  assertStableId(createdBy, "created_by");
  const editionSha256 = digestCanonical({
    schema_version: "gradia.guard.evidence-edition.v1",
    project_id: options.projectId,
    bundle_sha256: bundleSha256,
    rights: options.rights,
    retention_policy_id: options.retentionPolicyId,
    created_by: createdBy,
  });
  if (payload["edition_sha256"] !== editionSha256) throw new Error("upload_edition_digest_mismatch");
  const remoteAnchorValue = payload["remote_anchor"];
  const remoteAnchorVerification = verifyGuardRemoteAnchor(remoteAnchorValue, {
    guardEvidenceEditionId: editionId,
    projectId: options.projectId,
    sessionId,
    bundleSha256,
    editionSha256,
    retentionPolicyId: options.retentionPolicyId,
    createdBy,
  });
  return {
    guardEvidenceEditionId: editionId,
    bundleSha256,
    editionSha256,
    requestId,
    statusCode: response.status,
    remoteAnchor: remoteAnchorValue as GuardRemoteAnchor,
    remoteAnchorVerification,
  };
}

export function tokenFromEnvironment(environmentName: string): string {
  assertEnvironmentName(environmentName);
  const value = process.env[environmentName];
  if (!value?.trim()) throw new Error(`upload_token_environment_missing:${environmentName}`);
  return value;
}

function readStoredBundle(directory: string): StoredBundle {
  const manifest = JSON.parse(readFileSync(join(directory, "bundle.json"), "utf8")) as
    | EvidenceBundleManifest
    | GatewayEvidenceBundleManifest
    | SdkEvidenceBundleManifest;
  const frames = readFileSync(join(directory, "frames.ndjson"), "utf8")
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as EvidenceFrame | GatewayEvidenceFrame | SdkEvidenceFrame);
  return { manifest, frames };
}

function ingestionEndpoint(apiBase: string, projectId: string): URL {
  assertStableId(projectId, "project_id");
  let base: URL;
  try {
    base = new URL(apiBase);
  } catch {
    throw new Error("upload_api_base_invalid");
  }
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(base.hostname);
  if (base.protocol !== "https:" && !(base.protocol === "http:" && loopback)) {
    throw new Error("upload_api_base_requires_https");
  }
  if (base.username || base.password || base.search || base.hash) {
    throw new Error("upload_api_base_invalid");
  }
  base.pathname = `/v1/projects/${encodeURIComponent(projectId)}/guard/evidence-editions`;
  return base;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function problemCode(payload: unknown): string {
  if (!isRecord(payload)) return "unknown";
  const blockers = payload["blockers"];
  if (Array.isArray(blockers) && blockers.every((value) => typeof value === "string")) {
    return blockers.join(",") || "unknown";
  }
  const title = payload["title"];
  return typeof title === "string" ? title.replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 200) : "unknown";
}
