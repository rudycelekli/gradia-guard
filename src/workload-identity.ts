import {
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
  type KeyLike,
  type KeyObject,
} from "node:crypto";
import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";
import { assertStableId } from "./security.js";

export const WORKLOAD_IDENTITY_SCHEMA_VERSION = "gradia.guard.workload-identity.v1" as const;
export const WORKLOAD_IDENTITY_ALGORITHM = "Ed25519" as const;

export interface GuardWorkloadIdentityClaims {
  issuer_id: string;
  organization_id: string;
  project_id: string;
  workload_id: string;
  deployment_id: string;
  audience: string;
  policy_sha256: string;
  image_sha256: string;
  configuration_sha256: string;
  collector_sha256: string;
  authority_scope_ids: readonly string[];
  issued_at_unix: number;
  not_before_unix: number;
  expires_at_unix: number;
  nonce_sha256: string;
}

export interface GuardWorkloadIdentityProtected {
  schema_version: typeof WORKLOAD_IDENTITY_SCHEMA_VERSION;
  algorithm: typeof WORKLOAD_IDENTITY_ALGORITHM;
  key_id: string;
}

export interface GuardWorkloadIdentity {
  protected: GuardWorkloadIdentityProtected;
  claims: GuardWorkloadIdentityClaims;
  signature_base64url: string;
  identity_sha256: string;
}

export interface WorkloadIdentityExpectation {
  issuerId: string;
  organizationId: string;
  projectId: string;
  workloadId: string;
  deploymentId: string;
  audience: string;
  policySha256: string;
  imageSha256: string;
  configurationSha256: string;
  collectorSha256: string;
  requiredAuthorityScopeIds: readonly string[];
}

export interface VerifyWorkloadIdentityOptions {
  trustedPublicKeys: Readonly<Record<string, KeyLike>>;
  expectation: WorkloadIdentityExpectation;
  nowUnix: number;
  maxLifetimeSeconds: number;
  clockSkewSeconds?: number;
}

export interface VerifiedWorkloadIdentity {
  identitySha256: string;
  keyId: string;
  claims: GuardWorkloadIdentityClaims;
}

export function issueWorkloadIdentity(
  claims: GuardWorkloadIdentityClaims,
  keyId: string,
  privateKey: KeyLike,
): GuardWorkloadIdentity {
  validateClaims(claims);
  assertStableId(keyId, "guard_workload_key_id");
  const protectedHeader: GuardWorkloadIdentityProtected = {
    schema_version: WORKLOAD_IDENTITY_SCHEMA_VERSION,
    algorithm: WORKLOAD_IDENTITY_ALGORITHM,
    key_id: keyId,
  };
  const key = requireEd25519PrivateKey(privateKey);
  const signatureBase64url = signBytes(null, signingBytes(protectedHeader, claims), key).toString(
    "base64url",
  );
  const unsigned = {
    protected: protectedHeader,
    claims,
    signature_base64url: signatureBase64url,
  };
  return {
    ...JSON.parse(canonicalJson(unsigned)),
    identity_sha256: digestCanonical(unsigned),
  } as GuardWorkloadIdentity;
}

export function verifyWorkloadIdentity(
  identity: GuardWorkloadIdentity,
  options: VerifyWorkloadIdentityOptions,
): VerifiedWorkloadIdentity {
  validateIdentityShape(identity);
  validateVerificationOptions(options);
  const unsigned = {
    protected: identity.protected,
    claims: identity.claims,
    signature_base64url: identity.signature_base64url,
  };
  if (identity.identity_sha256 !== digestCanonical(unsigned)) {
    throw new Error("guard_workload_identity_digest_mismatch");
  }
  const trusted = options.trustedPublicKeys[identity.protected.key_id];
  if (!trusted) throw new Error("guard_workload_identity_key_untrusted");
  const publicKey = requireEd25519PublicKey(trusted);
  const signature = decodeBase64url(identity.signature_base64url);
  if (!verifyBytes(null, signingBytes(identity.protected, identity.claims), publicKey, signature)) {
    throw new Error("guard_workload_identity_signature_invalid");
  }
  verifyTime(identity.claims, options);
  verifyExpectation(identity.claims, options.expectation);
  return {
    identitySha256: identity.identity_sha256,
    keyId: identity.protected.key_id,
    claims: JSON.parse(canonicalJson(identity.claims)) as GuardWorkloadIdentityClaims,
  };
}

function validateIdentityShape(identity: GuardWorkloadIdentity): void {
  assertExactKeys(identity as unknown as Record<string, unknown>, [
    "claims",
    "identity_sha256",
    "protected",
    "signature_base64url",
  ], "guard_workload_identity");
  assertExactKeys(identity.protected as unknown as Record<string, unknown>, [
    "algorithm",
    "key_id",
    "schema_version",
  ], "guard_workload_identity_protected");
  if (identity.protected.schema_version !== WORKLOAD_IDENTITY_SCHEMA_VERSION) {
    throw new Error("guard_workload_identity_schema_unsupported");
  }
  if (identity.protected.algorithm !== WORKLOAD_IDENTITY_ALGORITHM) {
    throw new Error("guard_workload_identity_algorithm_unsupported");
  }
  assertStableId(identity.protected.key_id, "guard_workload_key_id");
  validateClaims(identity.claims);
  if (!isSha256(identity.identity_sha256)) throw new Error("guard_workload_identity_digest_invalid");
  decodeBase64url(identity.signature_base64url);
}

function validateClaims(claims: GuardWorkloadIdentityClaims): void {
  assertExactKeys(claims as unknown as Record<string, unknown>, [
    "audience",
    "authority_scope_ids",
    "collector_sha256",
    "configuration_sha256",
    "deployment_id",
    "expires_at_unix",
    "image_sha256",
    "issued_at_unix",
    "issuer_id",
    "nonce_sha256",
    "not_before_unix",
    "organization_id",
    "policy_sha256",
    "project_id",
    "workload_id",
  ], "guard_workload_identity_claims");
  for (const [field, value] of [
    ["issuer_id", claims.issuer_id],
    ["organization_id", claims.organization_id],
    ["project_id", claims.project_id],
    ["workload_id", claims.workload_id],
    ["deployment_id", claims.deployment_id],
    ["audience", claims.audience],
  ] as const) {
    assertStableId(value, `guard_workload_${field}`);
  }
  for (const [field, value] of [
    ["policy_sha256", claims.policy_sha256],
    ["image_sha256", claims.image_sha256],
    ["configuration_sha256", claims.configuration_sha256],
    ["collector_sha256", claims.collector_sha256],
    ["nonce_sha256", claims.nonce_sha256],
  ] as const) {
    if (!isSha256(value)) throw new Error(`guard_workload_${field}_invalid`);
  }
  canonicalScopes(claims.authority_scope_ids, "guard_workload_authority_scope_ids");
  for (const [field, value] of [
    ["issued_at_unix", claims.issued_at_unix],
    ["not_before_unix", claims.not_before_unix],
    ["expires_at_unix", claims.expires_at_unix],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`guard_workload_${field}_invalid`);
  }
  if (claims.not_before_unix < claims.issued_at_unix) {
    throw new Error("guard_workload_identity_not_before_precedes_issue");
  }
  if (claims.expires_at_unix <= claims.not_before_unix) {
    throw new Error("guard_workload_identity_expiry_invalid");
  }
}

function validateVerificationOptions(options: VerifyWorkloadIdentityOptions): void {
  if (!Number.isSafeInteger(options.nowUnix) || options.nowUnix < 0) {
    throw new Error("guard_workload_identity_now_invalid");
  }
  if (!Number.isSafeInteger(options.maxLifetimeSeconds) || options.maxLifetimeSeconds < 1) {
    throw new Error("guard_workload_identity_max_lifetime_invalid");
  }
  const skew = options.clockSkewSeconds ?? 0;
  if (!Number.isSafeInteger(skew) || skew < 0 || skew > 300) {
    throw new Error("guard_workload_identity_clock_skew_invalid");
  }
  validateExpectation(options.expectation);
}

function verifyTime(
  claims: GuardWorkloadIdentityClaims,
  options: VerifyWorkloadIdentityOptions,
): void {
  const skew = options.clockSkewSeconds ?? 0;
  if (claims.expires_at_unix - claims.issued_at_unix > options.maxLifetimeSeconds) {
    throw new Error("guard_workload_identity_lifetime_exceeded");
  }
  if (options.nowUnix + skew < claims.not_before_unix) {
    throw new Error("guard_workload_identity_not_yet_valid");
  }
  if (options.nowUnix - skew >= claims.expires_at_unix) {
    throw new Error("guard_workload_identity_expired");
  }
}

function validateExpectation(expectation: WorkloadIdentityExpectation): void {
  for (const [field, value] of [
    ["issuer_id", expectation.issuerId],
    ["organization_id", expectation.organizationId],
    ["project_id", expectation.projectId],
    ["workload_id", expectation.workloadId],
    ["deployment_id", expectation.deploymentId],
    ["audience", expectation.audience],
  ] as const) {
    assertStableId(value, `guard_workload_expected_${field}`);
  }
  for (const [field, value] of [
    ["policy_sha256", expectation.policySha256],
    ["image_sha256", expectation.imageSha256],
    ["configuration_sha256", expectation.configurationSha256],
    ["collector_sha256", expectation.collectorSha256],
  ] as const) {
    if (!isSha256(value)) throw new Error(`guard_workload_expected_${field}_invalid`);
  }
  canonicalScopes(expectation.requiredAuthorityScopeIds, "guard_workload_required_scope_ids");
}

function verifyExpectation(
  claims: GuardWorkloadIdentityClaims,
  expectation: WorkloadIdentityExpectation,
): void {
  const exact: readonly [string, string, string][] = [
    ["issuer", claims.issuer_id, expectation.issuerId],
    ["organization", claims.organization_id, expectation.organizationId],
    ["project", claims.project_id, expectation.projectId],
    ["workload", claims.workload_id, expectation.workloadId],
    ["deployment", claims.deployment_id, expectation.deploymentId],
    ["audience", claims.audience, expectation.audience],
    ["policy", claims.policy_sha256, expectation.policySha256],
    ["image", claims.image_sha256, expectation.imageSha256],
    ["configuration", claims.configuration_sha256, expectation.configurationSha256],
    ["collector", claims.collector_sha256, expectation.collectorSha256],
  ];
  for (const [field, actual, expected] of exact) {
    if (actual !== expected) throw new Error(`guard_workload_identity_${field}_mismatch`);
  }
  const offered = new Set(claims.authority_scope_ids);
  if (!expectation.requiredAuthorityScopeIds.every((scope) => offered.has(scope))) {
    throw new Error("guard_workload_identity_authority_scope_missing");
  }
}

function signingBytes(
  protectedHeader: GuardWorkloadIdentityProtected,
  claims: GuardWorkloadIdentityClaims,
): Buffer {
  return Buffer.from(canonicalJson({ protected: protectedHeader, claims }), "utf8");
}

function requireEd25519PrivateKey(value: KeyLike): KeyObject {
  let key: KeyObject;
  try {
    key = value instanceof Object && "type" in value ? (value as KeyObject) : createPrivateKey(value);
  } catch {
    throw new Error("guard_workload_identity_private_key_invalid");
  }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new Error("guard_workload_identity_private_key_not_ed25519");
  }
  return key;
}

function requireEd25519PublicKey(value: KeyLike): KeyObject {
  let key: KeyObject;
  try {
    if (value instanceof Object && "type" in value) {
      const supplied = value as KeyObject;
      key = supplied.type === "public" ? supplied : createPublicKey(supplied);
    } else {
      key = createPublicKey(value);
    }
  } catch {
    throw new Error("guard_workload_identity_public_key_invalid");
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new Error("guard_workload_identity_public_key_not_ed25519");
  }
  return key;
}

function decodeBase64url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("guard_workload_identity_signature_invalid");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 64 || decoded.toString("base64url") !== value) {
    throw new Error("guard_workload_identity_signature_invalid");
  }
  return decoded;
}

function canonicalScopes(scopes: readonly string[], field: string): readonly string[] {
  if (!Array.isArray(scopes) || scopes.length === 0) throw new Error(`${field}_missing`);
  for (const scope of scopes) assertStableId(scope, field);
  const canonical = [...new Set(scopes)].sort();
  if (canonical.length !== scopes.length || canonical.some((scope, index) => scope !== scopes[index])) {
    throw new Error(`${field}_not_canonical`);
  }
  return canonical;
}

function assertExactKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...allowed].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(`${label}_keys_invalid`);
}
