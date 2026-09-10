import { randomBytes, verify as verifyBytes, type KeyLike } from "node:crypto";
import { canonicalJson } from "./canonical.js";
import { verifyWorkloadIdentity, type GuardWorkloadIdentity, type WorkloadIdentityExpectation } from "./workload-identity.js";

export interface ManagedWorkloadIdentityOptions {
  apiBase: string;
  organizationId: string;
  projectId: string;
  grantId: string;
  expectedTrustPolicySha256: string;
  requestId: string;
  trustedPublicKeys: Readonly<Record<string, KeyLike>>;
  expectation: WorkloadIdentityExpectation;
  /** Read a fresh platform-issued JWT; never persist it in Guard evidence. */
  sourceToken: () => Promise<string>;
  fetchImpl?: typeof fetch;
  nowUnix?: () => number;
}

/** Pinned federation, bounded renewal and a fresh signed check before dispatch.
 * Process loss/ambiguous exchange is not silently retried; a new caller must
 * intentionally reconstruct the original request. No side effects are resumed.
 */
export class ManagedWorkloadIdentityClient {
  private current: GuardWorkloadIdentity | null = null;
  private issuanceId: string | null = null;
  private pending: Promise<GuardWorkloadIdentity> | null = null;
  private failure: Error | null = null;
  private renewal = 0;
  private readonly base: string;
  constructor(private readonly options: ManagedWorkloadIdentityOptions) {
    const base = new URL(options.apiBase);
    if ((base.protocol !== "https:" && !(base.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(base.hostname)))
      || base.username || base.password || base.search || base.hash || base.pathname !== "/"
      || !/^[0-9a-f]{64}$/.test(options.expectedTrustPolicySha256)
      || options.organizationId !== options.expectation.organizationId || options.projectId !== options.expectation.projectId) {
      throw new Error("managed_workload_configuration_invalid");
    }
    this.base = base.origin;
  }
  private now(): number { return this.options.nowUnix?.() ?? Math.floor(Date.now() / 1000); }
  async identity(): Promise<GuardWorkloadIdentity> {
    if (this.failure !== null) throw this.failure;
    if (this.current !== null && this.current.claims.expires_at_unix > this.now() + 30) return this.current;
    if (this.pending !== null) return this.pending;
    this.pending = this.exchange();
    try { return await this.pending; }
    catch { this.failure = new Error("managed_workload_exchange_uncertain_or_refused_no_retry"); throw this.failure; }
    finally { this.pending = null; }
  }
  private async exchange(): Promise<GuardWorkloadIdentity> {
    const token = await this.options.sourceToken();
    if (typeof token !== "string" || token.length > 16384) throw new Error("managed_workload_source_invalid");
    const response = await this.post("exchange", {
      organization_id: this.options.organizationId, project_id: this.options.projectId,
      grant_id: this.options.grantId, source_token: token,
      request_id: this.renewal === 0 ? this.options.requestId : `${this.options.requestId.slice(0, 80)}.renew.${this.renewal}`,
      expected_policy_sha256: this.options.expectedTrustPolicySha256,
      renewal_of: this.issuanceId,
    });
    const identity = response["identity"] as GuardWorkloadIdentity;
    verifyWorkloadIdentity(identity, { trustedPublicKeys: this.options.trustedPublicKeys,
      expectation: this.options.expectation, nowUnix: this.now(), maxLifetimeSeconds: 300 });
    if (response["policy_sha256"] !== this.options.expectedTrustPolicySha256
      || typeof response["issuance_id"] !== "string" || !/^[0-9a-f]{32}$/.test(response["issuance_id"])) {
      throw new Error("managed_workload_exchange_binding_invalid");
    }
    this.current = identity;
    this.issuanceId = response["issuance_id"];
    this.renewal++;
    return identity;
  }
  async check(identity: GuardWorkloadIdentity): Promise<void> {
    // Check the exact token passed by the adapter, including after a renewal.
    verifyWorkloadIdentity(identity, { trustedPublicKeys: this.options.trustedPublicKeys,
      expectation: this.options.expectation, nowUnix: this.now(), maxLifetimeSeconds: 300 });
    const nonce = randomBytes(32).toString("hex");
    const response = await this.post("check", { organization_id: this.options.organizationId,
      project_id: this.options.projectId, identity_sha256: identity.identity_sha256, request_nonce: nonce });
    const value = response["attestation"];
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("managed_workload_check_invalid");
    const attestation = value as Record<string, unknown>;
    const now = this.now();
    if (Object.keys(attestation).sort().join() !== "checked_at_unix,claim_boundary,expires_at_unix,identity_sha256,key_id,policy_sha256,request_nonce,schema_version"
      || attestation["schema_version"] !== "gradia.guard.current-workload-trust.v1"
      || attestation["claim_boundary"] !== "current_database_trust_check_not_dispatch_or_non_bypassability"
      || attestation["identity_sha256"] !== identity.identity_sha256 || attestation["request_nonce"] !== nonce
      || attestation["policy_sha256"] !== this.options.expectedTrustPolicySha256
      || attestation["key_id"] !== identity.protected.key_id
      || !Number.isSafeInteger(attestation["checked_at_unix"]) || !Number.isSafeInteger(attestation["expires_at_unix"])
      || (attestation["checked_at_unix"] as number) > now || (attestation["expires_at_unix"] as number) <= now
      || (attestation["expires_at_unix"] as number) - (attestation["checked_at_unix"] as number) > 5
      || typeof response["signature_base64url"] !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(response["signature_base64url"])) {
      throw new Error("managed_workload_check_binding_invalid");
    }
    const key = this.options.trustedPublicKeys[identity.protected.key_id];
    if (key === undefined || !verifyBytes(null, Buffer.from(canonicalJson(attestation)), key,
      Buffer.from(response["signature_base64url"], "base64url"))) throw new Error("managed_workload_check_signature_invalid");
  }
  private async post(kind: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response = await (this.options.fetchImpl ?? fetch)(`${this.base}/v1/guard/workload-identities/${kind}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: canonicalJson(body),
      redirect: "error", signal: AbortSignal.timeout(5000),
    });
    if (!response.ok || response.body === null) throw new Error("managed_workload_service_refused");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = []; let size = 0;
    try {
      for (;;) {
        const next = await reader.read(); if (next.done) break;
        size += next.value.length;
        if (size > 65536) { await reader.cancel(); throw new Error("managed_workload_response_too_large"); }
        chunks.push(next.value);
      }
    } finally { reader.releaseLock(); }
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("managed_workload_response_invalid");
    return value as Record<string, unknown>;
  }
}
