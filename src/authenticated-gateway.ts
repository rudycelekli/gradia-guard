import type { KeyLike } from "node:crypto";
import {
  GatewayIdentityMismatchError,
  GatewayRecorder,
  type GatewayPolicyDecisionInput,
} from "./gateway.js";
import { evaluateModelPolicy, verifyPolicy, type GuardPolicy } from "./policy.js";
import {
  completeProviderAttempt,
  failProviderTransport,
  prepareProviderAttempt,
  requestedModelFromProviderRequest,
  type NativeGatewayProvider,
} from "./provider-adapters.js";
import type { GatewayActionFrame, GatewayProvider } from "./types.js";
import {
  verifyWorkloadIdentity,
  type GuardWorkloadIdentity,
  type WorkloadIdentityExpectation,
} from "./workload-identity.js";

export interface AuthenticatedGatewayOptions {
  directory: string;
  policy: GuardPolicy;
  workloadIdentity: GuardWorkloadIdentity;
  trustedPublicKeys: Readonly<Record<string, KeyLike>>;
  workloadExpectation: Omit<WorkloadIdentityExpectation, "requiredAuthorityScopeIds">;
  maxIdentityLifetimeSeconds: number;
  clockSkewSeconds?: number;
  nowUnix?: () => number;
  upstreamDispatch: (input: ProviderDispatchInput) => Promise<ProviderDispatchResponse>;
}

export interface AuthenticatedGatewayRequest {
  provider: NativeGatewayProvider;
  requestBody: Uint8Array;
  requestMediaType: "application/json";
  requestedModelFromRoute: string | null;
  logicalRequestId: string;
  attemptNumber: number;
  retryOfOccurrenceSha256: string | null;
  authorityScopeIds: readonly string[];
}

export interface ProviderDispatchInput {
  provider: NativeGatewayProvider;
  requestedModel: string;
  requestBody: Uint8Array;
  requestMediaType: "application/json";
}

export interface ProviderDispatchResponse {
  responseBody: Uint8Array;
  responseMediaType: string;
  httpStatus: number;
}

export interface AuthenticatedGatewayResult {
  disposition: "blocked" | "completed" | "transport_failure" | "identity_mismatch";
  occurrenceSha256: string;
  identitySha256: string | null;
  action: GatewayActionFrame | null;
  response: ProviderDispatchResponse | null;
}

export class AuthenticatedProviderGateway {
  readonly recorder: GatewayRecorder;
  private readonly policy: GuardPolicy;
  private readonly workloadIdentity: GuardWorkloadIdentity;
  private readonly trustedPublicKeys: Readonly<Record<string, KeyLike>>;
  private readonly workloadExpectation: Omit<
    WorkloadIdentityExpectation,
    "requiredAuthorityScopeIds"
  >;
  private readonly maxIdentityLifetimeSeconds: number;
  private readonly clockSkewSeconds: number;
  private readonly nowUnix: () => number;
  private readonly upstreamDispatch: AuthenticatedGatewayOptions["upstreamDispatch"];
  private finalized = false;

  constructor(options: AuthenticatedGatewayOptions) {
    this.policy = options.policy;
    verifyPolicy(this.policy);
    this.workloadIdentity = options.workloadIdentity;
    this.trustedPublicKeys = options.trustedPublicKeys;
    this.workloadExpectation = options.workloadExpectation;
    this.maxIdentityLifetimeSeconds = options.maxIdentityLifetimeSeconds;
    this.clockSkewSeconds = options.clockSkewSeconds ?? 0;
    this.nowUnix = options.nowUnix ?? (() => Math.floor(Date.now() / 1000));
    this.upstreamDispatch = options.upstreamDispatch;
    this.recorder = new GatewayRecorder({ directory: options.directory });
  }

  async dispatch(input: AuthenticatedGatewayRequest): Promise<AuthenticatedGatewayResult> {
    if (this.finalized) throw new Error("authenticated_gateway_finalized");
    const requestedModel = requestedModelFromProviderRequest(
      input.provider,
      input.requestBody,
      input.requestedModelFromRoute,
    );
    const authorization = this.authorize(input, requestedModel);
    const prepared = prepareProviderAttempt(this.recorder, {
      provider: input.provider,
      requestBody: input.requestBody,
      requestMediaType: input.requestMediaType,
      requestedModelFromRoute: input.requestedModelFromRoute,
      logicalRequestId: input.logicalRequestId,
      attemptNumber: input.attemptNumber,
      retryOfOccurrenceSha256: input.retryOfOccurrenceSha256,
      policy: authorization.policy,
    });
    if (prepared.attempt.censored) {
      return {
        disposition: "blocked",
        occurrenceSha256: prepared.attempt.occurrenceSha256,
        identitySha256: authorization.identitySha256,
        action: null,
        response: null,
      };
    }

    prepared.attempt.markDispatched();
    let response: ProviderDispatchResponse;
    try {
      response = await this.upstreamDispatch({
        provider: input.provider,
        requestedModel,
        requestBody: input.requestBody,
        requestMediaType: input.requestMediaType,
      });
    } catch {
      const action = failProviderTransport(prepared, "upstream_transport_failure");
      return {
        disposition: "transport_failure",
        occurrenceSha256: prepared.attempt.occurrenceSha256,
        identitySha256: authorization.identitySha256,
        action,
        response: null,
      };
    }

    try {
      const action = completeProviderAttempt(prepared, response);
      return {
        disposition: "completed",
        occurrenceSha256: prepared.attempt.occurrenceSha256,
        identitySha256: authorization.identitySha256,
        action,
        response,
      };
    } catch (error) {
      if (error instanceof GatewayIdentityMismatchError) {
        return {
          disposition: "identity_mismatch",
          occurrenceSha256: prepared.attempt.occurrenceSha256,
          identitySha256: authorization.identitySha256,
          action: error.frame,
          response: null,
        };
      }
      throw error;
    }
  }

  finalize(): void {
    if (this.finalized) return;
    this.recorder.finalize();
    this.finalized = true;
  }

  private authorize(
    input: AuthenticatedGatewayRequest,
    requestedModel: string,
  ): { policy: GatewayPolicyDecisionInput; identitySha256: string | null } {
    let identitySha256: string | null = null;
    try {
      const verified = verifyWorkloadIdentity(this.workloadIdentity, {
        trustedPublicKeys: this.trustedPublicKeys,
        expectation: {
          ...this.workloadExpectation,
          requiredAuthorityScopeIds: input.authorityScopeIds,
        },
        nowUnix: this.nowUnix(),
        maxLifetimeSeconds: this.maxIdentityLifetimeSeconds,
        clockSkewSeconds: this.clockSkewSeconds,
      });
      identitySha256 = verified.identitySha256;
    } catch {
      return {
        policy: {
          decision: "blocked",
          censorKind: "policy",
          reasonCodes: ["workload_identity_refused"],
          policySha256: this.policy.policy_sha256,
        },
        identitySha256: null,
      };
    }

    const evaluated = evaluateModelPolicy(this.policy, {
      provider: input.provider as GatewayProvider,
      requestedModel,
      requestByteLength: input.requestBody.byteLength,
      attemptNumber: input.attemptNumber,
      authorityScopeIds: input.authorityScopeIds,
    });
    return {
      policy: {
        ...evaluated,
        reasonCodes: [...evaluated.reasonCodes, `workload_identity_sha256:${identitySha256}`].sort(),
      },
      identitySha256,
    };
  }
}
