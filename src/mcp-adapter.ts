import type { KeyLike } from "node:crypto";
import { canonicalJson } from "./canonical.js";
import {
  enforcementBoundary,
  verifyEnforcementBoundary,
  type GuardEnforcementBoundary,
} from "./enforcement-boundary.js";
import { evaluateToolPolicy, verifyPolicy, type GuardPolicy } from "./policy.js";
import {
  SdkIdentityMismatchError,
  SdkRecorder,
  type SdkPolicyDecisionInput,
} from "./sdk.js";
import { assertStableId } from "./security.js";
import type {
  SdkActionFrame,
  SdkStateRootIdentity,
  SdkToolIdentity,
} from "./types.js";
import {
  verifyWorkloadIdentity,
  type GuardWorkloadIdentity,
  type WorkloadIdentityExpectation,
} from "./workload-identity.js";

export interface AuthenticatedMcpToolAdapterOptions {
  directory: string;
  policy: GuardPolicy;
  workloadIdentity: GuardWorkloadIdentity;
  trustedPublicKeys: Readonly<Record<string, KeyLike>>;
  workloadExpectation: Omit<WorkloadIdentityExpectation, "requiredAuthorityScopeIds">;
  maxIdentityLifetimeSeconds: number;
  clockSkewSeconds?: number;
  nowUnix?: () => number;
  invokeTool: GuardMcpToolInvoker;
}

export interface AuthenticatedMcpToolRequest {
  serverId: string;
  toolIdentity: SdkToolIdentity;
  toolRequestBody: Uint8Array;
  toolRequestMediaType: "application/json";
  authorityScopeIds: readonly string[];
  logicalOperationId: string;
  attemptNumber: number;
  retryOfOccurrenceSha256: string | null;
  parentOccurrenceSha256: string | null;
  stateRootBefore: SdkStateRootIdentity | null;
}

export interface GuardMcpInvocationInput {
  serverId: string;
  toolIdentity: SdkToolIdentity;
  toolRequestBody: Uint8Array;
  toolRequestMediaType: "application/json";
}

export interface GuardMcpInvocationResponse {
  resolvedServerId: string;
  resolvedToolIdentity: SdkToolIdentity;
  toolResultBody: Uint8Array;
  toolResultMediaType: string;
  isError: boolean;
  stateRootAfter: SdkStateRootIdentity | null;
}

export type GuardMcpToolInvoker = (
  input: GuardMcpInvocationInput,
) => Promise<GuardMcpInvocationResponse>;

export interface AuthenticatedMcpToolResult {
  disposition:
    | "blocked"
    | "completed"
    | "tool_failure"
    | "protocol_failure"
    | "identity_mismatch";
  occurrenceSha256: string;
  identitySha256: string | null;
  action: SdkActionFrame | null;
  response: GuardMcpInvocationResponse | null;
  boundary: GuardEnforcementBoundary;
}

export class AuthenticatedMcpToolAdapter {
  readonly recorder: SdkRecorder;
  readonly boundary: GuardEnforcementBoundary;
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
  private readonly invokeTool: GuardMcpToolInvoker;
  private finalized = false;

  constructor(options: AuthenticatedMcpToolAdapterOptions) {
    verifyPolicy(options.policy);
    if (options.workloadExpectation.policySha256 !== options.policy.policy_sha256) {
      throw new Error("guard_mcp_expected_policy_mismatch");
    }
    this.policy = JSON.parse(canonicalJson(options.policy)) as GuardPolicy;
    this.workloadIdentity = JSON.parse(
      canonicalJson(options.workloadIdentity),
    ) as GuardWorkloadIdentity;
    this.trustedPublicKeys = options.trustedPublicKeys;
    this.workloadExpectation = JSON.parse(
      canonicalJson(options.workloadExpectation),
    ) as Omit<WorkloadIdentityExpectation, "requiredAuthorityScopeIds">;
    this.maxIdentityLifetimeSeconds = options.maxIdentityLifetimeSeconds;
    this.clockSkewSeconds = options.clockSkewSeconds ?? 0;
    this.nowUnix = options.nowUnix ?? (() => Math.floor(Date.now() / 1000));
    this.invokeTool = options.invokeTool;
    this.boundary = enforcementBoundary("mcp_tool_adapter");
    verifyEnforcementBoundary(this.boundary);
    this.recorder = new SdkRecorder({ directory: options.directory });
  }

  async invoke(input: AuthenticatedMcpToolRequest): Promise<AuthenticatedMcpToolResult> {
    if (this.finalized) throw new Error("guard_mcp_adapter_finalized");
    assertExactKeys(
      input as unknown as Record<string, unknown>,
      [
        "attemptNumber",
        "authorityScopeIds",
        "logicalOperationId",
        "parentOccurrenceSha256",
        "retryOfOccurrenceSha256",
        "serverId",
        "stateRootBefore",
        "toolIdentity",
        "toolRequestBody",
        "toolRequestMediaType",
      ],
      "guard_mcp_request",
    );
    assertStableId(input.serverId, "guard_mcp_server_id");
    const authorization = this.authorize(input);
    const operation = this.recorder.beginRegisteredToolCall({
      actorId: this.workloadExpectation.workloadId,
      principalId: this.workloadExpectation.projectId,
      authorityScopeIds: input.authorityScopeIds,
      logicalOperationId: input.logicalOperationId,
      attemptNumber: input.attemptNumber,
      retryOfOccurrenceSha256: input.retryOfOccurrenceSha256,
      parentOccurrenceSha256: input.parentOccurrenceSha256,
      stateRootBefore: input.stateRootBefore,
      toolIdentity: input.toolIdentity,
      toolRequestBody: input.toolRequestBody,
      toolRequestMediaType: input.toolRequestMediaType,
      policy: authorization.policy,
    });
    if (operation.censored) {
      return this.result(
        "blocked",
        operation.occurrenceSha256,
        authorization.identitySha256,
        null,
        null,
      );
    }

    operation.markDispatched();
    let response: GuardMcpInvocationResponse;
    try {
      response = await this.invokeTool({
        serverId: input.serverId,
        toolIdentity: JSON.parse(canonicalJson(input.toolIdentity)) as SdkToolIdentity,
        toolRequestBody: input.toolRequestBody,
        toolRequestMediaType: input.toolRequestMediaType,
      });
    } catch {
      const action = operation.fail({
        outcome: "tool_failure",
        resolvedToolIdentity: null,
        toolResultBody: null,
        toolResultMediaType: null,
        stateRootAfter: input.stateRootBefore,
        failureCode: "mcp_transport_failure",
      });
      return this.result(
        "tool_failure",
        operation.occurrenceSha256,
        authorization.identitySha256,
        action,
        null,
      );
    }

    try {
      validateInvocationResponse(response);
    } catch {
      const action = operation.fail({
        outcome: "protocol_failure",
        resolvedToolIdentity: null,
        toolResultBody: null,
        toolResultMediaType: null,
        stateRootAfter: input.stateRootBefore,
        failureCode: "mcp_response_contract_invalid",
      });
      return this.result(
        "protocol_failure",
        operation.occurrenceSha256,
        authorization.identitySha256,
        action,
        null,
      );
    }

    const resolvedIdentity = {
      ...response.resolvedToolIdentity,
      registry_id: response.resolvedServerId,
    };
    try {
      if (response.isError) {
        const action = operation.fail({
          outcome: "tool_failure",
          resolvedToolIdentity: resolvedIdentity,
          toolResultBody: response.toolResultBody,
          toolResultMediaType: response.toolResultMediaType,
          stateRootAfter: response.stateRootAfter,
          failureCode: "mcp_tool_error",
        });
        return this.result(
          "tool_failure",
          operation.occurrenceSha256,
          authorization.identitySha256,
          action,
          response,
        );
      }
      const action = operation.succeed({
        resolvedToolIdentity: resolvedIdentity,
        toolResultBody: response.toolResultBody,
        toolResultMediaType: response.toolResultMediaType,
        stateRootAfter: response.stateRootAfter,
      });
      return this.result(
        "completed",
        operation.occurrenceSha256,
        authorization.identitySha256,
        action,
        response,
      );
    } catch (error) {
      if (error instanceof SdkIdentityMismatchError) {
        return this.result(
          "identity_mismatch",
          operation.occurrenceSha256,
          authorization.identitySha256,
          error.frame,
          null,
        );
      }
      const action = operation.fail({
        outcome: "protocol_failure",
        resolvedToolIdentity: null,
        toolResultBody: null,
        toolResultMediaType: null,
        stateRootAfter: input.stateRootBefore,
        failureCode: "mcp_response_identity_invalid",
      });
      return this.result(
        "protocol_failure",
        operation.occurrenceSha256,
        authorization.identitySha256,
        action,
        null,
      );
    }
  }

  finalize(): void {
    if (this.finalized) return;
    this.recorder.finalize();
    this.finalized = true;
  }

  private authorize(input: AuthenticatedMcpToolRequest): {
    policy: SdkPolicyDecisionInput;
    identitySha256: string | null;
  } {
    const reasons: string[] = [
      `enforcement_boundary_sha256:${this.boundary.boundary_sha256}`,
      `mcp_configuration_sha256:${this.workloadExpectation.configurationSha256}`,
    ];
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
      reasons.push(`workload_identity_sha256:${identitySha256}`);
    } catch {
      reasons.push("workload_identity_refused");
    }
    if (input.serverId !== input.toolIdentity.registry_id) {
      reasons.push("mcp_server_identity_mismatch");
    }
    const evaluated = evaluateToolPolicy(this.policy, {
      toolIdentity: input.toolIdentity,
      requestByteLength: input.toolRequestBody.byteLength,
      attemptNumber: input.attemptNumber,
      authorityScopeIds: input.authorityScopeIds,
    });
    reasons.push(...evaluated.reasonCodes);
    const allowed =
      identitySha256 !== null &&
      input.serverId === input.toolIdentity.registry_id &&
      evaluated.decision === "allowed";
    return {
      policy: {
        decision: allowed ? "allowed" : "blocked",
        censorKind:
          allowed
            ? null
            : identitySha256 !== null &&
                input.serverId === input.toolIdentity.registry_id &&
                evaluated.censorKind === "authority"
              ? "authority"
              : "policy",
        reasonCodes: [...new Set(reasons)].sort(),
        policySha256: this.policy.policy_sha256,
      },
      identitySha256,
    };
  }

  private result(
    disposition: AuthenticatedMcpToolResult["disposition"],
    occurrenceSha256: string,
    identitySha256: string | null,
    action: SdkActionFrame | null,
    response: GuardMcpInvocationResponse | null,
  ): AuthenticatedMcpToolResult {
    return {
      disposition,
      occurrenceSha256,
      identitySha256,
      action,
      response,
      boundary: this.boundary,
    };
  }
}

function validateInvocationResponse(response: GuardMcpInvocationResponse): void {
  assertExactKeys(
    response as unknown as Record<string, unknown>,
    [
      "isError",
      "resolvedServerId",
      "resolvedToolIdentity",
      "stateRootAfter",
      "toolResultBody",
      "toolResultMediaType",
    ],
    "guard_mcp_response",
  );
  assertStableId(response.resolvedServerId, "guard_mcp_resolved_server_id");
  if (!(response.toolResultBody instanceof Uint8Array) || response.toolResultBody.byteLength === 0) {
    throw new Error("guard_mcp_result_body_invalid");
  }
  if (!/^[\x20-\x7e]{1,200}$/.test(response.toolResultMediaType)) {
    throw new Error("guard_mcp_result_media_type_invalid");
  }
  if (typeof response.isError !== "boolean") throw new Error("guard_mcp_is_error_invalid");
}

function assertExactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) throw new Error(`${label}_keys_invalid`);
}
