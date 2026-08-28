import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";

export const ENFORCEMENT_BOUNDARY_SCHEMA_VERSION =
  "gradia.guard.enforcement-boundary.v1" as const;

export type EnforcementBoundaryKind = "local_http_proxy" | "mcp_tool_adapter";

export interface GuardEnforcementBoundary {
  schema_version: typeof ENFORCEMENT_BOUNDARY_SCHEMA_VERSION;
  boundary_kind: EnforcementBoundaryKind;
  capture_boundary: "explicit_local_http_proxy" | "explicit_mcp_tool_adapter";
  covered_surfaces: readonly string[];
  bypass_possible: true;
  bypass_declaration:
    | "traffic_not_routed_through_this_proxy_is_not_enforced"
    | "tools_not_invoked_through_this_adapter_are_not_enforced";
  full_host_enforcement: false;
  kubernetes_network_policy_enforced: false;
  boundary_sha256: string;
}

export function enforcementBoundary(kind: EnforcementBoundaryKind): GuardEnforcementBoundary {
  const body =
    kind === "local_http_proxy"
      ? {
          schema_version: ENFORCEMENT_BOUNDARY_SCHEMA_VERSION,
          boundary_kind: kind,
          capture_boundary: "explicit_local_http_proxy" as const,
          covered_surfaces: [
            "http.dispatch",
            "model.route",
            "policy.pre_dispatch",
            "workload.identity",
          ],
          bypass_possible: true as const,
          bypass_declaration: "traffic_not_routed_through_this_proxy_is_not_enforced" as const,
          full_host_enforcement: false as const,
          kubernetes_network_policy_enforced: false as const,
        }
      : {
          schema_version: ENFORCEMENT_BOUNDARY_SCHEMA_VERSION,
          boundary_kind: kind,
          capture_boundary: "explicit_mcp_tool_adapter" as const,
          covered_surfaces: [
            "mcp.tool.invoke",
            "policy.pre_dispatch",
            "tool.identity",
            "workload.identity",
          ],
          bypass_possible: true as const,
          bypass_declaration: "tools_not_invoked_through_this_adapter_are_not_enforced" as const,
          full_host_enforcement: false as const,
          kubernetes_network_policy_enforced: false as const,
        };
  return Object.freeze({ ...body, covered_surfaces: Object.freeze([...body.covered_surfaces]), boundary_sha256: digestCanonical(body) });
}

export function verifyEnforcementBoundary(boundary: GuardEnforcementBoundary): void {
  const expectedKeys = [
    "boundary_kind",
    "boundary_sha256",
    "bypass_declaration",
    "bypass_possible",
    "capture_boundary",
    "covered_surfaces",
    "full_host_enforcement",
    "kubernetes_network_policy_enforced",
    "schema_version",
  ].sort();
  const actualKeys = Object.keys(boundary).sort();
  if (canonicalJson(actualKeys) !== canonicalJson(expectedKeys)) {
    throw new Error("guard_enforcement_boundary_keys_invalid");
  }
  if (boundary.schema_version !== ENFORCEMENT_BOUNDARY_SCHEMA_VERSION) {
    throw new Error("guard_enforcement_boundary_schema_unsupported");
  }
  const expected = enforcementBoundary(boundary.boundary_kind);
  if (!isSha256(boundary.boundary_sha256)) {
    throw new Error("guard_enforcement_boundary_digest_invalid");
  }
  if (canonicalJson(boundary) !== canonicalJson(expected)) {
    throw new Error("guard_enforcement_boundary_mismatch");
  }
}
