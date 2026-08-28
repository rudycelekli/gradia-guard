import { createPublicKey, type KeyLike, type KeyObject } from "node:crypto";
import { canonicalJson, digestCanonical, isSha256, sha256 } from "./canonical.js";
import {
  verifyKubernetesEnforcementReceipt,
  type KubernetesEnforcementReceipt,
} from "./kubernetes-enforcement.js";
import { assertStableId } from "./security.js";
import {
  verifyWorkloadIdentity,
  type GuardWorkloadIdentity,
  type WorkloadIdentityExpectation,
} from "./workload-identity.js";

export const KUBERNETES_IDENTITY_EXCHANGE_SCHEMA_VERSION =
  "gradia.guard.kubernetes-identity-exchange-receipt.v1" as const;

export const KUBERNETES_WORKLOAD_IDENTITY_AUDIENCE =
  "gradia-guard-workload-identity" as const;
export const KUBERNETES_API_AUDIENCE =
  "https://kubernetes.default.svc.cluster.local" as const;
export const KUBERNETES_GATEWAY_SUBJECT =
  "system:serviceaccount:gradia-guard:gradia-guard-gateway" as const;
export const KUBERNETES_BROKER_SUBJECT =
  "system:serviceaccount:gradia-guard:gradia-guard-identity-broker" as const;

export interface KubernetesTokenReviewObservation {
  api_version: "authentication.k8s.io/v1";
  authenticated: true;
  token_sha256: string;
  requested_audiences: readonly [typeof KUBERNETES_WORKLOAD_IDENTITY_AUDIENCE];
  returned_audiences: readonly [typeof KUBERNETES_WORKLOAD_IDENTITY_AUDIENCE];
  username: typeof KUBERNETES_GATEWAY_SUBJECT;
  user_uid_sha256: string;
  credential_id_sha256: string;
  groups: readonly [
    "system:authenticated",
    "system:serviceaccounts",
    "system:serviceaccounts:gradia-guard",
  ];
  pod_name_sha256: string;
  pod_uid_sha256: string;
  issued_at_unix: number;
  expires_at_unix: number;
  lifetime_seconds: 600;
}

export interface KubernetesIdentityBrokerObservation {
  service_account_name: "gradia-guard-identity-broker";
  reviewer_subject: typeof KUBERNETES_BROKER_SUBJECT;
  reviewer_audience: typeof KUBERNETES_API_AUDIENCE;
  token_review_permission: "create.authentication.k8s.io/tokenreviews";
  issuer_key_id: "kubernetes-tokenreview-issuer-v1";
  issuer_public_key_spki_sha256: string;
  exchange_tls_ca_sha256: string;
  broker_deployment_uid_sha256: string;
  broker_pod_uid_sha256: string;
  broker_configured_image_sha256: string;
  broker_running_image_id_sha256: string;
  cluster_role_rules_sha256: string;
  cluster_role_binding_subjects_sha256: string;
  accepted_exchanges: 1;
  replay_rejections: 1;
  replay_guard: "single_use_token_sha256_in_memory";
  private_signing_key_mount: "identity_broker_only";
  trusted_public_key_mount: "gateway_only";
}

export interface KubernetesIdentityExchangeNetworkObservation {
  agent_direct_broker_egress: "blocked";
  gateway_broker_tls_reachability: "allowed_with_pinned_ca";
  broker_kubernetes_api_reachability: "allowed";
  gateway_token_replay: "rejected";
  network_policy_sha256s: Readonly<Record<string, string>>;
  probe_command_sha256s: Readonly<Record<string, string>>;
}

export interface KubernetesIdentityExchangeCoverage {
  kubernetes_token_review_authenticated: true;
  token_review_result_bound_into_signed_nonce: true;
  broker_issued_guard_workload_identity: true;
  broker_tls_ca_pin_observed: true;
  signing_key_withheld_from_agent_and_gateway_configuration: true;
  provider_credential_withheld_from_agent_and_broker_configuration: true;
  projected_token_withheld_from_agent_and_broker_configuration: true;
  single_process_replay_rejection_observed: true;
  local_ephemeral_cluster_only: true;
  managed_gradia_identity_service_proved: false;
  cloud_workload_identity_federation_proved: false;
  issuer_key_rotation_revocation_or_hsm_proved: false;
  broker_restart_replay_persistence_proved: false;
  cluster_admin_or_node_operator_bypass_possible: true;
  live_provider_behavior_proved: false;
  exhaustive_bypass_resistance_proved: false;
}

export interface KubernetesIdentityExchangeReceiptBody {
  schema_version: typeof KUBERNETES_IDENTITY_EXCHANGE_SCHEMA_VERSION;
  runtime_id: string;
  observed_at: string;
  parent_kubernetes_enforcement_receipt_sha256: string;
  collector_authority: "broker_response_kubectl_admin_inspection_and_in_pod_probes";
  claim_boundary: "one_local_kind_cluster_one_tokenreview_exchange_not_managed_federation_or_operator_resistance";
  token_review: KubernetesTokenReviewObservation;
  broker: KubernetesIdentityBrokerObservation;
  guard_workload_identity: GuardWorkloadIdentity;
  network: KubernetesIdentityExchangeNetworkObservation;
  coverage: KubernetesIdentityExchangeCoverage;
}

export interface KubernetesIdentityExchangeReceipt
  extends KubernetesIdentityExchangeReceiptBody {
  receipt_sha256: string;
}

export interface VerifyKubernetesIdentityExchangeOptions {
  parentReceipt: unknown;
  gatewayEvidenceDirectory: string;
  trustedIssuerPublicKey: KeyLike;
  trustedBrokerTlsCa: Uint8Array;
}

const NETWORK_POLICY_NAMES = Object.freeze([
  "agent-egress-only-to-guard-gateway",
  "broker-egress-only-to-dns-and-kube-api",
  "broker-ingress-only-from-gateway",
  "default-deny-all",
  "gateway-egress-to-identity-broker",
  "gateway-ingress-only-from-agent",
  "gateway-standard-egress",
]);

const PROBE_NAMES = Object.freeze([
  "agent_direct_broker",
  "broker_kubernetes_api",
  "gateway_broker_tls",
  "gateway_token_replay",
]);

const COVERAGE: KubernetesIdentityExchangeCoverage = Object.freeze({
  kubernetes_token_review_authenticated: true,
  token_review_result_bound_into_signed_nonce: true,
  broker_issued_guard_workload_identity: true,
  broker_tls_ca_pin_observed: true,
  signing_key_withheld_from_agent_and_gateway_configuration: true,
  provider_credential_withheld_from_agent_and_broker_configuration: true,
  projected_token_withheld_from_agent_and_broker_configuration: true,
  single_process_replay_rejection_observed: true,
  local_ephemeral_cluster_only: true,
  managed_gradia_identity_service_proved: false,
  cloud_workload_identity_federation_proved: false,
  issuer_key_rotation_revocation_or_hsm_proved: false,
  broker_restart_replay_persistence_proved: false,
  cluster_admin_or_node_operator_bypass_possible: true,
  live_provider_behavior_proved: false,
  exhaustive_bypass_resistance_proved: false,
});

export function tokenReviewNonceSha256(
  runtimeId: string,
  observation: KubernetesTokenReviewObservation,
): string {
  assertStableId(runtimeId, "kubernetes_identity_exchange_runtime_id");
  verifyTokenReview(observation);
  return digestCanonical({
    runtime_id: runtimeId,
    token_sha256: observation.token_sha256,
    username: observation.username,
    user_uid_sha256: observation.user_uid_sha256,
    credential_id_sha256: observation.credential_id_sha256,
    pod_name_sha256: observation.pod_name_sha256,
    pod_uid_sha256: observation.pod_uid_sha256,
    requested_audiences: observation.requested_audiences,
    returned_audiences: observation.returned_audiences,
  });
}

export function createKubernetesIdentityExchangeReceipt(
  body: KubernetesIdentityExchangeReceiptBody,
  options: VerifyKubernetesIdentityExchangeOptions,
): KubernetesIdentityExchangeReceipt {
  const receipt = { ...body, receipt_sha256: digestCanonical(body) };
  return verifyKubernetesIdentityExchangeReceipt(receipt, options);
}

export function verifyKubernetesIdentityExchangeReceipt(
  value: unknown,
  options: VerifyKubernetesIdentityExchangeOptions,
): KubernetesIdentityExchangeReceipt {
  if (!record(value)) throw new Error("kubernetes_identity_exchange_receipt_shape_invalid");
  exactKeys(value, [
    "broker",
    "claim_boundary",
    "collector_authority",
    "coverage",
    "guard_workload_identity",
    "network",
    "observed_at",
    "parent_kubernetes_enforcement_receipt_sha256",
    "receipt_sha256",
    "runtime_id",
    "schema_version",
    "token_review",
  ], "kubernetes_identity_exchange_receipt");
  const receipt = value as unknown as KubernetesIdentityExchangeReceipt;
  if (receipt.schema_version !== KUBERNETES_IDENTITY_EXCHANGE_SCHEMA_VERSION) {
    throw new Error("kubernetes_identity_exchange_schema_invalid");
  }
  assertStableId(receipt.runtime_id, "kubernetes_identity_exchange_runtime_id");
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(receipt.observed_at) ||
    receipt.collector_authority !==
      "broker_response_kubectl_admin_inspection_and_in_pod_probes" ||
    receipt.claim_boundary !==
      "one_local_kind_cluster_one_tokenreview_exchange_not_managed_federation_or_operator_resistance"
  ) {
    throw new Error("kubernetes_identity_exchange_boundary_invalid");
  }
  const parent = verifyKubernetesEnforcementReceipt(
    options.parentReceipt,
    options.gatewayEvidenceDirectory,
  );
  if (
    receipt.parent_kubernetes_enforcement_receipt_sha256 !== parent.receipt_sha256 ||
    receipt.runtime_id !== parent.runtime_id
  ) {
    throw new Error("kubernetes_identity_exchange_parent_mismatch");
  }
  verifyTokenReview(receipt.token_review);
  verifyBroker(
    receipt.broker,
    options.trustedIssuerPublicKey,
    options.trustedBrokerTlsCa,
  );
  verifyNetwork(receipt.network);
  if (canonicalJson(receipt.coverage) !== canonicalJson(COVERAGE)) {
    throw new Error("kubernetes_identity_exchange_coverage_overclaim");
  }
  const identity = receipt.guard_workload_identity;
  const expectation = identityExpectation(identity);
  const observedAtUnix = Math.floor(Date.parse(receipt.observed_at) / 1_000);
  if (!Number.isSafeInteger(observedAtUnix)) {
    throw new Error("kubernetes_identity_exchange_observed_at_invalid");
  }
  const verified = verifyWorkloadIdentity(identity, {
    trustedPublicKeys: { [receipt.broker.issuer_key_id]: options.trustedIssuerPublicKey },
    expectation,
    nowUnix: observedAtUnix,
    maxLifetimeSeconds: 300,
    clockSkewSeconds: 0,
  });
  if (
    identity.protected.key_id !== receipt.broker.issuer_key_id ||
    verified.identitySha256 !== parent.gateway_evidence.guard_workload_identity_sha256 ||
    identity.claims.issuer_id !== "gradia-kubernetes-tokenreview" ||
    identity.claims.organization_id !== "org-kubernetes-proof" ||
    identity.claims.project_id !== "project-kubernetes-proof" ||
    identity.claims.workload_id !== "agent-kubernetes-openai-proof" ||
    identity.claims.deployment_id !== "deployment-kubernetes-proof" ||
    identity.claims.audience !== "guard-runtime" ||
    canonicalJson(identity.claims.authority_scope_ids) !== canonicalJson(["model.invoke"]) ||
    identity.claims.policy_sha256 !== parent.gateway_evidence.policy_sha256 ||
    identity.claims.configuration_sha256 !== parent.gateway_evidence.configuration_sha256 ||
    identity.claims.image_sha256 !== parent.gateway.configured_image_sha256 ||
    identity.claims.collector_sha256 !== digestCanonical({
      collector: "container-sdk-route-v1",
      provider: "openai",
    }) ||
    identity.claims.nonce_sha256 !== tokenReviewNonceSha256(receipt.runtime_id, receipt.token_review) ||
    identity.claims.issued_at_unix < receipt.token_review.issued_at_unix ||
    identity.claims.expires_at_unix > receipt.token_review.expires_at_unix ||
    identity.claims.expires_at_unix - identity.claims.issued_at_unix > 300
  ) {
    throw new Error("kubernetes_identity_exchange_signed_binding_invalid");
  }
  if (!isSha256(receipt.receipt_sha256)) {
    throw new Error("kubernetes_identity_exchange_receipt_digest_invalid");
  }
  const { receipt_sha256: _digest, ...body } = receipt;
  if (receipt.receipt_sha256 !== digestCanonical(body)) {
    throw new Error("kubernetes_identity_exchange_receipt_digest_mismatch");
  }
  return receipt;
}

function identityExpectation(identity: GuardWorkloadIdentity): WorkloadIdentityExpectation {
  return {
    issuerId: identity.claims.issuer_id,
    organizationId: identity.claims.organization_id,
    projectId: identity.claims.project_id,
    workloadId: identity.claims.workload_id,
    deploymentId: identity.claims.deployment_id,
    audience: identity.claims.audience,
    policySha256: identity.claims.policy_sha256,
    imageSha256: identity.claims.image_sha256,
    configurationSha256: identity.claims.configuration_sha256,
    collectorSha256: identity.claims.collector_sha256,
    requiredAuthorityScopeIds: ["model.invoke"],
  };
}

function verifyTokenReview(review: KubernetesTokenReviewObservation): void {
  exactKeys(review as unknown as Record<string, unknown>, [
    "api_version",
    "authenticated",
    "credential_id_sha256",
    "expires_at_unix",
    "groups",
    "issued_at_unix",
    "lifetime_seconds",
    "pod_name_sha256",
    "pod_uid_sha256",
    "requested_audiences",
    "returned_audiences",
    "token_sha256",
    "user_uid_sha256",
    "username",
  ], "kubernetes_token_review");
  if (
    review.api_version !== "authentication.k8s.io/v1" ||
    review.authenticated !== true ||
    !isSha256(review.token_sha256) ||
    canonicalJson(review.requested_audiences) !==
      canonicalJson([KUBERNETES_WORKLOAD_IDENTITY_AUDIENCE]) ||
    canonicalJson(review.returned_audiences) !==
      canonicalJson([KUBERNETES_WORKLOAD_IDENTITY_AUDIENCE]) ||
    review.username !== KUBERNETES_GATEWAY_SUBJECT ||
    canonicalJson(review.groups) !== canonicalJson([
      "system:authenticated",
      "system:serviceaccounts",
      "system:serviceaccounts:gradia-guard",
    ]) ||
    !isSha256(review.user_uid_sha256) ||
    !isSha256(review.credential_id_sha256) ||
    !isSha256(review.pod_name_sha256) ||
    !isSha256(review.pod_uid_sha256) ||
    !Number.isSafeInteger(review.issued_at_unix) ||
    !Number.isSafeInteger(review.expires_at_unix) ||
    review.expires_at_unix - review.issued_at_unix !== 600 ||
    review.lifetime_seconds !== 600
  ) {
    throw new Error("kubernetes_token_review_observation_invalid");
  }
}

function verifyBroker(
  broker: KubernetesIdentityBrokerObservation,
  trustedIssuerPublicKey: KeyLike,
  trustedBrokerTlsCa: Uint8Array,
): void {
  exactKeys(broker as unknown as Record<string, unknown>, [
    "accepted_exchanges",
    "broker_configured_image_sha256",
    "broker_deployment_uid_sha256",
    "broker_pod_uid_sha256",
    "broker_running_image_id_sha256",
    "cluster_role_binding_subjects_sha256",
    "cluster_role_rules_sha256",
    "exchange_tls_ca_sha256",
    "issuer_key_id",
    "issuer_public_key_spki_sha256",
    "private_signing_key_mount",
    "replay_guard",
    "replay_rejections",
    "reviewer_audience",
    "reviewer_subject",
    "service_account_name",
    "token_review_permission",
    "trusted_public_key_mount",
  ], "kubernetes_identity_broker");
  const publicKey =
    typeof trustedIssuerPublicKey === "object" &&
    trustedIssuerPublicKey !== null &&
    "type" in trustedIssuerPublicKey &&
    (trustedIssuerPublicKey as KeyObject).type === "public"
      ? trustedIssuerPublicKey as KeyObject
      : createPublicKey(trustedIssuerPublicKey);
  const spki = publicKey.export({ format: "der", type: "spki" });
  if (
    broker.service_account_name !== "gradia-guard-identity-broker" ||
    broker.reviewer_subject !== KUBERNETES_BROKER_SUBJECT ||
    broker.reviewer_audience !== KUBERNETES_API_AUDIENCE ||
    broker.token_review_permission !== "create.authentication.k8s.io/tokenreviews" ||
    broker.issuer_key_id !== "kubernetes-tokenreview-issuer-v1" ||
    broker.issuer_public_key_spki_sha256 !== sha256(spki) ||
    broker.exchange_tls_ca_sha256 !== sha256(trustedBrokerTlsCa) ||
    broker.accepted_exchanges !== 1 ||
    broker.replay_rejections !== 1 ||
    broker.replay_guard !== "single_use_token_sha256_in_memory" ||
    broker.private_signing_key_mount !== "identity_broker_only" ||
    broker.trusted_public_key_mount !== "gateway_only" ||
    broker.cluster_role_rules_sha256 !== digestCanonical([{
      apiGroups: ["authentication.k8s.io"],
      resources: ["tokenreviews"],
      verbs: ["create"],
    }]) ||
    broker.cluster_role_binding_subjects_sha256 !== digestCanonical([{
      kind: "ServiceAccount",
      name: "gradia-guard-identity-broker",
      namespace: "gradia-guard",
    }])
  ) {
    throw new Error("kubernetes_identity_broker_observation_invalid");
  }
  for (const digest of [
    broker.exchange_tls_ca_sha256,
    broker.broker_deployment_uid_sha256,
    broker.broker_pod_uid_sha256,
    broker.broker_configured_image_sha256,
    broker.broker_running_image_id_sha256,
    broker.cluster_role_rules_sha256,
    broker.cluster_role_binding_subjects_sha256,
  ]) {
    if (!isSha256(digest)) throw new Error("kubernetes_identity_broker_digest_invalid");
  }
}

function verifyNetwork(network: KubernetesIdentityExchangeNetworkObservation): void {
  exactKeys(network as unknown as Record<string, unknown>, [
    "agent_direct_broker_egress",
    "broker_kubernetes_api_reachability",
    "gateway_broker_tls_reachability",
    "gateway_token_replay",
    "network_policy_sha256s",
    "probe_command_sha256s",
  ], "kubernetes_identity_exchange_network");
  if (
    network.agent_direct_broker_egress !== "blocked" ||
    network.gateway_broker_tls_reachability !== "allowed_with_pinned_ca" ||
    network.broker_kubernetes_api_reachability !== "allowed" ||
    network.gateway_token_replay !== "rejected" ||
    canonicalJson(Object.keys(network.network_policy_sha256s).sort()) !==
      canonicalJson(NETWORK_POLICY_NAMES) ||
    canonicalJson(Object.keys(network.probe_command_sha256s).sort()) !==
      canonicalJson(PROBE_NAMES)
  ) {
    throw new Error("kubernetes_identity_exchange_network_invalid");
  }
  for (const digest of [
    ...Object.values(network.network_policy_sha256s),
    ...Object.values(network.probe_command_sha256s),
  ]) {
    if (!isSha256(digest)) throw new Error("kubernetes_identity_exchange_network_digest_invalid");
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...allowed].sort())) {
    throw new Error(`${label}_keys_invalid`);
  }
}
