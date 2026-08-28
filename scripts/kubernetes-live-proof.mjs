import { execFileSync, spawnSync } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  createKubernetesEnforcementReceipt,
  createKubernetesIdentityExchangeReceipt,
  digestCanonical,
  frameworkSdkCompatibilityCatalog,
  sealHttpEgressConfiguration,
  sealPolicy,
  sha256,
  verifyKubernetesEnforcementReceipt,
  verifyKubernetesIdentityExchangeReceipt,
} from "../dist/src/index.js";

const KIND_VERSION = "v0.33.0";
const NODE_IMAGE =
  "kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed";
const NODE_IMAGE_SHA256 = NODE_IMAGE.split("@sha256:")[1];
const RUNTIME_ID = "guard-kubernetes-proof-20260828";
const NAMESPACE = "gradia-guard";
const AGENT_DEPLOYMENT = "gradia-guard-agent";
const GATEWAY_DEPLOYMENT = "gradia-guard-gateway";
const GATEWAY_SERVICE = "gradia-guard-gateway";
const BROKER_DEPLOYMENT = "gradia-guard-identity-broker";
const BROKER_SERVICE = "gradia-guard-identity-broker";
const PROVIDER = "openai";
const FRAMEWORK = "vercel_ai_sdk";
const kind = process.env.GRADIA_KIND_BINARY ?? "kind";
const kubectl = process.env.GRADIA_KUBECTL_BINARY ?? "kubectl";
const clusterName = `gradia-guard-proof-${process.pid}-${randomBytes(3).toString("hex")}`;
const output = process.env.GRADIA_KUBERNETES_PROOF_OUT
  ? resolve(process.env.GRADIA_KUBERNETES_PROOF_OUT)
  : mkdtempSync(join(tmpdir(), "gradia-kubernetes-proof-"));
const secretDirectory = mkdtempSync(join(tmpdir(), "gradia-kubernetes-identity-secrets-"));
const kubeconfig = join(secretDirectory, "kubeconfig");
const gatewayDirectory = join(output, "gateway-evidence");
const receiptPath = join(output, "kubernetes-enforcement.json");
const exchangeReceiptPath = join(output, "kubernetes-identity-exchange.json");
const issuerPublicKeyPath = join(output, "issuer-public-key.pem");
const brokerCaPath = join(output, "identity-broker-ca.pem");
const localCapability = randomBytes(32).toString("base64url");

const probeCommands = Object.freeze({
  direct_raw_ip: Object.freeze([
    "node",
    "-e",
    "const n=require('node:net');const s=n.connect(443,'1.1.1.1');s.setTimeout(4000);s.once('connect',()=>process.exit(42));s.once('error',()=>process.exit(0));s.once('timeout',()=>process.exit(0));",
  ]),
  gateway_health: Object.freeze([
    "node",
    "-e",
    "const c=new AbortController();setTimeout(()=>c.abort(),4000);fetch('http://gradia-guard-gateway:8787/health',{signal:c.signal}).then(r=>process.exit(r.ok?0:41)).catch(()=>process.exit(40));",
  ]),
  link_local_raw_ip: Object.freeze([
    "node",
    "-e",
    "const n=require('node:net');const s=n.connect(80,'169.254.169.254');s.setTimeout(4000);s.once('connect',()=>process.exit(42));s.once('error',()=>process.exit(0));s.once('timeout',()=>process.exit(0));",
  ]),
  root_write: Object.freeze([
    "node",
    "-e",
    "const f=require('node:fs');try{f.writeFileSync('/guard-root-write','x');process.exit(42)}catch{process.exit(0)}",
  ]),
  tmp_round_trip: Object.freeze([
    "node",
    "-e",
    "const f=require('node:fs');f.writeFileSync('/tmp/guard-proof','ok');process.exit(f.readFileSync('/tmp/guard-proof','utf8')==='ok'?0:41)",
  ]),
  api_token_absence: Object.freeze([
    "node",
    "-e",
    "const f=require('node:fs');process.exit(f.existsSync('/var/run/secrets/kubernetes.io/serviceaccount/token')?42:0)",
  ]),
  spawned_subprocess_raw_ip: Object.freeze([
    "node",
    "-e",
    "const{spawnSync}=require('node:child_process');const c=spawnSync(process.execPath,['-e',\"const n=require('node:net');const s=n.connect(443,'1.1.1.1');s.setTimeout(4000);s.once('connect',()=>process.exit(42));s.once('error',()=>process.exit(0));s.once('timeout',()=>process.exit(0));\"]);process.exit(c.status===0?0:42)",
  ]),
  agent_direct_broker: Object.freeze([
    "node",
    "-e",
    "const n=require('node:net');const s=n.connect(9443,'gradia-guard-identity-broker');s.setTimeout(4000);s.once('connect',()=>process.exit(42));s.once('error',()=>process.exit(0));s.once('timeout',()=>process.exit(0));",
  ]),
});

const identityProbeCommands = Object.freeze({
  agent_direct_broker: probeCommands.agent_direct_broker,
  broker_kubernetes_api: Object.freeze([
    "broker-status",
    "accepted_exchange_requires_successful_tokenreview",
  ]),
  gateway_broker_tls: Object.freeze([
    "gateway-startup",
    "pinned-ca-https-post-v1-exchange",
  ]),
  gateway_token_replay: Object.freeze([
    "node",
    "repost-mounted-projected-token-with-pinned-ca-expect-409",
  ]),
});

if (
  existsSync(receiptPath) ||
  existsSync(exchangeReceiptPath) ||
  existsSync(gatewayDirectory) ||
  existsSync(issuerPublicKeyPath) ||
  existsSync(brokerCaPath)
) {
  throw new Error("kubernetes_live_proof_refuses_overwrite");
}
mkdirSync(output, { recursive: true, mode: 0o700 });

function run(binary, args, options = {}) {
  return execFileSync(binary, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
    ...options,
  });
}

function kube(args, options = {}) {
  return run(kubectl, ["--kubeconfig", kubeconfig, ...args], options);
}

function kubeJson(args) {
  return JSON.parse(kube([...args, "-o", "json"]));
}

function docker(args, options = {}) {
  return run("docker", args, options);
}

function imageReference(tag) {
  const inspected = JSON.parse(docker(["image", "inspect", tag]));
  const digests = inspected[0]?.RepoDigests;
  if (!Array.isArray(digests) || digests.length !== 1 || !digests[0]?.includes("@sha256:")) {
    throw new Error("kubernetes_live_proof_image_digest_missing");
  }
  return digests[0];
}

function apply(path, namespace = null) {
  const args = namespace ? ["-n", namespace, "apply", "-f", path] : ["apply", "-f", path];
  kube(args, { stdio: "ignore" });
}

function podForRole(role, excludedUid = null) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const rows = kubeJson([
      "-n",
      NAMESPACE,
      "get",
      "pods",
      "-l",
      `gradia.dev/boundary-role=${role}`,
    ]).items.filter((pod) => !pod.metadata.deletionTimestamp);
    const ready = rows.find(
      (pod) =>
        pod.metadata.uid !== excludedUid &&
        pod.status.phase === "Running" &&
        pod.status.conditions?.some(
          (condition) => condition.type === "Ready" && condition.status === "True",
        ),
    );
    if (ready) return ready;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
  }
  throw new Error(`kubernetes_live_proof_${role}_pod_not_ready`);
}

function agentProbe(pod, command) {
  run(
    kubectl,
    ["--kubeconfig", kubeconfig, "-n", NAMESPACE, "exec", pod.metadata.name, "--", ...command],
    { stdio: "ignore", timeout: 15_000 },
  );
}

function waitForNetworkBoundary(pod) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      agentProbe(pod, probeCommands.direct_raw_ip);
      agentProbe(pod, probeCommands.gateway_health);
      return;
    } catch {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
    }
  }
  throw new Error("kubernetes_live_proof_network_policy_not_observed");
}

function gatewayStatus(pod) {
  return JSON.parse(
    kube(["-n", NAMESPACE, "exec", pod.metadata.name, "--", "cat", "/tmp/guard-status.json"]),
  );
}

function brokerStatus(pod) {
  return JSON.parse(
    kube(["-n", NAMESPACE, "exec", pod.metadata.name, "--", "cat", "/tmp/broker-status.json"]),
  );
}

function gatewayReplayProbe(pod) {
  const script = [
    "const h=require('node:https'),f=require('node:fs');",
    "const t=f.readFileSync('/var/run/secrets/gradia/identity.jwt','utf8').trim();",
    "const b=Buffer.from(JSON.stringify({projected_service_account_token:t}));",
    "const r=h.request({hostname:'gradia-guard-identity-broker',port:9443,path:'/v1/exchange',method:'POST',ca:f.readFileSync('/var/run/secrets/gradia-broker-ca/ca.crt'),servername:'gradia-guard-identity-broker',headers:{'content-type':'application/json','content-length':b.length}},s=>{const c=[];s.on('data',x=>c.push(x));s.on('end',()=>{let j={};try{j=JSON.parse(Buffer.concat(c))}catch{}process.exit(s.statusCode===409&&j.error==='identity_broker_token_replay_rejected'?0:42)})});",
    "r.setTimeout(5000,()=>r.destroy());r.on('error',()=>process.exit(41));r.end(b);",
  ].join("");
  run(
    kubectl,
    [
      "--kubeconfig",
      kubeconfig,
      "-n",
      NAMESPACE,
      "exec",
      pod.metadata.name,
      "--",
      "node",
      "-e",
      script,
    ],
    { stdio: "ignore", timeout: 15_000 },
  );
}

function waitForFinalizedGateway(pod) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const status = gatewayStatus(pod);
    if (status.finalized === true) return status;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
  }
  throw new Error("kubernetes_live_proof_gateway_not_finalized");
}

function createProofResources(
  agentImage,
  gatewayImage,
  brokerImage,
  issuerPrivateKey,
  issuerPublicKey,
  brokerTlsKey,
  brokerTlsCertificate,
  brokerCaCertificate,
) {
  const labels = (role, name) => ({
    "app.kubernetes.io/name": name,
    "gradia.dev/boundary-role": role,
  });
  const containerSecurity = {
    allowPrivilegeEscalation: false,
    privileged: false,
    readOnlyRootFilesystem: true,
    capabilities: { drop: ["ALL"] },
  };
  const podSecurity = {
    runAsNonRoot: true,
    runAsUser: 65532,
    runAsGroup: 65532,
    fsGroup: 65532,
    seccompProfile: { type: "RuntimeDefault" },
  };
  const deployment = (name, role, image, container) => ({
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { name, namespace: NAMESPACE, labels: labels(role, name) },
    spec: {
      replicas: 1,
      selector: { matchLabels: { "app.kubernetes.io/name": name } },
      template: {
        metadata: { labels: labels(role, name) },
        spec: {
          serviceAccountName: name,
          automountServiceAccountToken: false,
          enableServiceLinks: false,
          hostNetwork: false,
          hostPID: false,
          hostIPC: false,
          securityContext: podSecurity,
          containers: [{
            name: role,
            image,
            imagePullPolicy: "Never",
            securityContext: containerSecurity,
            resources: {
              requests: { cpu: "50m", memory: "64Mi" },
              limits: { cpu: "1", memory: "512Mi" },
            },
            ...container,
          }],
          volumes: [{ name: "tmp", emptyDir: { medium: "Memory", sizeLimit: "64Mi" } }],
        },
      },
    },
  });
  const secretEnvironment = (name, key) => ({
    name,
    valueFrom: {
      secretKeyRef: { name: "gradia-guard-proof-secrets", key },
    },
  });
  const secret = {
    apiVersion: "v1",
    kind: "Secret",
    metadata: { name: "gradia-guard-proof-secrets", namespace: NAMESPACE },
    type: "Opaque",
    data: {
      local_capability: Buffer.from(localCapability).toString("base64"),
      provider_fixture: Buffer.from("fixture-parent-only-provider-value").toString("base64"),
    },
  };
  const issuerSecret = {
    apiVersion: "v1",
    kind: "Secret",
    metadata: { name: "gradia-guard-identity-issuer", namespace: NAMESPACE },
    immutable: true,
    type: "Opaque",
    data: {
      "issuer-private-key.pem": Buffer.from(issuerPrivateKey).toString("base64"),
    },
  };
  const tlsSecret = {
    apiVersion: "v1",
    kind: "Secret",
    metadata: { name: "gradia-guard-identity-broker-tls", namespace: NAMESPACE },
    immutable: true,
    type: "kubernetes.io/tls",
    data: {
      "tls.key": Buffer.from(brokerTlsKey).toString("base64"),
      "tls.crt": Buffer.from(brokerTlsCertificate).toString("base64"),
    },
  };
  const issuerPublicConfig = {
    apiVersion: "v1",
    kind: "ConfigMap",
    metadata: { name: "gradia-guard-identity-issuer-public", namespace: NAMESPACE },
    immutable: true,
    data: { "issuer-public-key.pem": issuerPublicKey },
  };
  const brokerCaConfig = {
    apiVersion: "v1",
    kind: "ConfigMap",
    metadata: { name: "gradia-guard-identity-broker-ca", namespace: NAMESPACE },
    immutable: true,
    data: { "ca.crt": brokerCaCertificate },
  };
  const policy = sealPolicy({
    schema_version: "gradia.guard.policy.v1",
    policy_id: "container-sdk-openai-policy",
    policy_version: "v1",
    default_decision: "blocked",
    model_routes: [{
      provider: "openai",
      requested_model: "gpt-5.6-2026-08-01",
      authority_scope_ids: ["model.invoke"],
      max_request_bytes: 10_000,
      max_attempt_number: 1,
    }],
    tool_routes: [],
  });
  const configuration = sealHttpEgressConfiguration({
    schema_version: "gradia.guard.local-http-egress-configuration.v1",
    configuration_id: "container-sdk-openai-egress",
    configuration_version: "v1",
    default_decision: "blocked",
    model_routes: [{
      provider: "openai",
      target_url: "https://api.openai.example/v1/responses",
      method: "POST",
      request_media_type: "application/json",
      redirect_mode: "error",
      timeout_ms: 5_000,
      max_response_bytes: 100_000,
    }],
  });
  const gatewayServiceAccount = kubeJson([
    "-n",
    NAMESPACE,
    "get",
    "serviceaccount",
    GATEWAY_DEPLOYMENT,
  ]);
  const gatewayImageSha256 = digestFromImageReference(gatewayImage);
  const collectorSha256 = digestCanonical({
    collector: "container-sdk-route-v1",
    provider: PROVIDER,
  });
  const agent = deployment(AGENT_DEPLOYMENT, "agent", agentImage, {
    env: [
      secretEnvironment("GRADIA_GUARD_LOCAL_CAPABILITY", "local_capability"),
      { name: "GRADIA_GUARD_LOCAL_ORIGIN", value: `http://${GATEWAY_SERVICE}:8787` },
      { name: "GRADIA_GUARD_RUNTIME_ID", value: RUNTIME_ID },
    ],
    volumeMounts: [{ name: "tmp", mountPath: "/tmp" }],
  });
  const gateway = deployment(GATEWAY_DEPLOYMENT, "gateway", gatewayImage, {
    ports: [{ name: "http", containerPort: 8787, protocol: "TCP" }],
    env: [
      secretEnvironment("GRADIA_GUARD_LOCAL_CAPABILITY", "local_capability"),
      secretEnvironment("OPENAI_API_KEY", "provider_fixture"),
      { name: "GRADIA_GUARD_RUNTIME_ID", value: RUNTIME_ID },
      { name: "GRADIA_GUARD_PROOF_PROVIDER", value: PROVIDER },
      {
        name: "GRADIA_GUARD_KUBERNETES_TOKEN_PATH",
        value: "/var/run/secrets/gradia/identity.jwt",
      },
      {
        name: "GRADIA_GUARD_KUBERNETES_IDENTITY_EXCHANGE_ORIGIN",
        value: `https://${BROKER_SERVICE}:9443`,
      },
      {
        name: "GRADIA_GUARD_KUBERNETES_IDENTITY_EXCHANGE_CA_PATH",
        value: "/var/run/secrets/gradia-broker-ca/ca.crt",
      },
      {
        name: "GRADIA_GUARD_ISSUER_PUBLIC_KEY_PATH",
        value: "/var/run/secrets/gradia-issuer-public/issuer-public-key.pem",
      },
      { name: "GRADIA_GUARD_WORKLOAD_IMAGE_SHA256", value: gatewayImageSha256 },
    ],
    readinessProbe: {
      httpGet: { path: "/health", port: "http" },
      periodSeconds: 2,
      timeoutSeconds: 1,
      failureThreshold: 10,
    },
    livenessProbe: {
      httpGet: { path: "/health", port: "http" },
      periodSeconds: 10,
      timeoutSeconds: 2,
      failureThreshold: 3,
    },
    volumeMounts: [
      { name: "workload-identity", mountPath: "/var/run/secrets/gradia", readOnly: true },
      { name: "identity-broker-ca", mountPath: "/var/run/secrets/gradia-broker-ca", readOnly: true },
      { name: "identity-issuer-public", mountPath: "/var/run/secrets/gradia-issuer-public", readOnly: true },
      { name: "tmp", mountPath: "/tmp" },
    ],
  });
  gateway.spec.template.spec.volumes.push(
    {
      name: "workload-identity",
      projected: {
        defaultMode: 0o400,
        sources: [{
          serviceAccountToken: {
            audience: "gradia-guard-workload-identity",
            expirationSeconds: 600,
            path: "identity.jwt",
          },
        }],
      },
    },
    {
      name: "identity-broker-ca",
      configMap: {
        name: "gradia-guard-identity-broker-ca",
        defaultMode: 0o400,
      },
    },
    {
      name: "identity-issuer-public",
      configMap: {
        name: "gradia-guard-identity-issuer-public",
        defaultMode: 0o400,
      },
    },
  );
  const broker = deployment(BROKER_DEPLOYMENT, "identity-broker", brokerImage, {
    ports: [{ name: "https", containerPort: 9443, protocol: "TCP" }],
    env: [
      { name: "GRADIA_GUARD_RUNTIME_ID", value: RUNTIME_ID },
      { name: "GRADIA_GUARD_EXPECTED_POLICY_SHA256", value: policy.policy_sha256 },
      { name: "GRADIA_GUARD_EXPECTED_IMAGE_SHA256", value: gatewayImageSha256 },
      {
        name: "GRADIA_GUARD_EXPECTED_CONFIGURATION_SHA256",
        value: configuration.configuration_sha256,
      },
      { name: "GRADIA_GUARD_EXPECTED_COLLECTOR_SHA256", value: collectorSha256 },
      {
        name: "GRADIA_GUARD_EXPECTED_SERVICE_ACCOUNT_UID_SHA256",
        value: sha256(Buffer.from(gatewayServiceAccount.metadata.uid)),
      },
      {
        name: "GRADIA_GUARD_ISSUER_PRIVATE_KEY_PATH",
        value: "/var/run/secrets/gradia-issuer/issuer-private-key.pem",
      },
      {
        name: "GRADIA_GUARD_REVIEWER_TOKEN_PATH",
        value: "/var/run/secrets/gradia-reviewer/reviewer.jwt",
      },
      {
        name: "GRADIA_GUARD_KUBERNETES_CA_PATH",
        value: "/var/run/secrets/kubernetes-ca/ca.crt",
      },
      {
        name: "GRADIA_GUARD_BROKER_TLS_KEY_PATH",
        value: "/var/run/secrets/gradia-broker-tls/tls.key",
      },
      {
        name: "GRADIA_GUARD_BROKER_TLS_CERT_PATH",
        value: "/var/run/secrets/gradia-broker-tls/tls.crt",
      },
    ],
    readinessProbe: {
      httpGet: { scheme: "HTTPS", path: "/health", port: "https" },
      periodSeconds: 2,
      timeoutSeconds: 1,
      failureThreshold: 15,
    },
    livenessProbe: {
      httpGet: { scheme: "HTTPS", path: "/health", port: "https" },
      periodSeconds: 10,
      timeoutSeconds: 2,
      failureThreshold: 3,
    },
    volumeMounts: [
      { name: "identity-issuer", mountPath: "/var/run/secrets/gradia-issuer", readOnly: true },
      { name: "identity-reviewer", mountPath: "/var/run/secrets/gradia-reviewer", readOnly: true },
      { name: "kubernetes-ca", mountPath: "/var/run/secrets/kubernetes-ca", readOnly: true },
      { name: "identity-broker-tls", mountPath: "/var/run/secrets/gradia-broker-tls", readOnly: true },
      { name: "tmp", mountPath: "/tmp" },
    ],
  });
  broker.spec.template.spec.volumes.push(
    {
      name: "identity-issuer",
      secret: { secretName: "gradia-guard-identity-issuer", defaultMode: 0o440 },
    },
    {
      name: "identity-reviewer",
      projected: {
        defaultMode: 0o400,
        sources: [{
          serviceAccountToken: {
            audience: "https://kubernetes.default.svc.cluster.local",
            expirationSeconds: 600,
            path: "reviewer.jwt",
          },
        }],
      },
    },
    {
      name: "kubernetes-ca",
      configMap: {
        name: "kube-root-ca.crt",
        items: [{ key: "ca.crt", path: "ca.crt" }],
        defaultMode: 0o400,
      },
    },
    {
      name: "identity-broker-tls",
      secret: { secretName: "gradia-guard-identity-broker-tls", defaultMode: 0o440 },
    },
  );
  const service = (name, role, port, targetPort) => ({
    apiVersion: "v1",
    kind: "Service",
    metadata: { name, namespace: NAMESPACE },
    spec: {
      type: "ClusterIP",
      selector: { "app.kubernetes.io/name": role },
      ports: [{ name: targetPort, port, targetPort, protocol: "TCP" }],
    },
  });
  kube(["apply", "-f", "-"], {
    input: JSON.stringify({
      apiVersion: "v1",
      kind: "List",
      items: [
        secret,
        issuerSecret,
        tlsSecret,
        issuerPublicConfig,
        brokerCaConfig,
        agent,
        broker,
        gateway,
        service(GATEWAY_SERVICE, GATEWAY_DEPLOYMENT, 8787, "http"),
        service(BROKER_SERVICE, BROKER_DEPLOYMENT, 9443, "https"),
      ],
    }),
    stdio: ["pipe", "ignore", "pipe"],
  });
}

function digestFromImageReference(reference) {
  const match = /@sha256:([0-9a-f]{64})$/.exec(reference);
  if (!match?.[1]) throw new Error("kubernetes_live_proof_configured_image_invalid");
  return match[1];
}

function digestFromRunningImage(reference) {
  const match = /@sha256:([0-9a-f]{64})$/.exec(reference);
  if (!match?.[1]) throw new Error("kubernetes_live_proof_running_image_invalid");
  return match[1];
}

const providerCredentialNames = new Set([
  "ANTHROPIC_API_KEY",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "OPENAI_API_KEY",
  "XAI_API_KEY",
]);

function workloadPosture(deployment, pod) {
  const spec = deployment.spec.template.spec;
  const container = spec.containers[0];
  const status = pod.status.containerStatuses[0];
  const names = (container.env ?? [])
    .map((entry) => entry.name)
    .filter((name) => providerCredentialNames.has(name))
    .sort();
  return {
    deployment_uid_sha256: sha256(Buffer.from(deployment.metadata.uid)),
    pod_uid_sha256: sha256(Buffer.from(pod.metadata.uid)),
    configured_image_sha256: digestFromImageReference(container.image),
    running_image_id_sha256: digestFromRunningImage(status.imageID),
    service_account_name: spec.serviceAccountName,
    automount_service_account_token: spec.automountServiceAccountToken,
    host_network: spec.hostNetwork ?? false,
    host_pid: spec.hostPID ?? false,
    host_ipc: spec.hostIPC ?? false,
    run_as_non_root: spec.securityContext.runAsNonRoot,
    run_as_user: spec.securityContext.runAsUser,
    seccomp_profile: spec.securityContext.seccompProfile.type,
    allow_privilege_escalation: container.securityContext.allowPrivilegeEscalation,
    privileged: container.securityContext.privileged ?? false,
    read_only_root_filesystem: container.securityContext.readOnlyRootFilesystem,
    cap_drop_all: container.securityContext.capabilities.drop.includes("ALL"),
    provider_credential_names_present: names,
  };
}

function sanitizedDeployment(deployment, name) {
  const candidate = structuredClone(deployment);
  candidate.metadata.name = name;
  delete candidate.metadata.uid;
  delete candidate.metadata.resourceVersion;
  delete candidate.metadata.generation;
  delete candidate.metadata.creationTimestamp;
  delete candidate.metadata.annotations;
  delete candidate.status;
  candidate.spec.selector.matchLabels["app.kubernetes.io/name"] = name;
  candidate.spec.template.metadata.labels["app.kubernetes.io/name"] = name;
  return candidate;
}

function exactAdmissionRefusal(deployment, name, mutate, expectedMessage) {
  const candidate = sanitizedDeployment(deployment, name);
  mutate(candidate);
  const result = spawnSync(
    kubectl,
    ["--kubeconfig", kubeconfig, "create", "--dry-run=server", "-f", "-"],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      input: JSON.stringify(candidate),
      timeout: 30_000,
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  const outputText = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (
    result.status === 0 ||
    !outputText.includes("ValidatingAdmissionPolicy 'gradia-guard-boundary'") ||
    !outputText.includes(expectedMessage)
  ) {
    throw new Error(`kubernetes_live_proof_admission_refusal_missing:${name}`);
  }
  return true;
}

function networkPolicyDigests() {
  const rows = kubeJson(["-n", NAMESPACE, "get", "networkpolicies"]).items;
  const expected = [
    "agent-egress-only-to-guard-gateway",
    "default-deny-all",
    "gateway-ingress-only-from-agent",
    "gateway-standard-egress",
  ];
  const selected = rows.filter((row) => expected.includes(row.metadata.name));
  if (selected.length !== expected.length) throw new Error("kubernetes_live_proof_policy_missing");
  const byName = Object.fromEntries(selected.map((row) => [row.metadata.name, row]));
  if (
    Object.keys(byName["default-deny-all"].spec.podSelector).length !== 0 ||
    byName["agent-egress-only-to-guard-gateway"].spec.podSelector.matchLabels[
      "gradia.dev/boundary-role"
    ] !== "agent" ||
    byName["gateway-ingress-only-from-agent"].spec.podSelector.matchLabels[
      "gradia.dev/boundary-role"
    ] !== "gateway"
  ) {
    throw new Error("kubernetes_live_proof_policy_semantics_invalid");
  }
  return Object.fromEntries(
    expected.map((name) => [name, digestCanonical(byName[name].spec)]),
  );
}

function identityNetworkPolicyDigests() {
  const rows = kubeJson(["-n", NAMESPACE, "get", "networkpolicies"]).items;
  const expected = [
    "agent-egress-only-to-guard-gateway",
    "broker-egress-only-to-dns-and-kube-api",
    "broker-ingress-only-from-gateway",
    "default-deny-all",
    "gateway-egress-to-identity-broker",
    "gateway-ingress-only-from-agent",
    "gateway-standard-egress",
  ];
  const byName = Object.fromEntries(rows.map((row) => [row.metadata.name, row]));
  if (expected.some((name) => !byName[name])) {
    throw new Error("kubernetes_live_proof_identity_policy_missing");
  }
  return Object.fromEntries(expected.map((name) => [name, digestCanonical(byName[name].spec)]));
}

let clusterCreated = false;
try {
  const issuerKeys = generateKeyPairSync("ed25519");
  const issuerPrivateKey = issuerKeys.privateKey.export({ format: "pem", type: "pkcs8" });
  const issuerPublicKey = issuerKeys.publicKey.export({ format: "pem", type: "spki" });
  const caKeyPath = join(secretDirectory, "ca.key");
  const caCertificatePath = join(secretDirectory, "ca.crt");
  const tlsKeyPath = join(secretDirectory, "tls.key");
  const tlsCsrPath = join(secretDirectory, "tls.csr");
  const tlsCertificatePath = join(secretDirectory, "tls.crt");
  const tlsExtensionsPath = join(secretDirectory, "tls.ext");
  run("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    caKeyPath,
    "-out",
    caCertificatePath,
    "-days",
    "1",
    "-sha256",
    "-subj",
    "/CN=Gradia Guard local proof CA",
  ], { stdio: "ignore" });
  run("openssl", [
    "req",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    tlsKeyPath,
    "-out",
    tlsCsrPath,
    "-subj",
    `/CN=${BROKER_SERVICE}`,
  ], { stdio: "ignore" });
  writeFileSync(
    tlsExtensionsPath,
    `subjectAltName=DNS:${BROKER_SERVICE},DNS:${BROKER_SERVICE}.${NAMESPACE}.svc\nextendedKeyUsage=serverAuth\n`,
    { mode: 0o600 },
  );
  run("openssl", [
    "x509",
    "-req",
    "-in",
    tlsCsrPath,
    "-CA",
    caCertificatePath,
    "-CAkey",
    caKeyPath,
    "-CAcreateserial",
    "-out",
    tlsCertificatePath,
    "-days",
    "1",
    "-sha256",
    "-extfile",
    tlsExtensionsPath,
  ], { stdio: "ignore" });
  const brokerTlsKey = readFileSync(tlsKeyPath, "utf8");
  const brokerTlsCertificate = readFileSync(tlsCertificatePath, "utf8");
  const brokerCaCertificate = readFileSync(caCertificatePath, "utf8");
  const kindVersion = run(kind, ["version"]).trim();
  if (!kindVersion.startsWith(`kind ${KIND_VERSION} `)) {
    throw new Error(`kubernetes_live_proof_kind_version_invalid:${kindVersion}`);
  }
  docker([
    "build",
    "--target",
    "agent",
    "-t",
    "gradia-guard-k8s-agent:proof",
    "-f",
    "test/fixtures/kubernetes-enforcement/Dockerfile",
    "../..",
  ], { stdio: "ignore" });
  docker([
    "build",
    "--target",
    "gateway",
    "-t",
    "gradia-guard-k8s-gateway:proof",
    "-f",
    "test/fixtures/kubernetes-enforcement/Dockerfile",
    "../..",
  ], { stdio: "ignore" });
  docker([
    "build",
    "--target",
    "identity-broker",
    "-t",
    "gradia-guard-k8s-identity-broker:proof",
    "-f",
    "test/fixtures/kubernetes-enforcement/Dockerfile",
    "../..",
  ], { stdio: "ignore" });
  const agentImage = imageReference("gradia-guard-k8s-agent:proof");
  const gatewayImage = imageReference("gradia-guard-k8s-gateway:proof");
  const brokerImage = imageReference("gradia-guard-k8s-identity-broker:proof");
  run(kind, [
    "create",
    "cluster",
    "--name",
    clusterName,
    "--image",
    NODE_IMAGE,
    "--kubeconfig",
    kubeconfig,
    "--wait",
    "120s",
  ], { stdio: "ignore", timeout: 180_000 });
  clusterCreated = true;
  run(kind, [
    "load",
    "docker-image",
    "gradia-guard-k8s-agent:proof",
    "gradia-guard-k8s-gateway:proof",
    "gradia-guard-k8s-identity-broker:proof",
    "--name",
    clusterName,
  ], { stdio: "ignore" });
  const nodeContainer = `${clusterName}-control-plane`;
  for (const [tag, reference] of [
    ["docker.io/library/gradia-guard-k8s-agent:proof", agentImage],
    ["docker.io/library/gradia-guard-k8s-gateway:proof", gatewayImage],
    ["docker.io/library/gradia-guard-k8s-identity-broker:proof", brokerImage],
  ]) {
    const fullyQualifiedDigestReference = `docker.io/library/${reference}`;
    docker(
      [
        "exec",
        nodeContainer,
        "ctr",
        "-n",
        "k8s.io",
        "images",
        "tag",
        tag,
        fullyQualifiedDigestReference,
      ],
      { stdio: "ignore" },
    );
  }

  apply("kubernetes/base/namespace.yaml");
  apply("kubernetes/base/serviceaccounts.yaml", NAMESPACE);
  apply("kubernetes/base/identity-broker-rbac.yaml");
  apply("kubernetes/base/network-policies.yaml", NAMESPACE);
  apply("kubernetes/base/validating-admission-policy.yaml");
  const kubernetesService = kubeJson(["-n", "default", "get", "service", "kubernetes"]);
  if (kubernetesService.spec.clusterIP !== "10.96.0.1") {
    throw new Error("kubernetes_live_proof_api_service_ip_changed");
  }
  const kubernetesEndpointSlices = kubeJson([
    "-n",
    "default",
    "get",
    "endpointslices",
    "-l",
    "kubernetes.io/service-name=kubernetes",
  ]);
  const apiEndpointIp = kubernetesEndpointSlices.items?.[0]?.endpoints?.[0]?.addresses?.[0];
  const apiEndpointPort = kubernetesEndpointSlices.items?.[0]?.ports?.[0]?.port;
  if (
    typeof apiEndpointIp !== "string" ||
    !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(apiEndpointIp) ||
    apiEndpointPort !== 6443
  ) {
    throw new Error("kubernetes_live_proof_api_endpoint_invalid");
  }
  kube([
    "-n",
    NAMESPACE,
    "patch",
    "networkpolicy",
    "broker-egress-only-to-dns-and-kube-api",
    "--type=json",
    "-p",
    JSON.stringify([
      {
        op: "replace",
        path: "/spec/egress/1/to/0/ipBlock/cidr",
        value: `${apiEndpointIp}/32`,
      },
      {
        op: "replace",
        path: "/spec/egress/1/ports/0/port",
        value: apiEndpointPort,
      },
    ]),
  ], { stdio: "ignore" });
  createProofResources(
    agentImage,
    gatewayImage,
    brokerImage,
    issuerPrivateKey,
    issuerPublicKey,
    brokerTlsKey,
    brokerTlsCertificate,
    brokerCaCertificate,
  );
  try {
    kube(["-n", NAMESPACE, "rollout", "status", `deployment/${BROKER_DEPLOYMENT}`, "--timeout=90s"], {
      stdio: "ignore",
    });
    kube(["-n", NAMESPACE, "rollout", "status", `deployment/${AGENT_DEPLOYMENT}`, "--timeout=90s"], {
      stdio: "ignore",
    });
    kube(["-n", NAMESPACE, "rollout", "status", `deployment/${GATEWAY_DEPLOYMENT}`, "--timeout=90s"], {
      stdio: "ignore",
    });
  } catch (error) {
    const diagnostics = [
      kube(["-n", NAMESPACE, "get", "pods", "-o", "wide"]),
      kube(["-n", NAMESPACE, "get", "events", "--sort-by=.lastTimestamp"]),
      kube(["-n", NAMESPACE, "logs", `deployment/${BROKER_DEPLOYMENT}`, "--tail=100"]),
      kube(["-n", NAMESPACE, "exec", `deployment/${BROKER_DEPLOYMENT}`, "--", "cat", "/tmp/broker-status.json"]),
      kube(["-n", NAMESPACE, "logs", "-l", "gradia.dev/boundary-role=gateway", "--previous", "--tail=100"]),
    ].join("\n");
    process.stderr.write(`kubernetes_live_proof_rollout_diagnostics\n${diagnostics}\n`);
    throw error;
  }

  const brokerPod = podForRole("identity-broker");
  const gatewayPod = podForRole("gateway");
  const beforeAgentPod = podForRole("agent");
  waitForNetworkBoundary(beforeAgentPod);
  agentProbe(beforeAgentPod, probeCommands.agent_direct_broker);
  gatewayReplayProbe(gatewayPod);
  const beforeUid = beforeAgentPod.metadata.uid;
  kube(["-n", NAMESPACE, "delete", "pod", beforeAgentPod.metadata.name, "--wait=false"], {
    stdio: "ignore",
  });
  const agentPod = podForRole("agent", beforeUid);
  waitForNetworkBoundary(agentPod);
  agentProbe(agentPod, probeCommands.link_local_raw_ip);
  agentProbe(agentPod, probeCommands.root_write);
  agentProbe(agentPod, probeCommands.tmp_round_trip);
  agentProbe(agentPod, probeCommands.api_token_absence);
  agentProbe(agentPod, probeCommands.spawned_subprocess_raw_ip);
  agentProbe(agentPod, probeCommands.agent_direct_broker);

  const probeText = kube([
    "-n",
    NAMESPACE,
    "exec",
    agentPod.metadata.name,
    "--",
    "sh",
    "-c",
    'OPENAI_API_KEY="$GRADIA_GUARD_LOCAL_CAPABILITY" OPENAI_BASE_URL="$GRADIA_GUARD_LOCAL_ORIGIN/openai/v1" node /opt/guard/vercel-provider-probe.mjs openai',
  ]);
  const probeOutput = JSON.parse(probeText);
  const status = waitForFinalizedGateway(gatewayPod);
  const brokerState = brokerStatus(brokerPod);
  if (
    brokerState.accepted_exchanges !== 1 ||
    brokerState.replay_rejections !== 1 ||
    !status.kubernetes_identity_exchange ||
    brokerState.last_exchange?.workload_identity_sha256 !== status.workload_identity_sha256
  ) {
    throw new Error("kubernetes_live_proof_identity_exchange_status_invalid");
  }

  mkdirSync(gatewayDirectory, { mode: 0o700 });
  const bundleText = kube([
    "-n",
    NAMESPACE,
    "exec",
    gatewayPod.metadata.name,
    "--",
    "cat",
    "/tmp/model-gateway/bundle.json",
  ]);
  const framesText = kube([
    "-n",
    NAMESPACE,
    "exec",
    gatewayPod.metadata.name,
    "--",
    "cat",
    "/tmp/model-gateway/frames.ndjson",
  ]);
  writeFileSync(join(gatewayDirectory, "bundle.json"), bundleText, { mode: 0o600, flag: "wx" });
  writeFileSync(join(gatewayDirectory, "frames.ndjson"), framesText, { mode: 0o600, flag: "wx" });

  const agentDeployment = kubeJson(["-n", NAMESPACE, "get", "deployment", AGENT_DEPLOYMENT]);
  const gatewayDeployment = kubeJson(["-n", NAMESPACE, "get", "deployment", GATEWAY_DEPLOYMENT]);
  const brokerDeployment = kubeJson(["-n", NAMESPACE, "get", "deployment", BROKER_DEPLOYMENT]);
  const policy = kubeJson(["get", "validatingadmissionpolicy", "gradia-guard-boundary"]);
  const binding = kubeJson(["get", "validatingadmissionpolicybinding", "gradia-guard-boundary"]);
  exactAdmissionRefusal(
    agentDeployment,
    "gradia-guard-admission-unpinned",
    (candidate) => {
      candidate.spec.template.spec.containers[0].image = "node:22-alpine";
    },
    "Every Guard boundary image must use an exact SHA-256 digest pin.",
  );
  exactAdmissionRefusal(
    agentDeployment,
    "gradia-guard-admission-writable",
    (candidate) => {
      candidate.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem = false;
    },
    "Guard boundary Pods must remain non-root/seccomp-confined",
  );
  exactAdmissionRefusal(
    agentDeployment,
    "gradia-guard-admission-credential",
    (candidate) => {
      candidate.spec.template.spec.containers[0].env.push({
        name: "OPENAI_API_KEY",
        value: "not-a-live-secret",
      });
    },
    "Agent and identity-broker Pods may not receive provider credentials.",
  );
  exactAdmissionRefusal(
    brokerDeployment,
    "gradia-guard-admission-broker-credential",
    (candidate) => {
      candidate.spec.template.spec.containers[0].env.push({
        name: "OPENAI_API_KEY",
        value: "not-a-live-secret",
      });
    },
    "Agent and identity-broker Pods may not receive provider credentials.",
  );
  exactAdmissionRefusal(
    agentDeployment,
    "gradia-guard-admission-signing-key",
    (candidate) => {
      candidate.spec.template.spec.volumes.push({
        name: "issuer-key",
        secret: { secretName: "gradia-guard-identity-issuer" },
      });
    },
    "Only the identity-broker Pod may mount the Guard identity issuer key.",
  );
  exactAdmissionRefusal(
    gatewayDeployment,
    "gradia-guard-admission-service-account",
    (candidate) => {
      candidate.spec.template.spec.serviceAccountName = "gradia-guard-identity-broker";
    },
    "Every Guard boundary role must use its exact dedicated ServiceAccount.",
  );

  const version = kubeJson(["version"]);
  const nodes = kubeJson(["get", "nodes"]).items;
  const namespace = kubeJson(["get", "namespace", NAMESPACE]);
  const kindnet = kubeJson(["-n", "kube-system", "get", "pods", "-l", "k8s-app=kindnet"])
    .items.find((pod) => pod.status.containerStatuses?.[0]?.ready === true);
  if (!kindnet) throw new Error("kubernetes_live_proof_network_policy_engine_not_ready");
  const catalog = frameworkSdkCompatibilityCatalog();
  const entry = catalog.entries.find(
    (candidate) => candidate.framework === FRAMEWORK && candidate.provider === PROVIDER,
  );
  if (!entry) throw new Error("kubernetes_live_proof_framework_entry_missing");
  const projected = status.kubernetes_projected_identity;
  const body = {
    schema_version: "gradia.guard.kubernetes-enforcement-receipt.v1",
    runtime_id: RUNTIME_ID,
    observed_at: new Date().toISOString(),
    orchestrator: "kubernetes",
    collector_authority: "kubectl_admin_inspection_server_dry_run_and_in_pod_probes",
    claim_boundary:
      "one_ephemeral_cluster_one_exact_framework_provider_cell_not_exhaustive_non_bypassability",
    cluster: {
      cluster_provisioner: `kind/${KIND_VERSION}`,
      kind_node_image_sha256: NODE_IMAGE_SHA256,
      kubernetes_git_version: version.serverVersion.gitVersion,
      server_platform: version.serverVersion.platform,
      node_count: nodes.length,
      node_uid_sha256s: nodes.map((node) => sha256(Buffer.from(node.metadata.uid))).sort(),
      container_runtime_versions: nodes.map((node) => node.status.nodeInfo.containerRuntimeVersion).sort(),
      namespace_uid_sha256: sha256(Buffer.from(namespace.metadata.uid)),
      namespace_pod_security_enforce: namespace.metadata.labels["pod-security.kubernetes.io/enforce"],
      network_policy_engine_image_id_sha256: sha256(
        Buffer.from(kindnet.status.containerStatuses[0].imageID),
      ),
      network_policy_engine_ready: true,
    },
    agent: workloadPosture(agentDeployment, agentPod),
    gateway: workloadPosture(gatewayDeployment, gatewayPod),
    separate_agent_and_gateway_pods: true,
    restart: {
      before_pod_uid_sha256: sha256(Buffer.from(beforeUid)),
      after_pod_uid_sha256: sha256(Buffer.from(agentPod.metadata.uid)),
      replacement_observed: true,
    },
    projected_identity: projected,
    admission: {
      policy_uid_sha256: sha256(Buffer.from(policy.metadata.uid)),
      binding_uid_sha256: sha256(Buffer.from(binding.metadata.uid)),
      failure_policy: policy.spec.failurePolicy,
      validation_actions: [...binding.spec.validationActions].sort(),
      type_check_warnings: policy.status?.typeChecking?.expressionWarnings?.length ?? 0,
      unpinned_image_rejected_by_exact_policy: true,
      writable_root_rejected_by_exact_policy: true,
      agent_provider_credential_rejected_by_exact_policy: true,
    },
    network: {
      network_policy_sha256s: networkPolicyDigests(),
      pre_restart_direct_raw_ip_egress: "blocked",
      pre_restart_gateway_reachability: "allowed",
      post_restart_direct_raw_ip_egress: "blocked",
      post_restart_gateway_reachability: "allowed",
      link_local_metadata_raw_ip: "blocked",
      root_filesystem_write: "blocked",
      writable_tmp_round_trip: "allowed",
      spawned_subprocess_raw_ip_egress: "blocked",
      automatic_api_token_present_in_agent: false,
      probe_command_sha256s: Object.fromEntries(
        [
          "api_token_absence",
          "direct_raw_ip",
          "gateway_health",
          "link_local_raw_ip",
          "root_write",
          "spawned_subprocess_raw_ip",
          "tmp_round_trip",
        ].map((name) => [name, digestCanonical(probeCommands[name])]),
      ),
    },
    sdk_route: {
      framework_catalog_sha256: catalog.catalog_sha256,
      framework_entry_sha256: digestCanonical(entry),
      probe_environment_names: [
        "GRADIA_GUARD_LOCAL_CAPABILITY",
        "GRADIA_GUARD_LOCAL_ORIGIN",
        "GRADIA_GUARD_RUNTIME_ID",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
      ],
      probe_command_sha256: digestCanonical([
        "node",
        "/opt/guard/vercel-provider-probe.mjs",
        "openai",
      ]),
      probe_output: probeOutput,
      probe_output_sha256: digestCanonical(probeOutput),
    },
    gateway_evidence: {
      session_id: status.gateway_verification.session_id,
      frame_count: status.gateway_verification.frame_count,
      chain_head_sha256: status.gateway_verification.chain_head_sha256,
      bundle_sha256: digestCanonical(JSON.parse(bundleText)),
      policy_sha256: status.policy_sha256,
      configuration_sha256: status.configuration_sha256,
      guard_workload_identity_sha256: status.workload_identity_sha256,
      local_capability_sha256: status.local_capability_sha256,
      accepted_local_requests: status.accepted_local_requests,
      native_provider_requests: status.native_provider_requests,
      unauthorized_local_requests: status.unauthorized_local_requests,
      malformed_local_requests: status.malformed_local_requests,
    },
    coverage: {
      observed_standard_network_policy_enforcement: true,
      agent_restart_preserved_observed_policy: true,
      provider_credentials_withheld_from_agent_configuration: true,
      projected_service_account_identity_observed: true,
      guard_dispatch_policy_observed_before_mocked_transport: true,
      exact_framework_provider_route_observed: true,
      live_provider_behavior_proved: false,
      kubernetes_identity_federation_exchange_proved: false,
      network_policy_failure_mode_fail_closed_proved: false,
      cluster_admin_or_node_operator_bypass_possible: true,
      exhaustive_bypass_resistance_proved: false,
      process_capture_complete: false,
      file_read_capture_complete: false,
      side_effect_capture_complete: false,
      full_host_enforcement: false,
      full_world_state_capture: false,
    },
  };
  const receipt = createKubernetesEnforcementReceipt(body, gatewayDirectory);
  writeFileSync(receiptPath, `${JSON.stringify(receipt)}\n`, { mode: 0o600, flag: "wx" });
  const verification = verifyKubernetesEnforcementReceipt(receipt, gatewayDirectory);
  const clusterRole = kubeJson(["get", "clusterrole", "gradia-guard-token-reviewer"]);
  const clusterRoleBinding = kubeJson([
    "get",
    "clusterrolebinding",
    "gradia-guard-token-reviewer",
  ]);
  const brokerContainer = brokerDeployment.spec.template.spec.containers[0];
  const brokerContainerStatus = brokerPod.status.containerStatuses[0];
  const exchangeBody = {
    schema_version: "gradia.guard.kubernetes-identity-exchange-receipt.v1",
    runtime_id: RUNTIME_ID,
    observed_at: new Date().toISOString(),
    parent_kubernetes_enforcement_receipt_sha256: receipt.receipt_sha256,
    collector_authority: "broker_response_kubectl_admin_inspection_and_in_pod_probes",
    claim_boundary:
      "one_local_kind_cluster_one_tokenreview_exchange_not_managed_federation_or_operator_resistance",
    token_review: status.kubernetes_identity_exchange.token_review,
    broker: {
      service_account_name: "gradia-guard-identity-broker",
      reviewer_subject:
        "system:serviceaccount:gradia-guard:gradia-guard-identity-broker",
      reviewer_audience: "https://kubernetes.default.svc.cluster.local",
      token_review_permission: "create.authentication.k8s.io/tokenreviews",
      issuer_key_id: "kubernetes-tokenreview-issuer-v1",
      issuer_public_key_spki_sha256: sha256(
        issuerKeys.publicKey.export({ format: "der", type: "spki" }),
      ),
      exchange_tls_ca_sha256: sha256(Buffer.from(brokerCaCertificate)),
      broker_deployment_uid_sha256: sha256(Buffer.from(brokerDeployment.metadata.uid)),
      broker_pod_uid_sha256: sha256(Buffer.from(brokerPod.metadata.uid)),
      broker_configured_image_sha256: digestFromImageReference(brokerContainer.image),
      broker_running_image_id_sha256: digestFromRunningImage(brokerContainerStatus.imageID),
      cluster_role_rules_sha256: digestCanonical(clusterRole.rules),
      cluster_role_binding_subjects_sha256: digestCanonical(clusterRoleBinding.subjects),
      accepted_exchanges: brokerState.accepted_exchanges,
      replay_rejections: brokerState.replay_rejections,
      replay_guard: "single_use_token_sha256_in_memory",
      private_signing_key_mount: "identity_broker_only",
      trusted_public_key_mount: "gateway_only",
    },
    guard_workload_identity: status.kubernetes_identity_exchange.guard_workload_identity,
    network: {
      agent_direct_broker_egress: "blocked",
      gateway_broker_tls_reachability: "allowed_with_pinned_ca",
      broker_kubernetes_api_reachability: "allowed",
      gateway_token_replay: "rejected",
      network_policy_sha256s: identityNetworkPolicyDigests(),
      probe_command_sha256s: Object.fromEntries(
        Object.entries(identityProbeCommands).map(([name, command]) => [
          name,
          digestCanonical(command),
        ]),
      ),
    },
    coverage: {
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
    },
  };
  const exchangeReceipt = createKubernetesIdentityExchangeReceipt(exchangeBody, {
    parentReceipt: receipt,
    gatewayEvidenceDirectory: gatewayDirectory,
    trustedIssuerPublicKey: issuerPublicKey,
    trustedBrokerTlsCa: brokerCaCertificate,
  });
  writeFileSync(exchangeReceiptPath, `${JSON.stringify(exchangeReceipt)}\n`, {
    mode: 0o600,
    flag: "wx",
  });
  writeFileSync(issuerPublicKeyPath, issuerPublicKey, { mode: 0o644, flag: "wx" });
  writeFileSync(brokerCaPath, brokerCaCertificate, { mode: 0o644, flag: "wx" });
  const exchangeVerification = verifyKubernetesIdentityExchangeReceipt(exchangeReceipt, {
    parentReceipt: receipt,
    gatewayEvidenceDirectory: gatewayDirectory,
    trustedIssuerPublicKey: issuerPublicKey,
    trustedBrokerTlsCa: brokerCaCertificate,
  });
  process.stdout.write(`${JSON.stringify({
    ok: true,
    output_directory: output,
    receipt_sha256: verification.receipt_sha256,
    gateway_chain_head_sha256: verification.gateway_evidence.chain_head_sha256,
    agent_restart_observed: verification.restart.replacement_observed,
    identity_exchange_receipt_sha256: exchangeVerification.receipt_sha256,
    tokenreview_authenticated: exchangeVerification.token_review.authenticated,
    replay_rejections: exchangeVerification.broker.replay_rejections,
    admission_refusals: 6,
    live_provider_behavior_proved: verification.coverage.live_provider_behavior_proved,
  })}\n`);
} finally {
  if (clusterCreated) {
    run(kind, ["delete", "cluster", "--name", clusterName], { stdio: "ignore", timeout: 120_000 });
  }
  rmSync(secretDirectory, { recursive: true, force: true });
}
