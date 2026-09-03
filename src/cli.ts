#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  analyzeSdkActorGraph,
  canonicalSdkActorGraph,
  formatSdkActorGraph,
} from "./actor-graph.js";
import {
  canonicalGuardCapabilityCatalog,
  formatGuardCapabilityCatalog,
  guardCapabilityCatalog,
} from "./capabilities.js";
import { canonicalJson, isSha256 } from "./canonical.js";
import { formatGuardDoctorReport, guardDoctor } from "./doctor.js";
import {
  collectDockerContainerBypassBattery,
  verifyContainerBypassBatteryReceipt,
} from "./container-bypass-battery.js";
import { collectDockerContainerEnforcement } from "./container-enforcement.js";
import {
  collectDockerContainerSdkRoute,
  verifyContainerSdkRouteReceipt,
} from "./container-sdk-route.js";
import { canonicalComparison, compareBundles, formatComparison } from "./compare.js";
import {
  formatFrameworkSdkCompatibilityCatalog,
  frameworkSdkCompatibilityCatalog,
} from "./framework-sdk-compatibility.js";
import { canonicalInspection, formatInspection, inspectBundle } from "./inspect.js";
import { verifyGuardRemoteAnchor } from "./remote-anchor.js";
import { verifyKubernetesEnforcementReceipt } from "./kubernetes-enforcement.js";
import { verifyKubernetesIdentityExchangeReceipt } from "./kubernetes-identity-exchange.js";
import {
  McpHttpAccessRecorder,
  verifyMcpHttpAccessBundleDirectory,
} from "./mcp-http-evidence.js";
import { verifyMcpStdioAccessBundleDirectory } from "./mcp-stdio-evidence.js";
import { recoverInterruptedMcpStdioAccess } from "./mcp-stdio-proxy.js";
import {
  composeRuntimeEvidence,
  verifyRuntimeCompositionReceipt,
} from "./runtime-composition.js";
import { verifyRuntimeEvidenceBundle } from "./runtime-evidence.js";
import {
  assessEvidenceReadiness,
  canonicalEvidenceReadiness,
  formatEvidenceReadiness,
  loadEvidenceProfile,
  sealEvidenceProfile,
  starterEvidenceProfileBody,
} from "./evidence-readiness.js";
import {
  formatProviderSdkCompatibilityCatalog,
  providerSdkCompatibilityCatalog,
} from "./provider-sdk-compatibility.js";
import {
  canonicalProofPackVerification,
  verifyProofPackDirectory,
} from "./proof-pack.js";
import { runGuardedProcess } from "./run.js";
import {
  evaluateModelPolicy,
  evaluateToolPolicy,
  loadPolicy,
  sealPolicy,
  starterPolicyBody,
} from "./policy.js";
import { decodeKeyFromEnvironment } from "./spool.js";
import {
  tokenFromEnvironment,
  uploadEvidenceBundle,
  uploadRuntimeEvidenceBundle,
  type GuardRights,
} from "./upload.js";
import { verifyUniverseAnchor } from "./universe-anchor.js";
import { canonicalVerificationResult, verifyBundle } from "./verify.js";
import type { CaptureMode, GatewayProvider } from "./types.js";

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (!command || command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(help());
    return command ? 0 : 2;
  }
  if (command === "run") return await runCommand(rest);
  if (command === "verify") return verifyCommand(rest);
  if (command === "inspect") return inspectCommand(rest);
  if (command === "capabilities") return capabilitiesCommand(rest);
  if (command === "doctor") return doctorCommand(rest);
  if (command === "anchor") return anchorCommand(rest);
  if (command === "actors") return actorsCommand(rest);
  if (command === "compare") return compareCommand(rest);
  if (command === "policy") return policyCommand(rest);
  if (command === "readiness") return readinessCommand(rest);
  if (command === "proof-pack") return proofPackCommand(rest);
  if (command === "sdk-matrix") return sdkMatrixCommand(rest);
  if (command === "framework-matrix") return frameworkMatrixCommand(rest);
  if (command === "mcp-http") return mcpHttpCommand(rest);
  if (command === "mcp-stdio") return mcpStdioCommand(rest);
  if (command === "runtime") return await runtimeCommand(rest);
  if (command === "upload") return await uploadCommand(rest);
  process.stderr.write(`unknown command: ${command}\n\n${help()}`);
  return 2;
}

function mcpHttpCommand(argv: string[]): number {
  const [subcommand, directory, ...rest] = argv;
  if (
    (subcommand !== "verify" && subcommand !== "recover")
    || !directory
    || directory.startsWith("-")
    || rest.length > 0
  ) {
    throw new Error(`mcp_http_subcommand_invalid:${subcommand ?? "missing"}`);
  }
  const resolved = resolve(directory);
  if (subcommand === "verify") {
    const verification = verifyMcpHttpAccessBundleDirectory(resolved);
    process.stdout.write(`${canonicalJson(verification)}\n`);
    return verification.ok ? 0 : 1;
  }
  const recorder = McpHttpAccessRecorder.recover(
    resolved,
    () => new Date().toISOString(),
  );
  const bundle = recorder.finalize();
  const verification = verifyMcpHttpAccessBundleDirectory(resolved);
  if (!verification.ok) {
    throw new Error(`mcp_http_recovered_bundle_unverified:${verification.blockers.join(",")}`);
  }
  process.stdout.write(`${canonicalJson({
    bundle_path: recorder.bundlePath,
    chain_head_sha256: bundle.finalization.chain_head_sha256,
    ok: true,
    receipt_count: bundle.finalization.receipt_count,
    recovery_performed: true,
    session_id: bundle.finalization.session_id,
    terminal_status: "recovered_interruption",
  })}\n`);
  return 0;
}

function mcpStdioCommand(argv: string[]): number {
  const [subcommand, directory, ...rest] = argv;
  if (
    (subcommand !== "verify" && subcommand !== "recover")
    || !directory
    || directory.startsWith("-")
    || rest.length > 0
  ) {
    throw new Error(`mcp_stdio_subcommand_invalid:${subcommand ?? "missing"}`);
  }
  const resolved = resolve(directory);
  if (subcommand === "verify") {
    const verification = verifyMcpStdioAccessBundleDirectory(resolved);
    process.stdout.write(`${canonicalJson(verification)}\n`);
    return verification.ok ? 0 : 1;
  }
  const bundle = recoverInterruptedMcpStdioAccess(
    resolved,
    () => new Date().toISOString(),
  );
  const verification = verifyMcpStdioAccessBundleDirectory(resolved);
  if (!verification.ok) {
    throw new Error(`mcp_stdio_recovered_bundle_unverified:${verification.blockers.join(",")}`);
  }
  process.stdout.write(`${canonicalJson({
    bundle_path: resolve(resolved, "bundle.json"),
    chain_head_sha256: bundle.finalization.chain_head_sha256,
    ok: true,
    receipt_count: bundle.finalization.receipt_count,
    recovery_performed: true,
    session_id: bundle.finalization.session_id,
    terminal_status: "recovered_interruption",
  })}\n`);
  return 0;
}

function doctorCommand(argv: string[]): number {
  if (argv.length > 1 || (argv.length === 1 && argv[0] !== "--json")) {
    throw new Error("doctor_option_invalid");
  }
  const report = guardDoctor();
  process.stdout.write(
    argv[0] === "--json" ? `${canonicalJson(report)}\n` : formatGuardDoctorReport(report),
  );
  return report.node_supported ? 0 : 1;
}

function sdkMatrixCommand(argv: string[]): number {
  if (argv.length > 1 || (argv.length === 1 && argv[0] !== "--json")) {
    throw new Error("sdk_matrix_option_invalid");
  }
  const catalog = providerSdkCompatibilityCatalog();
  process.stdout.write(
    argv[0] === "--json" ? `${canonicalJson(catalog)}\n` : formatProviderSdkCompatibilityCatalog(catalog),
  );
  return 0;
}

function frameworkMatrixCommand(argv: string[]): number {
  if (argv.length > 1 || (argv.length === 1 && argv[0] !== "--json")) {
    throw new Error("framework_matrix_option_invalid");
  }
  const catalog = frameworkSdkCompatibilityCatalog();
  process.stdout.write(
    argv[0] === "--json"
      ? `${canonicalJson(catalog)}\n`
      : formatFrameworkSdkCompatibilityCatalog(catalog),
  );
  return 0;
}

async function runtimeCommand(argv: string[]): Promise<number> {
  const [subcommand, ...rest] = argv;
  if (subcommand === "verify") return runtimeVerifyCommand(rest);
  if (subcommand === "upload") return await runtimeUploadCommand(rest);
  if (subcommand === "compose") return runtimeComposeCommand(rest);
  if (subcommand === "verify-composition") return runtimeVerifyCompositionCommand(rest);
  if (subcommand === "probe-docker-bypass") return runtimeProbeDockerBypassCommand(rest);
  if (subcommand === "verify-docker-bypass") return runtimeVerifyDockerBypassCommand(rest);
  if (subcommand === "probe-docker-sdk") return runtimeProbeDockerSdkCommand(rest);
  if (subcommand === "verify-docker-sdk") return runtimeVerifyDockerSdkCommand(rest);
  if (subcommand === "verify-kubernetes") return runtimeVerifyKubernetesCommand(rest);
  if (subcommand === "verify-kubernetes-identity") {
    return runtimeVerifyKubernetesIdentityCommand(rest);
  }
  if (subcommand !== "collect-docker") throw new Error(`runtime_subcommand_invalid:${subcommand ?? "missing"}`);
  const values: Record<string, string> = {};
  const allowed = new Set([
    "--agent",
    "--configuration-sha256",
    "--direct-url",
    "--gateway",
    "--gateway-url",
    "--internal-network",
    "--out",
    "--policy-sha256",
    "--probe-runtime",
    "--runtime-id",
    "--workload-identity-sha256",
  ]);
  for (let index = 0; index < rest.length; index += 2) {
    const option = rest[index];
    const value = rest[index + 1];
    if (!option || !value || !allowed.has(option)) {
      throw new Error(`runtime_collect_docker_option_invalid:${option ?? "missing"}`);
    }
    if (values[option]) throw new Error(`runtime_collect_docker_option_duplicate:${option}`);
    values[option] = value;
  }
  const required = (name: string): string => {
    const value = values[name];
    if (!value) throw new Error(`runtime_collect_docker_option_required:${name}`);
    return value;
  };
  const directUrl = exactProbeUrl(required("--direct-url"), "https:", "direct");
  const gatewayUrl = exactProbeUrl(required("--gateway-url"), "http:", "gateway");
  const probeRuntime = values["--probe-runtime"] ?? "node";
  if (probeRuntime !== "node" && probeRuntime !== "python") {
    throw new Error("runtime_collect_docker_probe_runtime_invalid");
  }
  const probes = dockerNetworkProbeCommands(probeRuntime, directUrl, gatewayUrl);
  const receipt = collectDockerContainerEnforcement({
    runtimeId: required("--runtime-id"),
    agentContainer: required("--agent"),
    gatewayContainer: required("--gateway"),
    internalNetwork: required("--internal-network"),
    policySha256: required("--policy-sha256"),
    configurationSha256: required("--configuration-sha256"),
    workloadIdentitySha256: required("--workload-identity-sha256"),
    directEgressProbeCommand: probes.direct,
    gatewayProbeCommand: probes.gateway,
  });
  const output = resolve(required("--out"));
  if (existsSync(output)) throw new Error("runtime_collect_docker_refuses_overwrite");
  writeFileSync(output, `${canonicalJson(receipt)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(
    `${JSON.stringify({ path: output, receipt_sha256: receipt.receipt_sha256, coverage: receipt.coverage })}\n`,
  );
  return 0;
}

function dockerNetworkProbeCommands(
  runtime: "node" | "python",
  directUrl: string,
  gatewayUrl: string,
): { direct: readonly string[]; gateway: readonly string[] } {
  if (runtime === "node") {
    return {
      direct: [
        "node",
        "-e",
        "const n=require('node:net');const u=new URL(process.argv[1]);const s=n.connect(Number(u.port||443),u.hostname);s.setTimeout(4000);s.once('connect',()=>process.exit(42));s.once('error',()=>process.exit(0));s.once('timeout',()=>process.exit(0));",
        directUrl,
      ],
      gateway: [
        "node",
        "-e",
        "const c=new AbortController();setTimeout(()=>c.abort(),4000);fetch(process.argv[1],{signal:c.signal}).then(r=>process.exit(r.ok?0:41)).catch(()=>process.exit(40));",
        gatewayUrl,
      ],
    };
  }
  return {
    direct: [
      "python",
      "-c",
      "import socket,sys,urllib.parse\nu=urllib.parse.urlparse(sys.argv[1])\ntry: socket.create_connection((u.hostname,u.port or 443),4); raise SystemExit(42)\nexcept SystemExit: raise\nexcept Exception: raise SystemExit(0)",
      directUrl,
    ],
    gateway: [
      "python",
      "-c",
      "import sys,urllib.request\ntry: r=urllib.request.urlopen(sys.argv[1],timeout=4); raise SystemExit(0 if 200<=r.status<300 else 41)\nexcept SystemExit: raise\nexcept Exception: raise SystemExit(40)",
      gatewayUrl,
    ],
  };
}

function runtimeProbeDockerBypassCommand(argv: string[]): number {
  const values = exactValueOptions(
    argv,
    new Set(["--agent", "--container-receipt", "--out"]),
    "runtime_probe_docker_bypass",
  );
  const receipt = collectDockerContainerBypassBattery({
    agentContainer: required(values, "--agent"),
    containerEnforcementReceipt: loadRuntimeJsonArtifact(
      required(values, "--container-receipt"),
    ),
  });
  const output = resolve(required(values, "--out"));
  if (existsSync(output)) throw new Error("runtime_probe_docker_bypass_refuses_overwrite");
  writeFileSync(output, `${canonicalJson(receipt)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(
    `${canonicalJson({
      path: output,
      receipt_sha256: receipt.receipt_sha256,
      probes: receipt.probes,
      coverage: receipt.coverage,
      claim_boundary: receipt.claim_boundary,
    })}\n`,
  );
  return 0;
}

function runtimeVerifyDockerBypassCommand(argv: string[]): number {
  const values = exactValueOptions(
    argv,
    new Set(["--receipt", "--container-receipt"]),
    "runtime_verify_docker_bypass",
  );
  const receipt = verifyContainerBypassBatteryReceipt(
    loadRuntimeJsonArtifact(required(values, "--receipt")),
    loadRuntimeJsonArtifact(required(values, "--container-receipt")),
  );
  process.stdout.write(
    `${canonicalJson({
      ok: true,
      runtime_id: receipt.runtime_id,
      receipt_sha256: receipt.receipt_sha256,
      probes: receipt.probes,
      coverage: receipt.coverage,
      claim_boundary: receipt.claim_boundary,
    })}\n`,
  );
  return 0;
}

function runtimeProbeDockerSdkCommand(argv: string[]): number {
  const values = exactValueOptions(
    argv,
    new Set([
      "--agent",
      "--capability-env",
      "--container-receipt",
      "--framework",
      "--gateway",
      "--gateway-evidence-out",
      "--local-origin",
      "--out",
      "--provider",
    ]),
    "runtime_probe_docker_sdk",
  );
  const capabilityEnvironment = required(values, "--capability-env");
  if (!/^[A-Z][A-Z0-9_]{0,127}$/.test(capabilityEnvironment)) {
    throw new Error("runtime_probe_docker_sdk_capability_env_invalid");
  }
  const localCapability = process.env[capabilityEnvironment];
  if (!localCapability) throw new Error("runtime_probe_docker_sdk_capability_missing");
  const framework = required(values, "--framework");
  if (framework !== "vercel_ai_sdk" && framework !== "langchain") {
    throw new Error("runtime_probe_docker_sdk_framework_invalid");
  }
  const provider = required(values, "--provider");
  if (provider !== "anthropic" && provider !== "gemini" && provider !== "openai" && provider !== "xai") {
    throw new Error("runtime_probe_docker_sdk_provider_invalid");
  }
  const receipt = collectDockerContainerSdkRoute({
    framework,
    provider,
    agentContainer: required(values, "--agent"),
    gatewayContainer: required(values, "--gateway"),
    containerEnforcementReceipt: loadRuntimeJsonArtifact(
      required(values, "--container-receipt"),
    ),
    gatewayEvidenceOutputDirectory: resolve(required(values, "--gateway-evidence-out")),
    localCapability,
    localOrigin: required(values, "--local-origin"),
  });
  const output = resolve(required(values, "--out"));
  if (existsSync(output)) throw new Error("runtime_probe_docker_sdk_refuses_overwrite");
  writeFileSync(output, `${canonicalJson(receipt)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(
    `${canonicalJson({
      path: output,
      receipt_sha256: receipt.receipt_sha256,
      gateway_chain_head_sha256: receipt.gateway_chain_head_sha256,
      probe_output: receipt.probe_output,
      coverage: receipt.coverage,
      claim_boundary: receipt.claim_boundary,
    })}\n`,
  );
  return 0;
}

function runtimeVerifyDockerSdkCommand(argv: string[]): number {
  const values = exactValueOptions(
    argv,
    new Set(["--container-receipt", "--gateway-evidence", "--receipt"]),
    "runtime_verify_docker_sdk",
  );
  const verification = verifyContainerSdkRouteReceipt(
    loadRuntimeJsonArtifact(required(values, "--receipt")),
    loadRuntimeJsonArtifact(required(values, "--container-receipt")),
    resolve(required(values, "--gateway-evidence")),
  );
  process.stdout.write(`${canonicalJson(verification)}\n`);
  return verification.ok ? 0 : 1;
}

function runtimeVerifyKubernetesCommand(argv: string[]): number {
  const values = exactValueOptions(
    argv,
    new Set(["--gateway-evidence", "--receipt"]),
    "runtime_verify_kubernetes",
  );
  const receipt = verifyKubernetesEnforcementReceipt(
    loadRuntimeJsonArtifact(required(values, "--receipt")),
    resolve(required(values, "--gateway-evidence")),
  );
  process.stdout.write(
    `${canonicalJson({
      ok: true,
      runtime_id: receipt.runtime_id,
      receipt_sha256: receipt.receipt_sha256,
      gateway_chain_head_sha256: receipt.gateway_evidence.chain_head_sha256,
      restart: receipt.restart,
      admission: receipt.admission,
      coverage: receipt.coverage,
      claim_boundary: receipt.claim_boundary,
    })}\n`,
  );
  return 0;
}

function runtimeVerifyKubernetesIdentityCommand(argv: string[]): number {
  const values = exactValueOptions(
    argv,
    new Set([
      "--gateway-evidence",
      "--broker-ca",
      "--issuer-public-key",
      "--kubernetes-receipt",
      "--receipt",
    ]),
    "runtime_verify_kubernetes_identity",
  );
  const receipt = verifyKubernetesIdentityExchangeReceipt(
    loadRuntimeJsonArtifact(required(values, "--receipt")),
    {
      parentReceipt: loadRuntimeJsonArtifact(required(values, "--kubernetes-receipt")),
      gatewayEvidenceDirectory: resolve(required(values, "--gateway-evidence")),
      trustedIssuerPublicKey: readFileSync(resolve(required(values, "--issuer-public-key"))),
      trustedBrokerTlsCa: readFileSync(resolve(required(values, "--broker-ca"))),
    },
  );
  process.stdout.write(
    `${canonicalJson({
      ok: true,
      runtime_id: receipt.runtime_id,
      receipt_sha256: receipt.receipt_sha256,
      parent_kubernetes_enforcement_receipt_sha256:
        receipt.parent_kubernetes_enforcement_receipt_sha256,
      token_review: receipt.token_review,
      broker: receipt.broker,
      coverage: receipt.coverage,
      claim_boundary: receipt.claim_boundary,
    })}\n`,
  );
  return 0;
}

function runtimeComposeCommand(argv: string[]): number {
  const values = runtimeCompositionOptions(argv, true);
  const receipt = composeRuntimeEvidence({
    credentiallessRuntimeDirectory: required(values, "--credentialless"),
    containerEnforcementReceipt: loadRuntimeJsonArtifact(required(values, "--container")),
    runtimeEvidenceBundle: loadRuntimeJsonArtifact(required(values, "--bundle")),
    createdAt: required(values, "--created-at"),
  });
  const output = resolve(required(values, "--out"));
  if (existsSync(output)) throw new Error("runtime_composition_refuses_overwrite");
  writeFileSync(output, `${canonicalJson(receipt)}\n`, { flag: "wx", mode: 0o600 });
  process.stdout.write(
    `${canonicalJson({ path: output, receipt_sha256: receipt.receipt_sha256, coverage: receipt.coverage, claim_boundary: receipt.claim_boundary })}\n`,
  );
  return 0;
}

function runtimeVerifyCompositionCommand(argv: string[]): number {
  const values = runtimeCompositionOptions(argv, false);
  const receipt = loadRuntimeJsonArtifact(required(values, "--receipt"));
  const createdAt = runtimeCompositionCreatedAt(receipt);
  const verification = verifyRuntimeCompositionReceipt(receipt, {
    credentiallessRuntimeDirectory: required(values, "--credentialless"),
    containerEnforcementReceipt: loadRuntimeJsonArtifact(required(values, "--container")),
    runtimeEvidenceBundle: loadRuntimeJsonArtifact(required(values, "--bundle")),
    createdAt,
  });
  process.stdout.write(`${canonicalJson(verification)}\n`);
  return verification.ok ? 0 : 1;
}

function runtimeCompositionOptions(
  argv: readonly string[],
  creating: boolean,
): Record<string, string> {
  const allowed = new Set([
    "--bundle",
    "--container",
    "--credentialless",
    ...(creating ? ["--created-at", "--out"] : ["--receipt"]),
  ]);
  return exactValueOptions(argv, allowed, "runtime_composition");
}

function runtimeCompositionCreatedAt(value: unknown): string {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    typeof (value as Record<string, unknown>)["created_at"] !== "string"
  ) {
    throw new Error("runtime_composition_created_at_unreadable");
  }
  return (value as Record<string, string>)["created_at"] as string;
}

function runtimeVerifyCommand(argv: string[]): number {
  if (argv.length !== 1) throw new Error("runtime_verify_requires_one_bundle_file");
  const verification = verifyRuntimeEvidenceBundle(loadRuntimeJsonArtifact(argv[0] as string));
  process.stdout.write(`${canonicalJson(verification)}\n`);
  return verification.ok ? 0 : 1;
}

async function runtimeUploadCommand(argv: string[]): Promise<number> {
  const parsed = parseUploadOptions(argv, "runtime_upload_bundle_file_required");
  const result = await uploadRuntimeEvidenceBundle(loadRuntimeJsonArtifact(parsed.artifact), {
    apiBase: parsed.apiBase,
    projectId: parsed.projectId,
    token: tokenFromEnvironment(parsed.tokenEnvironment),
    retentionPolicyId: parsed.retentionPolicyId,
    rights: parsed.rights,
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
  return 0;
}

function loadRuntimeJsonArtifact(path: string): unknown {
  try {
    return JSON.parse(readFileSync(resolve(path), "utf8")) as unknown;
  } catch {
    throw new Error("runtime_bundle_json_unreadable");
  }
}

function exactProbeUrl(value: string, protocol: "http:" | "https:", label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`runtime_collect_docker_${label}_url_invalid`);
  }
  if (
    parsed.protocol !== protocol ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    parsed.toString() !== value
  ) {
    throw new Error(`runtime_collect_docker_${label}_url_invalid`);
  }
  return value;
}

function readinessCommand(argv: string[]): number {
  const [subcommand, ...rest] = argv;
  if (subcommand === "init") return readinessInitCommand(rest);
  if (subcommand === "verify") return readinessVerifyCommand(rest);
  if (subcommand === "assess") return readinessAssessCommand(rest);
  throw new Error(`readiness_subcommand_invalid:${subcommand ?? "missing"}`);
}

function readinessInitCommand(argv: string[]): number {
  let output = "gradia-evidence-profile.json";
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const value = argv[index + 1];
    if (option === "--out" && value) {
      output = value;
      index += 1;
    } else throw new Error(`readiness_init_option_invalid:${option ?? "missing"}`);
  }
  const path = resolve(output);
  if (existsSync(path)) throw new Error("readiness_init_refuses_overwrite");
  const profile = sealEvidenceProfile(starterEvidenceProfileBody());
  writeFileSync(path, `${canonicalJson(profile)}\n`, { flag: "wx" });
  process.stdout.write(`${JSON.stringify({ path, profile_sha256: profile.profile_sha256 })}\n`);
  return 0;
}

function readinessVerifyCommand(argv: string[]): number {
  if (argv.length !== 1) throw new Error("readiness_verify_requires_one_file");
  const profile = loadEvidenceProfile(resolve(argv[0] as string));
  process.stdout.write(
    `${JSON.stringify({ ok: true, profile_id: profile.profile_id, profile_version: profile.profile_version, profile_sha256: profile.profile_sha256 })}\n`,
  );
  return 0;
}

function readinessAssessCommand(argv: string[]): number {
  let json = false;
  const positional: string[] = [];
  for (const option of argv) {
    if (option === "--json") json = true;
    else if (!option.startsWith("-")) positional.push(option);
    else throw new Error(`readiness_assess_option_invalid:${option}`);
  }
  if (positional.length !== 2) {
    throw new Error("readiness_assess_requires_profile_and_bundle_directory");
  }
  const report = assessEvidenceReadiness(
    resolve(positional[1] as string),
    loadEvidenceProfile(resolve(positional[0] as string)),
  );
  process.stdout.write(json ? canonicalEvidenceReadiness(report) : formatEvidenceReadiness(report));
  return report.bundle.verified ? 0 : 1;
}

function policyCommand(argv: string[]): number {
  const [subcommand, ...rest] = argv;
  if (subcommand === "init") return policyInitCommand(rest);
  if (subcommand === "verify") return policyVerifyCommand(rest);
  if (subcommand === "check-model") return policyCheckModelCommand(rest);
  if (subcommand === "check-tool") return policyCheckToolCommand(rest);
  throw new Error(`policy_subcommand_invalid:${subcommand ?? "missing"}`);
}

function policyInitCommand(argv: string[]): number {
  let output = "gradia-guard-policy.json";
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const value = argv[index + 1];
    if (option === "--out" && value) {
      output = value;
      index += 1;
    } else throw new Error(`policy_init_option_invalid:${option ?? "missing"}`);
  }
  const path = resolve(output);
  if (existsSync(path)) throw new Error("policy_init_refuses_overwrite");
  const policy = sealPolicy(starterPolicyBody());
  writeFileSync(path, canonicalJson(policy) + "\n", { flag: "wx" });
  process.stdout.write(`${JSON.stringify({ path, policy_sha256: policy.policy_sha256 })}\n`);
  return 0;
}

function policyVerifyCommand(argv: string[]): number {
  if (argv.length !== 1) throw new Error("policy_verify_requires_one_file");
  const policy = loadPolicy(resolve(argv[0] as string));
  process.stdout.write(
    `${JSON.stringify({ ok: true, policy_id: policy.policy_id, policy_version: policy.policy_version, policy_sha256: policy.policy_sha256 })}\n`,
  );
  return 0;
}

function policyCheckModelCommand(argv: string[]): number {
  const options = parsePolicyCheckOptions(argv, ["--provider", "--model"]);
  const provider = requiredValue(options, "--provider") as GatewayProvider;
  const requestedModel = requiredValue(options, "--model");
  const decision = evaluateModelPolicy(loadPolicy(resolve(options.file)), {
    provider,
    requestedModel,
    requestByteLength: requiredIntegerOption(options, "--request-bytes"),
    attemptNumber: requiredIntegerOption(options, "--attempt"),
    authorityScopeIds: options.scopes,
  });
  process.stdout.write(`${JSON.stringify(decision)}\n`);
  return decision.decision === "allowed" ? 0 : 1;
}

function policyCheckToolCommand(argv: string[]): number {
  const options = parsePolicyCheckOptions(argv, [
    "--registry",
    "--tool",
    "--tool-version",
    "--interface-sha256",
  ]);
  const interfaceSha256 = requiredValue(options, "--interface-sha256");
  if (!isSha256(interfaceSha256)) throw new Error("policy_check_interface_sha256_invalid");
  const decision = evaluateToolPolicy(loadPolicy(resolve(options.file)), {
    toolIdentity: {
      schema_version: "gradia.guard.sdk-tool-identity.v1",
      registry_id: requiredValue(options, "--registry"),
      tool_id: requiredValue(options, "--tool"),
      tool_version: requiredValue(options, "--tool-version"),
      interface_sha256: interfaceSha256,
    },
    requestByteLength: requiredIntegerOption(options, "--request-bytes"),
    attemptNumber: requiredIntegerOption(options, "--attempt"),
    authorityScopeIds: options.scopes,
  });
  process.stdout.write(`${JSON.stringify(decision)}\n`);
  return decision.decision === "allowed" ? 0 : 1;
}

interface PolicyCheckOptions {
  file: string;
  scopes: string[];
  values: Record<string, string>;
}

function parsePolicyCheckOptions(argv: string[], kindOptions: readonly string[]): PolicyCheckOptions {
  let file: string | undefined;
  const scopes: string[] = [];
  const values: Record<string, string> = {};
  const valueOptions = new Set([...kindOptions, "--request-bytes", "--attempt"]);
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const value = argv[index + 1];
    if (option === "--scope" && value) {
      scopes.push(value);
      index += 1;
    } else if (option && valueOptions.has(option) && value) {
      values[option] = value;
      index += 1;
    } else if (!option?.startsWith("-") && !file) file = option;
    else throw new Error(`policy_check_option_invalid:${option ?? "missing"}`);
  }
  if (!file) throw new Error("policy_check_file_required");
  if (scopes.length === 0) throw new Error("policy_check_scope_required");
  scopes.sort();
  if (new Set(scopes).size !== scopes.length) throw new Error("policy_check_scope_duplicate");
  return { file, scopes, values };
}

function requiredValue(options: PolicyCheckOptions, name: string): string {
  const value = options.values[name];
  if (!value) throw new Error(`policy_check_value_required:${name}`);
  return value;
}

function requiredIntegerOption(options: PolicyCheckOptions, name: string): number {
  const raw = requiredValue(options, name);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`policy_check_integer_invalid:${name}`);
  return value;
}

function compareCommand(argv: string[]): number {
  let json = false;
  const directories: string[] = [];
  for (const option of argv) {
    if (option === "--json") json = true;
    else if (!option.startsWith("-")) directories.push(option);
    else throw new Error(`compare_option_invalid:${option}`);
  }
  if (directories.length !== 2) throw new Error("compare_requires_exactly_two_bundle_directories");
  const comparison = compareBundles(resolve(directories[0] as string), resolve(directories[1] as string));
  process.stdout.write(json ? canonicalComparison(comparison) : formatComparison(comparison));
  return comparison.ok ? 0 : 1;
}

function inspectCommand(argv: string[]): number {
  let json = false;
  let directory: string | undefined;
  for (const option of argv) {
    if (option === "--json") json = true;
    else if (!option.startsWith("-") && !directory) directory = option;
    else throw new Error(`inspect_option_invalid:${option}`);
  }
  if (!directory) throw new Error("inspect_bundle_directory_required");
  const inspection = inspectBundle(resolve(directory));
  process.stdout.write(json ? canonicalInspection(inspection) : formatInspection(inspection));
  return inspection.ok ? 0 : 1;
}

function actorsCommand(argv: string[]): number {
  let json = false;
  let directory: string | undefined;
  for (const option of argv) {
    if (option === "--json") json = true;
    else if (!option.startsWith("-") && !directory) directory = option;
    else throw new Error(`actors_option_invalid:${option}`);
  }
  if (!directory) throw new Error("actors_bundle_directory_required");
  const report = analyzeSdkActorGraph(resolve(directory));
  process.stdout.write(json ? canonicalSdkActorGraph(report) : formatSdkActorGraph(report));
  return 0;
}

function capabilitiesCommand(argv: string[]): number {
  let json = false;
  for (const option of argv) {
    if (option === "--json" && !json) json = true;
    else throw new Error(`capabilities_option_invalid:${option}`);
  }
  const catalog = guardCapabilityCatalog();
  process.stdout.write(
    json ? canonicalGuardCapabilityCatalog(catalog) : formatGuardCapabilityCatalog(catalog),
  );
  return 0;
}

function anchorCommand(argv: string[]): number {
  const [subcommand, ...rest] = argv;
  if (subcommand === "verify-guard") return verifyGuardAnchorCommand(rest);
  if (subcommand === "verify-universe") return verifyUniverseAnchorCommand(rest);
  throw new Error(`anchor_subcommand_invalid:${subcommand ?? "missing"}`);
}

function verifyGuardAnchorCommand(argv: string[]): number {
  const values = exactValueOptions(
    argv,
    new Set([
      "--anchor",
      "--bundle-sha256",
      "--created-by",
      "--edition",
      "--edition-sha256",
      "--project",
      "--public-key-ed25519",
      "--retention-policy",
      "--session",
    ]),
    "anchor_verify_guard",
  );
  const anchorPath = required(values, "--anchor");
  const guardEvidenceEditionId = required(values, "--edition");
  const projectId = required(values, "--project");
  const sessionId = required(values, "--session");
  const bundleSha256 = required(values, "--bundle-sha256");
  const editionSha256 = required(values, "--edition-sha256");
  const retentionPolicyId = required(values, "--retention-policy");
  const createdBy = required(values, "--created-by");
  const pinnedPublicKeyEd25519 = required(values, "--public-key-ed25519");
  const result = verifyGuardRemoteAnchor(loadJsonArtifact(anchorPath), {
    guardEvidenceEditionId,
    projectId,
    sessionId,
    bundleSha256,
    editionSha256,
    retentionPolicyId,
    createdBy,
    pinnedPublicKeyEd25519,
  });
  process.stdout.write(
    `${canonicalJson({
      schema_version: "gradia.guard.portable-anchor-verification.v1",
      anchor_kind: "guard_evidence_edition",
      ok: result.ok,
      anchor_sha256: result.anchorSha256,
      public_key_id: result.publicKeyId,
      trust_boundary:
        "signature_and_exact_bindings_verified_under_required_full_ed25519_public_key_pin",
      claim_boundary:
        "admitted_edition_and_retention_declaration_only_no_retention_execution_deletion_or_residency_claim",
    })}\n`,
  );
  return 0;
}

function verifyUniverseAnchorCommand(argv: string[]): number {
  const values = exactValueOptions(
    argv,
    new Set([
      "--anchor",
      "--episode",
      "--project",
      "--public-key-ed25519",
      "--run",
      "--scenario-digest",
      "--task",
    ]),
    "anchor_verify_universe",
  );
  const taskId = values["--task"];
  const scenarioDigest = values["--scenario-digest"];
  const anchorPath = required(values, "--anchor");
  const projectId = required(values, "--project");
  const runId = required(values, "--run");
  const episodeId = required(values, "--episode");
  const pinnedPublicKeyEd25519 = required(values, "--public-key-ed25519");
  const result = verifyUniverseAnchor(loadJsonArtifact(anchorPath), {
    projectId,
    runId,
    episodeId,
    ...(taskId ? { taskId } : {}),
    ...(scenarioDigest ? { scenarioDigest } : {}),
    pinnedPublicKeyEd25519,
  });
  process.stdout.write(
    `${canonicalJson({
      schema_version: "gradia.guard.portable-anchor-verification.v1",
      anchor_kind: "universe_observatory_prefix",
      ok: result.ok,
      anchor_sha256: result.anchorSha256,
      public_key_id: result.publicKeyId,
      coverage: {
        counterfactual_pair: result.coverage.counterfactualPair,
        evolution_witness: result.coverage.evolutionWitness,
        full_host_enforcement: result.coverage.fullHostEnforcement,
        snapshot_restore: result.coverage.snapshotRestore,
      },
      trust_boundary:
        "signature_and_exact_bindings_verified_under_required_full_ed25519_public_key_pin",
      claim_boundary:
        "verified_durable_observatory_prefix_only_no_counterfactual_pair_or_full_host_enforcement_claim",
    })}\n`,
  );
  return 0;
}

function exactValueOptions(
  argv: readonly string[],
  allowed: ReadonlySet<string>,
  label: string,
): Record<string, string> {
  if (argv.length % 2 !== 0) throw new Error(`${label}_option_value_missing`);
  const values: Record<string, string> = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    const value = argv[index + 1];
    if (!option || !value || !allowed.has(option)) {
      throw new Error(`${label}_option_invalid:${option ?? "missing"}`);
    }
    if (values[option]) throw new Error(`${label}_option_duplicate:${option}`);
    values[option] = value;
  }
  return values;
}

function required(values: Readonly<Record<string, string>>, option: string): string {
  const value = values[option];
  if (!value) throw new Error(`anchor_option_required:${option}`);
  return value;
}

function loadJsonArtifact(path: string): unknown {
  try {
    return JSON.parse(readFileSync(resolve(path), "utf8")) as unknown;
  } catch {
    throw new Error("anchor_json_unreadable");
  }
}

async function uploadCommand(argv: string[]): Promise<number> {
  const parsed = parseUploadOptions(argv, "upload_bundle_directory_required");
  const result = await uploadEvidenceBundle(resolve(parsed.artifact), {
    apiBase: parsed.apiBase,
    projectId: parsed.projectId,
    token: tokenFromEnvironment(parsed.tokenEnvironment),
    retentionPolicyId: parsed.retentionPolicyId,
    rights: parsed.rights,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  return 0;
}

interface ParsedUploadOptions {
  apiBase: string;
  projectId: string;
  artifact: string;
  tokenEnvironment: string;
  retentionPolicyId: string;
  rights: GuardRights;
}

function parseUploadOptions(argv: readonly string[], missingArtifactError: string): ParsedUploadOptions {
  let apiBase: string | undefined;
  let projectId: string | undefined;
  let artifact: string | undefined;
  let tokenEnvironment = "GRADIA_GUARD_TOKEN";
  let retentionPolicyId = "local-digests-v1";
  const rights: GuardRights = {
    evaluation: false,
    redistribution: false,
    derived_publication: false,
    training: false,
    raw_trajectory: false,
  };
  const rightFlags: Record<string, keyof GuardRights> = {
    "--allow-evaluation": "evaluation",
    "--allow-redistribution": "redistribution",
    "--allow-derived-publication": "derived_publication",
    "--allow-training": "training",
    "--allow-raw-trajectory": "raw_trajectory",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const value = argv[index + 1];
    if (option === "--api-base" && value) {
      apiBase = value;
      index += 1;
    } else if (option === "--project" && value) {
      projectId = value;
      index += 1;
    } else if (option === "--token-env" && value) {
      tokenEnvironment = value;
      index += 1;
    } else if (option === "--retention-policy" && value) {
      retentionPolicyId = value;
      index += 1;
    } else if (option && rightFlags[option]) {
      rights[rightFlags[option]] = true;
    } else if (!option?.startsWith("-") && !artifact) artifact = option;
    else throw new Error(`upload_option_invalid:${option ?? "missing"}`);
  }
  if (!apiBase) throw new Error("upload_api_base_required");
  if (!projectId) throw new Error("upload_project_required");
  if (!artifact) throw new Error(missingArtifactError);
  return {
    apiBase,
    projectId,
    artifact,
    tokenEnvironment,
    retentionPolicyId,
    rights,
  };
}

async function runCommand(argv: string[]): Promise<number> {
  let outputRoot = ".gradia/evidence";
  let captureMode: CaptureMode = "digest-only";
  let keyEnvironment = "GRADIA_GUARD_SPOOL_KEY";
  let keyId: string | undefined;
  const separator = argv.indexOf("--");
  if (separator < 0 || separator === argv.length - 1) throw new Error("run_requires_double_dash_and_command");
  const options = argv.slice(0, separator);
  const childCommand = argv.slice(separator + 1);
  for (let index = 0; index < options.length; index += 1) {
    const option = options[index];
    const value = options[index + 1];
    if (option === "--out" && value) {
      outputRoot = value;
      index += 1;
    } else if (option === "--spool" && (value === "digest-only" || value === "encrypted")) {
      captureMode = value;
      index += 1;
    } else if (option === "--key-env" && value) {
      keyEnvironment = value;
      index += 1;
    } else if (option === "--key-id" && value) {
      keyId = value;
      index += 1;
    } else throw new Error(`run_option_invalid:${option ?? "missing"}`);
  }
  const encryptionKey = captureMode === "encrypted" ? decodeKeyFromEnvironment(keyEnvironment) : undefined;
  if (captureMode === "encrypted" && !keyId) throw new Error("encrypted_spool_requires_key_id");
  const result = await runGuardedProcess({
    command: childCommand,
    outputRoot: resolve(outputRoot),
    captureMode,
    ...(encryptionKey ? { encryptionKey } : {}),
    ...(keyId ? { keyId } : {}),
    onBundle: (directory) => process.stderr.write(`gradia evidence: ${directory}\n`),
  });
  return result.exitCode;
}

function verifyCommand(argv: string[]): number {
  let keyEnvironment: string | undefined;
  let expectedKeyId: string | undefined;
  let directory: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const value = argv[index + 1];
    if (option === "--key-env" && value) {
      keyEnvironment = value;
      index += 1;
    } else if (option === "--key-id" && value) {
      expectedKeyId = value;
      index += 1;
    } else if (!option?.startsWith("-") && !directory) directory = option;
    else throw new Error(`verify_option_invalid:${option ?? "missing"}`);
  }
  if (!directory) throw new Error("verify_bundle_directory_required");
  const encryptionKey = keyEnvironment ? decodeKeyFromEnvironment(keyEnvironment) : undefined;
  const result = verifyBundle(resolve(directory), {
    ...(encryptionKey ? { encryptionKey } : {}),
    ...(expectedKeyId ? { expectedKeyId } : {}),
  });
  process.stdout.write(canonicalVerificationResult(result));
  return result.ok ? 0 : 1;
}

function proofPackCommand(argv: string[]): number {
  const [subcommand, ...rest] = argv;
  if (subcommand !== "verify") {
    throw new Error(`proof_pack_subcommand_invalid:${subcommand ?? "missing"}`);
  }
  if (rest.length !== 1 || !rest[0] || rest[0].startsWith("-")) {
    throw new Error("proof_pack_verify_directory_required");
  }
  const result = verifyProofPackDirectory(resolve(rest[0]));
  process.stdout.write(canonicalProofPackVerification(result));
  return result.ok ? 0 : 1;
}

function help(): string {
  return `Gradia Guard 0.1.0-beta.6

Usage:
  gradia-guard run [--out DIR] [--spool digest-only|encrypted] [--key-env NAME --key-id ID] -- COMMAND [ARGS...]
  gradia-guard verify [--key-env NAME --key-id ID] BUNDLE_DIR
  gradia-guard proof-pack verify PROOF_PACK_DIR
  gradia-guard inspect [--json] BUNDLE_DIR
  gradia-guard capabilities [--json]
  gradia-guard doctor [--json]
  gradia-guard anchor verify-guard --anchor FILE --public-key-ed25519 HEX --edition ID
    --project ID --session ID --bundle-sha256 SHA --edition-sha256 SHA
    --retention-policy ID --created-by ID
  gradia-guard anchor verify-universe --anchor FILE --public-key-ed25519 HEX --project ID
    --run ID --episode ID [--task ID] [--scenario-digest SHA]
  gradia-guard actors [--json] SDK_BUNDLE_DIR
  gradia-guard compare [--json] LEFT_BUNDLE_DIR RIGHT_BUNDLE_DIR
  gradia-guard policy init [--out FILE]
  gradia-guard policy verify FILE
  gradia-guard policy check-model FILE --provider NAME --model PIN --request-bytes N --attempt N --scope ID [...]
  gradia-guard policy check-tool FILE --registry ID --tool ID --tool-version PIN --interface-sha256 SHA --request-bytes N --attempt N --scope ID [...]
  gradia-guard readiness init [--out FILE]
  gradia-guard readiness verify FILE
  gradia-guard readiness assess [--json] PROFILE_FILE BUNDLE_DIR
  gradia-guard sdk-matrix [--json]
  gradia-guard framework-matrix [--json]
  gradia-guard mcp-http verify MCP_HTTP_ACCESS_BUNDLE_DIR
  gradia-guard mcp-http recover INTERRUPTED_MCP_HTTP_ACCESS_DIR
  gradia-guard mcp-stdio verify MCP_STDIO_ACCESS_BUNDLE_DIR
  gradia-guard mcp-stdio recover INTERRUPTED_MCP_STDIO_ACCESS_DIR
  gradia-guard runtime verify BUNDLE_FILE
  gradia-guard runtime upload --api-base HTTPS_ORIGIN --project ID [--token-env NAME]
    [--retention-policy ID] [--allow-evaluation] [--allow-redistribution]
    [--allow-derived-publication] [--allow-training] [--allow-raw-trajectory] BUNDLE_FILE
  gradia-guard runtime compose --credentialless DIR --container FILE --bundle G3_FILE
    --created-at ISO_TIMESTAMP --out FILE
  gradia-guard runtime verify-composition --receipt FILE --credentialless DIR
    --container FILE --bundle G3_FILE
  gradia-guard runtime collect-docker --runtime-id ID --agent CONTAINER --gateway CONTAINER
    --internal-network NETWORK --policy-sha256 SHA --configuration-sha256 SHA
    --workload-identity-sha256 SHA --probe-runtime node|python
    --direct-url HTTPS_URL --gateway-url HTTP_URL --out FILE
  gradia-guard runtime probe-docker-bypass --agent CONTAINER
    --container-receipt FILE --out FILE
  gradia-guard runtime verify-docker-bypass --receipt FILE --container-receipt FILE
  gradia-guard runtime probe-docker-sdk --agent CONTAINER --gateway CONTAINER
    --container-receipt FILE --framework vercel_ai_sdk|langchain
    --provider anthropic|gemini|openai|xai
    --local-origin http://gateway:8787
    --capability-env NAME --gateway-evidence-out DIR --out FILE
  gradia-guard runtime verify-docker-sdk --receipt FILE --container-receipt FILE
    --gateway-evidence DIR
  gradia-guard runtime verify-kubernetes --receipt FILE --gateway-evidence DIR
  gradia-guard runtime verify-kubernetes-identity --receipt FILE
    --kubernetes-receipt FILE --gateway-evidence DIR --issuer-public-key PEM_FILE
    --broker-ca PEM_FILE
  gradia-guard upload --api-base HTTPS_ORIGIN --project ID [--token-env NAME] [--retention-policy ID]
    [--allow-evaluation] [--allow-redistribution] [--allow-derived-publication]
    [--allow-training] [--allow-raw-trajectory] BUNDLE_DIR

The one-line process wrapper captures process dispatch, lifecycle, stdout and stderr.
It does not claim model/tool semantics, filesystem/network effects, agent-visible state,
or full-world capture. Those require gateway, SDK, instrumented-runtime, or Universe
integrations whose coverage receipts prove their stronger surfaces.

Upload verifies locally before dispatch, reads its service-account token only from the
named environment variable, and declares each permitted evidence use explicitly. It
does not make the evidence a benchmark or certificate.

Inspect is local and account-free. It reports what the verified bundle captured,
what remained unobserved, the exact assurance ceiling, and the next integration that
would materially increase coverage.

Capabilities is local and account-free. Its canonical machine-readable catalog
separates useful free/local functions from authenticated, deployment-specific
managed services. Payment may change service availability, but never observed
coverage, claim truth, or admission-gate outcomes.

Doctor is local, account-free, and performs no network call. It reports runtime
compatibility, privacy-safe defaults, the exact G0 assurance ceiling, and the
first capture/verify commands. It never treats package installation as managed
connectivity or non-bypassable governance.

Anchor verification is local and account-free. Both commands require the full
independently pinned Ed25519 public key plus exact artifact bindings; a
self-signed substituted anchor is refused. Guard anchors prove an admitted
edition and retention declaration, not retention execution, deletion, or
residency. Universe anchors prove only their signed observatory-prefix coverage;
they do not infer counterfactual pairing or host enforcement.

Actors is local and account-free. It verifies an SDK bundle before deriving a
payload-free graph of application-declared actor/principal labels and parent
links. The labels are not authenticated by this graph, and parent links prove
neither delegation nor causal contribution. Actor and principal IDs remain
plaintext metadata and must not contain secrets or unnecessary personal data.

Compare is also local and account-free. It verifies both bundles and reports structural,
coverage, frame-count, and digest-identity differences. It never labels those differences
as a behavioral regression without a separately admitted evaluation contract.

Policy commands are local and account-free. Policies are deny-by-default, canonical and
self-digested. The simulator evaluates exact model/tool routes, authority scopes, request
size and attempt limits before dispatch; it does not enforce calls that bypass it.

Readiness commands are local and account-free. They map a verified bundle's observed
surfaces to opaque organization or licensed-framework control references. Evidence-ready
does not mean compliant, certified, effective, or accepted by an auditor.

Proof Pack verification is local and account-free. Its versioned profile
recomputes the frame chain, exploit semantics, every published aggregate and the
manifest self-digest. A passing result proves integrity and derivation only—not
authorship, timestamp, data rights, runtime enforcement, or scientific validity.

MCP HTTP verification is local and account-free. Recovery independently
replays one unfinalized v2 header and fsync journal, refuses malformed,
noncanonical, truncated, legacy or already-finalized prefixes, and writes one
atomic terminal bundle labeled recovered_interruption. It cannot resume the
proxy, prove the cause of interruption, or reconstruct requests that were not
durably appended.

MCP stdio verification is local and account-free. Recovery independently
replays one unfinalized digest-only authorization journal and finalizes every
open transaction as interrupted_unknown. It cannot resume the child, prove
whether child stdin was written before interruption, attest executable bytes or
child identity, or cover direct processes and other stdio paths.

Runtime collect-docker asks the Docker daemon for the exact agent, gateway, and network
posture, then launches one blocked-direct-egress probe and one allowed-gateway probe from
the agent container. Its receipt proves only that measured container/network/credential
boundary. It preserves operator or Docker-daemon bypass as true and full process, file,
side-effect, host, and world-state coverage as false.

Runtime verify replays the portable G3 receipt, finalization, and self-contained
anchor chain locally. Runtime upload performs that replay before any network call,
then requires the same explicit rights, HTTPS, authenticated managed admission, and
remote-anchor verification as other Guard uploads. A portable declared-recorder
bundle still proves neither root ownership nor non-bypassability by itself.

Runtime compose independently verifies and binds one provider-credentialless
child receipt, one measured Docker enforcement receipt, and one portable G3
bundle to the same runtime, policy, configuration, and workload-identity digest.
Its coverage retains Docker-operator and declared-recorder bypass as possible;
the composition does not imply full-host or full-world capture.

The Docker bypass battery independently binds five observed probes to an exact
measured container-enforcement receipt: alternate-client raw TCP, link-local
metadata reachability, root-filesystem writes, writable scratch space, and
spawned-subprocess raw TCP. Passing proves only those observations at probe
time. It does not establish exhaustive non-bypassability or full-host control,
and Docker-daemon/operator bypass remains explicit.

The Docker SDK probe binds one exact pinned Vercel/OpenAI SDK call inside that
same measured agent to the same measured gateway's independently replayable
Guard bundle. The local capability is read from a named environment variable
and forwarded by environment name, not command-line value. This is one mocked-
upstream compatibility cell, not live-provider, arbitrary-framework,
exhaustive-bypass, cluster, full-host, or full-world proof.
`;
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "unknown_failure";
    process.stderr.write(`gradia-guard refused: ${message}\n`);
    process.exitCode = 2;
  });
