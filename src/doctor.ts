import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";
import { GUARD_PACKAGE_VERSION } from "./capabilities.js";

export const GUARD_DOCTOR_SCHEMA_VERSION = "gradia.guard.doctor.v1" as const;
export const MINIMUM_NODE_MAJOR = 20 as const;

export interface GuardDoctorBody {
  schema_version: typeof GUARD_DOCTOR_SCHEMA_VERSION;
  package_name: "@gradia/guard";
  package_version: typeof GUARD_PACKAGE_VERSION;
  node_version: string;
  node_supported: boolean;
  status: "ready_for_local_capture" | "unsupported_runtime";
  defaults: {
    telemetry: "off";
    content_capture: "digest_only";
    managed_upload: "not_connected";
  };
  local_assurance_ceiling: "G0_explicit_process_boundary";
  first_command: "npx @gradia/guard run -- node agent.js";
  verify_command: "npx @gradia/guard verify .gradia/evidence/SESSION_ID";
  blockers: readonly string[];
}

export interface GuardDoctorReport extends GuardDoctorBody {
  report_sha256: string;
}

export function guardDoctor(nodeVersion = process.versions.node): GuardDoctorReport {
  const major = parseNodeMajor(nodeVersion);
  const nodeSupported = major >= MINIMUM_NODE_MAJOR;
  const body: GuardDoctorBody = {
    schema_version: GUARD_DOCTOR_SCHEMA_VERSION,
    package_name: "@gradia/guard",
    package_version: GUARD_PACKAGE_VERSION,
    node_version: nodeVersion,
    node_supported: nodeSupported,
    status: nodeSupported ? "ready_for_local_capture" : "unsupported_runtime",
    defaults: {
      telemetry: "off",
      content_capture: "digest_only",
      managed_upload: "not_connected",
    },
    local_assurance_ceiling: "G0_explicit_process_boundary",
    first_command: "npx @gradia/guard run -- node agent.js",
    verify_command: "npx @gradia/guard verify .gradia/evidence/SESSION_ID",
    blockers: nodeSupported ? [] : [`node_${MINIMUM_NODE_MAJOR}_or_newer_required`],
  };
  return { ...body, report_sha256: digestCanonical(body) };
}

export function verifyGuardDoctorReport(value: unknown): asserts value is GuardDoctorReport {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("guard_doctor_shape_invalid");
  }
  const record = value as Record<string, unknown>;
  if (!isSha256(record["report_sha256"])) {
    throw new Error("guard_doctor_digest_invalid");
  }
  const { report_sha256: reportSha256, ...body } = record;
  if (digestCanonical(body) !== reportSha256) {
    throw new Error("guard_doctor_digest_mismatch");
  }
  const expected = guardDoctor(String(record["node_version"] ?? ""));
  if (canonicalJson(value) !== canonicalJson(expected)) {
    throw new Error("guard_doctor_contract_mismatch");
  }
}

export function formatGuardDoctorReport(report: GuardDoctorReport): string {
  verifyGuardDoctorReport(report);
  const lines = [
    `Gradia Guard ${report.package_version}: ${report.status}`,
    `Node: ${report.node_version} (${report.node_supported ? "supported" : "unsupported"})`,
    "Defaults: telemetry off; digest-only content; no managed connection",
    "Local ceiling: G0 explicit process boundary (bypassable; not full-system governance)",
    `Start: ${report.first_command}`,
    `Verify: ${report.verify_command}`,
    ...(report.blockers.length ? [`Blockers: ${report.blockers.join(", ")}`] : []),
    `Report SHA-256: ${report.report_sha256}`,
  ];
  return `${lines.join("\n")}\n`;
}

function parseNodeMajor(nodeVersion: string): number {
  if (!/^\d+\.\d+\.\d+(?:[-+].*)?$/.test(nodeVersion)) {
    throw new Error("guard_doctor_node_version_invalid");
  }
  const major = Number(nodeVersion.split(".", 1)[0]);
  if (!Number.isSafeInteger(major)) throw new Error("guard_doctor_node_version_invalid");
  return major;
}
