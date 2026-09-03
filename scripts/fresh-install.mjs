import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const packageRoot = process.cwd();
const temporary = mkdtempSync(join(tmpdir(), "gradia-guard-consumer-"));
try {
  const output = execFileSync(
    "npm",
    ["pack", "--ignore-scripts", "--json", "--pack-destination", temporary],
    { cwd: packageRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  const parsed = JSON.parse(output);
  if (!Array.isArray(parsed) || parsed.length !== 1 || typeof parsed[0]?.filename !== "string") {
    throw new Error("fresh_install_pack_shape_invalid");
  }
  const tarball = resolve(temporary, parsed[0].filename);
  const consumer = join(temporary, "consumer");
  writeFileSync(
    join(temporary, "package.json"),
    `${JSON.stringify({ name: "guard-fresh-consumer", private: true, type: "module" }, null, 2)}\n`,
    { flag: "wx", mode: 0o600 },
  );
  execFileSync(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
    { cwd: temporary, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );

  const cli = join(temporary, "node_modules", ".bin", "gradia-guard");
  const doctor = JSON.parse(
    execFileSync(cli, ["doctor", "--json"], {
      cwd: temporary,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }),
  );
  if (doctor.status !== "ready_for_local_capture" || doctor.defaults?.telemetry !== "off") {
    throw new Error("fresh_install_doctor_invalid");
  }
  const capabilities = JSON.parse(
    execFileSync(cli, ["capabilities", "--json"], {
      cwd: temporary,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }),
  );
  if (capabilities.package_boundary?.license !== "Apache-2.0") {
    throw new Error("fresh_install_capability_boundary_invalid");
  }

  writeFileSync(
    consumer,
    [
      "import { createProofBoundAguiProposal, guardDoctor, guardCapabilityCatalog, verifyProofBoundAguiProposal } from '@gradia/guard';",
      "const report = guardDoctor();",
      "const catalog = guardCapabilityCatalog();",
      "const proposal = createProofBoundAguiProposal({ proposalId: 'fresh-install', kind: 'steer', runId: 'run-fresh-install', payload: { episodeId: 'episode-1', eventId: 'event-1' } });",
      "verifyProofBoundAguiProposal(proposal, 'run-fresh-install');",
      "if (!report.node_supported || catalog.package_boundary.private) process.exit(1);",
      "process.stdout.write('fresh_import_ok\\n');",
      "",
    ].join("\n"),
    { flag: "wx", mode: 0o600 },
  );
  const imported = execFileSync(process.execPath, [consumer], {
    cwd: temporary,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (imported !== "fresh_import_ok\n") throw new Error("fresh_install_import_invalid");

  const tarballSha256 = createHash("sha256").update(readFileSync(tarball)).digest("hex");
  process.stdout.write(
    `${JSON.stringify({
      schema_version: "gradia.guard.fresh-install.v1",
      package_version: doctor.package_version,
      tarball_sha256: tarballSha256,
      doctor_report_sha256: doctor.report_sha256,
      capability_catalog_sha256: capabilities.catalog_sha256,
      cli: true,
      esm_import: true,
      network_used_by_guard: false,
    })}\n`,
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
