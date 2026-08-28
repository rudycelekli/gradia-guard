import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import test from "node:test";
import {
  digestCanonical,
  guardDoctor,
  verifyGuardDoctorReport,
  type GuardDoctorReport,
} from "../src/index.js";

test("doctor exposes safe defaults and the exact local assurance ceiling", () => {
  const report = guardDoctor("24.1.0");
  verifyGuardDoctorReport(report);
  assert.equal(report.status, "ready_for_local_capture");
  assert.deepEqual(report.defaults, {
    telemetry: "off",
    content_capture: "digest_only",
    managed_upload: "not_connected",
  });
  assert.equal(report.local_assurance_ceiling, "G0_explicit_process_boundary");
  assert.equal(report.blockers.length, 0);
});

test("doctor refuses unsupported and malformed Node versions", () => {
  const unsupported = guardDoctor("18.20.0");
  assert.equal(unsupported.status, "unsupported_runtime");
  assert.deepEqual(unsupported.blockers, ["node_20_or_newer_required"]);
  assert.throws(() => guardDoctor("latest"), /guard_doctor_node_version_invalid/);
});

test("doctor verifier refuses recomputed semantic inflation", () => {
  const report = structuredClone(guardDoctor("24.1.0")) as GuardDoctorReport;
  const mutable = report as unknown as {
    local_assurance_ceiling: string;
    report_sha256: string;
  };
  mutable.local_assurance_ceiling = "complete_non_bypassable_governance";
  const { report_sha256: _old, ...body } = report;
  mutable.report_sha256 = digestCanonical(body);
  assert.throws(() => verifyGuardDoctorReport(report), /guard_doctor_contract_mismatch/);
});

test("doctor CLI emits human and canonical JSON reports", () => {
  const human = execFileSync(process.execPath, ["dist/src/cli.js", "doctor"], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.match(human, /ready_for_local_capture/);
  assert.match(human, /telemetry off; digest-only content; no managed connection/);
  assert.match(human, /G0 explicit process boundary \(bypassable; not full-system governance\)/);

  const machine = JSON.parse(
    execFileSync(process.execPath, ["dist/src/cli.js", "doctor", "--json"], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
  ) as GuardDoctorReport;
  verifyGuardDoctorReport(machine);

  const invalid = spawnSync(process.execPath, ["dist/src/cli.js", "doctor", "--json", "--json"], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /doctor_option_invalid/);
});
