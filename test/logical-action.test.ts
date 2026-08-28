import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  createLogicalActionIdentity,
  isLogicalActionOccurrenceId,
  logicalActionIdentityForSdkFrame,
  verifyLogicalActionIdentity,
  type LogicalActionCoordinates,
  type SdkEvidenceFrame,
} from "../src/index.js";

const fixturePath = join(
  process.cwd(),
  "test",
  "fixtures",
  "logical-action-reference.json",
);

function fixture(): Record<string, unknown> {
  return JSON.parse(readFileSync(fixturePath, "utf8")) as Record<string, unknown>;
}

test("logical action identity reproduces the cross-language golden vector", () => {
  const verified = verifyLogicalActionIdentity(fixture());
  assert.equal(
    verified.coordinates_sha256,
    "ca2b979656fc6ccaa69a2ad34520c0be8da58df54706b300bbd02edc8c955575",
  );
  assert.equal(isLogicalActionOccurrenceId(verified.occurrence_id), true);
});

test("G2 decision and action frames derive one action identity", () => {
  const frames = readFileSync(
    join(process.cwd(), "test", "fixtures", "sdk-reference-bundle", "frames.ndjson"),
    "utf8",
  )
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as SdkEvidenceFrame);
  assert.equal(frames.length, 4);
  const pairs: readonly (readonly [SdkEvidenceFrame, SdkEvidenceFrame])[] = [
    [frames[0]!, frames[1]!],
    [frames[2]!, frames[3]!],
  ];
  for (const [decision, action] of pairs) {
    assert.deepEqual(
      logicalActionIdentityForSdkFrame(decision),
      logicalActionIdentityForSdkFrame(action),
    );
  }
  assert.notEqual(
    logicalActionIdentityForSdkFrame(frames[0]!).coordinates_sha256,
    logicalActionIdentityForSdkFrame(frames[2]!).coordinates_sha256,
  );
});

test("every coordinate changes the identity and invalid shapes fail closed", () => {
  const base = (fixture()["coordinates"] as LogicalActionCoordinates);
  const expected = createLogicalActionIdentity(base).coordinates_sha256;
  for (const changed of [
    { ...base, action_namespace_id: "run-conditional-underwriting-002" },
    { ...base, actor_id: "underwriter-agent-02" },
    { ...base, logical_operation_id: "loan-case-042.final-review" },
    { ...base, attempt_number: 3 },
  ]) {
    assert.notEqual(createLogicalActionIdentity(changed).coordinates_sha256, expected);
  }
  assert.throws(
    () => createLogicalActionIdentity({ ...base, attempt_number: 0 }),
    /logical_action_attempt_number_invalid/,
  );
  assert.throws(
    () => verifyLogicalActionIdentity({ ...fixture(), surprise: true }),
    /logical_action_identity_keys_invalid/,
  );
  const tampered = fixture();
  tampered["coordinates_sha256"] = "f".repeat(64);
  assert.throws(
    () => verifyLogicalActionIdentity(tampered),
    /logical_action_identity_binding_invalid/,
  );
});
