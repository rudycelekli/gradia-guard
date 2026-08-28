import assert from "node:assert/strict";
import { join } from "node:path";
import test from "node:test";
import { verifyBundle } from "../src/index.js";

test("cross-language reference fixture verifies under the public ABI", () => {
  const result = verifyBundle(join("test", "fixtures", "reference-bundle"));
  assert.equal(result.ok, true, result.blockers.join(","));
  assert.equal(result.frame_count, 4);
  assert.equal(
    result.chain_head_sha256,
    "d66ceb6b2dd261767f0ef3bb4667b1dac1c775a04d0bbc6087c7868484eec5ac",
  );
});

test("gateway cross-language fixture verifies under the G1 ABI", () => {
  const result = verifyBundle(join("test", "fixtures", "gateway-reference-bundle"));
  assert.equal(result.ok, true, result.blockers.join(","));
  assert.equal(result.frame_count, 2);
  assert.equal(
    result.chain_head_sha256,
    "77137a6b6a30aca92662badda1d8feb270d81cdb7d380a04d8bda7a7753a97a6",
  );
});

test("SDK cross-language fixture verifies under the G2 ABI", () => {
  const result = verifyBundle(join("test", "fixtures", "sdk-reference-bundle"));
  assert.equal(result.ok, true, result.blockers.join(","));
  assert.equal(result.frame_count, 4);
  assert.equal(
    result.chain_head_sha256,
    "4542aa5dcadfd66bc0847b3b584fe0cce400425f3125414f8f85b561d2124c9d",
  );
});
