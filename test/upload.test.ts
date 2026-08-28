import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, digestCanonical } from "../src/canonical.js";
import { uploadEvidenceBundle } from "../src/upload.js";

const FIXTURE = join(process.cwd(), "test", "fixtures", "reference-bundle");
const SDK_FIXTURE = join(process.cwd(), "test", "fixtures", "sdk-reference-bundle");

function fixtureBundle(directory = FIXTURE): unknown {
  return {
    manifest: JSON.parse(readFileSync(join(directory, "bundle.json"), "utf8")),
    frames: readFileSync(join(directory, "frames.ndjson"), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line)),
  };
}

function fixtureSessionId(directory = FIXTURE): string {
  const manifest = JSON.parse(readFileSync(join(directory, "bundle.json"), "utf8")) as {
    session_id: string;
  };
  return manifest.session_id;
}

function signedAnchor(input: {
  editionId: string;
  projectId: string;
  sessionId: string;
  bundleSha256: string;
  editionSha256: string;
  retentionPolicyId: string;
  createdBy: string;
}): unknown {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const publicRaw = publicDer.subarray(publicDer.length - 32);
  const attestation = {
    schema_version: "gradia.guard.remote-anchor.v1",
    anchor_scope: "admitted_edition_and_retention_declaration",
    guard_evidence_edition_id: input.editionId,
    org_id: "org-01",
    project_id: input.projectId,
    session_id: input.sessionId,
    bundle_sha256: input.bundleSha256,
    edition_sha256: input.editionSha256,
    verification_sha256: "a".repeat(64),
    retention_policy_id: input.retentionPolicyId,
    retention_execution_proved: false,
    deletion_proved: false,
    storage_residency_proved: false,
    created_by: input.createdBy,
    created_at: "2026-08-26T20:00:00+00:00",
  } as const;
  return {
    attestation,
    signature_ed25519: sign(
      null,
      Buffer.from(canonicalJson(attestation)),
      privateKey,
    ).toString("hex"),
    public_key_ed25519: publicRaw.toString("hex"),
    public_key_id: createHash("sha256").update(publicRaw).digest("hex").slice(0, 16),
  };
}

test("managed upload verifies locally, keeps the token in the header, and binds the server digest", async () => {
  const bundle = fixtureBundle();
  const expectedDigest = digestCanonical(bundle);
  const expectedEditionDigest = digestCanonical({
    schema_version: "gradia.guard.evidence-edition.v1",
    project_id: "project-01",
    bundle_sha256: expectedDigest,
    rights: {
      evaluation: true,
      redistribution: false,
      derived_publication: false,
      training: false,
      raw_trajectory: false,
    },
    retention_policy_id: "local-digests-v1",
    created_by: "collector-01",
  });
  let observedUrl = "";
  let observedInit: RequestInit | undefined;
  const result = await uploadEvidenceBundle(FIXTURE, {
    apiBase: "https://ingest.example.test",
    projectId: "project-01",
    token: "service-account-secret",
    retentionPolicyId: "local-digests-v1",
    rights: {
      evaluation: true,
      redistribution: false,
      derived_publication: false,
      training: false,
      raw_trajectory: false,
    },
    fetchImpl: async (input, init) => {
      observedUrl = String(input);
      observedInit = init;
      const requestId = new Headers(init?.headers).get("x-request-id") ?? "";
      return new Response(
        JSON.stringify({
          guard_evidence_edition_id: "guard-edition-01",
          bundle_sha256: expectedDigest,
          edition_sha256: expectedEditionDigest,
          created_by: "collector-01",
          remote_anchor: signedAnchor({
            editionId: "guard-edition-01",
            projectId: "project-01",
            sessionId: fixtureSessionId(),
            bundleSha256: expectedDigest,
            editionSha256: expectedEditionDigest,
            retentionPolicyId: "local-digests-v1",
            createdBy: "collector-01",
          }),
        }),
        {
          status: 201,
          headers: { "content-type": "application/json", "x-request-id": requestId },
        },
      );
    },
  });
  assert.equal(
    observedUrl,
    "https://ingest.example.test/v1/projects/project-01/guard/evidence-editions",
  );
  const headers = observedInit?.headers as Record<string, string>;
  assert.equal(headers["authorization"], "Bearer service-account-secret");
  assert.equal(headers["x-request-id"], result.requestId);
  assert.match(headers["idempotency-key"] ?? "", /^[0-9a-f]{64}$/);
  const body = String(observedInit?.body);
  assert.ok(!body.includes("service-account-secret"));
  assert.deepEqual(JSON.parse(body), {
    bundle,
    rights: {
      evaluation: true,
      redistribution: false,
      derived_publication: false,
      training: false,
      raw_trajectory: false,
    },
    retention_policy_id: "local-digests-v1",
  });
  assert.equal(result.bundleSha256, expectedDigest);
  assert.equal(result.editionSha256, expectedEditionDigest);
  assert.equal(result.guardEvidenceEditionId, "guard-edition-01");
  assert.equal(result.statusCode, 201);
  assert.equal(result.remoteAnchorVerification.ok, true);
  assert.match(result.requestId, /^guard-upload-[0-9a-f]{32}$/);
});

test("managed upload accepts a locally verified G2 SDK bundle and binds its canonical digest", async () => {
  const bundle = fixtureBundle(SDK_FIXTURE);
  const expectedDigest = digestCanonical(bundle);
  const rights = {
    evaluation: true,
    redistribution: false,
    derived_publication: false,
    training: false,
    raw_trajectory: false,
  };
  const expectedEditionDigest = digestCanonical({
    schema_version: "gradia.guard.evidence-edition.v1",
    project_id: "project-01",
    bundle_sha256: expectedDigest,
    rights,
    retention_policy_id: "digest-only-v1",
    created_by: "collector-01",
  });
  const result = await uploadEvidenceBundle(SDK_FIXTURE, {
    apiBase: "https://ingest.example.test",
    projectId: "project-01",
    token: "service-account-secret",
    retentionPolicyId: "digest-only-v1",
    rights,
    fetchImpl: async (_input, init) => {
      assert.equal(String(init?.body).includes("fixture-case"), false);
      const requestId = new Headers(init?.headers).get("x-request-id") ?? "";
      return new Response(
        JSON.stringify({
          guard_evidence_edition_id: "guard-edition-sdk-01",
          bundle_sha256: expectedDigest,
          edition_sha256: expectedEditionDigest,
          created_by: "collector-01",
          remote_anchor: signedAnchor({
            editionId: "guard-edition-sdk-01",
            projectId: "project-01",
            sessionId: fixtureSessionId(SDK_FIXTURE),
            bundleSha256: expectedDigest,
            editionSha256: expectedEditionDigest,
            retentionPolicyId: "digest-only-v1",
            createdBy: "collector-01",
          }),
        }),
        { status: 201, headers: { "x-request-id": requestId } },
      );
    },
  });
  assert.equal(result.bundleSha256, expectedDigest);
  assert.equal(result.editionSha256, expectedEditionDigest);
});

test("managed upload refuses plaintext remote transport and server digest substitution", async () => {
  const options = {
    projectId: "project-01",
    token: "service-account-secret",
    retentionPolicyId: "local-digests-v1",
    rights: {
      evaluation: false,
      redistribution: false,
      derived_publication: false,
      training: false,
      raw_trajectory: false,
    },
  } as const;
  await assert.rejects(
    uploadEvidenceBundle(FIXTURE, { ...options, apiBase: "http://example.test" }),
    /upload_api_base_requires_https/,
  );
  await assert.rejects(
    uploadEvidenceBundle(FIXTURE, {
      ...options,
      apiBase: "https://ingest.example.test",
      fetchImpl: async (_input, init) => {
        const requestId = new Headers(init?.headers).get("x-request-id") ?? "";
        return new Response(
          JSON.stringify({
            guard_evidence_edition_id: "guard-edition-01",
            bundle_sha256: "0".repeat(64),
            edition_sha256: "0".repeat(64),
            created_by: "collector-01",
          }),
          { status: 201, headers: { "x-request-id": requestId } },
        );
      },
    }),
    /upload_bundle_digest_mismatch/,
  );
});
