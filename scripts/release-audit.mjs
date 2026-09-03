import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { relative, resolve } from "node:path";

const allowDirty = process.argv.slice(2).includes("--allow-dirty");
if (process.argv.length > (allowDirty ? 3 : 2)) refuse("release_audit_option_invalid");

const packageRoot = process.cwd();
const metadata = JSON.parse(readFileSync(resolve(packageRoot, "package.json"), "utf8"));
if (metadata.private !== false) refuse("release_audit_package_private");
if (metadata.license !== "Apache-2.0") refuse("release_audit_license_mismatch");
if (metadata.name !== "@gradia/guard") refuse("release_audit_package_name_mismatch");
if (metadata.version !== "0.1.0-beta.6") refuse("release_audit_version_mismatch");
if (metadata.publishConfig?.access !== "public" || metadata.publishConfig?.provenance !== true) {
  refuse("release_audit_publish_config_invalid");
}

let gitSha;
let gitRoot;
try {
  gitSha = git(["rev-parse", "--verify", "HEAD"]);
  gitRoot = git(["rev-parse", "--show-toplevel"]);
} catch {
  refuse("release_audit_git_state_unknown");
}
if (!/^[0-9a-f]{40}$/.test(gitSha)) refuse("release_audit_git_sha_invalid");

const packagePath = relative(gitRoot, packageRoot) || ".";
for (const sourceContract of [
  "action.yml",
  ".github/workflows/proof-pack.yml",
  "scripts/proof-pack-action.mjs",
  "test/fixtures/proof-pack-reference/manifest.json",
  "test/fixtures/proof-pack-reference/frames.ndjson",
]) {
  try {
    readFileSync(resolve(packageRoot, sourceContract));
  } catch {
    refuse(`release_audit_source_contract_missing:${sourceContract}`);
  }
}
let packageStatus;
try {
  packageStatus = execFileSync(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all", "--", packagePath],
    {
      cwd: gitRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  ).trim();
} catch {
  refuse("release_audit_git_status_unknown");
}
const packageClean = packageStatus.length === 0;
if (!packageClean && !allowDirty) refuse("release_audit_package_tree_dirty");

let pack;
try {
  const output = execFileSync(
    "npm",
    ["pack", "--dry-run", "--ignore-scripts", "--json"],
    { cwd: packageRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  const parsed = JSON.parse(output);
  if (!Array.isArray(parsed) || parsed.length !== 1) refuse("release_audit_pack_shape_invalid");
  pack = parsed[0];
} catch (error) {
  if (error instanceof Error && error.message.startsWith("release_audit_")) throw error;
  refuse("release_audit_pack_failed");
}

const files = pack.files?.map((item) => item.path).sort();
if (!Array.isArray(files) || files.length === 0) refuse("release_audit_pack_files_missing");
for (const required of [
  "CHANGELOG.md",
  "COMPATIBILITY.md",
  "CONTRIBUTING.md",
  "LICENSE",
  "NOTICE",
  "README.md",
  "SECURITY.md",
  "SUPPORT.md",
  "dist/src/cli.js",
  "dist/src/ag-ui.js",
  "dist/src/index.d.ts",
  "dist/src/index.js",
  "examples/copilotkit-proof-bound-ag-ui.mjs",
  "kubernetes/README.md",
  "package.json",
]) {
  if (!files.includes(required)) refuse(`release_audit_required_file_missing:${required}`);
}

const forbidden = files.filter(
  (path) =>
    /(^|\/)(?:node_modules|test|tests|scripts|results|private-provider|\.git)(?:\/|$)/.test(path) ||
    /(^|\/)(?:\.env(?:\.|$)|[^/]+\.(?:key|pem|p12|pfx))$/i.test(path),
);
if (forbidden.length) refuse(`release_audit_forbidden_file:${forbidden[0]}`);

const fileListSha256 = createHash("sha256").update(`${files.join("\n")}\n`).digest("hex");
process.stdout.write(
  `${JSON.stringify({
    schema_version: "gradia.guard.release-audit.v1",
    package_name: metadata.name,
    package_version: metadata.version,
    git_sha: gitSha,
    package_clean: packageClean,
    publishable: packageClean,
    file_count: files.length,
    file_list_sha256: fileListSha256,
    unpacked_size: pack.unpackedSize,
  })}\n`,
);

function git(args) {
  return execFileSync("git", args, {
    cwd: packageRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function refuse(message) {
  throw new Error(message);
}
