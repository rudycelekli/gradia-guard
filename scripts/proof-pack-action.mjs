import { appendFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  canonicalProofPackVerification,
  verifyProofPackDirectory,
} from "../dist/src/proof-pack.js";

const [directory, ...extra] = process.argv.slice(2);
if (!directory || extra.length > 0) {
  process.stderr.write("usage: proof-pack-action.mjs PROOF_PACK_DIR\n");
  process.exitCode = 2;
} else {
  const result = verifyProofPackDirectory(resolve(process.cwd(), directory));
  process.stdout.write(canonicalProofPackVerification(result));

  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      [
        `ok=${String(result.ok)}`,
        `manifest_sha256=${result.manifest_sha256 ?? ""}`,
        `frames_chain_head=${result.frames_chain_head ?? ""}`,
        "",
      ].join("\n"),
    );
  }

  if (process.env.GITHUB_STEP_SUMMARY) {
    const checks = Object.entries(result.aggregate_checks)
      .map(([name, ok]) => `| ${name} | ${ok ? "pass" : "refused"} |`)
      .join("\n");
    appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      [
        "## Gradia Proof Pack verification",
        "",
        `**Result:** ${result.ok ? "verified" : "refused"}`,
        "",
        `**Profile:** \`${result.profile ?? "unsupported"}\``,
        "",
        `**Manifest:** \`${result.manifest_sha256 ?? "unavailable"}\``,
        "",
        `**Frame-chain head:** \`${result.frames_chain_head ?? "unavailable"}\``,
        "",
        "| Derived surface | Result |",
        "| --- | --- |",
        checks,
        "",
        `**Claim boundary:** \`${result.claim_boundary}\``,
        "",
        ...(result.blockers.length
          ? ["**Blockers:**", "", ...result.blockers.map((item) => `- \`${item}\``), ""]
          : []),
      ].join("\n"),
    );
  }

  if (!result.ok) process.exitCode = 1;
}
