import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, digestCanonical, isSha256 } from "./canonical.js";

export const PROOF_PACK_VERIFICATION_SCHEMA_VERSION =
  "gradia.proof-pack.verification.v1" as const;
export const WIND_TUNNEL_FRAMES_SCHEMA_VERSION =
  "gradia-wind-tunnel-frames.v1" as const;
export const WIND_TUNNEL_MANIFEST_SCHEMA_VERSION =
  "gradia-wind-tunnel-evidence-manifest.v1" as const;

const EPISODE_KEYS = [
  "answer_sha256",
  "cost_usd",
  "factors",
  "favored_phrase",
  "is_exploit",
  "item_id",
  "judge_pass",
  "judge_score",
  "oracle_wrong",
  "rung",
  "transform_id",
] as const;
const FRAME_KEYS = [...EPISODE_KEYS, "frame_sha256"].sort();
const MAGNITUDE_LABELS = ["0.00-0.25", "0.25-0.50", "0.50-0.75", "0.75-1.01"] as const;
const STABLE_LABEL = /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$/;
const SHORT_CONTENT_DIGEST = /^[0-9a-f]{16}$/;

export interface ProofPackInput {
  manifest: unknown;
  frames: readonly unknown[];
  frameLogTerminated?: boolean;
}

export interface ProofPackVerification {
  schema_version: typeof PROOF_PACK_VERIFICATION_SCHEMA_VERSION;
  ok: boolean;
  blockers: readonly string[];
  profile: typeof WIND_TUNNEL_MANIFEST_SCHEMA_VERSION | null;
  run_id: string | null;
  benchmark_id: string | null;
  frame_count: number;
  frames_chain_head: string | null;
  manifest_sha256: string | null;
  aggregate_checks: {
    totals: boolean;
    density_by_rung: boolean;
    density_by_transform: boolean;
    density_by_benchmark: boolean;
    exploit_magnitude_hist: boolean;
  };
  claim_boundary: string;
}

interface Episode {
  answer_sha256: string;
  cost_usd: number;
  factors: Record<string, unknown>;
  favored_phrase: string | null;
  is_exploit: boolean;
  item_id: string;
  judge_pass: boolean;
  judge_score: number;
  oracle_wrong: boolean;
  rung: string;
  transform_id: string;
}

export function verifyProofPackDirectory(directory: string): ProofPackVerification {
  let manifest: unknown;
  try {
    manifest = JSON.parse(readFileSync(join(directory, "manifest.json"), "utf8")) as unknown;
  } catch {
    return proofPackResult(["proof_pack_manifest_unreadable"], null, [], null);
  }
  let raw: string;
  try {
    raw = readFileSync(join(directory, "frames.ndjson"), "utf8");
  } catch {
    return proofPackResult(["proof_pack_frame_log_unreadable"], record(manifest), [], null);
  }
  const blockers: string[] = [];
  const frames: unknown[] = [];
  if (raw.length > 0 && !raw.endsWith("\n")) blockers.push("proof_pack_frame_log_truncated");
  raw.split("\n").forEach((line, index) => {
    if (!line) return;
    try {
      const parsed = JSON.parse(line) as unknown;
      frames.push(parsed);
      if (canonicalJson(parsed) !== line) blockers.push(`proof_pack_frame_not_canonical:${index}`);
    } catch {
      blockers.push(`proof_pack_frame_json_invalid:${index}`);
    }
  });
  const result = verifyProofPack({
    manifest,
    frames,
    frameLogTerminated: raw.length === 0 || raw.endsWith("\n"),
  });
  return { ...result, blockers: [...new Set([...blockers, ...result.blockers])].sort(), ok: blockers.length === 0 && result.ok };
}

export function verifyProofPack(input: ProofPackInput): ProofPackVerification {
  const blockers: string[] = [];
  const manifest = record(input.manifest);
  if (!manifest) return proofPackResult(["proof_pack_manifest_shape_invalid"], null, input.frames, null);
  if (input.frameLogTerminated === false) blockers.push("proof_pack_frame_log_truncated");
  if (manifest["schema"] !== WIND_TUNNEL_MANIFEST_SCHEMA_VERSION) {
    blockers.push("proof_pack_profile_unsupported");
  }
  if (manifest["frames_schema"] !== WIND_TUNNEL_FRAMES_SCHEMA_VERSION) {
    blockers.push("proof_pack_frames_schema_invalid");
  }
  validateManifestIdentity(manifest, blockers);

  const episodes: Episode[] = [];
  let head = digestCanonical({ schema: WIND_TUNNEL_FRAMES_SCHEMA_VERSION });
  input.frames.forEach((value, index) => {
    const frame = record(value);
    if (!frame) {
      blockers.push(`proof_pack_frame_shape_invalid:${index}`);
      return;
    }
    const keys = Object.keys(frame).sort();
    if (canonicalJson(keys) !== canonicalJson(FRAME_KEYS)) {
      blockers.push(`proof_pack_frame_fields_invalid:${index}`);
    }
    const episodeValue = Object.fromEntries(EPISODE_KEYS.map((key) => [key, frame[key]]));
    const episode = parseEpisode(episodeValue, index, blockers);
    const expected = digestCanonical({ prev: head, episode: episodeValue });
    if (frame["frame_sha256"] !== expected) blockers.push(`proof_pack_frame_digest_mismatch:${index}`);
    head = expected;
    if (episode) episodes.push(episode);
  });
  if (input.frames.length === 0) blockers.push("proof_pack_frame_log_empty");
  if (manifest["frames_chain_head"] !== head) blockers.push("proof_pack_chain_head_mismatch");

  const aggregates = deriveAggregates(episodes, stringValue(manifest["benchmark_id"]));
  const aggregateChecks = {
    totals: canonicalJson(manifest["totals"]) === canonicalJson(aggregates.totals),
    density_by_rung:
      canonicalJson(manifest["density_by_rung"]) === canonicalJson(aggregates.density_by_rung),
    density_by_transform:
      canonicalJson(manifest["density_by_transform"]) === canonicalJson(aggregates.density_by_transform),
    density_by_benchmark:
      canonicalJson(manifest["density_by_benchmark"]) === canonicalJson(aggregates.density_by_benchmark),
    exploit_magnitude_hist:
      canonicalJson(manifest["exploit_magnitude_hist"]) ===
      canonicalJson(aggregates.exploit_magnitude_hist),
  };
  for (const [name, ok] of Object.entries(aggregateChecks)) {
    if (!ok) blockers.push(`proof_pack_aggregate_mismatch:${name}`);
  }

  const storedManifestSha = manifest["manifest_sha256"];
  const manifestBody = Object.fromEntries(
    Object.entries(manifest).filter(([key]) => key !== "manifest_sha256"),
  );
  if (!isSha256(storedManifestSha)) blockers.push("proof_pack_manifest_digest_invalid");
  else if (storedManifestSha !== digestCanonical(manifestBody)) {
    blockers.push("proof_pack_manifest_digest_mismatch");
  }
  return proofPackResult(blockers, manifest, input.frames, head, aggregateChecks);
}

function validateManifestIdentity(manifest: Record<string, unknown>, blockers: string[]): void {
  for (const name of ["run_id", "benchmark_id", "judge"] as const) {
    if (!isStableLabel(manifest[name])) blockers.push(`proof_pack_manifest_${name}_invalid`);
  }
  if (typeof manifest["interpretation"] !== "string" || manifest["interpretation"].length < 1 || manifest["interpretation"].length > 4000) {
    blockers.push("proof_pack_manifest_interpretation_invalid");
  }
  if (typeof manifest["benchmark_real"] !== "boolean") blockers.push("proof_pack_manifest_benchmark_real_invalid");
  const gitSha = manifest["git_sha"];
  if (typeof gitSha !== "string" || !/^[0-9a-f]{40}$/.test(gitSha)) blockers.push("proof_pack_manifest_git_sha_invalid");
  if (!isSha256(manifest["preregistration_sha256"])) blockers.push("proof_pack_manifest_preregistration_digest_invalid");
  const spend = record(manifest["spend"]);
  if (
    !spend ||
    Object.keys(spend).sort().join(",") !== "max_cost_usd,spent_usd" ||
    !isNonnegativeNumber(spend["max_cost_usd"]) ||
    !isNonnegativeNumber(spend["spent_usd"]) ||
    (typeof spend["spent_usd"] === "number" &&
      typeof spend["max_cost_usd"] === "number" &&
      spend["spent_usd"] > spend["max_cost_usd"])
  ) {
    blockers.push("proof_pack_manifest_spend_invalid");
  }
}

function parseEpisode(value: Record<string, unknown>, index: number, blockers: string[]): Episode | null {
  const factors = record(value["factors"]);
  const valid =
    typeof value["answer_sha256"] === "string" &&
    SHORT_CONTENT_DIGEST.test(value["answer_sha256"]) &&
    isNonnegativeNumber(value["cost_usd"]) &&
    factors !== null &&
    Object.keys(factors).every((key) => STABLE_LABEL.test(key)) &&
    (value["favored_phrase"] === null ||
      (typeof value["favored_phrase"] === "string" && value["favored_phrase"].length <= 4000)) &&
    typeof value["is_exploit"] === "boolean" &&
    isStableLabel(value["item_id"]) &&
    typeof value["judge_pass"] === "boolean" &&
    typeof value["judge_score"] === "number" &&
    Number.isFinite(value["judge_score"]) &&
    value["judge_score"] >= 0 &&
    value["judge_score"] <= 1 &&
    typeof value["oracle_wrong"] === "boolean" &&
    isStableLabel(value["rung"]) &&
    isStableLabel(value["transform_id"]);
  if (!valid) {
    blockers.push(`proof_pack_episode_invalid:${index}`);
    return null;
  }
  const episode = value as unknown as Episode;
  if (episode.is_exploit !== (episode.oracle_wrong && episode.judge_pass)) {
    blockers.push(`proof_pack_exploit_semantics_invalid:${index}`);
  }
  return episode;
}

function deriveAggregates(episodes: readonly Episode[], manifestBenchmark: string | null) {
  const bucket = (key: (episode: Episode) => string) => {
    const groups = new Map<string, Episode[]>();
    for (const episode of episodes) {
      const label = key(episode);
      groups.set(label, [...(groups.get(label) ?? []), episode]);
    }
    return Object.fromEntries(
      [...groups.entries()]
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([label, values]) => [label, aggregate(values)]),
    );
  };
  const histogram = Object.fromEntries(MAGNITUDE_LABELS.map((label) => [label, 0])) as Record<string, number>;
  for (const episode of episodes.filter((item) => item.is_exploit)) {
    const label =
      episode.judge_score < 0.25
        ? "0.00-0.25"
        : episode.judge_score < 0.5
          ? "0.25-0.50"
          : episode.judge_score < 0.75
            ? "0.50-0.75"
            : "0.75-1.01";
    histogram[label] = (histogram[label] ?? 0) + 1;
  }
  return {
    totals: {
      attempts: episodes.length,
      exploits: episodes.filter((item) => item.is_exploit).length,
      overall_density_per_1000: density(episodes),
      total_cost_usd: roundHalfEven(episodes.reduce((sum, item) => sum + item.cost_usd, 0), 4),
    },
    density_by_rung: bucket((item) => item.rung),
    density_by_transform: bucket((item) => item.transform_id),
    density_by_benchmark: bucket((item) => {
      const benchmark = item.factors["benchmark_id"];
      return typeof benchmark === "string" ? benchmark : (manifestBenchmark ?? "?");
    }),
    exploit_magnitude_hist: histogram,
  };
}

function aggregate(episodes: readonly Episode[]) {
  return {
    attempts: episodes.length,
    exploits: episodes.filter((item) => item.is_exploit).length,
    density_per_1000: density(episodes),
  };
}

function density(episodes: readonly Episode[]): number {
  if (episodes.length === 0) return 0;
  return roundHalfEven((1000 * episodes.filter((item) => item.is_exploit).length) / episodes.length, 1);
}

function roundHalfEven(value: number, places: number): number {
  const scale = 10 ** places;
  const scaled = value * scale;
  const floor = Math.floor(scaled);
  const fraction = scaled - floor;
  if (Math.abs(fraction - 0.5) <= Number.EPSILON * Math.max(1, Math.abs(scaled))) {
    return (floor % 2 === 0 ? floor : floor + 1) / scale;
  }
  return Math.round(scaled) / scale;
}

function proofPackResult(
  blockerValues: readonly string[],
  manifestValue: Record<string, unknown> | null,
  frames: readonly unknown[],
  head: string | null,
  aggregateChecks = {
    totals: false,
    density_by_rung: false,
    density_by_transform: false,
    density_by_benchmark: false,
    exploit_magnitude_hist: false,
  },
): ProofPackVerification {
  const blockers = [...new Set(blockerValues)].sort();
  const manifest = record(manifestValue);
  return {
    schema_version: PROOF_PACK_VERIFICATION_SCHEMA_VERSION,
    ok: blockers.length === 0,
    blockers,
    profile:
      manifest?.["schema"] === WIND_TUNNEL_MANIFEST_SCHEMA_VERSION
        ? WIND_TUNNEL_MANIFEST_SCHEMA_VERSION
        : null,
    run_id: stringValue(manifest?.["run_id"]),
    benchmark_id: stringValue(manifest?.["benchmark_id"]),
    frame_count: frames.length,
    frames_chain_head: isSha256(head) ? head : null,
    manifest_sha256: isSha256(manifest?.["manifest_sha256"])
      ? (manifest["manifest_sha256"] as string)
      : null,
    aggregate_checks: aggregateChecks,
    claim_boundary:
      "integrity_and_declared_aggregate_derivation_only;not_authorship_timestamp_rights_runtime_enforcement_or_scientific_validity",
  };
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function isStableLabel(value: unknown): value is string {
  return typeof value === "string" && STABLE_LABEL.test(value);
}

function isNonnegativeNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

export function canonicalProofPackVerification(result: ProofPackVerification): string {
  return `${canonicalJson(result)}\n`;
}
