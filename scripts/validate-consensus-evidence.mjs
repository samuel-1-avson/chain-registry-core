#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

function usage() {
  console.log(`Usage: node scripts/validate-consensus-evidence.mjs [--fixtures-dir DIR] [--print-digests]

Validates the scanner-profile and evidence-bundle fixtures used by the
evidence-bound validator vote path.`);
}

let fixturesDir = "config/consensus-evidence/fixtures";
let printDigests = false;

for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  if (arg === "--fixtures-dir") {
    fixturesDir = process.argv[++i];
    if (!fixturesDir) {
      throw new Error("--fixtures-dir requires a value");
    }
  } else if (arg === "--print-digests") {
    printDigests = true;
  } else if (arg === "--help" || arg === "-h") {
    usage();
    process.exit(0);
  } else {
    throw new Error(`unknown argument: ${arg}`);
  }
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function stable(value) {
  if (Array.isArray(value)) {
    return value.map(stable);
  }
  if (value && typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = stable(value[key]);
        return acc;
      }, {});
  }
  return value;
}

function requireString(value, path) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${path} must be a non-empty string`);
  }
}

function requireDigest(value, path) {
  requireString(value, path);
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${path} must be a lowercase sha256 hex digest`);
  }
}

function requireSignatureList(value, path) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${path} must contain at least one signature reference`);
  }
  for (const [index, sig] of value.entries()) {
    requireString(sig.key_id, `${path}[${index}].key_id`);
    if (sig.algorithm !== "ed25519") {
      throw new Error(`${path}[${index}].algorithm must be ed25519`);
    }
    requireString(sig.signature, `${path}[${index}].signature`);
  }
}

function effectiveOsvEpoch(bundles) {
  const osv = bundles?.osv_snapshot_epoch;
  if (typeof osv === "string" && osv.trim() !== "") {
    return osv.trim();
  }
  return "osv-off";
}

function validateAnalysisBundles(bundles, path) {
  for (const key of [
    "policy_bundle_id",
    "feature_schema_id",
    "expert_bundle_id",
    "embedding_model_id",
    "index_epoch",
    "threshold_profile_id",
    "llm_prompt_profile_id",
    "osv_snapshot_epoch",
  ]) {
    requireString(bundles?.[key], `${path}.${key}`);
  }
}

readJson("config/consensus-evidence/scanner-profile.schema.json");
readJson("config/consensus-evidence/evidence-bundle.schema.json");

const profile = readJson(join(fixturesDir, "valid-scanner-profile.json"));
const evidence = readJson(join(fixturesDir, "valid-evidence-bundle.json"));

if (profile.schema_version !== 1) {
  throw new Error("scanner profile schema_version must be 1");
}
requireString(profile.profile_id, "profile.profile_id");
requireString(profile.scanner_version, "profile.scanner_version");
if (profile.scanner_version.startsWith("degraded")) {
  throw new Error("scanner profile must not use a degraded scanner_version");
}
validateAnalysisBundles(profile.analysis_bundles, "profile.analysis_bundles");
requireDigest(profile.profile_digest, "profile.profile_digest");
requireSignatureList(profile.signed_by, "profile.signed_by");

const b = profile.analysis_bundles;
const profileInput = [
  "creg-scanner-profile-v1",
  `scanner=${profile.scanner_version.trim()}`,
  `policy=${b.policy_bundle_id.trim()}`,
  `features=${b.feature_schema_id.trim()}`,
  `experts=${b.expert_bundle_id.trim()}`,
  `embedding=${b.embedding_model_id.trim()}`,
  `index=${b.index_epoch.trim()}`,
  `thresholds=${b.threshold_profile_id.trim()}`,
  `llm_prompt=${b.llm_prompt_profile_id.trim()}`,
  `osv=${effectiveOsvEpoch(b)}`,
].join("|");
const computedProfileDigest = sha256Hex(profileInput);

if (computedProfileDigest !== profile.profile_digest) {
  throw new Error(
    `scanner profile digest mismatch: declared=${profile.profile_digest} computed=${computedProfileDigest}`,
  );
}

if (evidence.schema_version !== 1) {
  throw new Error("evidence bundle schema_version must be 1");
}
requireString(evidence.evidence_bundle_id, "evidence.evidence_bundle_id");
requireString(evidence.package?.ecosystem, "evidence.package.ecosystem");
requireString(evidence.package?.name, "evidence.package.name");
requireString(evidence.package?.version, "evidence.package.version");
requireString(evidence.package?.canonical, "evidence.package.canonical");
requireDigest(evidence.package?.content_hash, "evidence.package.content_hash");
requireDigest(evidence.scanner_profile_digest, "evidence.scanner_profile_digest");
validateAnalysisBundles(evidence.analysis_bundles, "evidence.analysis_bundles");
requireDigest(evidence.evidence_digest, "evidence.evidence_digest");
requireSignatureList(evidence.signed_by, "evidence.signed_by");

if (evidence.scanner_profile_digest !== profile.profile_digest) {
  throw new Error("evidence bundle does not reference the scanner profile digest");
}

const canonical = `${evidence.package.ecosystem}:${evidence.package.name}@${evidence.package.version}`;
if (evidence.package.canonical !== canonical) {
  throw new Error(`package canonical mismatch: expected ${canonical}`);
}

const evidenceForDigest = structuredClone(evidence);
delete evidenceForDigest.evidence_digest;
delete evidenceForDigest.signed_by;
const computedEvidenceDigest = sha256Hex(JSON.stringify(stable(evidenceForDigest)));

if (printDigests) {
  console.log(`profile_digest=${computedProfileDigest}`);
  console.log(`evidence_digest=${computedEvidenceDigest}`);
}

if (computedEvidenceDigest !== evidence.evidence_digest) {
  throw new Error(
    `evidence digest mismatch: declared=${evidence.evidence_digest} computed=${computedEvidenceDigest}`,
  );
}

console.log("consensus evidence fixtures are valid");
