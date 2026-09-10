# Security policy

Please report suspected vulnerabilities privately through the repository's
GitHub Security Advisory flow. Do not include customer evidence, credentials,
raw trajectories, prompts, outputs, or private reasoning in an issue.

The default Python SDK writes only content length, media type, and SHA-256.
Identity and policy fields reject credential-shaped and private-reasoning field
names. Bundles are created in a new mode-`0700` directory with mode-`0600`
files, append-and-fsync frame writes, and atomic manifest replacement.

The SDK is voluntary G2 capture. It does not enforce network egress, filesystem
access, subprocess behavior, credential delivery, side effects, host isolation,
or complete world visibility. Use the measured Guard gateway/runtime for those
boundaries and retain the coverage declaration in every downstream claim.
