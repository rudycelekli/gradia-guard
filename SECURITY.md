# Security policy

## Supported release

Security fixes are provided for the newest `0.1.x` beta release. Beta APIs may
change according to `COMPATIBILITY.md`; a security fix never silently expands
an evidence claim or treats an uncovered surface as covered.

## Report a vulnerability

Do not open a public issue for a vulnerability, credential, customer artifact,
or suspected data exposure. Use the private **Report a vulnerability** flow in
the GitHub Security tab for `rudycelekli/gradia-guard`. Include:

- affected version and operating system;
- the smallest safe reproduction;
- whether confidentiality, integrity, authorization, or evidence coverage is
  affected; and
- whether a public proof of concept already exists.

Do not include live credentials, raw customer traces, or personal data. Gradia
will acknowledge a valid private report as soon as practical, coordinate a fix
and disclosure window, and credit the reporter if requested. This community
policy is not a contractual response-time or remediation-time SLO.

## Security boundary

The one-line wrapper and voluntary SDK are bypassable. They observe only calls
that cross their explicit boundary. Container and Kubernetes receipts cover
only the exact measured runtime and finite bypass probes recorded in the
receipt; they do not prove kernel-complete capture or eliminate operator,
daemon, node, or cluster-administrator bypass. Managed admission independently
reverifies submitted artifacts but cannot repair missing source coverage.

Telemetry is off by default. Local content capture is digest-only by default.
Never place secrets in actor identifiers, policy files, CLI arguments, evidence
metadata, or issue reports.
