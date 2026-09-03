# `@gradia/guard`

[![Guard CI](https://github.com/rudycelekli/gradia-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rudycelekli/gradia-guard/actions/workflows/ci.yml)
[![Proof Pack](https://github.com/rudycelekli/gradia-guard/actions/workflows/proof-pack.yml/badge.svg)](https://github.com/rudycelekli/gradia-guard/actions/workflows/proof-pack.yml)

> Apache-2.0 public beta. The local SDK and verifier are useful without an
> account; managed availability never upgrades evidence coverage or claim
> truth. A wrapper or voluntary SDK remains bypassable unless a separately
> measured enforcing runtime proves a stronger boundary.

Gradia Guard is a proof-bound evidence recorder and verifier for AI-system
execution. Its optional AG-UI edge uses one exact runtime dependency,
`@ag-ui/core==0.0.59`, so projected events are checked against the upstream
wire schema as well as Guard's stricter authority and evidence rules.

## Proof-bound CopilotKit / AG-UI edge

CopilotKit can provide the operator experience—live progress, rendered tool
activity, and human steering—without becoming the source of tool authority.
The Guard client verifies fragmented SSE before yielding an event, creates
canonical proposals, and verifies the action receipt returned by Gradia:

```ts
import {
  createProofBoundAguiProposal,
  parseProofBoundAguiSseStream,
  verifyProofBoundAguiActionReceipt,
} from "@gradia/guard";
```

The complete server-side example is
[`examples/copilotkit-proof-bound-ag-ui.mjs`](examples/copilotkit-proof-bound-ag-ui.mjs).
Only exact `steer` and `cancel` proposals currently cross the human-authorized
canonical action bridge. Browser tools, generic approvals, tool dispatch and
state patches remain non-authoritative. Frozen Universe tool contracts,
authenticated connectors, Guard pre-dispatch policy and canonical runtime
receipts—not CopilotKit registration—establish that a tool is correct and that
an observed effect occurred.

Python applications can use the source-complete beta in
`packages/guard-python`. It emits this package's exact
`gradia.guard.sdk-bundle.v1` ABI: either language's independent verifier can
replay either language's bundle. The Python candidate is not published to
PyPI, and its tested automatic framework cell is limited to
`langchain-core==1.6.1`; those boundaries are not implied away by ABI parity.

```bash
npx @gradia/guard run -- node agent.js
npx @gradia/guard verify .gradia/evidence/node-<session-id>
npx @gradia/guard proof-pack verify path/to/proof-pack
npx @gradia/guard inspect .gradia/evidence/node-<session-id>
npx @gradia/guard doctor
npx @gradia/guard capabilities --json
npx @gradia/guard anchor verify-guard --anchor anchor.json --public-key-ed25519 PINNED_HEX \
  --edition EDITION --project PROJECT --session SESSION --bundle-sha256 BUNDLE_SHA \
  --edition-sha256 EDITION_SHA --retention-policy POLICY --created-by COLLECTOR
npx @gradia/guard actors .gradia/evidence/sdk-<session-id>
npx @gradia/guard compare .gradia/evidence/before .gradia/evidence/after
```

Before the npm beta is published, the exact tagged public source release can be
installed with `npm install github:rudycelekli/gradia-guard#v0.1.0-beta.6`.
Registry publication is a separate signed release event and is never inferred
from this README.

For the authenticated managed beta, use the generated
[Guard API documentation](https://api-production-1634.up.railway.app/docs/guard). The API
publishes a focused generated schema at `/openapi/guard.json` and interactive
documentation at `/docs/guard`. Uploads are locally verified, HTTPS-only
outside loopback, retry-safe for the exact bundle/rights intent, correlated by
request id, and independently reverified by the server.

The wrapper records a hash-chained decision/action history for process dispatch, lifecycle, stdout, and stderr. Output bytes pass through normally; the default spool stores only byte lengths and SHA-256 digests.

`doctor` is local and performs no network call. It checks the supported Node
runtime and makes the safe defaults explicit: telemetry off, digest-only
content, no managed connection, and a G0 explicit-process ceiling. Installing
the package does not by itself make an arbitrary agent fully governed.

`inspect` is local and account-free. It verifies first, then prints what the
bundle captured, what remained invisible, its exact assurance ceiling, and the
next integration that would materially improve coverage. A tampered bundle is
refused before its declared coverage is displayed.

`compare` verifies two bundles and reports structural, coverage, frame-count,
and digest-identity changes locally. It deliberately does not call those
differences a behavioral regression: pass, drift, and regression require a
separately admitted frozen evaluation contract in managed Gradia.

`proof-pack verify` is also local, account-free, and telemetry-free. Its first
versioned profile independently replays the Reward-Hacking Wind Tunnel's
`frames.ndjson` and `manifest.json`: frame chain, exploit semantics,
attempt/exploit/cost totals, every density slice, magnitude histogram, and
manifest self-digest. A green result proves those bytes are internally intact
and the declared aggregates derive from them. It does not prove who authored or
timestamped them, that their data may be used, that the runtime was enforced,
or that the study is scientifically valid. The authenticated managed
`POST /v1/proof-packs/verify` route returns the same bounded verification and
stores nothing.

The repository also publishes a reusable account-free action pinned to the
same verifier source:

```yaml
- uses: actions/checkout@v6
- uses: rudycelekli/gradia-guard@v0.1.0-beta.6
  id: proof
  with:
    proof-pack: path/to/proof-pack
```

The action fails the job on any blocker and exposes only `ok`,
`manifest-sha256`, and `frames-chain-head`. Its job summary repeats the narrow
claim boundary; a green badge is not a certificate, rights decision, trusted
timestamp, runtime-enforcement claim, or scientific-validity judgment.

`capabilities` is an account-free, canonical product-boundary catalog. It keeps
local run, bundle/Proof-Pack verify, inspect, compare, actor-graph, evidence-readiness, policy,
explicit-adapter, and portable-anchor verification useful without a managed
account. It separately lists repository-implemented managed surfaces whose
availability remains deployment- and authorization-specific: authenticated
ingestion, remote-anchor issuance, retention declarations, human review,
Analytics+, regression evaluation, certification, and Universe composition.

The catalog encodes the commercial invariant directly: payment can change
service availability, but it cannot change evidence coverage, claim truth, or
admission-gate outcomes. A managed operation may support a stronger claim only
when it actually executes and emits new verified evidence. A retention policy
identifier remains a declaration rather than deletion, residency, or execution
proof. The package is Apache-2.0 and beta-versioned. The static catalog does not
claim that a registry publication occurred; verify the installed tarball,
version, provenance, and release digest independently.

## Portable anchor verification

Managed anchors remain verifiable without a Gradia account or network call. The
CLI requires the full independently pinned 32-byte Ed25519 public key and every
required artifact binding; it never treats the public key or short key ID
carried inside an anchor as a trust root by itself. A substituted key plus a
freshly signed payload therefore fails before any verified result is printed.

```bash
npx @gradia/guard anchor verify-universe \
  --anchor universe-anchor.json \
  --public-key-ed25519 PINNED_PUBLIC_KEY_HEX \
  --project PROJECT_ID \
  --run RUN_ID \
  --episode EPISODE_ID \
  --task TASK_ID \
  --scenario-digest SCENARIO_SHA256
```

The Guard-edition verifier returns only an admitted-edition and retention-
declaration result; it never upgrades the declaration into retention execution,
deletion, or residency proof. The Universe verifier reports only the signed
evolution-witness and snapshot/restore booleans. Counterfactual pairing and full
host enforcement remain `false` unless a future independently verified schema
can carry those stronger receipts.

`actors` verifies an SDK bundle before deriving a payload-free graph of the
actor and principal labels declared by the application. It reports root
operations, declared parent links, cross-actor links, parent execution state,
and maximum declared-parent depth without uploading prompts or outputs. G2
does not authenticate those labels, and a parent link proves neither delegation
nor causal contribution. Activity, message volume, team success, and centrality
never become competence or quality claims; those require a controlled
counterfactual receipt from a frozen Gradia Universe. Actor and principal IDs
remain plaintext metadata in the local report, so they must never contain
secrets or unnecessary personal data.

## Local evidence readiness

Guard can map a verified bundle's exact observed surfaces to an organization-
controlled evidence profile without an account:

```bash
npx @gradia/guard readiness init --out gradia-evidence-profile.json
npx @gradia/guard readiness verify gradia-evidence-profile.json
npx @gradia/guard readiness assess gradia-evidence-profile.json BUNDLE_DIR
```

Profiles carry opaque external control references and an optional digest of the
customer's licensed source bytes; Guard does not reproduce external standard
text. The assessment reports `evidence_ready`, `partial`, `missing`, or
`indeterminate` only after bundle verification. Evidence-ready means the
declared surfaces are present. It does not mean a control is effective, a law is
satisfied, an auditor has accepted the evidence, or an organization is
certified.

## Local policy and simulation

Guard includes an account-free, deny-by-default policy format for exact model
and registered-tool routes. Policies bind exact version pins, authority scopes,
request-size limits, attempt limits, and a canonical self-digest. The local
simulator returns the same typed pre-dispatch policy input consumed by the G1
gateway and G2 SDK recorders.

```bash
npx @gradia/guard policy init --out gradia-guard-policy.json
npx @gradia/guard policy verify gradia-guard-policy.json
npx @gradia/guard policy check-model gradia-guard-policy.json \
  --provider openai \
  --model gpt-5.6-2026-08-01 \
  --request-bytes 2048 \
  --attempt 1 \
  --scope case.read
```

The starter policy allows nothing. Add only routes and scopes your application
has approved, then seal the new digest. This is a local policy simulator, not a
network interceptor: it governs a dispatch only when the caller actually uses
its decision before dispatch. Calls made around Guard remain invisible and
unenforced.

## Authenticated workload identity contract

The package can issue and verify a short-lived Ed25519 workload identity. The
signed claims bind an issuer, organization, project, workload, deployment,
audience, exact policy, image, configuration, collector, authority scopes, and
validity window. Verification requires an explicitly trusted issuer key and an
exact expected deployment context.

```ts
import { verifyWorkloadIdentity } from "@gradia/guard";

const verified = verifyWorkloadIdentity(identity, {
  trustedPublicKeys: { "issuer-key-v1": issuerPublicKey },
  expectation: exactDeploymentExpectation,
  nowUnix: Math.floor(Date.now() / 1000),
  maxLifetimeSeconds: 600,
});
```

This contract proves that a trusted issuer signed those exact claims and that
the identity is currently eligible under the verifier's expectations. It does
not prove that a process used the named image or collector. The authenticated
dispatch helper below consumes the identity before a covered provider call;
root-owned runtime attestation is still required to prove that the named image,
configuration and collector actually ran.

## Authenticated provider dispatch

`AuthenticatedProviderGateway` composes the signed workload identity, sealed
deny-by-default policy, strict native provider adapters and G1 recorder into one
pre-dispatch boundary. Invalid identity or denied policy records a censored
attempt and never calls the supplied upstream transport. A provider-resolved
model substitution is recorded and its response is withheld from the caller.

```ts
import { AuthenticatedProviderGateway } from "@gradia/guard";

const gateway = new AuthenticatedProviderGateway({
  directory: ".gradia/evidence/gateway-run-1",
  policy: exactSealedPolicy,
  workloadIdentity: shortLivedIdentity,
  trustedPublicKeys,
  workloadExpectation: exactDeploymentExpectation,
  maxIdentityLifetimeSeconds: 600,
  upstreamDispatch: async ({ provider, requestedModel, requestBody }) => {
    // The credential stays in this root-owned closure. The callback receives
    // no header or credential field and returns the exact native wire response.
    return sendWithRootHeldCredential(provider, requestedModel, requestBody);
  },
});

const result = await gateway.dispatch(exactProviderRequest);
gateway.finalize();
```

This is an enforcing boundary only for calls routed through this object. It is
not yet an HTTP reverse proxy or network interceptor, and it cannot stop the
surrounding process from calling a provider directly. Every resulting G1
bundle therefore retains `bypass_possible: true`. Container/network policy and
root-owned runtime measurement are the separate proof needed to remove that
gap.

## Covered local egress and MCP enforcement

`LocalHttpEgressDispatcher` is the package's stronger local model-egress
boundary. Before its transport can run, it verifies the short-lived signed
workload identity, its exact sealed policy and configuration digests, authority
scopes, model pin, provider, request limit, attempt limit, media type, and one
canonical HTTPS target URL. Its supplied fetch transport sets
`redirect: "manual"`, refuses redirect and final-URL substitution, caps response
bytes, and receives credentials only from a closure whose headers are never
part of Guard's request or receipt schemas. Requested and provider-resolved
model substitution is withheld and fails offline evidence verification.
The credential closure is authentication-only: OpenAI and xAI accept only
`authorization`, Anthropic accepts only `x-api-key`, and Gemini accepts only
`x-goog-api-key`. Guard refuses cookies, forwarding/routing headers, tenant or
organization selectors, request-semantic headers, missing or case-insensitive
duplicate authentication headers, control characters, and non-canonical credential
values before `fetch` runs. Supporting another authentication scheme therefore
requires an explicit versioned Guard change instead of an unrecorded header
escape hatch.

```ts
import {
  createNoRedirectFetchTransport,
  LocalHttpEgressDispatcher,
} from "@gradia/guard";

const dispatcher = new LocalHttpEgressDispatcher({
  directory: ".gradia/evidence/covered-model-call",
  policy: exactSealedPolicy,
  configuration: exactSealedHttpConfiguration,
  workloadIdentity: shortLivedIdentity,
  trustedPublicKeys,
  workloadExpectation: exactDeploymentExpectation,
  maxIdentityLifetimeSeconds: 600,
  transport: createNoRedirectFetchTransport({
    credentialHeaders: () => ({ authorization: rootHeldAuthorization }),
  }),
});

const result = await dispatcher.dispatch(exactConfiguredRequest);
dispatcher.finalize();
```

`AuthenticatedMcpToolAdapter` provides the corresponding covered MCP call
boundary. It permits invocation only when the signed identity, policy digest,
canonical scopes, MCP server/registry ID, tool ID, exact tool version, interface
digest, request limit, and attempt number all match. It passes no credential or
header field to the recorder. Server, tool, version, or interface substitution
is withheld and makes the G2 bundle fail closed.

```ts
import { AuthenticatedMcpToolAdapter } from "@gradia/guard";

const tools = new AuthenticatedMcpToolAdapter({
  directory: ".gradia/evidence/covered-tool-call",
  policy: exactSealedPolicy,
  workloadIdentity: shortLivedIdentity,
  trustedPublicKeys,
  workloadExpectation: exactDeploymentExpectation,
  maxIdentityLifetimeSeconds: 600,
  invokeTool: exactRegisteredMcpInvoker,
});

const result = await tools.invoke(exactRegisteredToolRequest);
tools.finalize();
```

These are enforcing boundaries only for traffic routed through the dispatcher
and tools invoked through the adapter. Their self-digested boundary attestations
always say `bypass_possible: true`, `full_host_enforcement: false`, and
`kubernetes_network_policy_enforced: false`; changing those fields fails
verification. They are not an operating-system proxy, transparent interceptor,
DNS pinning layer, host firewall, Kubernetes NetworkPolicy, MCP discovery
client, or proof that uninstrumented I/O did not happen. A surrounding process
can bypass them unless a separately measured runtime and network policy remove
that route.

### Exact-route MCP 2026 HTTP proxy

`startAuthenticatedMcpHttpProxy` exposes one authenticated IPv4-loopback MCP
endpoint per sealed server ID. It implements the stateless MCP `2026-07-28`
`server/discover`, `tools/list`, and `tools/call` subset. Protocol, method, and
tool-name headers must agree with the JSON-RPC body; the per-request metadata
envelope must pin the same protocol revision; browser `Origin` requests are
refused; and a random local bearer capability is required before parsing. A
caller supplies only the tool name and arguments. Server ID, exact tool
version, interface digest, scopes, policy, and authenticated workload identity
come from the sealed parent configuration and are consumed before the root-held
invoker can run. Tool arguments and results enter the G2 bundle only as content
digests.

```ts
import {
  McpHttpAccessRecorder,
  sealMcpHttpProxyConfiguration,
  startAuthenticatedMcpHttpProxy,
  verifyMcpHttpAccessBundleDirectory,
} from "@gradia/guard";

const mcpConfiguration = sealMcpHttpProxyConfiguration(exactMcpConfigurationBody);
const proxy = await startAuthenticatedMcpHttpProxy({
  directory: ".gradia/evidence/mcp-proxy-1",
  policy: exactSealedPolicy,
  configuration: mcpConfiguration,
  workloadIdentity: shortLivedIdentity,
  trustedPublicKeys,
  workloadExpectation: exactDeploymentExpectation,
  maxIdentityLifetimeSeconds: 600,
  invokeTool: rootHeldExactMcpInvoker,
});

const childEnvironment = proxy.childEnvironment("case-tools");
// Configure a modern MCP client with this endpoint, authorization header,
// and exact protocol version.

const closed = await proxy.close();
const access = verifyMcpHttpAccessBundleDirectory(
  closed.http_access_bundle_directory,
);
if (!access.ok) throw new Error(access.blockers.join(","));
```

Every request that reaches the Node HTTP request listener is appended and
`fsync`ed before its response. The access receipt binds the exact sealed
configuration, policy, and startup-verified workload identity; request method,
target, header shape, body digest and byte lengths; authorization and Origin
*presence* (never values); a closed reason code; HTTP status; route-target
digest; upstream-invocation state; and the SDK occurrence digest when one
exists. Finalization seals the ordered receipt chain and derived counters, and
`verifyMcpHttpAccessBundleDirectory` independently compares the canonical
header, append journal, final bundle, hashes, order, timestamps and counts.
Origin/authentication, HTTP method/content type, target, body/envelope,
protocol/header, unsupported RPC method, unlisted tool, policy, adapter and
successful metadata/tool outcomes are distinct.

If the process exits before `close()`, a new process may recover the exact v2
access directory. Recovery replays the header and complete canonical journal,
forbids further appends, and writes the final bundle through an exclusive
atomic link so two recovery workers cannot overwrite each other:

```ts
const interrupted = McpHttpAccessRecorder.recover(
  ".gradia/evidence/mcp-proxy-1/mcp-http-access",
  () => new Date().toISOString(),
);
const recoveredBundle = interrupted.finalize();
if (recoveredBundle.finalization.schema_version !==
    "gradia.guard.mcp-http-access-finalization.v2" ||
    recoveredBundle.finalization.terminal_status !== "recovered_interruption") {
  throw new Error("unexpected_recovery_state");
}
```

The account-free equivalents are:

```sh
gradia-guard mcp-http recover .gradia/evidence/mcp-proxy-1/mcp-http-access
gradia-guard mcp-http verify .gradia/evidence/mcp-proxy-1/mcp-http-access
```

Finalized beta.3 v1 bundles remain verifiable. An unfinalized v1 prefix is
refused because its signed header explicitly fixed recovery support to false.
`recovered_interruption` is a recorder-lifecycle fact, not proof of an
operating-system crash. Recovery cannot resume the proxy or reconstruct a
request that never became a durable receipt.

If every request is refused before a tool decision, `close()` returns
`sdk_bundle_directory: null` and no empty SDK evidence bundle is fabricated;
the HTTP access bundle remains complete for the observed listener boundary.
Socket-parser failures, requests outside this proxy and a process crash before
a receipt is durable remain explicitly unobserved; clean or recovered
finalization cannot prove those events did not occur.

This first proxy edition deliberately supports only MCP `2026-07-28`; it is not
a compatibility claim for handshake-era clients, streaming subscriptions,
multi-round-trip input, browser clients, or every MCP extension. Unlisted tool
names, malformed/header-confused traffic, and unauthorized HTTP requests are
refused before the invoker. Only policy-bound tool attempts become G2 receipts;
pre-tool HTTP requests instead enter the separate verified access chain rather
than being relabeled as G2 tool decisions. Setting the endpoint in a client is
automatic routing, not
non-bypassability: direct network or stdio MCP paths remain possible until a
separately proved runtime blocks them.

### Authenticated MCP stdio child proxy

`startAuthenticatedMcpStdioProxy` starts one declared absolute child executable
with an empty environment and exposes a serialized, stateless,
newline-delimited JSON-RPC `tools/call` boundary. The sealed configuration,
deny-by-default policy, and short-lived signed workload identity must all agree
before the child is spawned. Every allowed or blocked authorization is appended
and `fsync`ed before Guard can call the child's stdin writer; terminal receipts
then bind the exact SDK occurrence and whether that write call occurred. Raw
arguments and results are not retained by the stdio access journal.

```ts
import {
  sealMcpStdioProxyConfiguration,
  startAuthenticatedMcpStdioProxy,
  verifyMcpStdioAccessBundleDirectory,
} from "@gradia/guard";

const configuration = sealMcpStdioProxyConfiguration(exactStdioConfigurationBody);
const proxy = await startAuthenticatedMcpStdioProxy({
  directory: ".gradia/evidence/mcp-stdio-1",
  policy: exactSealedPolicy,
  configuration,
  workloadIdentity: shortLivedIdentity,
  trustedPublicKeys,
  workloadExpectation: exactDeploymentExpectation,
  maxIdentityLifetimeSeconds: 600,
  command: "/absolute/path/to/mcp-server",
  args: [],
});

const result = await proxy.invoke(exactRegisteredToolRequest);
const closed = await proxy.close();
const access = verifyMcpStdioAccessBundleDirectory(
  closed.stdio_access_bundle_directory,
);
if (!access.ok) throw new Error(access.blockers.join(","));
```

Interrupted durable prefixes can be closed without inventing a successful or
failed tool outcome:

```sh
gradia-guard mcp-stdio recover .gradia/evidence/mcp-stdio-1/mcp-stdio-access
gradia-guard mcp-stdio verify .gradia/evidence/mcp-stdio-1/mcp-stdio-access
```

Recovery labels every open transaction `interrupted_unknown`, sets the SDK
occurrence and child-write fact to `null`, and atomically refuses overwrite.
The protocol subset deliberately excludes `initialize`, `initialized`,
discovery, notifications, streaming, and multi-round exchanges. The child
launch digest binds the declared path, arguments, empty environment, and
`shell: false`; it does not attest executable bytes or child identity. Direct
processes, other stdio paths, and parent failure before authorization `fsync`
remain outside coverage. Consequently this is an enforceable boundary for the
one spawned child, not a host, container, or Kubernetes non-bypassability claim.

The source release gate also runs one exact upstream compatibility cell against
the actual `@modelcontextprotocol/server-everything==2026.8.31` package over
stdio and its `echo` tool. That cell verifies the returned content, the SDK and
stdio-access chains, and absence of the raw request marker from the access
journal. The upstream package is a pinned development-only dependency; this
single cell does not broaden the protocol or non-bypassability claims above.

### Parent-owned provider-credentialless child boundary

`runProviderCredentiallessChild` composes the process wrapper and authenticated
HTTP dispatcher into a stronger local launch primitive. The parent binds an
IPv4-loopback gateway, creates a random per-run bearer capability, and starts an
absolute child executable with an explicit environment containing only the
gateway origin, runtime ID, provider SDK base URLs, and provider-shaped SDK
authentication variables whose values are the same random local capability.
Provider credentials remain in
the parent transport closure and are not forwarded in the child argv or in the
environment supplied by Guard.

```ts
import {
  createNoRedirectFetchTransport,
  runProviderCredentiallessChild,
} from "@gradia/guard";

const run = await runProviderCredentiallessChild({
  directory: ".gradia/evidence/credentialless-run-1",
  command: ["/absolute/path/to/node", "/absolute/path/to/agent.js"],
  policy: exactSealedPolicy,
  configuration: exactSealedHttpConfiguration,
  workloadIdentity: shortLivedIdentity,
  trustedPublicKeys,
  workloadExpectation: exactDeploymentExpectation,
  maxIdentityLifetimeSeconds: 600,
  transport: createNoRedirectFetchTransport({
    credentialHeaders: ({ provider }) => {
      if (provider === "anthropic") return { "x-api-key": parentHeldProviderKey };
      if (provider === "gemini") return { "x-goog-api-key": parentHeldProviderKey };
      return { authorization: `Bearer ${parentHeldProviderKey}` };
    },
  }),
});

if (!run.verification.ok) throw new Error(run.verification.blockers.join(","));
```

The explicit child API remains `POST /v1/model-dispatch`. The same gateway now
also serves OpenAI Responses, xAI Responses, Anthropic Messages, and Gemini
`generateContent` request shapes at provider-specific loopback paths. The
parent—not the child—maps those paths and pinned model bytes to one exact sealed
upstream target and policy route. The four native wire shapes, wrong local
credentials, unlisted models, and unsupported-path behavior are exercised by
the package suite. The suite also runs the real pinned clients through that
boundary: `@anthropic-ai/sdk@0.122.0` Messages,
`@google/genai@2.19.0` `generateContent`, `openai@7.8.0` Responses, and
the same OpenAI client against xAI's Responses-compatible route. Retries are
disabled so one application call must correspond to one admitted Guard call.

```bash
gradia-guard sdk-matrix
gradia-guard sdk-matrix --json
```

The canonical matrix is self-digested and names xAI accurately as
OpenAI-compatible rather than an official xAI SDK. It proves only those exact
package versions reaching the local Guard gateway. It does not prove live
provider behavior, arbitrary older/newer SDK compatibility, other framework
wrappers, or non-bypassability outside an enforced runtime.

The monorepo has a separate cross-language compatibility gate for the exact
Python live extra. It launches `anthropic==0.123.0`,
`google-genai==2.20.0`, and `openai==3.3.0` (for both OpenAI and the
OpenAI-compatible xAI route) through this same boundary:

```bash
npm run test:python-sdk
```

That gate is deliberately separate from `prepack`: the JavaScript package can
still build and verify without installing Python. The repository release gate
requires the pinned `.venv`, confirms four admitted local calls and four
root-owned upstream transports, and scans all three evidence bundles for a
distinct parent-only provider credential. It is still deterministic mocked-
upstream compatibility—not a live-provider or framework-wrapper result.

Two exact framework families are now admitted as well. Vercel AI SDK
`ai@7.0.83` uses exact provider packages for Anthropic `4.0.44`, Google
`4.0.56`, OpenAI `4.0.50`, and xAI `4.0.48`. The separate Python release gate
uses LangChain Core `1.6.1` with Anthropic `1.7.0`, Google GenAI `4.3.7`,
OpenAI `1.6.0`, and xAI `1.3.0` integrations. Both invoke the same Guard routes,
which authenticate workload, policy, model and target before the single
mocked-upstream dispatch. Inspect the self-digested cross-language boundary
with:

```bash
gradia-guard framework-matrix
gradia-guard framework-matrix --json
```

These are two exact framework release families, not “all Vercel AI SDK” or
“all LangChain,” and not LlamaIndex or framework telemetry capture. Either
framework can still bypass the configured base URL outside a separately
enforced runtime. All eight pinned Vercel and LangChain provider cells are now
also exercised inside fresh measured Docker boundaries described below; those
co-located proofs do not inflate other releases or frameworks into container
proofs.

Unknown fields, malformed bodies, wrong capabilities and non-JSON calls are
refused. Any unauthorized or malformed local request poisons admission even if
a later call succeeds. A run with no routed model call is not admitted. The
composite `runtime.json` receipt binds
the signed workload identity, policy and HTTP configuration, fixed parent-
supplied environment, local capability digest, child termination, verified G0
process bundle and verified G1 gateway bundle. Provider secrets and the local
capability value are absent from those receipts; environment variable names and
the loopback origin remain visible so the environment composition can be
recomputed offline.

This is **not** G3 runtime or host enforcement. The operating system may add
environment variables that this user-space parent cannot measure; a same-user
or privileged child may find credentials in files, metadata services or parent
memory; and direct child network/process activity remains possible. The
boundary therefore permanently records `bypass_possible: true`,
`operating_system_process_isolation_proved: false`,
`full_host_enforcement: false` and
`kubernetes_network_policy_enforced: false`. Removing those gaps still requires
root-owned container/sidecar isolation, DNS and egress policy, filesystem and
process measurement, and runtime attestation.

## Measured container and network enforcement

`runtime collect-docker` inspects a running, separate agent/gateway boundary
through the Docker daemon and launches two fixed probes from inside the agent:
direct external egress must fail, while the internal Guard gateway must answer.
The collector binds the exact container and image identities, network
identities, policy/configuration/workload-identity digests, non-root and
read-only posture, dropped capabilities, absence of host namespaces and Docker
socket, and absence of known provider credential names from the agent.

```bash
gradia-guard runtime collect-docker \
  --runtime-id production-run-01 \
  --agent exact-agent-container \
  --gateway exact-gateway-container \
  --internal-network exact-internal-network \
  --policy-sha256 "$POLICY_SHA256" \
  --configuration-sha256 "$CONFIGURATION_SHA256" \
  --workload-identity-sha256 "$WORKLOAD_IDENTITY_SHA256" \
  --direct-url https://example.com/ \
  --gateway-url http://guard-gateway:8787/health \
  --out container-enforcement.json
```

The receipt supports only the measured model/network/credential boundary: the
workload could not bypass the gateway through its only attached network at
probe time. It permanently preserves Docker-operator bypass as possible and
full host, process-spawn, file-read, side-effect and world-state coverage as
false. Rehashing the receipt cannot turn those fields true.

An independently verifiable bypass battery can then exercise five additional
surfaces inside that exact measured agent container:

```bash
gradia-guard runtime probe-docker-bypass \
  --agent exact-agent-container \
  --container-receipt container-enforcement.json \
  --out container-bypass-battery.json

gradia-guard runtime verify-docker-bypass \
  --receipt container-bypass-battery.json \
  --container-receipt container-enforcement.json
```

The fixed probes attempt direct raw-TCP egress with an alternate client,
link-local metadata access, a root-filesystem write, a writable `/tmp`
round-trip, and raw-TCP egress from a spawned subprocess. The receipt binds the
probe programs by digest and binds their observations to the container receipt,
runtime ID and measured agent identity. It explicitly records that five probes
are not an exhaustive proof of non-bypassability; Docker-daemon/operator bypass
and full-host enforcement remain outside the claim.

The stronger reference gate runs each of the eight exact pinned Vercel and
LangChain provider calls inside a fresh measured agent/gateway composition
rather than inferring co-location from adjacent tests. It injects only an
ephemeral local capability under the selected provider's SDK variable names in
the `docker exec` environment, invokes the exact framework/package pair, routes
the native request to the measured gateway, and copies out the two-frame
digest-only Guard gateway bundle for independent replay. The Vercel cells use
the pinned Node image; the LangChain cells use a digest-pinned Python base and
the repository's frozen `uv.lock` for the complete `guard-frameworks`
environment. The resulting image identity is bound by the container receipt:

```bash
GRADIA_PROOF_LOCAL_CAPABILITY="$(openssl rand -base64 32 | tr -d '=+/')" \
  gradia-guard runtime probe-docker-sdk \
    --agent exact-agent-container \
    --gateway exact-gateway-container \
    --container-receipt container-enforcement.json \
    --framework vercel_ai_sdk \
    --provider anthropic \
    --local-origin http://gateway:8787 \
    --capability-env GRADIA_PROOF_LOCAL_CAPABILITY \
    --gateway-evidence-out gateway-evidence \
    --out container-sdk-route.json

gradia-guard runtime verify-docker-sdk \
  --receipt container-sdk-route.json \
  --container-receipt container-enforcement.json \
  --gateway-evidence gateway-evidence
```

`npm run test:docker-sdk` reproduces eight fresh reference compositions and
tears each down afterward. Each checked-in receipt binds the exact agent and
gateway container identities, the direct-egress refusal, framework catalog and
selected package pin, local-capability digest, successful SDK output, policy/
configuration/workload identity, and independently verified gateway chain
head. The receipt also binds the exact environment-variable-name allowlist so
an extra provider alias fails verification. Each cell receives a distinct
randomly generated local capability; its value is propagated to Docker by
environment name rather than placed in command-line arguments or evidence.

This proves eight deterministic, mocked-upstream Vercel/LangChain provider
routes inside eight measured Docker boundaries. It does **not** prove live-
provider behavior, arbitrary framework versions, exhaustive bypass resistance, Docker-
operator resistance, kernel-complete process/file/side-effect capture, or full
Universe state. Those fields remain false in the receipt even if its outer hash
is recomputed.

The Kubernetes reference under `kubernetes/` uses separate agent, provider-
gateway and identity-broker Pods, restricted Pod Security, no automatic API
token, digest-pinned images, default-deny policy, agent-to-gateway-only egress,
broker-only TokenReview RBAC and fail-closed admission.
Standard NetworkPolicy cannot restrict exact external FQDNs, so an optional
Cilium policy defines the exact provider/Gradia hosts. The checked-in image
pins deliberately resolve nowhere until an operator supplies reviewed image
digests. Rendering a manifest is not proof that a cluster enforced it.

One exact local enforcement cell now has separately collected and checked-in
enforcement and identity-exchange receipts. `npm run test:kubernetes-live`
creates an ephemeral pinned kind cluster, applies the boundary, observes
restricted agent/gateway/broker posture, distinct projected identities,
credential/signing-key separation and seven NetworkPolicies,
replaces the agent Pod, repeats the direct/gateway probes, exercises raw-IP,
link-local, root-write, writable-scratch, automatic-token and subprocess
probes, authenticates the gateway token through the real Kubernetes TokenReview
API over pinned broker TLS, rejects a replay, verifies six exact admission
refusals, then routes one pinned Vercel AI SDK/OpenAI request through Guard. The
runner finalizes and verifies the Kubernetes receipt, TokenReview exchange
receipt and two-frame gateway bundle before deleting the cluster. Its
kubeconfig and all private material live in a separate temporary directory
that is deleted; only public keys, sanitized receipts and digest-only gateway
evidence may remain in the proof directory.

```bash
GRADIA_KIND_BINARY=/absolute/path/to/kind npm run test:kubernetes-live

gradia-guard runtime verify-kubernetes \
  --receipt test/fixtures/kubernetes-identity-exchange/live/kubernetes-enforcement.json \
  --gateway-evidence test/fixtures/kubernetes-identity-exchange/live/gateway-evidence

gradia-guard runtime verify-kubernetes-identity \
  --receipt test/fixtures/kubernetes-identity-exchange/live/kubernetes-identity-exchange.json \
  --kubernetes-receipt test/fixtures/kubernetes-identity-exchange/live/kubernetes-enforcement.json \
  --gateway-evidence test/fixtures/kubernetes-identity-exchange/live/gateway-evidence \
  --issuer-public-key test/fixtures/kubernetes-identity-exchange/live/issuer-public-key.pem \
  --broker-ca test/fixtures/kubernetes-identity-exchange/live/identity-broker-ca.pem
```

That finite, mocked-upstream proof is neither production/customer-cluster nor
live-provider evidence. It proves one point-in-time local TokenReview and
separate broker issuance, not managed Gradia identity, cloud workload
federation, issuer rotation/revocation/HSM custody, replay persistence across
broker restart or safe horizontal broker scaling, automated gateway identity
renewal, network-policy behavior
when the enforcement engine fails,
cluster-admin or node-operator resistance, exhaustive non-bypassability,
kernel-complete file/process/side-effect capture, full-host enforcement or
Universe world state. Those fields remain false in the exchange receipt.

## Portable G3 runtime evidence

The package now implements the same strict G3 runtime ABI accepted by Gradia's
managed ingestion service. `DurableRuntimeEvidenceRecorder` writes a canonical
header, an append-only NDJSON receipt chain, and a terminal/finalization/anchor
bundle. Every accepted receipt is validated against the complete candidate
prefix before append, then the file and containing directory are `fsync`ed.
Recovery refuses unreadable, truncated, or tampered prefixes. An explicitly
recovered interrupted run can be terminalized as `crashed` with
`crash_recovery: true`, preserving the difference between completion and
recovery rather than manufacturing a clean exit.

```ts
import { DurableRuntimeEvidenceRecorder } from "@gradia/guard";

const recorder = new DurableRuntimeEvidenceRecorder({
  directory: ".gradia/evidence/runtime-session-1",
  runtimeVersion: "customer-runtime.v1",
  sessionId: "runtime-session-1",
  createdAt: new Date().toISOString(),
  runtimeIdentitySha256,
  policySha256,
  credentialPolicySha256,
  declaredCredentialScopeIds: ["case.read"],
});

recorder.append(exactDigestOnlyFileOrNetworkReceipt, {
  logicalTime: 1,
  observedAt: new Date().toISOString(),
  occurrenceId: "receipt-1",
});
recorder.terminalize({
  logicalTime: 2,
  observedAt: new Date().toISOString(),
  occurrenceId: "terminal-1",
  terminalStatus: "completed",
  reasonCodes: ["application_completed"],
  crashRecovery: false,
});
const bundle = recorder.finalize(new Date().toISOString());
```

The resulting portable file can be independently replayed or admitted by the
managed service without custom application glue:

```bash
npx @gradia/guard runtime verify .gradia/evidence/runtime-session-1/bundle.json
npx @gradia/guard runtime upload \
  --api-base https://api.gradiahq.com \
  --project PROJECT_ID \
  --token-env GRADIA_GUARD_TOKEN \
  --retention-policy RETENTION_POLICY_ID \
  --allow-evaluation \
  .gradia/evidence/runtime-session-1/bundle.json
```

Both commands verify the exact receipt chain and semantic invariants before any
network dispatch. Managed upload also verifies the returned remote anchor
against the exact local bundle digest, project, session, edition, rights, and
retention declaration. The self-contained local anchor is a portable integrity
receipt, not an independently authenticated trust root or remote-retention
proof.

When the credentialless child and measured Docker boundary are available for
the same runtime, one command binds the three independently verified sources:

```bash
npx @gradia/guard runtime compose \
  --credentialless .gradia/evidence/credentialless-run-1 \
  --container container-enforcement.json \
  --bundle .gradia/evidence/runtime-session-1/bundle.json \
  --created-at 2026-08-27T14:00:03.000Z \
  --out runtime-composition.json

npx @gradia/guard runtime verify-composition \
  --receipt runtime-composition.json \
  --credentialless .gradia/evidence/credentialless-run-1 \
  --container container-enforcement.json \
  --bundle .gradia/evidence/runtime-session-1/bundle.json
```

The composition refuses a different runtime ID, policy, HTTP configuration,
workload-identity digest, G3 runtime identity, or substituted source receipt.
Its positive coverage is intentionally narrow: native provider routing and
pre-dispatch policy evidence, credential withholding, measured gateway-only
egress, read-only/non-root agent posture, and a durable declared G3 chain. It
keeps Docker-operator bypass and declared-recorder bypass `true`, and complete
process/file/side-effect/host/world coverage `false`.

This recorder remains deliberately bypassable: the calling application chooses
which operations to report. It does not prove root ownership, container or
Kubernetes enforcement, host persistence, complete file/process/network
capture, or full world state. Those claims require a separately bound live
runtime-enforcement receipt or Gradia Universe witness; changing the G3 claim
ceiling is rejected even when an attacker recomputes outer hashes.

## Stable logical-action identity

Guard SDK frames, G3 runtime receipts, and Gradia Universe field effects can
now share one provider-neutral identity for an action attempt. Its complete
coordinate set is intentionally small and exact:

```ts
const identity = createLogicalActionIdentity({
  schema_version: "gradia.logical-action-coordinates.v1",
  action_namespace_id: "run-conditional-underwriting-001",
  actor_id: "underwriter-agent-01",
  logical_operation_id: "loan-case-042.condition-review",
  attempt_number: 2,
});
```

`logicalActionIdentityForSdkFrame` derives those same coordinates from a G2
frame. `verifiedRuntimeReceiptForLogicalAction` first verifies the complete G3
bundle, then requires its session and one occurrence ID to match. The Python
Universe helper derives the same digest from a signed field-effect statement;
the checked-in golden vector is byte-identical in both languages.

An equal logical-action identity proves only equal declared coordinates. It
does not prove semantic equivalence, causality, complete capture, or that an
effect happened. Those stronger claims still require the independently
verified SDK/runtime/Universe source receipts. Managed persistence, Observatory
projection, certificate binding, and counterfactual-pair packaging remain GU5
work.

## Portable managed and Universe anchors

Every managed evidence edition response includes an Ed25519 remote anchor. The
signed attestation binds the exact immutable edition, project, session, bundle,
verification, rights-bound edition digest, collector, and declared retention-
policy identifier. `upload` verifies the signature and all bindings before
returning success. The verifier works offline and can pin the expected Gradia
public-key ID.

Signature verification against the key carried with the anchor proves internal
integrity; it does not independently establish who controls that key. Issuer
authentication requires a key ID pinned from a separately trusted channel
(Gradia exposes the current key at `/v1/certificates/public-key`). Rotation and
revocation policy remain managed-issuer work, not a property inferred from one
anchor.

That anchor explicitly leaves retention execution, deletion, and storage
residency false. Naming a retention policy is not evidence that it ran.

For Gradia-controlled Universes, `verifyUniverseAnchor` verifies the portable
anchor returned by:

```text
GET /v1/runs/{run_id}/observatory/episodes/{episode_id}/anchor
```

The server first replays the durable root/auditor and agent-visible chains and
rebinds every event frame to the frozen scenario occurrence witness. The
payload-free signature then binds frame counts, scenario/episode identities,
both chain heads, and the terminal world root. Its coverage says whether an
evolution event or restore was actually present. A single-episode anchor
cannot claim a verified counterfactual pair, full-host enforcement, retained
raw payloads, or retention execution.

## The claim boundary

The one-line wrapper produces **process-tier** evidence. It does not observe model prompts, tool semantics, files, network traffic, hidden state, or the complete world available to an agent. Its receipt says so. A verifier rejects a process-tier receipt that claims full-world capture.

| Tier | Required captured surfaces | What it can support |
| --- | --- | --- |
| `process` | dispatch, lifecycle, stdio | A particular process ran and emitted these byte identities |
| `gateway` | model request/response, identity, usage | Calls that actually crossed an instrumented model gateway |
| `sdk` | decision inputs/outputs and tool request/results | Decisions and tools explicitly reported through the SDK |
| `runtime` | lifecycle plus file/network effects and credential scopes | Effects inside a Gradia-instrumented runtime |
| `universe` | distinct agent/auditor projections, world roots, witness chain, snapshot/restore | Full frozen-world and visibility claims under enforced isolation |

Installing an SDK cannot retroactively prove information it could not observe. Only the instrumented-runtime and Universe integrations may make their stronger claims, and only when every required surface is present.

## G1 gateway recorder

The provider-neutral `GatewayRecorder` instruments a model call at the caller's real dispatch boundary. It is not a proxy and cannot observe a call made around it.

```ts
import { GatewayRecorder } from "@gradia/guard";

const recorder = new GatewayRecorder({ directory: ".gradia/evidence/gateway-run-1" });
const attempt = recorder.prepare({
  provider: "anthropic",
  requestedModel: "claude-opus-5-20260801",
  logicalRequestId: "request-1",
  attemptNumber: 1,
  retryOfOccurrenceSha256: null,
  requestBody: exactRequestBytes,
  requestMediaType: "application/json",
  policy: {
    decision: "allowed",
    censorKind: null,
    reasonCodes: ["budget_reserved", "policy_allowed"],
    policySha256: exactPolicyDigest,
  },
});

attempt.markDispatched(); // immediately before the actual provider call
const response = await callProviderWithoutPassingCredentialsToTheRecorder();
attempt.succeed({
  responseBody: response.exactBodyBytes,
  responseMediaType: "application/json",
  resolvedModel: response.model,
  usage: response.usage,
  httpStatus: response.status,
});
recorder.finalize();
```

G1 binds the exact request/response byte identities, requested and provider-resolved model, provider, usage, retry lineage, pre-dispatch policy receipt, HTTP disposition, and monotonic dispatch latency. Model aliases such as `latest` and unversioned pins are refused. A resolved-model mismatch records an `identity_mismatch` receipt and throws instead of returning success.

Gateway request and response bodies are always digest-only. The recorder accepts no header or credential field and stores no body text, private reasoning, or chain of thought. Policy/budget censorship is recorded before dispatch and remains distinct from provider, transport, and protocol failure.

Every G1 manifest states `capture_boundary: "explicit_recorder"`, `bypass_possible: true`, and `calls_outside_this_recorder_are_not_observed`. Removing that disclosure fails offline verification. Transparent interception and bypass resistance still require separately enforced host/runtime networking; the local dispatcher above does not claim either.

### Native provider wire adapters

`prepareProviderAttempt`, `completeProviderAttempt`, and
`failProviderTransport` map the supported OpenAI Responses, xAI Responses,
Anthropic Messages, and Gemini `generateContent` wire shapes into the same G1
evidence ABI. They bind the requested model from the request body (or Gemini
route), the provider-resolved model, token usage, cache usage, HTTP outcome, and
transport/protocol failure class without retaining raw request or response
bodies.

```ts
import {
  completeProviderAttempt,
  GatewayRecorder,
  prepareProviderAttempt,
} from "@gradia/guard";

const recorder = new GatewayRecorder({ directory: ".gradia/evidence/call-1" });
const prepared = prepareProviderAttempt(recorder, {
  provider: "openai",
  requestBody: exactRequestBytes,
  requestMediaType: "application/json",
  requestedModelFromRoute: null,
  logicalRequestId: "request-1",
  attemptNumber: 1,
  retryOfOccurrenceSha256: null,
  policy: exactPreDispatchPolicyReceipt,
});

prepared.attempt.markDispatched();
const response = await dispatchWithoutGivingGuardTheCredential();
completeProviderAttempt(prepared, {
  responseBody: response.exactBodyBytes,
  responseMediaType: response.mediaType,
  httpStatus: response.status,
});
recorder.finalize();
```

These are strict wire parsers and recording adapters, not monkey patches,
framework hooks, or an enforcing proxy. The application still owns dispatch;
direct calls around this boundary remain invisible and are declared as such.

## G2 portable SDK recorder

`SdkRecorder` adds explicit, provider- and framework-neutral instrumentation for application decisions and registered tool calls. It uses a separate ABI from G0/G1 and does not pretend to discover framework activity automatically.

```ts
import { SdkRecorder } from "@gradia/guard";

const recorder = new SdkRecorder({ directory: ".gradia/evidence/sdk-run-1" });
const decision = recorder.beginApplicationDecision({
  actorId: "agent-underwriter-01",
  principalId: "tenant-01",
  authorityScopeIds: ["case.read", "decision.write"],
  logicalOperationId: "decision-1",
  attemptNumber: 1,
  retryOfOccurrenceSha256: null,
  parentOccurrenceSha256: null,
  stateRootBefore: {
    schema_version: "gradia.guard.sdk-state-root.v1",
    source: "application_declared",
    namespace_id: "case-state",
    root_sha256: stateRootBeforeSha256,
  },
  decisionIdentity: {
    schema_version: "gradia.guard.sdk-decision-identity.v1",
    decision_type: "underwriting.disposition",
    executor_kind: "model",
    executor_id: "custom:underwriting-agent",
    executor_version: "2026.08.24",
    contract_sha256: decisionContractSha256,
  },
  decisionInputBody: exactDecisionInputBytes,
  decisionInputMediaType: "application/json",
  policy: {
    decision: "allowed",
    censorKind: null,
    reasonCodes: ["authority_confirmed", "policy_allowed"],
    policySha256: exactPolicyDigest,
  },
});

decision.markDispatched(); // immediately before the real application dispatch
const result = await makeDecisionOutsideTheRecorder();
decision.succeed({
  resolvedDecisionIdentity: result.exactIdentity,
  decisionOutputBody: result.exactOutputBytes,
  decisionOutputMediaType: "application/json",
  stateRootAfter: result.applicationDeclaredStateRoot,
});
recorder.finalize();
```

`beginRegisteredToolCall` follows the same lifecycle and additionally binds a registry ID, exact tool/version, interface digest, request/result digests, and optional parent occurrence. Retries must name the immediately preceding occurrence and preserve the actor, principal, authority scopes, and operation identity.

G2 records exact digest-only input/output or request/result references, typed requested/resolved identities, canonical nonempty authority scopes, pre-dispatch policy receipts, optional application-declared state-root identities, call lineage, outcome class, and monotonic dispatch latency. Model/component and tool versions must be exact pins; `latest`, `current`, `default`, and `auto` aliases are refused. Identity mismatch is recorded and makes verification fail.

The SDK accepts no headers, credential field, arbitrary metadata, rationale, scratchpad, or chain-of-thought field. Raw bodies pass through memory only long enough to compute length and SHA-256; they are never written by G2. A supplied state root proves only the identity the application declared—it is not a runtime-observed filesystem, database, or world root.

Every G2 manifest states `capture_boundary: "explicit_sdk"`, `bypass_possible: true`, and `uninstrumented_or_direct_io_is_not_observed`. Direct model, tool, network, subprocess, or filesystem activity outside these explicit methods remains invisible. Removing or strengthening that disclosure fails offline verification.

## Route expensive evidence work before dispatch

Guard ships the same pure GU6 policy evaluator used by the managed service.
It performs no network call and spends nothing. Integer basis points and
micro-USD keep the decision canonical across Python and TypeScript:

```ts
import {
  GOVERNANCE_ROUTING_CLAIM_BOUNDARY,
  GOVERNANCE_ROUTING_POLICY_SCHEMA_VERSION,
  GOVERNANCE_ROUTING_REQUEST_SCHEMA_VERSION,
  evaluateGovernanceRoute,
  sealGovernanceRoutingPolicy,
  sealGovernanceRoutingRequest,
} from "@gradia/guard";

const policy = sealGovernanceRoutingPolicy({
  schema_version: GOVERNANCE_ROUTING_POLICY_SCHEMA_VERSION,
  policy_id: "frontier-panel",
  policy_version: "v1",
  min_task_value_bps: 6000,
  min_evaluator_reliability_bps: 8000,
  max_diagnostic_budget_microusd: 20_000_000,
  max_panel_budget_microusd: 500_000_000,
  max_cost_per_accepted_result_microusd: 100_000_000,
  min_diagnostic_attempts_for_panel: 5,
  min_accepted_results_for_panel: 1,
  require_independent_human_panel_approval: true,
  claim_boundary: GOVERNANCE_ROUTING_CLAIM_BOUNDARY,
});

const request = sealGovernanceRoutingRequest({
  schema_version: GOVERNANCE_ROUTING_REQUEST_SCHEMA_VERSION,
  request_id: "diagnostic-001",
  study_key: "release-2026-08",
  requested_stage: "diagnostic",
  task_value_bps: 8500,
  evaluator_reliability_bps: 9000,
  cumulative_spend_microusd: 0,
  requested_incremental_budget_microusd: 20_000_000,
  attempted_results: 0,
  accepted_results: 0,
  result_set_sha256: null,
  panel_definition_sha256: "0".repeat(64),
  independent_human_approval_sha256: null,
});

const receipt = evaluateGovernanceRoute(policy, request);
if (!receipt.dispatch_eligible) throw new Error(receipt.blockers.join(","));
// A separate authenticated dispatcher may now decide whether to act.
```

Panel requests additionally require observed-result and independent-human-
approval digests. The local receipt proves deterministic policy application,
not that the approval is authentic. The managed API verifies that authority,
freezes one denominator per policy/study/stage, and still does not dispatch.

## Spool posture

Digest-only is the default and safest posture:

```bash
npx @gradia/guard run --spool digest-only -- node agent.js
```

For local encrypted payload retention, supply a 32-byte base64 key through an environment variable and a non-secret key identifier:

```bash
export GRADIA_GUARD_SPOOL_KEY="$(openssl rand -base64 32)"
npx @gradia/guard run --spool encrypted --key-id local-key.v1 -- node agent.js
npx @gradia/guard verify --key-env GRADIA_GUARD_SPOOL_KEY --key-id local-key.v1 .gradia/evidence/node-<session-id>
```

The key is never written to the bundle. Without it, verification still checks the frame chain and ciphertext digests and reports encrypted payloads as unavailable. With it, verification additionally decrypts each blob and checks its plaintext digest and length.

## Managed ingestion

When a separately deployed Gradia project has issued a project-scoped TDM or validator service account, upload a locally verified bundle without placing the token on the command line:

```bash
export GRADIA_GUARD_TOKEN="...from your approved secret manager..."
npx @gradia/guard upload \
  --api-base https://YOUR_GRADIA_ORIGIN \
  --project YOUR_PROJECT_ID \
  --allow-evaluation \
  .gradia/evidence/node-<session-id>
```

Upload always verifies the bundle before network dispatch, requires HTTPS except on loopback, sends the token only as an authorization header, and checks that the server returns the same canonical bundle digest. Every permitted use is opt-in. Ingestion creates immutable evidence eligible for human review; it does not make process evidence a benchmark, training set, or certificate.

The returned `remoteAnchor` is independently checked against the exact upload
intent and edition identity before the CLI exits successfully. Preserve the
anchor next to the local bundle; later verification needs only its public key,
not a Gradia token. Pin the expected public-key ID when issuer identity, rather
than self-consistency alone, is part of the acceptance decision.

## Safety properties

- Canonical JSON and SHA-256 bind every frame to its predecessor.
- The manifest is atomically refreshed after every append.
- A terminal frame is required and must be last; crashed or nonzero children are finalized honestly.
- Missing, reordered, truncated, or modified frames fail verification.
- Required capture surfaces are checked per tier; coverage overclaims fail verification.
- Evidence objects refuse secret-shaped keys and private chain-of-thought/scratchpad fields.
- Likely command-line credential flags are refused; pass credentials to the child through an appropriate secret manager or environment boundary instead.
- The covered HTTP transport accepts only the provider's authentication header from its root-held credential closure; it refuses header smuggling and ambiguous authentication before network dispatch.
- The parent-owned child launcher forwards no provider credential in argv or its explicit environment, requires an authenticated loopback hop, and binds process/gateway termination; unauthorized, malformed or unused local gateways fail admission.
- Raw private reasoning is outside the ABI. Store decision outcomes, evidence identities, policy receipts, and concise reason codes—not hidden reasoning.

This candidate now provides strict OpenAI/xAI Responses, Anthropic Messages and
Gemini `generateContent` wire adapters for explicit G1 gateway-call recording,
G2 application-decision and exact-version MCP tool enforcement, deny-by-default
policy, short-lived signed workload identity, exact-target HTTP dispatch,
provider-credentialless child composition, a live-proved Docker
agent/gateway-network collector, eight exact same-container Vercel/LangChain
provider SDK-to-Guard proofs, offline managed/Universe signature
verification, and a fail-closed Kubernetes deployment profile. It does not
provide monkey-patched automatic hooks for every third-party framework,
kernel-complete file/process/side-effect capture, proof that an unmeasured
Kubernetes cluster enforced the manifests, registry distribution, or a public
compatibility/license promise. Stronger claims remain conditional on the exact
receipt that proves the corresponding surface.
