# Gradia Guard Kubernetes boundary

This directory is a fail-closed deployment contract. A checked-in local kind
receipt now proves one exact application of the contract; it is not evidence
that a customer or production cluster applied it. The base keeps the agent, credential-holding
gateway and identity broker in separate Pods, disables automatic service-account tokens, applies
the restricted Pod Security profile, and lets the agent reach only cluster DNS
and the Guard gateway. The agent Pod has no provider Secret reference.

The checked-in images intentionally use non-existent, digest-shaped refusal
pins. Replace all three with images your organization built, scanned, admitted, and
pinned by exact digest before applying:

```bash
kubectl kustomize packages/guard/kubernetes/base > /tmp/guard-base.yaml
```

Standard Kubernetes `NetworkPolicy` cannot express exact provider hostnames.
The base therefore proves only that the **agent workload** cannot bypass the
gateway; its gateway may reach TCP 443. Clusters with Cilium should add the
`cilium-exact-egress.yaml` policy and remove the base gateway internet policy
to restrict the gateway to the four named provider APIs and Gradia's managed
anchor API. DNS answers, CNI behavior, admission success, effective runtime
state, and packet probes still require a cluster-collected receipt before an
edition may claim enforcement.

Provider credentials must be created out of band as
`gradia-guard-provider-credentials` in the target namespace. They enter only
the gateway Pod. This reference manifest does not contain credential values.

The gateway also receives a projected, audience-bound, short-lived Kubernetes
service-account token for workload-identity exchange. A separate broker receives
a different API-audience projected token and the sole `tokenreviews.create`
RBAC grant. The issuer private key is mounted only in that broker; the gateway
receives only its pinned public key and broker TLS CA. The agent receives no
Kubernetes API token, provider credential, issuer key or direct broker route.
The reference broker deliberately runs one replica because its replay set is
process-local. Horizontal scaling is refused as a claim until a shared durable
single-use store and restart proof exist.

The base broker NetworkPolicy contains a visibly annotated API-endpoint
template. CNI enforcement commonly observes the post-DNAT API endpoint rather
than the Kubernetes Service IP. Resolve the exact API endpoint IP and port for
the target cluster and replace that rule before applying. The live proof runner
does this resolution and exact patch automatically. A rendered template is not
evidence that a cluster applied or enforced the endpoint restriction.

## Exact local enforcement proof

`npm run test:kubernetes-live` builds digest-pinned agent, gateway and broker images,
creates an ephemeral `kind/v0.33.0` cluster on the pinned Kubernetes `v1.36.4`
node image, applies the base, and refuses to emit a receipt unless all of these
observations pass:

- the agent, gateway and broker run in separate restricted Pods as UID/GID `65532`,
  with `RuntimeDefault` seccomp, read-only roots, dropped capabilities, no host
  namespaces, no privilege escalation and no automatic service-account token;
- only the gateway configuration contains the selected provider credential
  name; the gateway and broker receive distinct 600-second projected tokens
  for the exact workload and Kubernetes-API audiences;
- the gateway sends its token through a pinned-TLS broker connection; the
  broker authenticates it with the real Kubernetes `TokenReview` API, requires
  exact audience, ServiceAccount UID, Pod UID and credential identity, then
  issues a <=300-second Ed25519 Guard identity whose signed nonce binds those
  sanitized review fields;
- a second exchange using the exact same token is rejected; the agent cannot
  connect directly to the broker; and the broker's only cluster permission is
  `create` on `authentication.k8s.io/tokenreviews`;
- direct raw-IP and link-local egress, root writes and spawned-subprocess raw-IP
  egress from the agent are blocked, while `/tmp` and the gateway stay usable;
- the network boundary still behaves the same after Kubernetes replaces the
  agent Pod;
- six server-side dry runs are denied by the exact ValidatingAdmissionPolicy,
  covering an unpinned image, writable root, agent/broker provider credentials,
  a signing-key mount outside the broker and a role/ServiceAccount mismatch; and
- one exact pinned Vercel AI SDK/OpenAI request traverses the gateway's real
  pre-dispatch Guard policy path and produces an independently replayable
  two-frame digest-only evidence chain.

The original enforcement-only receipt remains under
`test/fixtures/kubernetes-enforcement/live/`. The newer exchange proof is a
self-contained checked-in set under
`test/fixtures/kubernetes-identity-exchange/live/`. Replay both layers without
a cluster:

```bash
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

The exchange receipt proves point-in-time Kubernetes authentication and a
separate broker-issued identity in this one local cluster. It keeps managed
Gradia identity service, cloud workload federation, HSM/key rotation or
revocation, replay persistence across broker restart, live-provider behavior,
automated gateway identity renewal,
network-policy failure-mode behavior, cluster-admin/node-operator resistance,
exhaustive bypass resistance and full capture false. The local proof therefore
closes one exact deployment cell; it does not certify another cluster or
Kubernetes generally.
