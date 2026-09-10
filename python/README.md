# `gradia-guard`

> Apache-2.0 beta. Source and release files are distributed through the
> [public Guard repository](https://github.com/rudycelekli/gradia-guard).
> PyPI publication remains pending. Python capture is voluntary G2 SDK evidence. It is
> useful and independently verifiable, but direct or uninstrumented I/O remains
> outside its boundary. Installing this package does not make an arbitrary
> agent fully governed.

`gradia-guard` is the zero-runtime-dependency Python counterpart to
`@gradia/guard`. Both emit the exact `gradia.guard.sdk-bundle.v1` evidence ABI,
and either verifier can replay either language's bundle.

```bash
git clone https://github.com/rudycelekli/gradia-guard.git
cd gradia-guard
python -m pip install ./python
gradia-guard-python doctor
gradia-guard-python verify .gradia/evidence/python-session
gradia-guard-python inspect .gradia/evidence/python-session
```

The recorder retains content length and SHA-256 only. Prompts, outputs, tool
arguments, tool results, credentials, private reasoning, and raw trajectories
are not written by the default SDK.

```python
from gradia_guard import GuardRecorder, allowed_policy, decision_identity

recorder = GuardRecorder(".gradia/evidence/python-session")
operation = recorder.begin_application_decision(
    actor_id="agent.primary",
    principal_id="workload.local",
    authority_scope_ids=("model.invoke",),
    logical_operation_id="answer.case.001",
    attempt_number=1,
    decision_identity=decision_identity(
        decision_type="model_completion",
        executor_kind="model",
        executor_id="provider.model",
        executor_version="model-2026-08-01",
        contract_sha256="0" * 64,
    ),
    decision_input=b'{"prompt":"hello"}',
    decision_input_media_type="application/json",
    policy=allowed_policy("1" * 64),
)
operation.mark_dispatched()
operation.succeed(
    resolved_identity=operation.requested_identity,
    output=b'{"answer":"hello"}',
    output_media_type="application/json",
)
recorder.finalize()
```

`LangChainGuardCallback` implements the synchronous and asynchronous callback
surface without importing LangChain. It requires exact model/tool identities
and a caller-owned policy resolver, fails closed on unknown tool identities or
non-serializable evidence, and keeps `raise_error = True`. The hook records
framework-visible activity only; it does not enforce network egress or prove
that every call used the callback.

```python
from gradia_guard import LangChainGuardCallback

callback = LangChainGuardCallback(
    recorder=recorder,
    actor_id="agent.primary",
    principal_id="workload.local",
    authority_scope_ids=("model.invoke",),
    model_identity=my_exact_model_identity,
    tool_identities={"case_lookup": my_exact_tool_identity},
    policy_resolver=lambda kind, identity: allowed_policy(POLICY_SHA256),
)
result = model.invoke(messages, config={"callbacks": [callback]})
```

For enforcement, route provider and tool traffic through the separately
measured Guard gateway/runtime. A framework callback is evidence about calls it
observed, never evidence that an unobserved path did not exist.


Release readiness is checked independently of account access. From the Gradia
source repository, run `python -m build packages/guard-python --outdir
/tmp/guard-python-dist` and `python packages/guard-python/scripts/release_verify.py
--dist /tmp/guard-python-dist`, then the cross-language/fresh-wheel tests in
`tests/test_guard_python_package.py`. The `guard-python-v0.1.0b1` tag uses the
`pypi` GitHub environment and a configured PyPI trusted publisher to publish the
reviewed wheel and source distribution with attestations. Creating a workflow
or passing a local build does not mean the package exists on PyPI. No registry
credential is embedded in this package.

In the Gradia application checkout, the same Python package is located at `packages/guard-python`. In the public Guard checkout, it is located at `python`. Public Python release tags use `python-v0.1.0b1`; the release workflow must be configured as a PyPI trusted publisher before registry publication.
