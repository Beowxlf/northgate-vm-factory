# Disabled VM Factory control-plane candidate

This directory contains a reviewable interface candidate, not a deployable host release. It exists to freeze the smallest routine MCP surface and prove that every state-changing entry point fails closed while the factory remains plan-only.

## Current behavior

| MCP operation | Candidate function | Effective behavior |
| --- | --- | --- |
| `vm_factory_get_state` | `Get-NorthGateVmFactoryState` | Reports the non-operative proposed state. |
| `vm_factory_register_plan` | `Register-NorthGateVmFactoryPlan` | Rejects without parsing, storing, hashing, or reflecting the supplied plan. |
| `vm_factory_get_plan` | `Get-NorthGateVmFactoryPlan` | Rejects without consulting a registry or reflecting the supplied plan ID. |
| `vm_factory_apply_plan` | `Invoke-NorthGateVmFactoryApply` | Accepts only a plan-ID-shaped interface and rejects before any mutation. |

The module contains no Hyper-V, process, network, SSH, or file-mutation primitive. It does not implement application authentication, the plan registry, identity ledger, host lock, audit sink, provisioner, receipt signing, or recovery. Its fixed reason code is safe to return to clients because it never includes caller input.

## Execution boundary

Repository source is untrusted at the privileged boundary. This candidate may run only in local or hosted static validation. It must never be copied to the host and invoked from a checkout. A future implementation must be built, reviewed, signed, hash-pinned, installed under restrictive ACLs, and promoted separately from repository data and from the first canary request.

The production MCP binding must expose only the four typed operations above to the routine application identity. Any existing direct VM lifecycle operation must be removed from that identity and, if retained for recovery, placed behind a separately authenticated break-glass endpoint.

## Promotion sequence

1. Preserve this candidate as proposed and disabled while the forwarding-only tunnel identity is proven.
2. Implement application authentication before enabling plan registration or any mutating route.
3. Add strict canonical-plan validation, protected-branch reachability verification, an external identity ledger, an expiring authenticated plan registry, a host-wide writer lock, fail-closed audit, receipt signing, and quarantine/rollback handling. A verified merge signature is not a substitute for protected-branch reachability.
4. Package those components as an immutable signed installed release and prove restrictive code, state, key, and audit ACLs.
5. Run every control-plane and negative acceptance test, including concurrent apply and all direct-mutation bypass tests.
6. Promote a canary-only installed policy in a separate reviewed change. Keep normal resource policy disabled.
7. Add one separately reviewed `DisposableCanaryRequest`, register a fresh host plan, and require exact human approval of its host-issued ID and authenticated hash before apply.

No step in this directory activates the canary proposal, promotes an image or profile, creates a manifest, registers a live plan, or changes Hyper-V.

## Validate

Run the repository validator from the repository root. It validates the strict proposal metadata, performs negative mutations against its safety boundary, imports the local interface candidate, confirms the exact exported surface, checks non-reflection, and statically rejects live-mutation primitives.
