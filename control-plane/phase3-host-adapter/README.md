# Phase 3 host-adapter and immutable-promotion design

This directory contains a local-only, production-intent adapter candidate and its inert tests. It contains no installer, activation record, key, signature, live backend, or executable policy. Nothing in this directory may be copied to or executed from a deployment checkout on the Hyper-V host, installed, or used to enable the VM Factory.

## Repository candidate boundary

`NorthGate.VMFactory.HostAdapter.psm1` exports only a read-only state function. Production invocation is an unexported hard rejection until an independently signed release is installed through a later privileged change. The only executable model in this repository is a fixed inert backend reached by the local test script through module-private scope; no backend delegate, scriptblock, command, path, URL, switch name, VLAN, policy bundle, or arbitrary action can be supplied at runtime.

The candidate models a single typed `Create` operation and a fixed typed policy mapping. It validates Generation 2, destroy protection, firmware/image/bootstrap compatibility, immutable image digest and size, exact storage and network resource fingerprints, identity reservations and collisions, maintenance state, host processor/memory/storage reserves, and an exact normalized preflight hash while holding the same named system-wide lock contract as the engine scaffold. It cannot create or rebind fabric, update an existing VM, replace, adopt, decommission, purge, or invoke Hyper-V.

Existing-VM capacity evidence is deliberately normalized: static-memory VMs reserve startup memory even when Hyper-V reports a meaningless 1 TiB maximum, while dynamic-memory VMs reserve maximum memory. Checkpoints and differencing disks are explicit per-VM capacity and recovery records; unknown, mismatched, or incomplete chains fail closed. A backend throw or malformed response after the modeled irreversible boundary returns a strict `OutcomeUnknown`, requires quarantine and reconciliation, and blocks reservation reuse.

Run `Test-HostAdapter.ps1` under Windows PowerShell 5.1. The tests cover the exported boundary, production hard-disable, fixed profile resolution, strict typed success/failure/unknown outcomes, unsafe input rejection, exact preflight hashing, image/switch/capacity checks, static-memory normalization, checkpoint/AVHDX ambiguity, and lock contention. They invoke no Hyper-V or remote command.

## Smallest deployable increment

Phase 3 should promote exactly two installed components and nothing else:

1. A fixed, signed, create-only host adapter that consumes an already validated `Create` operation from the engine and maps opaque image, firmware, storage, network, bootstrap, and recovery identifiers through installed host policy.
2. A separately signed immutable promotion envelope that authorizes those exact adapter and engine release hashes despite the current inability to enforce GitHub branch protection.

Catalog promotion, resource-policy activation, a disposable-canary request, and its host-issued plan are later and separate promotion units. Phase 3 must leave both normal and canary apply disabled.

```mermaid
flowchart LR
    Build["Reviewed offline build"] --> Artifacts["Engine and fixed-adapter artifacts"]
    Artifacts --> Hashes["Exact SHA-256 release hashes"]
    Hashes --> Envelope["Canonical promotion envelope"]
    Envelope --> Sign["Detached signature from protected owner key"]
    Sign --> Verify["Host promotion verifier with pinned public key"]
    Verify --> Install["Restricted immutable install roots"]
    Install --> Tests["Read-only and negative host tests"]
    Tests --> Disabled["Installed but apply remains disabled"]
```

## Fixed adapter boundary

The adapter is selected at build time and has no runtime scriptblock, command, path, or plug-in input. Its routine interface accepts an internal typed operation object, not JSON or MCP input. The first release supports `Create` only and must:

- re-read the exact VM name, asset reservation, host capacity, storage headroom, image digest, switch fingerprint, firmware compatibility, and maintenance marker while holding the same system-wide writer lock as the engine;
- resolve only opaque identifiers through installed policy and reject any caller-supplied host path, switch name, VLAN, filename, URL, script, or command;
- create only Generation 2, destroy-protected artifacts carrying the change ID and asset identity needed for precise quarantine;
- return a strict typed outcome with the exact created VM ID and normalized after-state hash;
- treat a thrown, malformed, or incomplete result as outcome unknown, block identity reuse, and require reconciliation/quarantine;
- expose no update, replace, decommission, purge, switch, firewall, feature, service, or storage-root mutation;
- remain inaccessible to the forwarding identity and ordinary direct MCP methods.

The adapter must be built and signed outside the deployment checkout, installed under restrictive ACLs, and hash-pinned in installed policy. Tests may use a separately compiled inert adapter; the production module cannot accept an injected delegate. This repository candidate is source evidence only and is not that compiled or installed release.

## Signed-promotion compensating control

The preferred correction is still to make `main` protected and independently verify protected-branch reachability. GitHub currently reports the branch unprotected and ruleset/protection controls unavailable for the repository plan. A verified merge signature alone is not protection.

If the owner accepts the residual risk, a temporary signed-promotion exception can compensate for one exact release. It is not a permanent substitute for branch protection. The canonical envelope must bind:

- exception ID, reason, approving owner, issued time, expiry, and one-use nonce;
- repository identity, branch name, exact reachable commit and tree, and the explicit fact that branch protection was unavailable;
- successful static-validation evidence and exact source-tree hash;
- engine, adapter, policy-bundle, schema, and installer SHA-256 hashes plus version identifiers;
- required signer identity and signature algorithm;
- required install roots and restrictive ACL policy identifiers;
- rollback package hash and pre-install backup evidence;
- `applyEnabled: false`, empty executable actions, and `promotionScope: install-only` as constants.

The envelope receives a detached asymmetric signature from an owner-controlled code-signing key that is non-exportable where practical. Only its public certificate and exact signer identity are pinned on the host. The private key, signing token, and generated signature state never enter Git, MCP input, chat, the engine state root, or Operation-SeeSaw.

The host promotion verifier must consume canonical bytes, reject invalid UTF-8, unknown fields, duplicate keys, expiry, replayed nonces, a changed signer, any hash mismatch, any widened scope, or a missing rollback package. It records the consumed nonce and installed hashes in a protected append-only promotion ledger. Installation approval names the exact envelope hash and is separate from repository merge, future policy activation, and future plan approval.

## Required Phase 3 evidence

Before installation is proposed, local and isolated-host tests must prove:

- Authenticode or equivalent artifact signatures and detached envelope verification against the pinned signer;
- canonical-byte and malformed-UTF-8 rejection before parsing;
- fixed adapter identity and absence of runtime code injection;
- exact repository/commit/tree and authoritative policy/catalog/state/version binding;
- system-wide cross-process lock contention;
- restrictive code, state, key, ledger, audit, and backup ACLs;
- append-only sequenced audit with truncation/replay detection and evidence-reconciliation behavior;
- authenticated registry and ledger tamper rejection;
- expiry rechecks immediately before every irreversible transition;
- crash recovery from `Applying`, including outcome-unknown identity blocking;
- independently verifiable signed receipt containing actor, approval, repository, policy, operation, before/after, signer, and reconciliation evidence;
- rollback of the installed release without activating VM apply.

Only after that evidence is reviewed should the owner separately approve an install-only host plan. A later review may promote the canary policy; another later review may register the first Debian disposable-canary request and exact host-issued plan.

## Residual blockers

- No independently signed compiled adapter, installer, immutable promotion envelope, pinned signer, restricted install root, or rollback package exists here.
- No fixed live Hyper-V preflight collector or create backend is present; the repository backend is inert by construction.
- The engine and adapter have not yet been composed into one installed release with a proven single lock owner and crash-safe `Applying` journal.
- Host ACL, signature, reboot/crash recovery, receipt, audit, quarantine, and isolated canary evidence remain unproven.
- Repository policy and both normal and canary apply remain disabled, with no effective actions.
