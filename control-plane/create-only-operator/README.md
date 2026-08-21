# Create-only operator candidate

## Status

This directory is a **local-only, hard-disabled design candidate**. It does not install an SSH identity, enable plan registration on HC-HV01, call Hyper-V, create a VM, or return a production receipt. `Invoke-NorthGateCreateOnlyOperatorApply` always returns `NGCO-NOT-INDEPENDENTLY-PROMOTED` before inspecting or reflecting the supplied plan ID.

The candidate exists to freeze the smallest safe contract for the owner-approved 12-asset fleet while the production identity, host mappings, planner, live collector, adapter, audit, signing, crash recovery, and quarantine implementation are built and independently promoted.

## Implemented in this candidate

- Exactly four routine operations: `status`, `plan`, `apply`, and `receipt`.
- A fixed ordered allowlist for the two disposable canaries and ten persistent VMs in `proposals/full-fleet.proposed.json`.
- Exactly one typed `Create` operation per plan. All update, replace, adoption, decommission, delete, purge, switch, firewall, host-feature, guest-command, and arbitrary-command operations remain denied.
- Generation 2, destroy protection, fixed image digests, compute, disk size, opaque firmware/storage/network/bootstrap/recovery/access profiles, and initial power state `off` are bound into each desired-state hash.
- Strict canonical JSON string validation for the local model, including duplicate/case-colliding key, null, non-integer, unknown-field, extra-content, excessive-depth, and size rejection.
- A runtime-keyed HMAC plan registry and process-wide named writer lock usable only through a private `LocalTestOnly` context constructor. Registered records explicitly state `productionApplicable: false` and `applyEnabled: false`.
- A repository trust shape for the current private-repository constraint: exact repository identity, exact merged commit and tree, exact signed release SHA-256, and an installed host allowlist ID. This is a proposed compensating control, not an activated exception.
- Tests that prove the exported boundary, exact fleet, canonical binding, HMAC registry, lock contention, tamper rejection, constant apply denial, and absence of Hyper-V or generic execution primitives.

## Not implemented and therefore blocking activation

- A dedicated OS account, key, `sshd` forced-command rule, source restriction, or application authentication.
- A byte-oriented malformed-UTF-8 parser at the transport boundary. The local module receives a PowerShell string and must not be promoted as the production byte parser.
- A fixed data-only repository fetcher or signed planner.
- An independently reviewed governance decision authorizing the signed exact-commit/tree exception while private-repository branch protection is unavailable.
- A protected identity ledger, live VM/name/disk collision checks, or atomic reservation creation during host plan registration.
- Installed authoritative mappings from opaque profiles to exact storage roots, ISO files, virtual-switch identity/fingerprint, access VLAN, firmware template, bootstrap artifact, and recovery route.
- A fixed live Hyper-V inventory/preflight collector and repeated state revalidation under the writer lock.
- A live create backend, transaction journal, crash recovery, or quarantine reconciler.
- A separate one-time approval writer for the exact host-issued plan ID and authenticated hash.
- Sequenced hash-chained audit, OS-protected signing/MAC keys, asymmetric execution receipts, evidence reconciliation, installer, restrictive ACL evidence, backup, or rollback package.
- Immutable unattended/bootstrap artifacts for Debian, Windows, and Kali. Creating hardware and attaching an ISO is not the same as installing a guest OS.
- Final VM MAC addresses and the staged OPNsense DHCP/DNS/firewall policy. The new VLAN gateways are default-deny and the policy candidate deliberately leaves mappings disabled until the post-create MAC is known.

## Proposed forced-command boundary

Use a dedicated application identity that is distinct from the forwarding identity, normal interactive administrators, and break-glass access. The installed OpenSSH configuration must derive the actor from the authenticated OS session and force one fixed executable. It must disable interactive shell, PTY, agent forwarding, TCP forwarding, X11 forwarding, environment overrides, and arbitrary subsystem selection. Source restriction remains the authorized management workstation only.

The forced executable accepts only these byte-level forms:

| Command | Input | Result |
| --- | --- | --- |
| `status` | No arguments or stdin | Read-only installed release/policy state. |
| `plan` | Bounded canonical UTF-8 JSON on stdin | Host validates, reserves, registers, and returns a fresh plan ID/hash/expiry. |
| `apply ngp-<64 lower hex>` | One plan ID only | Consumes a separately recorded exact approval and applies that plan. |
| `receipt ngp-<64 lower hex>` | One plan ID only | Returns the authenticated receipt or fixed not-found result. |

Every other token count, casing, character, payload source, or command fails before a module is loaded. The handler never invokes a shell, expression evaluator, repository script, supplied path, or supplied command. The production operator receives a pre-opened bounded stdin stream and fixed installed policy; it does not read `SSH_ORIGINAL_COMMAND` as PowerShell source.

Legacy MCP mutators must not be wrapped as the backend. Routine discovery and authorization must exclude direct VM creation, resource updates, network mutation, checkpoints, start/stop, mount/export, delete, switch operations, and guest command execution. If retained for recovery, those operations belong on a separately authenticated break-glass endpoint whose credential is inaccessible to the factory executor.

## Smallest production implementation

### Planner and data acquisition

Add a separately signed `control-plane/planner-release` and fixed data-only fetcher. They consume only allowlisted canonical JSON from the exact merged commit/tree and never execute checkout content. The planner resolves approved manifests and catalogs once, reads normalized live state, and emits one `Create` or non-mutating `NoOp` operation. It recomputes the desired-state hash from the typed desired object rather than accepting a second client-supplied adapter operation.

The canonical plan must bind repository identity, commit, tree, signed release hash, host allowlist ID, manifest hash, installed policy/catalog hashes, observed-state hash/epoch, planner/operator/adapter versions, immutable image hash and size, and the one typed desired object. `NoOp` may be reported for an exact already-bound asset but is not an executable action.

### Registry and identity reservation

Promote a production engine derived from `control-plane/engine-candidate`, not the simulation module itself. Reuse its canonical record, HMAC registry, exact approval, idempotent receipt, ledger state, and one-time capability concepts. Replace these inert behaviors:

- remove `SimulationEnabled`, `Deployed=false`, the fixed mock, and every `simulated=true` field;
- require installed policy `applyEnabled=true` and `executableActions=["Create"]` at registration and immediately before the irreversible boundary;
- atomically create a `Reserved` ledger entry during registration after authoritative live collision checks instead of requiring test-seeded entries;
- limit a plan to one operation;
- reject every action except `Create` before reservation;
- bind the complete typed desired state needed by the adapter, not only its hash;
- re-read installed release, policy, catalog, maintenance marker, identity ledger, VM/name/disk state, image, switch, and capacity while holding the single host writer lock;
- journal `Applying` durably before creation and reconcile it at service startup before another reservation can be used;
- replace independent HMAC audit lines with a protected sequence and hash chain, and replace scaffold HMAC receipts with independently verifiable signed receipts.

The engine owns the named writer lock. The adapter must not attempt to acquire the same non-reentrant semaphore again.

### Exact approval

Keep `apply` input to the plan ID only. Add a separate installed approval recorder that is inaccessible to the executor identity. It accepts only the exact unexpired host-issued plan ID and full authenticated hash after the owner explicitly approves both, records approver identity/time/one-use nonce under protected ACLs, and never accepts a Git SHA or client hash as deployment authority. Apply rechecks expiry and state both before and after consuming the approval.

### Fixed host policy and adapter

Build a signed installed policy bundle from the 12 fixed entries modeled here. It must map opaque profiles to exact prevalidated host resources without accepting any caller path, filename, switch, VLAN, URL, command, or script. It must independently pin all three ISO hashes and sizes, two firmware profiles, five storage profiles, eight network profiles, eleven bootstrap profiles, recovery/access profiles, memory reserve, processor reserve, storage reserve, switch fingerprints, and access VLANs.

The production adapter is selected at build time and receives only the typed desired object derived from the approved plan. Under the engine-owned lock it performs this bounded transaction:

1. Revalidate identity, name, VM ID, disk, storage, image, switch/fingerprint, VLAN, firmware, capacity, maintenance marker, and pending reservations.
2. Write an authenticated `Prepared` journal naming the change, asset, reservation, deterministic transaction directory, and expected artifact identities.
3. Create only a Generation 2 VM in the `off` state. Construct the VHDX path from the installed storage mapping and fixed canonical name; never accept or reuse a caller path.
4. Configure CPU, dynamic memory, VHDX, ISO hash binding, Secure Boot, Windows vTPM/key protector where required, and an initially disconnected NIC.
5. Set the adapter access VLAN before connecting it to the exact fingerprinted existing switch. Never create or rebind a switch and never power on before all network controls read back correctly.
6. Stamp the exact change ID, asset ID, reservation ID, and transaction ID; re-read the VM by returned VM ID rather than by name.
7. Verify the complete normalized after-state, bind the VM ID in the identity ledger, commit the receipt, then mark the journal `Completed`.

Hyper-V creation is not truly atomic across VM metadata and VHDX. Before the VM exists, cleanup may remove only the transaction's newly created unopened artifact. After VM creation, any thrown or ambiguous result becomes `OutcomeUnknown`: do not remove by VM name or caller path. Stop and disconnect the exact returned/tagged VM ID, move only transaction-owned artifacts to the fixed quarantine root when ownership is provable, block identity reuse, and require reconciliation.

### Repository policy, catalogs, and intent records

The existing files are intentionally inert and need separate reviewed stages:

1. `schemas/resource-policy.schema.json` and `policy/resource-limits.json`: add an active-policy contract that permits only `Create`; keep the complete denied-operation set. Do not merely flip the current plan-only constants.
2. Image/profile catalogs: promote only records with live installed-policy mappings and immutable evidence. Image entries become `promoted/active`; referenced owner, firmware, storage, network, bootstrap, recovery, and access profiles become `approved`. Keep network `allowCreate=false` and `allowRebind=false`; VM `Create` means attach to an existing exact switch only.
3. `proposals/full-fleet.proposed.json` and its validator: preserve it as accepted design evidence without allowing it to remain a permanent proposed-catalog blocker. A proposal still never becomes a plan.
4. Add two separately governed `DisposableCanaryRequest` records for `NG-VM-018` and `NG-VM-010`. The create-only operator cannot delete them; retirement uses the separate decommission workflow after canary evidence.
5. Add ten `manifests/vms/ng-vm-*.json` standard manifests for `NG-VM-014`, `020`, `011` through `017`, and `021`, each with one approved `NG-CHG-*` reference and `desiredPowerState: off`. Access policy remains a companion workflow because the current VM manifest schema has no access field.
6. Update `scripts/Test-Repository.ps1` so active policy/catalog/manifests are validated without weakening the existing proposal and negative-test suites. Add a history/separation test proving catalog/policy promotion was merged before its first consuming request.

## Required test gates

- Byte-level invalid UTF-8, BOM, duplicate/case-colliding keys, null, float/exponent, control character, unknown field, oversized input, traversal/path/URI/command/secret, and canonical-byte rejection.
- Exact 12-asset allowlist, one-operation plan, only `Create`, immutable desired-state recomputation, and fixed image/profile binding.
- Same-name unmanaged VM, duplicate asset/name/MAC/disk, stale ledger, reused reservation, wrong VM ID, and implicit-adoption rejection.
- Exact ISO size/hash, Generation 2, Secure Boot/vTPM compatibility, switch fingerprint/VLAN, static/dynamic memory normalization, checkpoints/AVHDX accounting, and host reserve tests.
- Expiry before and after approval, wrong hash/ID, approval replay, registry/ledger/audit/receipt tamper, stale policy/catalog/state/version, and maintenance-marker tests.
- Cross-process lock contention and proof that all routine mutators share the same owner; no nested adapter lock.
- Failure injection before VHDX, after VHDX, after VM ID, after NIC, before ledger bind, after receipt, and across service/power loss. Prove exact quarantine ownership and no deletion by name/path.
- Tool-discovery and authorization tests proving the routine SSH/MCP identity has no direct Hyper-V, guest command, network, switch, checkpoint, export, start/stop, update, delete, or arbitrary-command route.
- Destination ACL/hash readback, signer pinning, rollback-resistant promotion replay state, backup/rollback, and an isolated disposable canary.

## Promotion sequence

1. Merge the current design/candidate branch. No activation.
2. Separately approve the private-repository signed exact-commit/tree governance exception. Do not make the repository public.
3. Build, sign, verify, back up, and install the operator, fixed fetcher/planner, policy resolver, adapter, approval recorder, keys, ledger, audit, receipt signer, crash recovery, and quarantine tooling with apply still disabled.
4. Prove the forced-command identity and remove all routine direct mutators. Run negative, ACL, power-loss, rollback, and isolated-host tests.
5. Promote immutable media and opaque host mappings in a separate change; keep normal apply disabled.
6. Activate only the Debian disposable-canary `Create` stage, register a fresh host plan, and obtain exact human approval of its issued ID/hash. Validate and retire it through the separate decommission workflow.
7. Repeat for the Windows disposable canary and prove Secure Boot/vTPM behavior.
8. Promote normal policy to `applyEnabled=true`, `executableActions=["Create"]` only, in a separate change after canary acceptance.
9. Merge the ten persistent manifests separately, then issue and approve one fresh host plan per VM in the reviewed rollout order. Revalidate capacity before every registration/apply.
10. Reconcile MAC/IP/DNS/OPNsense policy, guest bootstrap, Wazuh, TacticalRMM, backups, receipts, and Operation-SeeSaw evidence after each VM before proceeding.

No step may combine release installation, policy/catalog promotion, first consuming request, and plan approval into one authorization.
