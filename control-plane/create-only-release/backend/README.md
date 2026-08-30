# Create-only production backend

This folder contains the fixed planner and host apply backend for the NorthGate
Generation 2 VM factory. It is privileged installed code, not repository data.
Repository source must be packaged, signed, installed, and independently enabled
before these functions are reachable by the forced-command service.

## Security boundary

The backend accepts one canonical `CreateOnlyPlanRequest` and creates at most one
previously nonexistent VM. A plan is valid only when all of these installed or
host-issued anchors match:

- approved repository identity and exact merged commit/tree;
- signed release manifest and its SHA-256;
- signed host deployment authorization and its SHA-256;
- signed authoritative backend policy and its SHA-256;
- the immutable base-policy hash plus the current authenticated rollout-promotion
  sequence/hash, when a canary gate has advanced;
- signed, data-only repository bundle and its SHA-256;
- canonical manifest and catalog hashes;
- current host identity, protected-asset, switch, image, storage-root, collision,
  and capacity evidence;
- a random host-issued plan ID, plan SHA-256, and host HMAC authentication hash;
- a separately signed, expiring, one-use approval for that exact tuple.

The data bundle contains canonicalized JSON copies plus raw-Git blob provenance.
No repository script, hook, filter, submodule, executable, or checkout content is
invoked by this backend.

## Create transaction

The single-writer lock and an asset-specific lock are held across final preflight,
approval consumption, creation, configuration, verification, ledger binding, and
receipt production. An append-only per-asset journal records every irreversible
boundary. The backend itself generates the reservation ID, asset storage paths,
and accepts the VM ID only from Hyper-V after `New-VM` returns.

The production provider uses only fixed Hyper-V commands needed to create a new
VM, configure CPU/memory/firmware/DVD/network/VLAN, and optionally start that new
VM. It has no adoption, rename, replacement, disk attach-from-caller-path,
switch mutation, existing-VM update, remove, or delete path.

An approved manifest may request up to four new data disks by opaque ID and size.
The planner—not the caller—derives every path below the new asset root and assigns
SCSI controller 0 locations 1 through 4; the OS disk remains at location 0. Three
independent signed limits (asset, storage policy, and approved storage catalog)
must all authorize the requested count, maximum individual size, and total size.
Preflight collision and free-space checks cover the complete disk set. Apply may
create and attach only those plan-bound new VHDX files, and readback plus the
signed receipt must match every path and controller location before power-on.

New VMs begin powered off with a disconnected adapter. Network attachment and
power-on happen only after all configuration reads back correctly. Any partial or
uncertain result consumes the approval, blocks identity reuse, and requires
reconciliation. Only a VM carrying the exact transaction ownership note may be
stopped and disconnected for quarantine; unrelated or uncertain artifacts are
never touched.

Each approved asset has a policy-owned, locally administered static MAC address.
The planner rejects duplicates and collisions against every live host adapter,
then issues a separate random adapter reservation ID. During apply, the backend
captures the Hyper-V-issued adapter ID while the VM is still off, records the
adapter ID and static MAC in the authenticated journal, and rejects dynamic-MAC
drift. The plan and signed receipt bind the asset, adapter policy, reservation,
Hyper-V adapter ID, and MAC address.

Each VM boots from exactly one asset-bound derivative ISO. The base ISO is never
attached to a managed VM. Planning and apply both re-hash the derivative ISO and
its canonical provenance record and compare the source-image, builder release,
repository commit/tree, recipe, payload, and per-asset bundle-manifest bindings.
The plan and receipt carry the same immutable-media evidence.

## Canary rollout promotion

The installed backend policy and signature are immutable. Canary advancement
does not install a new release and does not move or copy the transaction ledger.
Instead, a native Administrator obtains an authenticated promotion context and
submits a canonical `northgate/create-only-rollout-promotion/v1` document signed
by the separately pinned approval signer.

`Register-NorthGateCreateOnlyRolloutPromotion` permits only sequence 1
(`debian-canary` to `windows-canary`) and sequence 2 (`windows-canary` to
`persistent-fleet`). Before committing either transition it verifies the exact
successful signed canary receipt, acceptance and retirement evidence hashes,
the authoritative ledger order, and live retirement (absent, or powered off
with every adapter disconnected). The service and routine SSH identities cannot
approve a promotion.

Immutable promotion records are HMAC-authenticated below
`<StateRoot>\rollout\promotions`; the effective monotonic anchor is atomically
replaced at `<StateRoot>\rollout\current.json`. Promotion IDs, nonces, and
sequence numbers are replay protected. An exact request retry is idempotent.
The base-policy hash remains unchanged and plan/receipt evidence separately
binds the effective rollout authorization hash, sequence, and stage.

## Firmware and virtual TPM contract

Firmware settings are exact policy, not caller choices. Windows Generation 2
guests require Microsoft Windows Secure Boot plus a local key protector and
enabled virtual TPM. Debian and other signed Linux guests require the Microsoft
UEFI Certificate Authority Secure Boot template and do not receive a vTPM. The
only Secure Boot exception is the exact authorized Kali installer image/profile:
`kali-2026.2-installer-netinst-amd64` with profile `kali-gen2-unsigned` and
exception `NG-FW-20260802-KALI-UNSIGNED`; it runs with Secure Boot disabled and
without vTPM. No generalized unsigned-media exception exists.

Firmware, TPM state, adapter identity, static MAC, switch, and VLAN all read back
before network attachment or power-on. A mismatch fails closed and leaves the
new VM off and quarantined when exact transaction ownership can be proven.

## State and signatures

Plans, approvals, ledger records, and journal events are authenticated with a
host-sealed 256-bit state key. Production loads the key from a DPAPI LocalMachine
blob created by the installer and protected by ACL. Approvals and data/control
artifacts use detached CMS signatures pinned by certificate SHA-256. Receipts are
detached-CMS signed by the separately pinned receipt signer.

All stored JSON uses the canonical serializer in the installed protocol module.
State writes use create-new or atomic replacement; journal event files are
append-only. Receipt failure is reported as evidence reconciliation pending and
never misrepresented as a VM rollback.

## Receipt reconciliation

`Invoke-NorthGateCreateOnlyReceiptReconciliation` repairs only the evidence tail
of a transaction whose VM was already verified and bound to the protected ledger.
It requires the exact original execution ID, consumed approval, bound ledger,
terminal evidence-pending journal, immutable signed plan/release anchors, usable
receipt signer, and exact live VM configuration. Historical release state is
admitted only after the currently installed production context is valid and the
single matching prior release directory independently validates its signed
manifest, authorization, policy, data bundle, state key, ACLs, and host/identity
bindings.

The operation never calls the create provider and has no VM mutation primitive.
It writes the missing detached-CMS receipt and authenticated completion records.
A retry returns the same receipt; drift, ambiguity, missing anchors, or signer
failure stops without touching the VM.

## Switch fingerprint contract

The authorized switch fingerprint is SHA-256 of canonical JSON containing exact
`id`, `name`, `switchType`, `netAdapterInterfaceDescription`, and
`allowManagementOS`. The authorized OPNsense trunk-adapter fingerprint is
SHA-256 of canonical JSON containing exact adapter ID, VM ID, switch ID, VLAN
operation mode, native VLAN, and normalized allowed VLAN list.

## Recovery behavior

`Invoke-NorthGateCreateOnlyCrashRecovery` never retries creation and never
deletes an artifact. It classifies incomplete journals as:

- `AbortedNoArtifacts` when no owned artifact exists;
- `Quarantined` after stopping/disconnecting an exactly tagged owned VM; or
- `OutcomeUnknown` when ownership cannot be proven.

All three outcomes consume the original approval and require a fresh plan.

`AbortedNoArtifacts` does not release an asset identity by itself. A retry is
allowed only after authenticated crash recovery re-observes no artifacts and
writes matching `RecoveredNoArtifacts` plan and chained-journal evidence.
Quarantined and outcome-unknown attempts remain hard identity-reuse blockers.

When the active service starts, it constructs and validates the signed backend
context, then invokes this recovery before opening the named-pipe request loop.
Recovery failure prevents the service from accepting plans or applies. Disabled
startup never constructs the backend and therefore never mutates transaction state.

## Tests

Run `./Test-CreateOnlyBackend.ps1`. The harness uses an inert in-memory provider,
ephemeral CMS certificates, and temporary authenticated state. It does not call
Hyper-V or write outside its temporary test root.
