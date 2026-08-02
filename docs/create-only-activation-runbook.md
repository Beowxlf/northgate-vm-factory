# Create-only fleet activation runbook

## Purpose

Standardize promotion of the NorthGate VM Factory from plan-only design to a narrowly scoped `Create` capability. This runbook never authorizes a VM by itself. Every install, policy promotion, and host-issued plan remains a distinct evidence-backed change.

## Permanent invariants

- The five retained VMs are never transaction, rollback, quarantine, or cleanup targets.
- Only the twelve fixed candidate asset IDs are recognized.
- Every executable plan contains exactly one `Create` operation.
- The client supplies an asset ID or plan ID only—never a path, switch, VLAN, ISO, URL, script, or command.
- Every VM is Generation 2, destroy-protected, and uses exactly one asset-bound full derivative ISO.
- `Create` may perform one bounded start of only the transaction-owned new VM after configuration readback. No standalone power, update, replace, adopt, decommission, delete, purge, switch, firewall, guest-command, or arbitrary-command operation exists on the routine identity.
- Any uncertain create result is forced off, disconnected, transaction-marked, and quarantined; retained VMs are untouched.
- Repository merge, policy promotion, release installation, and plan approval are separate decisions.

## Stage 0 — release source review

1. Validate the private repository, exact branch diff, and secret scan.
2. Run repository, candidate, parser, registry, approval, lock, adapter, failure-injection, installer, and rollback tests.
3. Review and merge the release source.
4. Record the exact repository identity, merged commit, tree, test result, and CI run.

Exit evidence: exact merged commit/tree and passing private CI. No live change.

## Stage 1 — immutable package and host policy

1. From a clean canonical checkout at the exact merged commit, write the fixed package
   allowlist to a new directory outside every repository using raw Git blobs only.
2. Verify the canonical version-2 manifest binds the repository origin, exact commit and
   derived tree, Git mode and blob OID plus SHA-256 and size for every file, package
   allowlist hash, host allowlist ID, and governance decision.
3. Generate an environment-specific version-2 host authorization outside Git that pins:
   - host identity;
   - both volume unique IDs and approved roots;
   - exact source-ISO paths, sizes, and SHA-256 values;
   - twelve unique asset-bound derivative ISO and provenance paths, sizes, hashes,
     source-image bindings, builder release, recipe, bundle-manifest, unattended-payload,
     commit, and tree provenance values;
   - exact existing switch and trunk-adapter identities and the eight fixed VLAN mappings;
   - all five retained VM identities plus their disk and adapter identities;
   - distinct SSH/service identities and distinct release, deployment, approval, and receipt signers;
   - fixed fleet specifications and one-canary rule;
   - memory, processor, and per-volume reserves;
   - apply disabled and no executable action.
4. Author the separately signed backend `Create` policy and the exact data-only fleet
   bundle; bind both hashes to the release installation tuple.
5. Generate one-time installer and rollback copies outside Git with only the approved
   public release and authorization signer SHA-256 pins substituted. Natively review
   their exact hashes before pinned transfer.
6. In a clean staging directory, prove the generated installer verifies the release,
   host authorization, backend policy, data bundle, native service, and derivative-media
   signatures by exact pin before importing package code. Never run code from the
   checkout or treat semantic validation as signature verification.

Exit evidence: package, authorization, backend-policy, data-bundle, and bootstrap hashes;
signer pins; file manifest; and successful offline verification. No live change.

## Stage 2 — backup and controlled install

Before mutation, capture and hash:

- MCP 1.8.0 source/package files and scheduled task XML;
- OpenSSH configuration, service state, and effective forwarder policy;
- workstation tunnel script/task and Codex MCP entry;
- retained VM inventory, IDs, paths, adapters, VLAN state, disks, checkpoints, and power state;
- volume identity/free space, switch identity, and media hashes.

Install the immutable package with the separately approved signed backend policy, create
the dedicated non-interactive application identity, register its pinned public key,
apply restrictive ACLs, and initialize the approval verifier, empty plan registry,
ledger, journal, audit, receipt, quarantine, and rollback state. A policy may expose
only `Create`; it cannot create anything without a fresh host-issued plan plus the
separately signed, single-use native-administrator approval for that exact plan.

Exit evidence: installed file hashes, immutable policy/data hashes, ACL readback,
application identity/effective SSH policy, empty registry/ledger, zero Hyper-V change,
and a tested rollback package.

## Stage 3 — isolation and negative tests

Prove all of the following before activation:

- Interactive shell, PTY, forwarding, subsystem, environment override, extra argument, malformed plan ID, oversized input, and arbitrary command are denied.
- The routine identity cannot reach legacy MCP port 3000 or invoke any broad MCP mutation.
- Missing/wrong keys, wrong source, wrong release/policy hash, stale allowlist, promotion replay, and tampered state fail closed.
- Unsigned rollout-stage advancement, missing/mismatched canary receipt, acceptance or retirement evidence, a still-running/connected retired canary, out-of-order asset, and a second nonterminal transaction are denied.
- Unmanaged same-name VM, asset/name/disk collision, reparse point, wrong volume or switch ID, wrong ISO size/hash, insufficient reserve, concurrent writer, stale plan, expired plan, wrong approval, approval replay, audit failure, and receipt failure are denied.
- Failure injection before and after VHD creation, VM registration, NIC configuration, ledger bind, and receipt leaves either no mutation or a transaction-marked `OutcomeUnknown` quarantine. Nothing is deleted by name or supplied path.
- Controlled-install rollback restores the prior tunnel/SSH/MCP state and leaves all retained VMs unchanged.

Exit evidence: complete negative-test matrix and rollback drill. No plan is approved and
no Hyper-V mutation has occurred.

## Stage 4 — Debian canary Create

1. Confirm the immutable installed backend policy begins at `debian-canary`, carries
   the exact twelve-asset order, and has both canary evidence records pending. Do not
   replace or mutate the installed policy to advance a rollout stage.
2. Revalidate capacity and prove no other canary is present or reserved.
3. Request a fresh plan for `NG-VM-018`.
4. Record the host-issued plan ID, authenticated plan hash, expiry, observed-state hash, policy/release hashes, resolved storage volume, ISO hash, switch ID, and VLAN.
5. Obtain explicit owner approval of that exact plan ID and hash.
6. Use the Administrator-only approval writer; then invoke `apply <plan-id>` through the forced-command identity.
7. Verify the returned VM ID, Generation 2, CPU/memory/disk, firmware, exactly one
   derivative-media DVD, bounded transaction-owned start, access-VLAN sequencing,
   switch binding, ledger, audit chain, journal completion, receipt, and retained-VM
   invariants. Any uncertain result must be off, disconnected, and quarantined.
8. Complete Debian installation, bootstrap, network, Wazuh, TacticalRMM, backup, and recovery validation as companion workflows.
9. Retire the disposable canary through the separately approved decommission workflow before another canary or persistent rollout.

Exit evidence: signed receipt, complete canary acceptance, Operation-SeeSaw publication, and separate retirement evidence.

## Stage 5 — Windows canary and persistent fleet

After Debian acceptance and retirement, use the installed native-Administrator-only
rollout-promotion helper. It requests the service's authenticated `rollout-context`,
binds the exact Debian receipt plus independent acceptance and retirement evidence
hashes, signs the canonical same-release promotion with the pinned non-exportable
approval key, and registers it with `promote-rollout`. Registration revalidates that
the Debian canary is absent or off and disconnected before atomically advancing to
`windows-canary`. Repeat Stage 4 for `NG-VM-010`, adding vTPM/key-protector and Windows
Secure Boot proof.

Only after Windows acceptance and retirement may a second signed same-release
promotion carry the Windows receipt and evidence while retaining the exact accepted
Debian record. The HMAC-protected `rollout/current.json` anchor advances monotonically;
the detached-CMS-signed, HMAC-protected promotion history remains immutable. The base
policy never changes. The host then admits one persistent asset at a time in the exact
fixed order.

Issue one fresh plan per persistent VM in the approved order. Revalidate capacity before every plan and finish IP/DNS/OPNsense, guest bootstrap, Wazuh, TacticalRMM, backup, receipt, and asset reconciliation before advancing.

## Rollback rules

- Before an apply begins, rollback may remove the new application identity and restore SSH/tunnel/MCP configuration from the exact backup.
- After an apply begins, control-plane rollback never deletes a VM. A transaction-marked new VM is left off and disconnected, recorded as `OutcomeUnknown`, and reconciled through the recovery/decommission workflow.
- A failed evidence publication does not imply Hyper-V rollback; it creates an evidence-reconciliation finding.
- Any mismatch involving a retained VM is a stop condition and incident, not a cleanup opportunity.
