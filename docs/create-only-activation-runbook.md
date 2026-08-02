# Create-only fleet activation runbook

## Purpose

Standardize promotion of the NorthGate VM Factory from plan-only design to a narrowly scoped `Create` capability. This runbook never authorizes a VM by itself. Every install, policy promotion, and host-issued plan remains a distinct evidence-backed change.

## Permanent invariants

- The five retained VMs are never transaction, rollback, quarantine, or cleanup targets.
- Only the twelve fixed candidate asset IDs are recognized.
- Every executable plan contains exactly one `Create` operation.
- The client supplies an asset ID or plan ID only—never a path, switch, VLAN, ISO, URL, script, or command.
- Every VM is Generation 2, destroy-protected, and off at the end of create.
- No update, power, replace, adopt, decommission, delete, purge, switch, firewall, guest-command, or arbitrary-command operation exists on the routine identity.
- Repository merge, policy promotion, release installation, and plan approval are separate decisions.

## Stage 0 — release source review

1. Validate the private repository, exact branch diff, and secret scan.
2. Run repository, candidate, parser, registry, approval, lock, adapter, failure-injection, installer, and rollback tests.
3. Review and merge the release source.
4. Record the exact repository identity, merged commit, tree, test result, and CI run.

Exit evidence: exact merged commit/tree and passing private CI. No live change.

## Stage 1 — immutable package and host policy

1. Build outside the repository checkout from the exact merged commit.
2. Produce a package manifest with every file SHA-256, release SHA-256, signer identity, commit, tree, and monotonic release version.
3. Generate an environment-specific host policy outside Git that pins:
   - host identity;
   - both volume unique IDs and approved roots;
   - exact ISO paths, sizes, and SHA-256 values;
   - exact existing switch ID and access VLAN mapping;
   - fixed fleet specifications and one-canary rule;
   - memory, processor, and per-volume reserves;
   - apply disabled and no executable action.
4. Verify the package and policy in a clean staging directory. Never run code from the checkout.

Exit evidence: package hash, policy hash, signer, file manifest, and successful offline verification. No live change.

## Stage 2 — backup and disabled install

Before mutation, capture and hash:

- MCP 1.8.0 source/package files and scheduled task XML;
- OpenSSH configuration, service state, and effective forwarder policy;
- workstation tunnel script/task and Codex MCP entry;
- retained VM inventory, IDs, paths, adapters, VLAN state, disks, checkpoints, and power state;
- volume identity/free space, switch identity, and media hashes.

Install the immutable package, create the dedicated non-interactive application identity, register its pinned public key, apply restrictive ACLs, create the approval verifier, registry, ledger, journal, audit, receipt, quarantine, and rollback directories, and keep `applyEnabled=false` with no executable action.

Exit evidence: installed file hashes, ACL readback, application identity/effective SSH policy, disabled status, and a tested rollback package.

## Stage 3 — isolation and negative tests

Prove all of the following before activation:

- Interactive shell, PTY, forwarding, subsystem, environment override, extra argument, malformed plan ID, oversized input, and arbitrary command are denied.
- The routine identity cannot reach legacy MCP port 3000 or invoke any broad MCP mutation.
- Missing/wrong keys, wrong source, wrong release/policy hash, stale allowlist, promotion replay, and tampered state fail closed.
- Unmanaged same-name VM, asset/name/disk collision, reparse point, wrong volume or switch ID, wrong ISO size/hash, insufficient reserve, concurrent writer, stale plan, expired plan, wrong approval, approval replay, audit failure, and receipt failure are denied.
- Failure injection before and after VHD creation, VM registration, NIC configuration, ledger bind, and receipt leaves either no mutation or a transaction-marked `OutcomeUnknown` quarantine. Nothing is deleted by name or supplied path.
- Disabled-install rollback restores the prior tunnel/SSH/MCP state and leaves all retained VMs unchanged.

Exit evidence: complete negative-test matrix and rollback drill. Apply remains disabled.

## Stage 4 — Debian canary Create

1. Promote only the Debian disposable-canary policy in a separate change.
2. Revalidate capacity and prove no other canary is present or reserved.
3. Request a fresh plan for `NG-VM-018`.
4. Record the host-issued plan ID, authenticated plan hash, expiry, observed-state hash, policy/release hashes, resolved storage volume, ISO hash, switch ID, and VLAN.
5. Obtain explicit owner approval of that exact plan ID and hash.
6. Use the Administrator-only approval writer; then invoke `apply <plan-id>` through the forced-command identity.
7. Verify the returned VM ID, Generation 2, off state, CPU/memory/disk, Secure Boot, ISO, disconnected-then-access-VLAN sequencing, switch binding, ledger, audit chain, journal completion, receipt, and retained-VM invariants.
8. Complete Debian installation, bootstrap, network, Wazuh, TacticalRMM, backup, and recovery validation as companion workflows.
9. Retire the disposable canary through the separately approved decommission workflow before another canary or persistent rollout.

Exit evidence: signed receipt, complete canary acceptance, Operation-SeeSaw publication, and separate retirement evidence.

## Stage 5 — Windows canary and persistent fleet

Repeat Stage 4 for `NG-VM-010`, adding vTPM/key-protector and Windows Secure Boot proof. Only after both canaries pass may normal policy be promoted to `applyEnabled=true` and `executableActions=["Create"]`.

Issue one fresh plan per persistent VM in the approved order. Revalidate capacity before every plan and finish IP/DNS/OPNsense, guest bootstrap, Wazuh, TacticalRMM, backup, receipt, and asset reconciliation before advancing.

## Rollback rules

- Before an apply begins, rollback may remove the new application identity and restore SSH/tunnel/MCP configuration from the exact backup.
- After an apply begins, control-plane rollback never deletes a VM. A transaction-marked new VM is left off and disconnected, recorded as `OutcomeUnknown`, and reconciled through the recovery/decommission workflow.
- A failed evidence publication does not imply Hyper-V rollback; it creates an evidence-reconciliation finding.
- Any mismatch involving a retained VM is a stop condition and incident, not a cleanup opportunity.
