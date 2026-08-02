# Acceptance gates and negative tests

The repository is plan-only. These tests define the minimum exit criteria before any apply capability is promoted.

## Control-plane gates

- MCP code and audit locations have verified restrictive ACLs, immutable release/hash metadata, backup, and rollback. Exact paths and findings remain in the private system of record.
- The create-only identity is source-restricted and forced-command only; it cannot open a shell or tunnel, access the break-glass key, or reach the broad MCP endpoint.
- Create requires application authentication, a live host-issued plan capability, separately recorded exact approval, and the host-wide writer lock.
- No ordinary MCP or SSH method or identity bypasses plan registration.
- The installed executor, provisioner, and host policy are signed/versioned promotion units separate from repository data.
- When private-repository branch protection is unavailable, promotion pins the exact merged commit, tree, signed release SHA-256, signer, and host allowlist without making the repository public.
- Hosted CI has read-only repository permission and no route or credential to NorthGate.

## Must-pass negative tests

1. Reject unknown or nested extra fields, duplicate JSON keys, nulls, floats for integer fields, invalid UTF-8/control characters, and oversized input.
2. Reject drive, UNC, device, traversal, reparse-escape, environment-variable, wildcard, ADS, path, filename, and URI-shaped manifest data client- and server-side.
3. Fail an unknown, missing, renamed, rebound, or fingerprint-mismatched network profile without any switch mutation.
4. Reject secret-like keys and PEM, JWT, PAT, private-key, or high-entropy credential content without echoing it.
5. Prove that manifest deletion/rename and `destroyProtection: false` cannot produce a delete action.
6. Fail duplicate/case-only names, duplicate asset IDs, unmanaged name collisions, wrong VM IDs, missing ledger bindings, and reused disks without adoption.
7. Fail incompatible image, guest family, generation, firmware, Secure Boot, and vTPM combinations.
8. Fail mutable `latest` images, digest changes under an existing ID, retired images, and artifact hash mismatches.
9. Prove duplicate apply is `NoOp` and observed/adoption records cannot be applied as create.
10. Limit planner output to `NoOp`, `Create`, `UpdateOnline`, `UpdateOffline`, `ReplaceRequired`, or `DecommissionRequired`; the last two are non-executable in the initial release.
11. Reject an arbitrary/fork/unmerged commit, moving branch or tag, wrong tree, wrong signer, release-hash mismatch, stale allowlist, or promotion replay.
12. Expire or stale a plan after relevant live state, policy, catalog, executor, provisioner, or maintenance-marker change.
13. Prove the forced-command key cannot request a shell, forwarding, subsystem, environment override, generic command, direct Hyper-V method, or mutation without an approved one-time plan capability.
14. Prove all normal mutation paths contend on the same host lock and concurrent apply fails closed.
15. Produce a signed receipt with repository, commit/tree, plan, actor, operations, and before/after hashes, and preserve an evidence-reconciliation finding if vault anchoring fails.
16. Reject any attempt to treat the canary proposal as active, give it effective actions, admit a standard `VirtualMachine` request, broaden it beyond `Create`, run more than one canary, co-promote its first request, or omit an exact-plan, quarantine, or receipt gate.
17. Reject any workload proposal that claims deployability, bypasses a host-issued plan, bundles a standard manifest, enables resource policy, collapses catalog/fabric promotion into a consuming workload, claims reserved identity, references an approved/unknown prerequisite instead of the exact proposed set, or introduces a raw path, VLAN/IP field, command, or secret-like value.
18. Reject any full-fleet proposal that admits fewer or more than the twelve reviewed candidate identities, changes their serialized canary-first order, claims an identity/address/DNS reservation, omits fresh capacity revalidation or the Kali promotion gate, marks a workload ready, catalogs a fabricated Kali artifact, misstates computed persistent-fleet totals, or introduces raw VLAN/IP/DNS fields into its machine-readable manifest envelopes.
19. Prove the fixed storage split, 15-percent/100-GiB per-volume reserve, one-canary concurrency rule, exact switch fingerprint/VLAN, ISO size/hash, Generation 2/off-only create, Secure Boot, Windows vTPM, collision denial, crash journal, outcome-unknown quarantine, and non-deletion of retained VMs.

## Canary exit

Use one disposable, non-domain-controller VM. Capture before/after inventory, failure injection, concurrency behavior, quarantine/rollback, logs, receipt, and Operation-SeeSaw evidence. A successful VM boot alone is not acceptance.
