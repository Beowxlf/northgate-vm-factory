# Acceptance gates and negative tests

The repository is plan-only. These tests define the minimum exit criteria before any apply capability is promoted.

## Control-plane gates

- MCP code and audit locations have verified restrictive ACLs, immutable release/hash metadata, backup, and rollback. Exact paths and findings remain in the private system of record.
- The forwarding identity cannot open an Administrator shell; the normal executor cannot access the break-glass key.
- MCP mutation requires application authentication, a live host-issued plan capability, and the host-wide writer lock.
- No ordinary MCP method or identity bypasses plan registration.
- The installed executor, provisioner, and host policy are signed/versioned promotion units separate from repository data.
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
11. Reject an arbitrary/fork/deleted-branch commit even if its ordinary SHA-256 matches supplied metadata.
12. Expire or stale a plan after relevant live state, policy, catalog, executor, provisioner, or maintenance-marker change.
13. Prove loopback requests without application authentication or a one-time plan capability cannot mutate state.
14. Prove all normal mutation paths contend on the same host lock and concurrent apply fails closed.
15. Produce a signed receipt with repository, commit/tree, plan, actor, operations, and before/after hashes, and preserve an evidence-reconciliation finding if vault anchoring fails.

## Canary exit

Use one disposable, non-domain-controller VM. Capture before/after inventory, failure injection, concurrency behavior, quarantine/rollback, logs, receipt, and Operation-SeeSaw evidence. A successful VM boot alone is not acceptance.
