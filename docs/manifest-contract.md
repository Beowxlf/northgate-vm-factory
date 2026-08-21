# Manifest contract

## Standard VM intent

`VirtualMachine` is a strict desired-state record for `create` or `manage` intent. It cannot claim a Hyper-V VM ID, a path, a switch, a VLAN, a filename, a URL, a command, a script, bootstrap material, or credentials. It contains only immutable asset identity, governance metadata, resource values, and opaque approved profile references.

Generation 2 and `destroyProtection: true` are constants in v1. Changes that require replacement are reported as `ReplaceRequired` and are not executable by the initial create-only release.

## Separate record types

- `ObservedVirtualMachine` is generated from read-only inventory and is never actionable.
- `AdoptionRequest` binds an exact live VM ID to an approved asset ID through a separate workflow. Its first accepted plan must be `NoOp`.
- `DecommissionRequest` requires the asset ID, exact ledger VM ID, quarantine action, retention deadline, recovery/export evidence, approval, and plan hash.
- Permanent purge is a second workflow after retention and is not exposed by the initial executor.

These record types intentionally have no schemas in the bootstrap repository because none is authorized for apply.

## Identity ledger

The ledger is protected outside Git and maps `assetId -> Hyper-V VMId -> canonical case-folded name`. The server rejects duplicate asset IDs or names, unmanaged same-name VMs, missing/wrong/duplicated VM IDs, name drift, and reused artifacts. It never interprets a collision as adoption.

## Opaque catalogs

Manifest references resolve exactly once to approved catalog entries. Network and storage catalogs contain opaque server policy IDs, not host paths or switch names. The installed host policy maps those IDs to approved canonical resources and may be stricter than Git. Git cannot widen server allowlists.

Catalogs may carry records with `approvalStatus: proposed` so an exact candidate can be reviewed without making it consumable. `promotedOnly: true` on the image catalog is a consumption rule: a manifest still fails unless its image is active, promoted, fully sized, and digest-pinned. Proposed network, storage, firmware, bootstrap, recovery, owner, and access profiles likewise fail standard manifest resolution until separately approved. Access profiles are companion guest-access policy records and are not a field in the current standard VM manifest; the selected bootstrap and separate guest-access workflow must enforce them.

Catalog and policy hashes are bound into the plan. Image IDs are immutable by digest. A catalog/policy release cannot be promoted in the same deployment as the first VM change that consumes it.

## Canonicalization and parsing

Before hashing or planning, implementations must parse strict UTF-8 JSON, reject duplicate keys, nulls, unknown fields, control characters, oversized documents, floats in integer fields, and implicit defaults, then serialize to one documented canonical JSON form. Repository validation is an early gate; the installed planner and host repeat authoritative validation.
