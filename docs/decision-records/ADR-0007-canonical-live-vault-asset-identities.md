# ADR-0007: Preserve canonical live and Operation-SeeSaw asset identities

- Status: accepted for repository correction
- Date: 2026-08-20
- Change: `NG-CHG-20260820-001`
- Authority: NorthGate Lab Owner; Operation-SeeSaw `DEC-005`
- Deployment effect: none; apply remains blocked

## Context

Read-only SW-EPIC-00 reconciliation found six asset-ID/name conflicts between repository main at `a9634a5`, the Operation-SeeSaw Asset Register, and current live VM names. No installed VM Factory ledger binds the live VMs to the repository manifests. Reassigning the vault or implicitly adopting same-name VMs would rewrite established asset history without a protected identity proof.

## Decision

Preserve the live/vault identities as canonical and correct repository data, schemas, tests, documentation, bootstrap mappings, proposals, promotion records, and non-installed control-plane candidates to the following exact map:

| Asset ID | Canonical VM name |
|---|---|
| `NG-VM-013` | `NG-MAIL-INT01` |
| `NG-VM-014` | `NG-MAIL-EXT01` |
| `NG-VM-015` | `NG-KALI-EXT01` |
| `NG-VM-019` | `NG-MGR-01` |
| `NG-VM-020` | `NG-IT-01` |
| `NG-VM-021` | `NG-CYBER-01` |

Dependencies and the Kali firmware exception follow the canonical workload identity. The repository validator must reject regression of any of these six pairings.

## Safety consequences

- This is a repository correction only. It does not create, manage, rename, rebuild, or adopt a live VM.
- All ten existing same-name persistent VMs remain unmanaged collisions until a separate adoption design is approved and a protected ledger is established.
- The staged release built from `a9634a5`, its signed fleet map, and any derived plan are superseded and must not be installed or applied.
- A future release requires a clean reviewed commit/tree, new package and signature, corrected release authorization, fresh live plan, and the later governance gates.
- Release packaging reads runtime reference assemblies with shared-read access so a clean Windows PowerShell 5.1 validation can hash already loaded framework assemblies without weakening package integrity checks.
- Missing or renamed manifests still never authorize deletion.

## Alternatives rejected

- Reassigning the Asset Register to the repository pairings: rejected because it overwrites established live/vault identity without ledger evidence.
- Treating names as adoption proof: rejected because names are mutable attributes and same-name unmanaged objects are hard collisions.
- Correcting only six manifest files: rejected because release candidates, schemas, tests, promotion data, bootstrap mappings, proposals, and documentation encoded the same superseded map.
