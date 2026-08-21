# ADR-0008: Separate source policy from installed runtime authority

- Status: accepted
- Date: 2026-08-20
- Scope: repository and runtime-state semantics
- Deployment effect: none

## Context

The repository previously called itself plan-only while its approved source resource policy contained `applyEnabled: true` and `Create` in `executableActions`. Current evidence also distinguishes an existing operational NorthGateMCP component from the create-only VM Factory release. Treating any one of those facts as the state of the others creates an unsafe ambiguity.

## Decision

Use three independent authorities:

1. **Repository source authority:** Git holds reviewed manifests, catalogs, approved source policy/promotion, tests, and immutable release inputs. Source `applyEnabled` expresses what a correctly installed release may permit; it does not mutate or configure the host.
2. **Installed create-only authority:** the host must contain and read back the exact signed release, installed authoritative policy, active-release record, constrained identity, protected ledger/registry, shared writer lock, audit path, and approval/receipt chain. Missing installed state means create-only apply is disabled.
3. **Existing operational management authority:** NorthGateMCP is a separate, currently governed operational/transition plane. Its service health or mutation capability never proves the create-only release is installed. It is not silently disabled, replaced, or broadened by a Git merge.

Operation-SeeSaw remains the authority for dated installed-state and component-disposition evidence. Repository documentation describes contracts and promotion state without claiming that drift-prone host state is current.

## Consequences

- A Git clone or pull may obtain reviewed data, but repository hooks, scripts, binaries, and arbitrary commands are never executed as the privileged data path.
- A fixed data-only fetcher may consume allowlisted canonical files from an exact merged commit/tree.
- A signed package in staging remains non-operative.
- Merge, source `applyEnabled`, an approved promotion, or a healthy NorthGateMCP endpoint cannot authorize create-only apply.
- Activation requires a separate host change and current evidence; VM operations still require the exact host-issued plan and all collision/capacity/approval gates.
- Existing same-name VMs remain hard collisions and are never implicit adoption targets.
