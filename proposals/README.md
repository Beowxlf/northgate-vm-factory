# Non-deployable workload proposals

This directory holds strict design-time records for workloads whose identities, prerequisite catalogs, installed policy, or control plane are not ready for a standard VM manifest.

A proposal:

- remains `status: proposed` and explicitly non-deployable;
- cannot reserve an asset identity or approve a change reference;
- cannot stand in for `manifests/vms/`, a host-registered plan, or exact-plan human approval;
- contains only opaque catalog references and bounded workload resource intent;
- cannot co-promote catalog/fabric policy with the first workload that consumes it; and
- must be removed or superseded through review when separately approved standard manifests are later authored.

The privileged fetcher must not ingest this directory as deployment input.

The strict [full-fleet proposal](full-fleet.proposed.json) holds the twelve reviewed candidate manifest envelopes and opaque profile selections without creating standard manifests or reservations. Exact proposed VLAN, address, DNS, assignment-method, capacity, and rollout handoff is documented in [the full-fleet foundation plan](../docs/full-fleet-foundation-plan.md). Its blocked state is intentional.
