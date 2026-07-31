# ADR-0001: GitOps-lite for NorthGate VM provisioning

- **Status:** Accepted for plan-only bootstrap
- **Date:** 2026-07-31
- **Scope:** NorthGate Hyper-V host and managed virtual machines

## Context

NorthGate is a single Windows Server 2022 Hyper-V host with an established loopback-only, audited MCP path and separate break-glass administrative access. The environment needs reproducible VM provisioning without placing a general-purpose automation runner, Git credential, or moving checkout on the hypervisor. Live inventory, topology, paths, findings, and identity mappings remain in the private system of record rather than GitHub.

## Decision

Use Git as the source of reviewed declarative intent and native Hyper-V PowerShell as the lifecycle engine behind plan-gated MCP operations. Run a fixed data-only fetcher and installed planner/executor on the authorized management workstation. Generate the final plan after merge, have the host validate and register it, approve the host-issued plan ID/hash separately, and keep a distinct Administrator identity for break-glass recovery.

## Consequences

### Positive

- Preserves the private tunnel and audited MCP boundary while adding application authorization.
- Avoids unsupported or immature direct Hyper-V provider dependency.
- Makes identity, policy, review, drift, rollback, plan authenticity, and evidence explicit.
- Keeps GitHub credentials, workflow execution, and repository content off the privileged host path.

### Costs

- Requires normalized-state planning, an identity ledger, server-side policy, plan registry, authenticated plan capability, signed receipts, and a lock shared by all normal mutations.
- Requires image, firmware, network, storage, bootstrap, owner, and recovery catalogs before repeatable deployment.
- Requires separate tunnel and break-glass identities.
- A single human owner does not provide true separation of duties.

## Rejected initial alternatives

- Unrestricted Administrator SSH for routine provisioning.
- A persistent GitHub Actions runner on the Hyper-V host.
- Terraform/OpenTofu with a community direct Hyper-V provider as the baseline.
- SCVMM or Azure Arc for a single-host lab.
- Packer, DSC, or Ansible as the running-VM lifecycle authority.
- Client-computed plan hashes or exact Git SHAs as sufficient deployment authorization.
