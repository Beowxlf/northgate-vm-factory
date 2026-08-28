# NorthGate VM provisioning architecture

## Decision

Use a Git-backed, human-approved GitOps-lite model with native Hyper-V PowerShell behind a dedicated forced-command create-only boundary. Keep GitHub, Codex, planning, and deployment control off the hypervisor. Treat Git as reviewed input, not an authority to mutate the host. Legacy broad MCP mutation remains a separate Administrator break-glass path; it is not routine factory transport.

The architecture map in the [repository README](../README.md#architecture-map) is canonical. Repository source approval, create-only runtime installation, and the existing NorthGateMCP operational plane are separate states; see [ADR-0008](decision-records/ADR-0008-source-policy-and-installed-runtime-authority.md).

Source-restricted public-key authentication plus the server-enforced forced command is the create-only application authentication boundary. Network locality, loopback binding, and SSH reachability alone are never client authorization.

## Trust boundaries

| Boundary | Permitted data/actions | Prohibited data/actions |
| --- | --- | --- |
| GitHub private repository | Canonical JSON manifests, opaque catalogs, proposed policy, tests, source, documentation | Secrets, live plans, receipts, identity ledger, private keys, generated credentials, Terraform state, lab credentials |
| GitHub-hosted CI | Read-only checkout; static syntax, schema, policy, and negative tests | NorthGate route, deployment credential, self-hosted runner, privileged apply, writable workflow token |
| Authorized workstation | Fixed data-only fetcher, installed signed planner/executor, protected credentials, manual invocation, receipt collection | Executing checkout content in the privileged path, moving branch references, accepting arbitrary commits, bypassing plan expiry |
| Routine application transport | Dedicated source-restricted forced-command identity for `status`, `plan`, `apply`, and `receipt`; a future read-only tunnel must use a distinct endpoint and credential | Reuse of the Administrator key, general shell, forwarding to the broad MCP endpoint, treating loopback as client authentication |
| Create-only host operator | Typed status, plan registration, plan-ID apply, receipts, host policy, audit, single-writer lock | Public/LAN listener, forwarding, generic routine shell, trusting client validation, mutating calls that bypass the plan registry |
| NorthGate Hyper-V host | Installed provisioner and policy bundle; native Hyper-V state transition | GitHub runner, Git credential, arbitrary checkout, automatic fabric, firewall, feature, or storage-root mutation |
| Operation-SeeSaw | Decisions, assets, risks, evidence hashes, signed receipt outcome | Credentials, private keys, unredacted secrets, executor write access, raw logs as executive narrative |

## Runtime-authority states

| State | Meaning | May mutate Hyper-V? |
|---|---|---|
| Reviewed repository source | Canonical manifests, approved source policy/promotion, tests, and release inputs at an exact commit/tree | No |
| Staged signed package | Immutable candidate package retained for inspection or installation | No |
| Installed disabled create-only release | Matching package and protected state exist; identity, policy, and registry are installed; `applyEnabled=false`, executable actions are empty, and the service is stopped with startup disabled | No |
| Installed active create-only release | Exact installed policy permits the action and every identity, plan, approval, lock, collision, capacity, and receipt gate passes | Only the accepted plan operation |
| Existing NorthGateMCP operational plane | Separately governed broad management/transition component | Only through its own authorization and audit controls; never proof that the create-only release is active |

## Authorization flow

1. The owner states the desired outcome, asset identity, ownership, purpose, classification, criticality, dependencies, recovery profile, and lifecycle intent.
2. Codex prepares canonical JSON data on a branch. Hosted CI validates it without lab access.
3. A human reviews and merges. Merge approves intent but does not approve deployment.
4. A fixed fetcher obtains only allowlisted data from the approved repository identity and exact merged commit/tree. It disables hooks, filters, submodules, LFS execution, and repository-supplied code.
5. The installed planner collects a normalized read set through the authenticated loopback tunnel and calculates the post-merge delta.
6. The plan binds repository identity, the reviewed promotion anchor, commit, tree, signed release hash, host allowlist, manifest, catalog, policy, observed state, image, and installed executor/provisioner versions. On the current private GitHub tier, the promotion anchor is the exact merged commit/tree plus signed-release allowlist defined in ADR-0005, not a moving branch.
7. The host independently validates the canonical plan against authoritative policy and live state, registers it, and issues an expiring plan ID plus an authenticated plan hash.
8. A human approves that exact plan ID and hash. A model, repository merge, or ordinary client-computed SHA-256 is not deployment approval.
9. The installed executor submits only the approved plan ID using a dedicated application identity. The host lock covers every routine mutating operation.
10. The host re-reads the relevant state, rejects any mismatch, resolves opaque policy identifiers, and invokes allowlisted Hyper-V operations.
11. A signed receipt records the change ID, repository/commit, plan, actor, operations, and before/after hashes. A separate collector anchors it in Operation-SeeSaw.

## Identity and authority

- A separately protected ledger binds immutable `assetId` to the Hyper-V VM ID and canonical case-folded name. The manifest cannot claim a VM ID.
- Protected Hyper-V adapter identity uses the bare adapter GUID. When Windows Server returns a null `AdapterId`, the backend may recover only the adapter GUID from an exact `Microsoft:<VM GUID>\\<adapter GUID>` provider identity whose VM GUID matches the selected VM; every malformed or cross-VM value fails closed.
- Asset IDs and names must be unique across desired manifests, observed inventory, the ledger, and live Hyper-V state.
- An unmanaged same-name VM, mismatched VM ID, reused disk, missing ledger binding, or name drift is a collision and hard stop. It is never implicit adoption.
- Observed inventory is non-actionable. Adoption and decommission use separate typed records and approvals; neither is represented by a standard VM manifest.
- The host-side installed policy is authoritative for storage roots, switch identity/fingerprint, image artifacts, firmware, capacity, and action allowlists. Git catalogs can narrow but never widen it.
- A repository policy with `applyEnabled: true` is release input only. If the matching installed policy, active-release record, constrained identity, or registry is absent, create-only apply is disabled regardless of Git state.
- Host-executed PowerShell is Authenticode-signed with SHA-256 by the pinned release signer and must validate under the host execution policy. Detached CMS signatures bind the package and executable provenance but do not replace Authenticode enforcement.
- Initial installed authority is copied from the signed host authorization. Backend-policy presence cannot change `initialPolicy.applyEnabled=false`, add an action, or start the disabled service. A later Debian planning activation requires the installed-only helper, a native human administrator, the pinned non-exportable approval signer, a short-lived canonical record bound to readiness evidence and the exact release tuple, plus HMAC-protected host registration. The service revalidates that record on every start.
- A proposed image or profile is design inventory only. `promotedOnly: true` means a standard manifest may resolve only an active promoted image even when the image catalog also carries a pinned proposed candidate awaiting artifact and boot evidence.

## Failure behavior

- **Invalid, duplicate, unknown, or secret-like input:** reject before planning without echoing the sensitive value.
- **Raw path, switch identity, URL, command, or script in a manifest:** reject before planning.
- **Unpromoted, retired, mutable, or digest-mismatched image:** reject before apply.
- **Image, generation, firmware, or vTPM incompatibility:** reject before apply.
- **Unmanaged identity/name/disk collision:** stop; never adopt, replace, or quarantine unrelated artifacts.
- **State drift, policy change, expiry, or host maintenance marker:** invalidate and re-plan.
- **Concurrent apply:** reject through the host-side lock shared by every normal mutating method.
- **Replacement-required change:** report `ReplaceRequired`; it is non-applicable in the initial executor.
- **Partial new-VM failure:** quarantine only artifacts carrying the matching change/asset identity.
- **Existing-VM change failure:** preserve before-state and require a new reviewed rollback plan.
- **Missing or renamed manifest:** report drift only; never infer deletion.
- **Evidence export failure:** mark evidence reconciliation pending; do not falsely claim Hyper-V rollback.

## Separation rules

- VM intent, catalog/policy, and privileged executor/provisioner releases are distinct promotion units. A VM change cannot consume a relaxed policy in the same deployment.
- A `WorkloadProvisioningProposal` is a strict, non-deployable design record. It cannot reserve an identity, stand in for a standard VM manifest, become a host-issued plan, or co-promote catalog/fabric policy with its first consuming workload.
- The inactive `CanaryExecutionStageProposal` is not an apply authority. Any future canary stage is a separate installed-policy promotion that accepts only a dedicated `DisposableCanaryRequest`, never a standard `VirtualMachine` manifest, and still requires a fresh host-issued plan plus exact human approval.
- The normal MCP identity cannot invoke a mutating bypass. Direct lifecycle tools, if retained, require a separate break-glass identity and maintenance/change record.
- The create-only SSH key is source-restricted and forced-command only. It is inaccessible to the Administrator approval writer and cannot forward to MCP. The administrative SSH key is inaccessible to the normal executor identity.
- Hosted CI has no inbound or outbound path to the private lab. The workstation is invoked manually or polls outbound; it exposes no webhook listener.

## Explicit non-goals for the initial release

- Terraform/OpenTofu as the direct Hyper-V lifecycle engine.
- SCVMM, Azure Arc, or an enterprise orchestration layer.
- A GitHub Actions runner on the hypervisor.
- Destructive reconciliation, automatic replacement, adoption, decommission, or purge.
- Automatic virtual-switch, firewall, host-feature, or storage-root changes.
- Guest configuration beyond a referenced, versioned bootstrap profile.
