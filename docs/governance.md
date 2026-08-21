# Repository and deployment governance

## Repository controls

- Visibility remains private and the approved repository identity is `Beowxlf/northgate-vm-factory`.
- Default branch is `main`.
- Initial bootstrap may be committed directly; subsequent changes use pull requests.
- Require validation checks and resolved review conversations before merge.
- Require review of `.github/`, `schemas/`, `catalog/`, `policy/`, `proposals/`, and future privileged source changes.
- Do not require an independent reviewer until a second trusted reviewer exists; otherwise a single-owner repository can deadlock itself. This is a residual separation-of-duties risk, not a compensating control.
- Disable force pushes and branch deletion when branch protection is enabled.
- Pin Actions to full commit identifiers and keep workflow permissions read-only.
- Reject submodules, symlinks/reparse points, unexpected executable content, filters, and LFS pointers from privileged data inputs.

## Deployment approval

Repository merge approves intent, not deployment. The final plan is generated after merge from the exact approved repository identity, commit, and tree. A separate approval must name the host-issued plan ID and authenticated plan-hash prefix.

Source policy approval and installed runtime authorization are different decisions. An approved source file may carry `applyEnabled: true` so an immutable release can be built and tested; it has no effect until that exact signed release and policy are installed, read back, activated through a separate host change, and bound to the constrained identity and plan chain. Existing NorthGateMCP deployment is governed separately and does not satisfy the create-only installation gate.

The approver reviews:

- repository identity, protected-branch reachability, exact merged commit/tree, and manifest hash;
- normalized before and desired state plus the non-volatile read set;
- operations, action class, and downtime classification;
- capacity, identity, image, firmware, network, storage, and dependency checks;
- rollback or quarantine route;
- plan expiry, host state hash, policy/catalog versions, installed executor/provisioner versions, and image digest.

An exact SHA alone is insufficient. The host accepts and registers the canonical plan, applies its authoritative policy, and returns the plan capability that is approved.

## Change classes

| Class | Examples | Minimum gate |
| --- | --- | --- |
| Documentation | Architecture prose, non-operative examples | Repository validation and review |
| Plan-only policy | Schema, catalog, limits while apply remains disabled | Security-sensitive review; no deployment |
| Safe lifecycle | Create canary, approved online resource update | Reviewed commit, post-merge live plan, human plan approval, lock, verification |
| Disruptive | Offline resource change, restart, checkpoint restore | Maintenance window and explicit downtime approval |
| Destructive | Replace, decommission, disk deletion, purge | Separate typed workflow, quarantine/retention, recovery evidence, second explicit approval |
| Control plane | MCP, executor, workflow, identities, ACLs, storage/network policy | Privileged change process with backup, negative tests, signed release/hash gate, rollback |

Catalog/policy changes and the first VM change that consumes them cannot share one deployment approval. Privileged code and policy are promoted as installed, signed bundles separate from repository data.

An owner-authorized source artifact, VLAN number, or target design may be recorded as a proposed catalog or workload-proposal entry. That records intent only: it does not approve the installed host/OPNsense mapping, image promotion, fabric mutation, standard manifest, host-issued plan, or apply. Network/fabric activation remains a control-plane change with configuration backup and readback; the first VM using that mapping is a later deployment unit.

The plan-only canary proposal is likewise not deployment approval. Activating a canary-only stage, introducing its dedicated request contract, and submitting the first disposable-canary request are separate review and promotion units. A standard `VirtualMachine` manifest can never use that stage.

## Evidence

Every lab-affecting action is correlated with one change ID across the pull request, commit/tree, plan registration, approval, MCP audit events, before/after inventory, signed receipt, and Operation-SeeSaw records.

The normal executor has no write access to Operation-SeeSaw. A separate off-host collector or verified Codex documentation step records the receipt and its SHA-256. Evidence-write failure creates a reconciliation finding; it does not rewrite the execution outcome.
