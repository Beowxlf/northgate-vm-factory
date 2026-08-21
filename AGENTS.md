# NorthGate VM Factory agent guidance

## Mission

Maintain a safe, reviewable, Git-backed desired-state system for NorthGate Hyper-V provisioning.

## Non-negotiable controls

- Treat the repository as **non-operative source input**. Repository policy may be approved and may contain `applyEnabled: true` for immutable release packaging, but that value is not installed apply authority. Only a matching installed signed release, authoritative host policy, constrained application identity, protected ledger/registry, and host-issued approved plan can make an operation executable.
- Never invoke a mutating NorthGate MCP tool merely because a manifest changed.
- Never use unrestricted host or guest SSH for routine provisioning. Direct SSH is bootstrap, recovery, or MCP-maintenance fallback only.
- Preserve loopback-only MCP, the encrypted tunnel, key-only SSH, pinned identities, source-restricted firewalls, auditing, and rollback gates.
- Never store or print passwords, tokens, private keys, generated unattend credentials, domain-join secrets, or Terraform state.
- The privileged path consumes canonical JSON data from an approved repository identity and exact merged commit/tree. Never execute repository hooks, filters, submodules, scripts, binaries, or PowerShell from a deployment checkout.
- Generate the final plan after merge. The host must validate and register it, then issue the expiring plan ID/hash that a human separately approves; a client hash or Git SHA is not sufficient authorization.
- Preserve application authentication and separate identities for forwarding, routine apply, and Administrator break-glass access.
- Manifests use immutable `assetId` identity and catalog references. They may not contain raw host paths, switch names, URLs, commands, or credential-like fields.
- Missing manifests do not imply deletion. Replace, decommission, quarantine, and purge require explicit typed lifecycle changes and separate approval.
- A same-name unmanaged VM or missing identity mapping is a hard stop, never an adoption signal.
- Keep the existing broad NorthGateMCP operational plane distinct from the create-only VM Factory release. Do not describe one component's deployed state as proof that the other is installed or authorized.
- Routine VM provisioning cannot create, remove, or rebind virtual switches or change host firewall, features, services, or storage roots.

## Change workflow

1. Inspect the requested scope and related Operation-SeeSaw records.
2. Make the smallest repository change that satisfies the request.
3. Run `./scripts/Test-Repository.ps1`.
4. Produce or update tests for any policy or schema behavior.
5. Review the diff for secret exposure, raw execution, implicit deletion, moving references, and weakened validation.
6. Use a pull request for post-bootstrap changes. Merge approval and deployment approval are separate.
7. For an approved lab apply, bind the plan to repository identity, merged commit/tree, canonical manifest, normalized observed state, policy/catalog, executor/provisioner, and image hashes; verify the host-issued plan capability, application identity, host-side lock, and expiry.
8. Verify the outcome and update Operation-SeeSaw asset, infrastructure, risk, evidence, and executive records.

## Definition of done

- Relevant validation passes.
- No secret or unrestricted command path was introduced.
- Architecture and documentation remain consistent with implementation.
- A deployment-affecting change has an explicit rollback or quarantine route.
- The final report distinguishes repository changes from actual Hyper-V changes.
