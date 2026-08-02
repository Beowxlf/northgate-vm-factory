# ADR-0005: Dedicated forced-command create-only release

- **Status:** Accepted for release engineering; live promotion pending
- **Date:** 2026-08-02
- **Scope:** Routine NorthGate VM creation for the approved 12-asset fleet

## Context

The live NorthGate MCP 1.8.0 service exposes read-only inventory and broad break-glass mutations on different URL paths of one loopback port. The forwarding-only SSH identity restricts the destination port, not the HTTP path, so it cannot enforce a create-only application role. The current private GitHub account also does not provide branch protection for private repositories. Making the repository public or treating an unprotected moving branch as deployment authority is unacceptable.

Codex supports environment-sourced bearer tokens for HTTP MCP servers, but it does not natively retrieve an arbitrary bearer secret from Windows Credential Manager. A securely reviewed process-only secret launcher does not yet exist in this environment. The existing source-restricted public-key SSH pattern is already deployed and understood.

## Decision

Use a separate, source-restricted SSH application identity whose server-side forced command exposes exactly four operations:

- `status`
- `plan`
- `apply ngp-<64-lowercase-hex>`
- `receipt ngp-<64-lowercase-hex>`

The identity has no interactive shell, PTY, forwarding, agent forwarding, X11, subsystem, environment override, or arbitrary command route. `plan` accepts only a bounded fixed asset identifier. `apply` accepts only a host-issued plan ID and succeeds only after a separate Administrator-only approval writer has recorded the exact plan ID and authenticated plan hash.

The installed release resolves all storage, ISO, switch, VLAN, firmware, and bootstrap values from an ACL-protected host policy. Callers cannot submit paths, switch names, VLANs, URLs, scripts, or PowerShell. Every plan contains one typed `Create` operation; created VMs are Generation 2, destroy-protected, and initially powered off. No update, start, stop, replace, adopt, decommission, delete, purge, switch, firewall, guest-command, or general execution operation is registered.

The broad MCP 1.8.0 endpoint remains available only to the separate Administrator break-glass path. Before routine create-only activation, the existing forwarding identity must lose access to port 3000. Read-only discovery may later move to a separately authenticated read-only service, but it is not allowed to delay removal of the broad routine tunnel.

```mermaid
flowchart LR
    Owner["Owner"] -->|"approve exact plan ID + hash"| Approval["Administrator-only approval writer"]
    Git["Private Git repository\nexact merged commit + tree"] --> Package["Signed release package\nexact SHA-256"]
    Package --> Allowlist["Host-installed release allowlist"]
    Codex["Codex on management workstation"] -->|"pinned public-key SSH"| Forced["Forced-command identity\nstatus / plan / apply / receipt"]
    Forced --> Registry["Plan registry + writer lock"]
    Approval --> Registry
    Allowlist --> Registry
    Registry --> Policy["Protected host policy\nfixed 12 assets"]
    Policy --> HyperV["Bounded native Hyper-V Create"]
    HyperV --> VM["Generation 2 VM\noff, VLAN fixed"]
    Registry --> Evidence["Hash-chained audit + receipt"]
    Admin["Administrator break-glass"] -.-> Legacy["Legacy MCP 1.8.0\nloopback port 3000"]
```

## Repository trust compensating control

Private-repository branch protection is unavailable on the current GitHub tier. The compensating control is content-addressed and fail-closed:

1. Human review and merge still establish intent.
2. Promotion names the exact repository identity, merged commit, tree, release SHA-256, signer identity, and host allowlist ID.
3. The installer verifies those exact values and installs immutable bytes; it never executes a checkout.
4. A moving branch, tag name, GitHub release name, or client-computed manifest hash is never deployment authority.
5. Reuse of an older allowed release is blocked by host promotion state.

This exception requires review as its own governance change. It does not relax the separate host-issued plan approval.

## Storage and rollout boundary

Environment-specific paths, volume identities, switch fingerprints, media locations, and addresses remain outside Git. The installed host policy must split the 900 GiB persistent disk ceiling across both approved Hyper-V volumes and permit only one disposable canary at a time. Capacity, media hashes, switch identity, collision state, maintenance state, and the release/policy hashes are revalidated while holding the host writer lock immediately before creation.

The first executable stage is the Debian disposable canary only. Windows canary activation follows independent Secure Boot and vTPM proof. Normal persistent `Create` remains disabled until both canaries pass and are retired through the separate decommission workflow.

## Failure and recovery behavior

- Existing VM name, identity, disk, or path collision is a hard stop; there is no implicit adoption.
- A stale, expired, unapproved, reused, or state-mismatched plan is rejected.
- Audit, registry, approval-verification, lock, media, or receipt failure before mutation is fail-closed.
- After the irreversible boundary, ambiguous results become `OutcomeUnknown`; asset and name reuse are blocked.
- Only transaction-marked new artifacts may enter quarantine. The operator never deletes by supplied name or path.
- Control-plane rollback removes the create-only identity and release but never deletes a VM already created.
- The five retained VMs are outside every candidate transaction and rollback scope.

## Promotion sequence

1. Merge and pin the design and release source without activation.
2. Review the exact release commit/tree and package hash.
3. Back up MCP 1.8.0, scheduled tasks, SSH configuration, tunnel configuration, and host policy state.
4. Install the release, identity, keys, ACLs, registry, ledger, audit, approval writer, and rollback package with apply disabled.
5. Prove command denial, source restriction, no broad MCP reachability, ACLs, lock, expiry, collision, capacity, media, switch, audit, failure injection, and rollback.
6. Promote only Debian canary `Create`, issue a fresh host plan, and request separate approval of its exact ID and hash.

No step combines release installation, policy promotion, first consuming request, and plan approval.

## Consequences

This path uses mature source-restricted public-key authentication and removes routine exposure to the broad MCP endpoint. It adds an installer, fixed host policy, forced-command dispatcher, approval signer/verifier, crash journal, ledger, audit chain, receipt, and rollback package that must be tested and promoted independently. OAuth-backed MCP may replace the forced-command transport later without changing the plan, approval, policy, or Hyper-V transaction contracts.
