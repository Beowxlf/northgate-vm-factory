# Security policy

## Scope

This private repository defines the intended control plane for a privileged Hyper-V lab. Treat schema, policy, catalog, workflow, and executor changes as security-sensitive.

## Reporting

Report suspected secret exposure, unauthorized repository access, unsafe workflow behavior, or a bypass of plan/apply controls directly to the repository owner. Do not place credentials, private infrastructure evidence, exploit details, or live tokens in a GitHub issue.

## Mandatory protections

- No secrets or host/guest private keys in Git, issues, pull requests, Actions logs, plans, or receipts.
- GitHub-hosted runners perform static validation only and have no NorthGate route or credentials.
- No self-hosted GitHub runner is permitted on the Hyper-V host.
- The final plan is produced after merge and binds the approved repository identity, exact commit/tree, canonical data, normalized state, policy, image, and installed component versions.
- Apply requires a host-validated, expiring plan ID with an authenticated hash, separate human approval, application authentication, and a host-side single-writer lock.
- The fixed executor and server-side MCP policy independently enforce allowlists; client-side validation is not sufficient.
- The forwarding identity cannot open an Administrator shell. The break-glass key is inaccessible to the normal executor identity.
- Repository content is untrusted data at the privileged boundary; hooks, filters, submodules, binaries, and checkout scripts are never executed there.
- Destructive operations, network changes, storage-root changes, policy changes, executor releases, and image promotion remain human-gated.

If a secret is committed, revoke or rotate it first, then remove it from repository history. Deleting the visible file alone is not remediation.
