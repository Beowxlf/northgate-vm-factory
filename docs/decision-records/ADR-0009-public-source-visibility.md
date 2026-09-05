# ADR-0009: Public source visibility

Date: 2026-09-04
Status: Owner-authorized publication decision

## Context

The VM Factory is a security-engineering portfolio project. Public access lets reviewers inspect its architecture, implementation, validation, and explicit separation of reviewed intent from live authority.

Earlier decisions kept the repository private. Before this publication, the owner was informed that the existing history includes internal lab inventory, network and storage details, and a host-specific signed clean-room installation kit. The owner explicitly chose to publish the existing repository and its history rather than create a sanitized companion.

## Decision

Make `Beowxlf/northgate-vm-factory` public with its existing history. Preserve the repository identity, commit history, signed source, and retained evidence. Do not rewrite commits or change any runtime, manifest, policy, catalog, signer, or activation setting as part of this visibility change.

This decision supersedes prior statements that visibility must remain private. Historical records remain intact and describe their original context.

## Publication review

The pre-change source was `d1d348ac31f78d9781a281e8a641c26c24a51468`.

- Fetched all advertised branches and tags into an isolated audit copy; 26 branches and 123 reachable commits were present.
- Completed Git object connectivity verification after refreshing an incomplete older local copy.
- Gitleaks 8.30.1 scanned all refs with `--log-opts=--all`; it reported 76 scanned commits with patches, exit code 0, and no detected leaks.
- A separate current-source scan with archive depth 3 reported exit code 0 and no detected leaks.
- Reviewed the retained kit inventory and its documented expiry. The host authorization and signed data expired on 2026-08-30; publication does not renew them. Public certificates and signatures are not private signing keys.

Secret scanning is bounded evidence, not a guarantee that every sensitive value is detectable. Historical issues, discussions, and Actions logs were not exhaustively scanned by this source review. The owner-approved scope includes the existing repository history and retained operational detail.

## Boundaries retained

- Public source is not permission to access or test the lab.
- Git remains non-operative reviewed intent; source `applyEnabled` is not installed host authority.
- Host installation, activation, VM execution, signing, identity changes, and network changes retain their existing independent controls.
- Expired host-specific artifacts remain historical evidence only.
- Public visibility does not grant a new software license; no license is added by this decision.
- Post-bootstrap changes continue through pull requests and validation. Existing exact commit/tree and signed-release controls remain in force.

Repository visibility must be read back after the setting changes. The merge of this decision alone is not evidence that the repository is public.
