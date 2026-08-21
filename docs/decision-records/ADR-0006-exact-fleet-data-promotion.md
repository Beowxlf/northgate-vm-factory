# ADR-0006: exact-fleet data promotion and Kali firmware exception

Status: accepted for implementation; no deployment promotion is present in the repository yet
Date: 2026-08-02

## Decision

The repository remains plan-only unless `policy/deployment-promotion.json` exists, validates against the fixed promotion schema, and names exactly the authorized twelve-asset fleet. When that record is present, `policy/resource-limits.json` may change only to `status: approved`, `applyEnabled: true`, and `executableActions: ["Create"]`.

The promotion record does not itself authorize a host mutation. Production still requires an immutable signed installed release, signed host authorization, raw-Git data-only bundle, current host plan, separate signed one-use approval for that exact plan, single-writer execution, quarantine on uncertainty, and a signed receipt. Every plan creates at most one asset. Delete, replace, adopt, rename, retained-asset mutation, and switch mutation remain unavailable.

The two disposable canaries remain first and sequential. Each persistent asset requires a new live-state and capacity collection, a new plan, and a new approval after both canaries have been independently accepted.

## Firmware profiles

- Windows uses Generation 2, the `MicrosoftWindows` Secure Boot template, a host-local key protector, and vTPM.
- Debian uses Generation 2, the `MicrosoftUEFICertificateAuthority` Secure Boot template, and no vTPM.
- Kali uses Generation 2 UEFI with Secure Boot disabled only for `NG-VM-015`, through profile `kali-gen2-unsigned` and exception `NG-FW-20260802-KALI-UNSIGNED`.

The Kali exception is narrow because the official Kali installation guide states that its installer kernel is not signed for Secure Boot: <https://www.kali.org/docs/installation/hard-disk-install/>. The exception cannot be assigned to Windows, Debian, another asset, or another image.

## Consequences

- A missing, malformed, widened, or reordered promotion record fails repository validation.
- An active resource policy without that exact promotion record fails validation.
- Catalog and manifest promotion can occur in a later reviewed commit without weakening the plan-only source-control commit.
- The installed release, authorization, backend policy, data bundle, request, plan, approval, and receipt all bind the same final repository commit and tree.
- The historical proposal files remain non-operative design records. They do not override an approved promotion record or provide host authorization.
