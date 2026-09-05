# RMM machine profiles

Owner request: complete the Version 1.0 Linux and Windows machine profiles.
The owner also removed dedicated RMM VLAN requirements on September 4, 2026.

## Source definitions

| Asset | Machine | CPU | RAM minimum/start/maximum | Disks | Shared network |
|---|---|---|---|---|---|
| NG-VM-022 | NG-RMM-CP01 | 4 | 4/8/8 GiB | 80 GiB OS, 100 GiB service-data | business-apps |
| NG-VM-023 | NG-RMM-CAN01 | 2 | 2/2/4 GiB | 40 GiB OS | business-apps |
| NG-VM-024 | NG-RMM-WIN01 | 2 | 4/4/8 GiB | 80 GiB OS | business-apps |

The canonical manifests are in `manifests/rmm`. Each references approved source
catalog entries, uses Generation 2, remains destroy-protected, and is created
off. Installation/start belongs to the subsequent bounded deployment operation.
The endpoints depend on NG-VM-022. The initial review date is October 4, 2026;
it is a review reminder, never an automatic retirement or deletion instruction.

The existing twelve-machine `manifests/vms` release and its promotion record are
unchanged. Repository validation covers both directories and checks identities
across them. The RMM definitions are separate release inputs, not additional
machines silently admitted to the historical release.

## Required host bindings and guest acceptance

| Profile | Required implementation and acceptance |
|---|---|
| persistent-rmm-protected | Protected F-volume storage; server-owned OS and data VHDX; at most one 100-GiB data disk; preserve 100-GiB/15-percent reserve checks and ownership checks. |
| rmm-linux-gen2-vtpm | Secure Boot using the Microsoft UEFI CA template and vTPM enabled. Debian base-image digest is unchanged; boot compatibility must be qualified with the asset-bound bootstrap media. |
| debian12-rmm-server | Debian 12; key-only non-root administration; LUKS2 OS and service-data volumes, TPM-bound normal unlock, distinct recovery material kept outside the guest. No credential embedded in source or logs. |
| debian12-rmm-canary | Disposable Debian 12; key-only administration; no production data or domain membership; RMM enrollment occurs after server readiness. |
| rmm-server-protected | Encrypted database-consistent backup, independently retained recovery material and audit evidence, tested isolated restore; checkpoints alone do not satisfy recovery. |
| rmm-canary-disposable | Rebuild from pinned media; revoke old endpoint identity before re-enrollment; retain test evidence. Destruction requires an explicit separate action. |
| windows11-disposable-canary | Existing Windows 11 25H2 bootstrap, Secure Boot and vTPM; local disposable identity, no domain join. Install the RMM Windows service only after server readiness. |
| business-apps | Existing private lab network for all three guests. No new VLANs, trunk extension, or public ingress. Resolve live addresses and switch identity at planning time. |

The server's disk limits must be present in all three enforcement layers:
storage catalog, signed host storage policy, and signed asset policy. The new
catalog values express approved source intent, not successful guest encryption,
backup, image compatibility testing, or installed host authorization.

## Validation and release boundary

`scripts/Test-Repository.ps1` checks schema, references, image compatibility,
network permissions, source identities, and resource envelopes. It also rejects
missing/unknown RMM assets, dedicated RMM networks, missing/oversized data disks,
domain-oriented Windows bootstrap, weakened server firmware, automatic starts,
and missing server dependencies.

The installed `ngcor-1.0.46-fda336c` release does not consume these profiles.
Its protocol/backend/fixed-fleet package still needs an explicit RMM release
extension with host bindings, media provenance, signing, and installation.
Do not copy these manifests into its protected state, change its allowlists in
place, or use the generic creator as a substitute. Live collision, capacity,
image/media, and identity-ledger checks remain required before any creation.

Rollback for profile authoring is a source revert. Deployment rollback must use
the signed release's retained prior package and quarantine only transaction-owned
new guest artifacts; existing guests and data are outside this profile change.
