# Bootstrap media acceptance and negative tests

## Offline gate

Run from the repository root using Windows PowerShell 5.1:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\bootstrap-media\Test-BootstrapMedia.ps1
```

Acceptance requires `NGBM_TESTS_OK`. The suite validates all 12 fixed asset/name/MAC/VLAN/IP bindings, exact source digests and sizes, Windows Pro index 6, family firmware policy, strict JSON properties, public-key structure, no-secret rendering, deterministic bundle hashes, Linux and Windows SSH restrictions, Windows in-memory credential generation, cleanup gates, source-integrity checks, WIM/architecture checks, and UEFI El Torito validation logic.

The BlueBench builder must then pass against the real source. Its successful terminal result is `NGBM_BUILD_OK` with the exact asset ID, output hash, and size. Retain the bundle manifest, final ISO SHA-256, and output provenance together.

## Pre-canary evidence

- Fresh collision readback for asset ID, VM name, VHD path, static MAC, VLAN, IP, DHCP/ARP/neighbor state, forward/reverse DNS, and protected ledger.
- Exact source filename, byte size, SHA-256, `x86_64` content, and required EFI paths.
- For Windows, `wimlib-imagex` proves index 6 is Windows 11 Pro x64.
- Derivative ISO contains an EFI El Torito image and the expected bootstrap files.
- Source hash/size are identical before and after building.
- OPNsense provides only the temporary install/DNS/time paths required for the one canary; all unrelated inter-zone paths remain denied and logged.
- Only one fresh, factory-owned disk and one exact static-MAC NIC are attached. Installer media is first boot only.

## Debian disposable canary (`NG-VM-018`)

- Generation 2; Secure Boot on with `MicrosoftUEFICertificateAuthority`; no vTPM requirement.
- Exact MAC `024E47000012`, access VLAN 150, temporary address `10.10.150.200/24`, gateway/DNS `10.10.150.1`.
- UEFI boots the derivative without a prompt and installation completes on the sole blank disk.
- Guest hostname, address, route, DNS, and time agree with the request.
- SSH succeeds from `10.10.100.11` with the pinned key and fails from another source, with a password, for root, and with forwarding.
- Temporary user has sudo only while the bootstrap gate remains open; the role marker is exactly `debian12-disposable-canary`.
- Wazuh enrollment, approved Linux management path, one reboot, update health, evidence, quarantine, and cleanup are proven before profile promotion.

## Windows disposable canary (`NG-VM-010`)

- Generation 2; Secure Boot on with `MicrosoftWindows`; vTPM present and healthy.
- Exact MAC `024E4700000A`, access VLAN 110, temporary address `10.10.110.200/24`, gateway `10.10.110.1`, DNS `10.10.100.150`.
- Windows Setup selects the non-evaluation Pro image at index 6 and completes without an answer-file password, product key, activation claim, or interactive account creation. Initial licensing evidence must read unactivated, not evaluation.
- SetupComplete status is `ready-key-only`; hostname/MAC/address/DNS readback matches exactly; DHCP is disabled.
- No generated credential appears in Panther, PowerShell, event, SetupComplete, RMM, or Wazuh logs.
- SSH succeeds only from `10.10.100.11` using the public key and fails from another source or by password.
- Secure Boot, vTPM, Defender, update, time, domain/OU/GPO, LAPS, TacticalRMM, and Wazuh gates pass in the sequence documented by the Windows workstation plan.
- The exact cleanup command succeeds only after domain, TacticalRMM, and Wazuh verification; the local bootstrap account, key, firewall rule, and SSH listener are no longer usable afterward.

## Kali canary/promotion test (`NG-VM-021`)

- Generation 2 UEFI, exact MAC `024E47000015`, VLAN 250, address `172.31.250.10/24`, gateway/DNS `172.31.250.1`.
- Secure Boot is disabled and bound to `kali-gen2-unsigned` plus exception `NG-FW-20260802-KALI-UNSIGNED`; vTPM is not required.
- The derivative contains amd64 installer paths and boots through UEFI without falling back to legacy BIOS.
- Static network, locked password, key/source-only SSH, sudo, role marker, updates, Wazuh, management fallback, reboot, and cleanup pass.
- Kali remains last and unpromoted until the unsigned-boot exception and canary evidence are separately approved.

## Required negative tests

- Wrong source name, byte size, SHA-256, architecture, WIM index/edition, missing EFI image, or source mutation: deny.
- Existing/reparse output, bundle path traversal, modified bundle file, manifest mismatch, unsupported builder, or unresolved template token: deny.
- Wrong asset/name/hostname/MAC/VLAN/IP/gateway/DNS/domain/role/image/firmware binding: deny.
- Unknown or credential-like JSON property; public key with options, multiple lines, wrong algorithm, malformed blob, or private-key marker: deny.
- Two disks, wrong NIC count/MAC, unavailable OpenSSH capability, invalid sshd configuration, or required restart during SetupComplete: record failure and do not claim readiness.
- Windows or Debian Secure Boot disabled: deny promotion. Kali Secure Boot enabled or the unsigned exception absent: deny promotion.
- Password, root, off-source SSH, IPv6 bypass, forwarding, unapproved inter-zone access, dashboard/API access from workload VLANs, and repeated use of an expired bootstrap identity: deny.
- Agent identity reuse, duplicate DNS/DHCP/ARP reservation, wrong RMM site/Wazuh group, failed telemetry, pending reboot, or absent recovery evidence: stop rollout.
