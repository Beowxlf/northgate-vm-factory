# Windows workstation deployment plan

## Status

This is the execution handoff for ADR-0003. It is **plan-only** and creates no authorization to change Hyper-V, OPNsense, Active Directory, TacticalRMM, Wazuh, or a guest. The current factory cannot apply this plan because the required image, profiles, host capabilities, planner, and plan registry are not promoted.

## Fleet baseline

| Order | Asset | Role | VLAN | Address | TRMM site intent | Wazuh role group | Recovery intent |
| ---: | --- | --- | ---: | --- | --- | --- | --- |
| 1 | `NG-VM-011` / `NG-WRK-01` | Worker and first production canary | 110 | `10.10.110.20` | `Windows Workstations` | `ng-win-worker` | Bronze; reconstructable endpoint |
| 2 | `NG-VM-012` / `NG-WRK-02` | Worker | 110 | `10.10.110.21` | `Windows Workstations` | `ng-win-worker` | Bronze; reconstructable endpoint |
| 3 | `NG-VM-019` / `NG-MGR-01` | Manager | 110 | `10.10.110.22` | `Windows Workstations` | `ng-win-manager` | Bronze; reconstructable endpoint |
| 4 | `NG-VM-020` / `NG-IT-01` | Privileged IT administration | 130 | `10.10.130.20` | `Privileged Workstations` | `ng-win-it` | Silver; protect administrative configuration |
| 5 | `NG-VM-021` / `NG-CYBER-01` | Blue-team analysis and detection engineering | 140 | `10.10.140.20` | `Security Lab` | `ng-win-cyber` | Silver; protect detection work and evidence |

`NG-VM-010` is the proposed disposable factory canary and is not one of the five requested workstations. None of these IDs is reserved until the protected identity ledger accepts it after a fresh collision check.

## Discovery-derived promotion gates

- Operation-SeeSaw contains the exact media hashes and inspection evidence. Use only an authentic approved-root Windows 11 artifact after image promotion; select and license Windows 11 Pro explicitly.
- The credential-bearing unattended derivative identified in the readiness evidence is rejected and quarantine-required. Never promote it, clone it, reveal its embedded value, or reuse that credential.
- The signed host capability must create and verify a local key protector and vTPM atomically before Windows 11 provisioning is enabled.
- The VLAN control plane requires guarded add-adapter, trunk, native-sink, access-VLAN, OPNsense, rollback, and readback operations before any workload attaches.
- The final plan recalculates CPU, startup/maximum memory, storage reserve, identity, path, DNS, address, agent, and adapter collisions. A readiness snapshot is not a reservation.

## Immutable build contract

Every workstation must satisfy this contract before acceptance:

- Windows 11 Pro from one promoted ISO/image digest with verified provenance, edition, architecture, and licensing route.
- Generation 2, Microsoft Windows Secure Boot, vTPM 2.0, and no compatibility bypass for Windows 11 requirements.
- A unique Hyper-V VM ID, virtual NIC identity, Windows machine SID, TacticalRMM agent identity, Mesh identity, Wazuh agent identity, and LAPS password. When Phase 4 enables BitLocker, it also creates and verifies a unique recovery key and escrow record.
- No management agent, enrollment key, deployment link, local password, domain credential, or reusable answer-file secret baked into the image.
- Fixed OPNsense reservation and forward/reverse DNS records after the final adapter identity is known.
- Membership in the correct `northgate.tooling` OU and only the GPOs approved for that role.
- Defender real-time protection on, firewall on, current security updates, no pending reboot, and no broad agent-created antivirus exclusion.
- TacticalRMM and Wazuh healthy with names, addresses, sites/groups, and asset records agreeing exactly.
- Wazuh Active Response off. Sysmon absent until its independent canary passes.

## Planning assumptions requiring approval

| Setting | Worker | Manager | IT | Cyber |
| --- | --- | --- | --- | --- |
| vCPU | 2 | 2 | 4 | 4 |
| Dynamic memory minimum/startup/maximum | 4/4/6 GiB | 4/4/6 GiB | 4/8/12 GiB | 4/8/12 GiB |
| OS disk | 80 GiB | 80 GiB | 100 GiB | 120 GiB |
| Data classification | Internal | Internal | Confidential | Restricted |
| Criticality | Low | Moderate | Moderate | Moderate |
| Interactive administration | No | No | Approved privileged path | Security tools only; no default domain administration |
| General email/web | Authenticated STARTTLS submission and trusted IMAPS to internal mail only; normal approved web policy | Authenticated STARTTLS submission and trusted IMAPS to internal mail only; normal approved web policy | Email/web minimized | Restricted to approved research/update sources; no direct external-mail or SIM-WAN path |

The resources, data classifications, criticalities, and recovery tiers in this table are proposed owner decisions, not approved manifest values. The five configured startup allocations total 28 GiB and the configured maximums total 42 GiB. Disk ceilings total 460 GiB. These reduced maxima preserve the approved 48 GiB host reserve at the last normalized snapshot, but they remain design values rather than current-capacity evidence; the planner must recalculate host and volume reserves immediately before deployment.

## Bootstrap sequence

1. Create the VM from the promoted Windows image and an approved Windows firmware profile. Verify Secure Boot and vTPM before the first unattended boot.
2. Use an answer file that contains only non-secret locale, edition, disk, and first-boot orchestration settings. Inject one-time secrets from a protected store at execution time or complete the credential-bearing steps through a human-controlled bootstrap channel.
3. Apply the exact access VLAN, acquire a bootstrap address if required, record the final adapter identity, create the OPNsense fixed reservation, and verify forward/reverse DNS.
4. Rename the guest, apply the approved opaque domain-DNS service reference through network/bootstrap policy, verify time and authoritative DNS readback, and join `northgate.tooling` into the correct role OU using a delegated one-time domain-join mechanism. Revoke or expire that capability immediately.
5. Apply Windows Update and the role GPO baseline. Reboot until update and pending-reboot checks are clear. Verify Defender, firewall, LAPS, audit policy, and activation state.
6. Generate a short-lived TacticalRMM installer for the exact site and workstation type. Verify its digest/source, install, confirm TacticalRMM and Mesh services and unique identity, then expire the installer token. Agent traffic uses the verified HTTPS front end on TCP 443; do not expose TacticalRMM backend listeners directly.
7. Create the required Wazuh baseline and role groups before enrollment. Use one reviewed, hashed TacticalRMM script with empty arguments and environment to install the pinned MSI. Follow the Wazuh standard's one-endpoint enrollment contract or inject the one-time key through the human console, enroll with the exact hostname and groups, validate indexed telemetry, and prove enrollment TCP 1515 is closed. Segmentation permits agent transport TCP 1514 but blocks dashboard/API access unless the role policy explicitly allows it.
8. Run the reviewed NorthGate basic-health script through TacticalRMM. Confirm that the result schema, returned hostname, target agent, exit code, service state, disk, update, reboot, Defender, and Wazuh checks all agree.
9. Capture the final signed factory receipt and reconcile the asset, address, domain, agent, security, storage, and recovery evidence in Operation-SeeSaw.

A rebuild never assumes that a replacement adapter retained the former MAC identity. Reconcile the old VM and adapter as absent, allocate or verify the new host-approved static MAC through the protected ledger, update the fixed reservation and DNS under the same reviewed change, and reject any duplicate before starting the guest.

## Canary and promotion order

The rollout has two canaries:

1. `NG-CANARY-01` / `NG-VM-010` proves factory creation, vTPM, VLAN, rollback/quarantine, bootstrap, and evidence controls. It is retired after acceptance.
2. `NG-WRK-01` proves the production user policy, domain/GPO placement, fixed reservation, TacticalRMM site, Wazuh role group, update cycle, and one planned reboot during a 48-hour observation.

No later endpoint starts while either canary has an unresolved identity, network, security, management, monitoring, update, or evidence finding. After `NG-WRK-01`, observe Worker 2 for 24 hours, then proceed through Manager, IT, and Cyber with a 24-hour gate after each privilege boundary so broader and more privileged policies are introduced last.

## Validation matrix

| Layer | Positive test | Required negative test |
| --- | --- | --- |
| Factory identity | Asset, VM, name, disk, NIC, image, and receipt hashes agree | Same-name, reused asset ID, reused disk, or stale plan is rejected |
| Firmware | Generation 2, Secure Boot, vTPM 2.0 visible to guest | Apply refuses when vTPM or key protector is unavailable |
| Network | Correct VLAN, gateway, fixed address, DNS, time, Internet/update path, and role-approved internal-mail access | Untagged traffic, other VLANs, OPNsense UI, Hyper-V management, direct TCP 25, EXT-MAIL, SIM-WAN, and unauthorized infrastructure destinations are denied |
| Domain | Correct OU, computer object, secure channel, GPO result, and time | A worker cannot use privileged IT policy or credentials |
| TacticalRMM | Exact client/site/type, unique agent/Mesh identity, check-in, basic-health pass | Expired token cannot enroll another endpoint; duplicate identity is rejected |
| Wazuh | Exact agent name/groups, active TCP 1514 transport, expected Defender event indexed | TCP 1515 closes after enrollment; management surfaces remain unreachable; Active Response stays off |
| Endpoint | Defender/firewall/LAPS healthy, patches current, no pending reboot | Broad Defender exclusions, reusable passwords, embedded token, or unexpected administrator membership fails acceptance |
| Recovery | Rebuild or restore route, BitLocker escrow when enabled, evidence readable | Missing recovery material or untested rollback blocks promotion |

## Rollback ownership

- **VLAN or routing failure:** restore the exact OPNsense backup only when the live configuration hash still matches the failed change's expected post-state and no intervening approved change exists. Otherwise apply a reviewed selective reverse diff. Remove only new trunk/VLAN artifacts owned by the matching change after adapter ownership and console recovery are verified.
- **VM creation failure:** stop and quarantine only factory-owned artifacts carrying the matching change and asset identity. Preserve logs and the signed failure receipt.
- **Domain/GPO failure:** unlink the new role GPO or move only the canary computer object to the quarantine OU; never weaken domain-wide policy to make a canary pass.
- **TacticalRMM failure:** revoke the deployment token, uninstall only the matching new agent when necessary, and remove the exact stale server registration after evidence capture.
- **Wazuh failure:** close enrollment, restore the previous group configuration, remove only the matching new agent registration when re-enrollment requires it, and verify retained agents remain active.

## Factory gate status at design time

| Gate | Status on 2026-08-01 | Required closure |
| --- | --- | --- |
| Factory apply | Blocked | `applyEnabled` remains false and executable actions are empty |
| Windows image | Blocked | No active promoted image; ISO hash, edition, source, and license are unapproved |
| Firmware/vTPM | Blocked | Windows profile is proposed and the exposed create operation has no vTPM parameter |
| Network | Blocked | VLAN trunk, access-mode mapping, OPNsense policy, and host fingerprints are not approved |
| Bootstrap | Blocked | Only `none` is approved; no deterministic secret-safe Windows/domain/TRMM/Wazuh profile exists |
| Other catalogs | Blocked | Owner, storage, recovery, and required network/firmware profiles are proposed, not approved |
| Planner/apply control | Blocked | Signed planner/executor, host plan registry, application authentication, shared lock, and signed receipts are incomplete |
| Disposable canary | Blocked | Phase 0 negative tests and `NG-VM-010` acceptance have not run |
| TacticalRMM workstation policy | Blocked | Report-only policies, permission templates, temporary-identity lifecycle, and the guarded helper contract require acceptance |
| Wazuh Windows baseline | Blocked | Baseline and role groups require separate promotion, and the one-endpoint enrollment/closure contract requires acceptance |

Do not translate this document into direct `hyperv_create_vm` calls or routine Administrator SSH. Closing these gates is part of the requested standardized process, not optional paperwork.
