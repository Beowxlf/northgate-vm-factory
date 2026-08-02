# NorthGate proposed IPAM plan

## Status and authority

This file records reviewed **proposed intent** for future isolated lab segments, the Windows workstation fleet, two SMTP servers, Kali, the Employee Hub, and Sentinel Atlas. VLAN 150 (`BUSINESS-APPS`) and VLAN 160 (`COMMERCIAL-DMZ`) now exist as isolated OPNsense-routed server zones on the private application fabric. Their gateways are live, DHCP is disabled, no workload adapter is connected, and no service address or DNS name is allocated by this document. This file is not authoritative live-state evidence and does not replace Operation-SeeSaw as the IPAM and asset record. Any deployment must revalidate collisions, interface identities, routes, reservations, default-deny policy, and the installed host mapping immediately before planning.

The existing trusted LAN remains `10.10.100.0/24`; its complete live address inventory stays in Operation-SeeSaw rather than being duplicated here.

Exact retained addresses, adapter identities, assignment methods, and service dependencies remain in Operation-SeeSaw.

## Retained infrastructure static-address control

Every retained interface on the untagged infrastructure LAN must use either a reviewed guest-static configuration or an OPNsense fixed mapping bound to a host-approved static Hyper-V MAC. No retained service identity relies on an ordinary dynamic lease. Operation-SeeSaw holds the exact live table; this repository defines the reconciliation process without duplicating environment mappings.

1. Inventory every retained VM ID, adapter/MAC, guest address, OPNsense lease/mapping, ARP/neighbor record, DNS record, domain identity, Wazuh agent, and TacticalRMM agent.
2. Choose guest-static only for a role that requires it; otherwise use a fixed OPNsense mapping. Record gateway, DNS, owner, recovery path, and change reference before conversion.
3. Prove the proposed address and MAC are unique across DHCP, DNS, ARP/neighbor state, Hyper-V, guests, agents, and the protected identity ledger. Silence from ping is insufficient.
4. Convert one non-critical retained canary first, then one asset at a time. Preserve the old guest/DHCP/DNS state and an exact rollback action for each asset.
5. After each conversion, verify lease or guest-static readback, forward/reverse DNS, gateway, domain/time, pinned administration, service health, Wazuh, TacticalRMM, and dependent reachability before continuing.
6. On mismatch, restore only that asset's previous address/mapping and DNS state. Do not broaden the pool, create a duplicate reservation, or change the router/DC to make a canary pass.

## Proposed subnets and fixed assignments

No general dynamic pool is enabled in steady state. OPNsense DHCP remains enabled only for approved fixed mappings bound to host-approved static Hyper-V MAC addresses. A `.200-.209` bootstrap pool requires a separate time-bounded change and is disabled after reservation and DNS readback.

### USERS

| Item | Proposed value | Purpose |
| --- | --- | --- |
| VLAN | `110` | Ordinary user and manager workstation access zone |
| Network | `10.10.110.0/24` | Routed only through OPNsense |
| Default gateway | `10.10.110.1` | OPNsense USERS interface |
| `NG-WRK-01` | `10.10.110.20` | Worker and first fleet canary |
| `NG-WRK-02` | `10.10.110.21` | Worker |
| `NG-MGR-01` | `10.10.110.22` | Manager; no network-administration privilege |
| Reserved infrastructure range | `10.10.110.2-19` | Future reviewed infrastructure only |
| Reserved endpoint range | `10.10.110.23-49` | Future fixed endpoint assignments |
| Temporary bootstrap range | `10.10.110.200-209` | Disabled at steady state; time-bounded deployment use only |

### IT-ADMIN

| Item | Proposed value | Purpose |
| --- | --- | --- |
| VLAN | `130` | Privileged administration workstation zone |
| Network | `10.10.130.0/24` | Routed only through OPNsense |
| Default gateway | `10.10.130.1` | OPNsense IT-ADMIN interface |
| `NG-IT-01` | `10.10.130.20` | Dedicated IT administration workstation |
| Reserved infrastructure range | `10.10.130.2-19` | Future reviewed infrastructure only |
| Reserved endpoint range | `10.10.130.21-49` | Future fixed privileged endpoints |
| Temporary bootstrap range | `10.10.130.200-209` | Disabled at steady state; time-bounded deployment use only |

### CYBER

| Item | Proposed value | Purpose |
| --- | --- | --- |
| VLAN | `140` | Blue-team and detection-engineering workstation zone |
| Network | `10.10.140.0/24` | Routed only through OPNsense |
| Default gateway | `10.10.140.1` | OPNsense CYBER interface |
| `NG-CYBER-01` | `10.10.140.20` | Cyber-defense workstation |
| Reserved infrastructure range | `10.10.140.2-19` | Future reviewed infrastructure only |
| Reserved endpoint range | `10.10.140.21-49` | Future fixed security endpoints |
| Temporary bootstrap range | `10.10.140.200-209` | Disabled at steady state; time-bounded deployment use only |

### BUSINESS-APPS

| Item | Proposed value | Purpose |
| --- | --- | --- |
| VLAN | `150` | Internal business-application service zone |
| Network | `10.10.150.0/24` | Routed only through OPNsense |
| Default gateway | `10.10.150.1` | OPNsense BUSINESS-APPS interface |
| `NG-HR-APP01` | `10.10.150.10` | Aegis Meridian Employee Hub; internal HTTPS only |
| Reserved infrastructure range | `10.10.150.2-9` | Future network infrastructure only |
| Reserved service range | `10.10.150.11-49` | Future reviewed internal applications |
| Unallocated range | `10.10.150.50-254` | No automatic assignment |

### COMMERCIAL-DMZ

| Item | Proposed value | Purpose |
| --- | --- | --- |
| VLAN | `160` | Customer-platform service zone with a separately canaried simulated-external path |
| Network | `10.10.160.0/24` | Routed only through OPNsense |
| Default gateway | `10.10.160.1` | OPNsense COMMERCIAL-DMZ interface |
| `NG-PLAT-APP01` | `10.10.160.10` | Sentinel Atlas Commercial; HTTPS only |
| Reserved infrastructure range | `10.10.160.2-9` | Future network infrastructure only |
| Reserved service range | `10.10.160.11-49` | Future reviewed customer-facing lab applications |
| Unallocated range | `10.10.160.50-254` | No automatic assignment |

### MAIL-INT

| Item | Proposed value | Purpose |
| --- | --- | --- |
| Network | `10.10.120.0/24` | Isolated internal mail-services zone |
| VLAN | `120` | Tagged MAIL-INT access zone |
| Default gateway | `10.10.120.1` | OPNsense MAIL-INT interface |
| `NG-MAIL-INT01` | `10.10.120.10` | Internal SMTP submission/delivery, IMAP, antispam, malware scanning, and Wazuh agent |
| Reserved infrastructure range | `10.10.120.2-9` | Future network infrastructure only |
| Reserved service range | `10.10.120.11-49` | Future reviewed static services |
| Unallocated range | `10.10.120.50-254` | No automatic assignment |

### EXT-MAIL

| Item | Proposed value | Purpose |
| --- | --- | --- |
| Network | `172.31.240.0/24` | Isolated simulated-external mail-services zone |
| VLAN | `240` | Tagged EXT-MAIL access zone |
| Default gateway | `172.31.240.1` | OPNsense EXT-MAIL interface |
| `NG-MAIL-EXT01` | `172.31.240.10` | External SMTP transfer/submission, test mailbox, and Wazuh agent |
| Internal-mail edge VIP | `172.31.240.25` | Source-restricted TCP 25 destination NAT to `10.10.120.10` |
| Reserved infrastructure range | `172.31.240.2-9` | Future network infrastructure only |
| Reserved service range | `172.31.240.11-24`, `172.31.240.26-49` | Future reviewed static services |
| Unallocated range | `172.31.240.50-254` | No automatic assignment |

### SIM-WAN

| Item | Proposed value | Purpose |
| --- | --- | --- |
| Network | `172.31.250.0/24` | Isolated, untrusted external-simulation segment |
| VLAN | `250` | Tagged hostile-simulation access zone |
| Default gateway | `172.31.250.1` | OPNsense SIM-WAN interface |
| `NG-KALI-EXT01` | `172.31.250.10` | Primary simulated external host |
| Reserved infrastructure range | `172.31.250.2-9` | Future network infrastructure only |
| Reserved adversary range | `172.31.250.11-49` | Future reviewed static simulation hosts |
| Unallocated range | `172.31.250.50-254` | No automatic assignment |

## Proposed name records

| Record | Proposed value | Scope |
| --- | --- | --- |
| A `mail.northgate.test` | `10.10.120.10` | USERS, IT-ADMIN, CYBER, and MAIL-INT test view |
| MX `northgate.test` | `mail.northgate.test` | Trusted client and MAIL-INT view |
| MX `northgate.test` | `mx-inbound.northgate.test` | EXT-MAIL-only view; delivers through the exact-source edge VIP |
| PTR `10.120.10.10.in-addr.arpa` | `mail.northgate.test` | Internal test reverse zone |
| A `mail.redteam.test` | `172.31.240.10` | MAIL-INT, EXT-MAIL, and SIM-WAN test view |
| MX `redteam.test` | `mail.redteam.test` | MAIL-INT, EXT-MAIL, and SIM-WAN test view |
| PTR `10.240.31.172.in-addr.arpa` | `mail.redteam.test` | Simulated-external reverse zone |
| A `mx-inbound.northgate.test` | `172.31.240.25` | EXT-MAIL-only view; exact-source internal-edge VIP |
| PTR `25.240.31.172.in-addr.arpa` | `mx-inbound.northgate.test` | EXT-MAIL reverse view for the edge VIP |
| A `ng-wrk-01.northgate.tooling` | `10.10.110.20` | AD-integrated workstation resolution |
| A `ng-wrk-02.northgate.tooling` | `10.10.110.21` | AD-integrated workstation resolution |
| A `ng-mgr-01.northgate.tooling` | `10.10.110.22` | AD-integrated workstation resolution |
| A `ng-it-01.northgate.tooling` | `10.10.130.20` | AD-integrated privileged-workstation resolution |
| A `ng-cyber-01.northgate.tooling` | `10.10.140.20` | AD-integrated security-workstation resolution |
| A `employees.aegismeridian.test` | `10.10.150.10` | Trusted USERS, manager, and approved IT views only |
| PTR `10.150.10.10.in-addr.arpa` | `employees.aegismeridian.test` | Trusted reverse view for Employee Hub |
| A `app.sentinelatlas.test` | `10.10.160.10` | Approved trusted and simulated-external test views |
| PTR `10.160.10.10.in-addr.arpa` | `app.sentinelatlas.test` | Approved reverse view for Sentinel Atlas |

The `.test` namespace prevents the lab design from depending on or colliding with public DNS. Split views must return only the records required by each zone: Kali uses an OPNsense-hosted simulation view and never queries Active Directory DNS directly; MAIL-INT can resolve the external A/MX/PTR records; only EXT-MAIL resolves the internal edge VIP. No wildcard, public MX, or physical-WAN record is part of this plan.

## Allocation rules

- Assign an address only after checking OPNsense configuration, ARP/neighbor state, Hyper-V adapter inventory, DNS, Wazuh, TacticalRMM, and the Operation-SeeSaw asset register.
- Record the VM asset ID, VM ID, interface identity, hostname, segment, fixed address, gateway, DNS source, owner, approval/change reference, and last verification date in Operation-SeeSaw.
- Never infer that an unused ping response proves an address is free.
- A duplicate address, unknown adapter, rebound switch, or network fingerprint mismatch is a hard stop.
- Network catalog IDs remain opaque. Subnets and interface mappings are resolved by approved host and OPNsense policy, not by VM manifests.
- Adding a reservation, DHCP pool, route, NAT rule, or DNS record requires its own reviewed change and readback validation.
- Workstation steady-state addresses use OPNsense fixed DHCP reservations bound to the final Hyper-V adapter identity. A temporary bootstrap lease is not the asset's fixed identity and is removed after reservation and DNS readback.
- Mail servers use reviewed guest-static addresses after their final adapter identities are registered. Server-zone DHCP is disabled in steady state.
- Employee Hub and Sentinel Atlas use reviewed guest-static addresses after their final adapter identities are registered. Any `.200-.209` bootstrap mapping is a separate time-bounded change, is never the service identity, and is removed after the guest-static address, forward/reverse DNS, gateway, administration, Wazuh, and approved TacticalRMM state pass; rollback restores only the recorded pre-bootstrap guest and network state.
- VLAN IDs, access/trunk mode, allowed VLAN lists, native VLAN behavior, and adapter fingerprints are host policy, not VM-manifest fields.
- Hyper-V trunk mode uses host-validated VLAN 4094 as a native sink. It has no subnet, OPNsense interface, address, DHCP, DNS, route, workload, or allow rule; untagged traffic must fail negative tests.

## Required validation before activation

1. Confirm `10.10.110.0/24`, `10.10.120.0/24`, `10.10.130.0/24`, `10.10.140.0/24`, `10.10.150.0/24`, `10.10.160.0/24`, `172.31.240.0/24`, and `172.31.250.0/24` are absent from live interfaces, routes, VPN selectors, DHCP scopes, DNS overrides, and retained VM configurations.
2. Confirm the single private Hyper-V segmentation switch has no external adapter binding or management-OS adapter and matches the installed host-policy fingerprint. Permit tagged VLANs 110, 120, 130, 140, 150, 160, 240, and 250 only; map required native traffic to sink VLAN 4094.
3. Confirm the OPNsense trunk parent and native sink are unnumbered, OPNsense is the only Layer 3 path for the eight routed VLANs, and administrative listeners are neither bound nor permitted on any of their interfaces.
4. From SIM-WAN, prove trusted-LAN and OPNsense-management access is denied and logged.
5. Prove only `172.31.240.10` can reach `172.31.240.25:25` and that it translates only to `10.10.120.10:25`; prove Kali cannot reach the VIP or MAIL-INT directly.
6. Prove Kali can reach only the approved SMTP and mailbox-test listeners on `172.31.240.10` and cannot reach that server's SSH, monitoring, or management paths.
7. Prove only `10.10.120.10` can reach `172.31.240.10:25` across the mail boundary, and prove direct outbound SMTP to the physical WAN is blocked from MAIL-INT, EXT-MAIL, and SIM-WAN.
8. Verify trusted internal submission/retrieval, external submission/retrieval, bidirectional cross-server delivery, open-relay rejection, Wazuh telemetry, DNS, time synchronization, controlled updates, and rollback.
9. Reconcile the final state into Operation-SeeSaw and bind evidence hashes to the approved change.
10. For VLANs 110, 130, and 140, prove the exact role-policy matrix in ADR-0003: ordinary users cannot reach management services; IT can reach only approved administration endpoints; Cyber can reach approved security consoles but has no default domain-administration or SIM-WAN path.
11. Prove that TacticalRMM and Wazuh agent traffic works without exposing either management plane, that Wazuh enrollment closes after each bounded window, and that all five workstation fixed mappings agree with VM, DNS, domain, and agent identities.
12. For VLAN 150, prove Employee Hub is reachable only through HTTPS from approved trusted roles and is unreachable from SIM-WAN, COMMERCIAL-DMZ, and unapproved management sources.
13. For VLAN 160, prove Sentinel Atlas is initially reachable only from approved trusted canaries; add one exact-source SIM-WAN HTTPS path only after internal acceptance, while Employee Hub, SSH, database, monitoring, and management listeners remain unreachable.
