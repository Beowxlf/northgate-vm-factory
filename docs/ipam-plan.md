# NorthGate proposed IPAM plan

## Status and authority

This file records reviewed **proposed intent** for future isolated lab segments. It is not live-state evidence, does not authorize a Hyper-V or OPNsense change, and does not replace Operation-SeeSaw as the authoritative IPAM and asset record. Any deployment must revalidate collisions, interface identities, routes, and reservations immediately before planning.

The existing trusted LAN remains `10.10.100.0/24`; its complete live address inventory stays in Operation-SeeSaw rather than being duplicated here.

## Proposed subnets and fixed assignments

All infrastructure addresses on these segments are static. DHCP is disabled unless a later reviewed decision explicitly adds a bounded test pool.

### MAIL-DMZ

| Item | Proposed value | Purpose |
| --- | --- | --- |
| Network | `10.10.120.0/24` | Isolated mail-services DMZ |
| Default gateway | `10.10.120.1` | OPNsense MAIL-DMZ interface |
| `NG-MAIL-01` | `10.10.120.10` | SMTP submission/delivery, IMAP, antispam, malware scanning, and Wazuh agent |
| Reserved infrastructure range | `10.10.120.2-9` | Future network infrastructure only |
| Reserved service range | `10.10.120.11-49` | Future reviewed static services |
| Unallocated range | `10.10.120.50-254` | No automatic assignment |

### SIM-WAN

| Item | Proposed value | Purpose |
| --- | --- | --- |
| Network | `172.31.250.0/24` | Isolated, untrusted external-simulation segment |
| Default gateway | `172.31.250.1` | OPNsense SIM-WAN interface |
| `NG-KALI-EXT01` | `172.31.250.10` | Primary simulated external host |
| Mail edge VIP | `172.31.250.25` | Source-restricted TCP 25 destination NAT to `10.10.120.10` |
| Reserved infrastructure range | `172.31.250.2-9` | Future network infrastructure only |
| Reserved adversary range | `172.31.250.11-24`, `172.31.250.26-49` | Future reviewed static simulation hosts |
| Unallocated range | `172.31.250.50-254` | No automatic assignment |

## Proposed name records

| Name | Proposed address | Scope |
| --- | --- | --- |
| `mail.northgate.test` | `10.10.120.10` | Trusted and MAIL-DMZ resolution |
| `mx-edge.northgate.test` | `172.31.250.25` | SIM-WAN resolution only |

The `.test` namespace prevents the lab design from depending on or colliding with public DNS. No public MX or physical-WAN record is part of this plan.

## Allocation rules

- Assign an address only after checking OPNsense configuration, ARP/neighbor state, Hyper-V adapter inventory, DNS, Wazuh, TacticalRMM, and the Operation-SeeSaw asset register.
- Record the VM asset ID, VM ID, interface identity, hostname, segment, fixed address, gateway, DNS source, owner, approval/change reference, and last verification date in Operation-SeeSaw.
- Never infer that an unused ping response proves an address is free.
- A duplicate address, unknown adapter, rebound switch, or network fingerprint mismatch is a hard stop.
- Network catalog IDs remain opaque. Subnets and interface mappings are resolved by approved host and OPNsense policy, not by VM manifests.
- Adding a reservation, DHCP pool, route, NAT rule, or DNS record requires its own reviewed change and readback validation.

## Required validation before activation

1. Confirm both subnets are absent from all current interfaces, routes, VPN selectors, DHCP scopes, DNS overrides, and retained VM configurations.
2. Confirm the two private Hyper-V switches have no external adapter binding and match the installed host-policy fingerprints.
3. Confirm OPNsense is the only Layer 3 path and administrative listeners are disabled on both new interfaces.
4. From SIM-WAN, prove trusted-LAN and OPNsense-management access is denied and logged.
5. Prove only `172.31.250.10` can reach the SMTP VIP on TCP 25 and that it translates only to `10.10.120.10:25`.
6. Prove direct outbound SMTP to the physical WAN is blocked from MAIL-DMZ and SIM-WAN.
7. Verify trusted mail submission and retrieval, Wazuh telemetry, DNS, time synchronization, controlled updates, and rollback.
8. Reconcile the final state into Operation-SeeSaw and bind evidence hashes to the approved change.
