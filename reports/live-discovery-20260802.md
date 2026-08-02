# NorthGate live discovery — 2026-08-02

Classification: internal, sanitized operational evidence
Evidence window: 2026-08-02 18:01–18:28 UTC
Method: read-only guarded MCP queries and strict, pinned, key-only SSH commands.
Change statement: **no live host, network, VM, guest, firewall, Wazuh, TacticalRMM, AD, or DNS state was changed.**

## Executive result

The Hyper-V host has sufficient observed compute/storage headroom, the required application trunk exists, and none of the five registered VM names collides with the proposed create-only fleet. VM creation is therefore technically feasible. Operational validation is not ready: the new VLAN interfaces have neither DHCP scopes nor interface allow rules, three retained Linux systems still report dynamic management addresses, and several storage/checkpoint artifacts require explicit exclusion or disposition before any apply.

The retained OPNsense, Wazuh, TacticalRMM, and AD/DNS services were available in bounded checks. The most important security finding is a configured broad IPv4 WAN-to-firewall pass rule on OPNsense; compiled private/bogon blocks precede it, so effective exposure was not inferred and requires a deliberate rule review. No malicious activity was identified in the bounded Wazuh sample, but this is not a full forensic conclusion.

## Host identity and capacity

- Host: `HC-HV01`, Windows Server 2022 Standard Evaluation, build 20348.
- SSH host-key self-report: `SHA256:TJSbnwH9IlEk/H4/SgVdOKMZ4HLKGm+r+kH6OwWp8UY` (ED25519). It exactly matched the pinned management identity.
- Capacity: 32 logical CPUs and approximately 192 GiB RAM.
- Approved storage roots: `D:\HyperV` and `F:\HyperV`.
- `D:` — volume ID `c1e6f82c-87a1-4bf7-8fcf-96560f6d43f4`, 999,635,808,256 bytes total, 738,789,482,496 bytes free.
- `F:` — volume ID `960fab31-7219-473a-8d45-3ab0054e4a1b`, 999,635,808,256 bytes total, 804,563,415,040 bytes free.
- Five VMs were registered and running. MCP 1.8.0 responded normally.

## Virtual switches

| Switch | ID | Type | Binding / management OS |
|---|---|---|---|
| `Tooling-SwitchConnector` | `38baacc8-7eff-4936-9713-b828ef4798c8` | External | Intel I350 rNDC #4; management OS disabled |
| `Tooling-WAN` | `42001f26-b52e-41ea-b2fe-315d62c4b685` | External | Intel I350 Adapter #4; management OS disabled |
| `Tooling-LAN` | `4a2c08e6-3de0-471e-aa1e-e057e02e3cec` | External | Intel I350 Adapter; management OS disabled |
| `Tooling-SW1` | `e6ff2629-4c12-429e-b8a1-1d0669a3559f` | Internal | management OS enabled |
| `NorthGate-SW1` | `f48b2c0b-e210-4692-bb70-a1606dab1e1d` | Internal | management OS enabled |
| `NorthGate-App-Trunk` | `97b5591d-27a6-4ab9-86a1-18ce70351466` | Private | management OS disabled |

## VM, adapter, VLAN, and storage attachment state

| VM | Network state | Attached storage and exceptional state |
|---|---|---|
| `JS-BlueBench` | `Tooling-SwitchConnector`, untagged; guest reports dynamic `10.10.100.17` | `D:\HyperV\VHDs\JS-BlueBench.vhdx`; no checkpoint; Parrot installer ISO remains mounted |
| `JS-Server-01` / guest `JS-DC-01` | `Tooling-SwitchConnector`, untagged; static `10.10.100.150` and `fd10:100::150` | Active differencing disk `F:\HyperV\VMs\JS-Server-01\Virtual Hard Disks\JS-Server-01_E7523308-5C3A-447B-B3FD-37C870661AD4.avhdx`, parent `JS-Server-01.vhdx`; one Standard checkpoint created 2026-07-31 05:07:36 UTC; Server installer ISO remains mounted |
| `OPNsense-Tooling` | WAN on `Tooling-WAN`; LAN on `Tooling-LAN`; `APP-TRUNK` on `NorthGate-App-Trunk`, trunk native VLAN 0, allowed `110,120,130,140,150,160,240,250` | Fixed `F:\HyperV\VHDs\OPNsense.vhdx`; no checkpoint; legacy config path under `C:\ProgramData\Microsoft\Windows\Hyper-V` |
| `TRMM-Tooling` | `Tooling-SwitchConnector`, untagged; guest reports dynamic `10.10.100.23` | `F:\HyperV\VHDs\TRMM-Tooling.vhdx`; no checkpoint; nonstandard VM configuration root `F:\HyperV\Disk\TRMM-Tooling` |
| `Wazuh-Machine` | `Tooling-SwitchConnector`, untagged; guest reports dynamic `10.10.100.14`; Hyper-V integration did not report an IP | OS disk `D:\HyperV\VHDs\Wazuh-Machine.vhdx` plus `F:\HyperV\VHDs\Wazuh-Machine-Snapshots.vhdx`; no Hyper-V checkpoint |

### Storage collisions and exclusions

- `D:\HyperV\VHDs\OPNsense.vhdx` is unattached while the live OPNsense disk is the same filename on `F:`. This is the highest-risk operator/path collision.
- Unattached remnants exist at `D:\HyperV\VHDs\Blue-Bench.vhdx`, `D:\HyperV\VHDs\Caldera-VM.vhdx`, and `D:\HyperV\VHDs\JS-RedMan.vhdx`. No deletion was performed.
- A JS-Server export exists under `F:\HyperV\Exports\JS-Server-01-prepatch-20260801T195100Z`; export disks must be excluded from live-attachment collision scans.
- The active JS-Server AVHDX must not be treated as an orphan. Merge, removal, or restore requires a separate checkpoint decision and backup validation.
- `Win11_25H2_Unattended.iso` exists in the ISO directory but is not an approved/promoted source and must remain excluded.

## OPNsense

- OPNsense 25.7 amd64 / FreeBSD 14.3; configuration hash `b67a88bece09133793af3164475c2ea1647d8c5824b1e62e04124e14ff4cd7fc`. Configuration permissions were restricted.
- Interfaces were internally consistent with the Hyper-V trunk:

| VLAN | Interface | Address |
|---:|---|---|
| 110 | USERS | `10.10.110.1/24` |
| 120 | MAIL_INT | `10.10.120.1/24` |
| 130 | IT_ADMIN | `10.10.130.1/24` |
| 140 | CYBER | `10.10.140.1/24` |
| 150 | BUSINESS_APPS | `10.10.150.1/24` |
| 160 | COMMERCIAL_DMZ | `10.10.160.1/24` |
| 240 | EXT_MAIL | `172.31.240.1/24` |
| 250 | SIM_WAN | `172.31.250.1/24` |

- WAN uses DHCP and currently has `192.168.1.33/24`; LAN is `10.10.100.1/24`; WireGuard is `10.10.250.1/24`.
- DHCP is enabled only on LAN, with pool `10.10.100.100–149` and seven static mappings. No VLAN DHCP scopes exist; Kea is disabled.
- Unbound is running and answered a recursive local query. Runtime configuration validation passed from its actual working directory. DNSSEC, forwarding, and automatic DHCP/static registration are disabled.
- PF and DHCP configuration validation passed. PF was enabled with 103 compiled filter rules and 27 NAT lines.
- No compiled interface allow rules were found for the eight VLAN interfaces; they remain default-blocked.
- A configured WAN rule permits IPv4 from any source to the WAN address for all protocols. Compiled private/bogon blocks precede it; actual reachability was not tested. The rule still violates least-privilege design and requires review before external validation.
- Hybrid automatic outbound NAT covers LAN and VLAN networks. No port-forward rules were configured.
- SSH listens only on management LAN addresses, uses public keys, disables password/KBI and root login, and restricts access to `wheel`.
- The web UI listens on ports 80 and 443; policy exposure depends on PF. Its self-signed certificate was valid through 2027-01-21. No private key material was collected.
- Default gateway reachability passed with no packet loss in the bounded test.

## Wazuh

- Ubuntu 22.04.5; Wazuh 4.14.6 manager/indexer/dashboard and Filebeat were active and enabled with no restart/error evidence in the sampled service journals.
- Indexer/API authentication challenges (`401`) and dashboard redirect (`302`) were reachable locally. Filebeat's authenticated TLS output test succeeded.
- Active agents: Smooth-Operator, JS-DC-01, HC-HV01, JS-BlueBench, and TRMM-Tooling. OPNsense is represented through syslog rather than an endpoint agent.
- `wazuh-authd` was not running, so new-agent enrollment availability must be verified before fleet onboarding.
- Root filesystem utilization was 54%; `/var/ossec/logs` used about 624 MB and the indexer used about 3.0 GB.
- Manager counters showed zero dropped events and zero queue utilization at capture time.
- A bounded sample of 9,999 valid current alert records contained no level-12-or-higher events. Elevated items were blocked multicast discovery traffic, two Windows profile-service errors, and known authorized creation/change of the NorthGate forwarder account. No malicious activity was identified in this sample. One concurrently written/partial JSON line was invalid.

## TacticalRMM

- TacticalRMM 1.3.1 on Debian 12; RMM, web, worker, NATS, MeshCentral, PostgreSQL, Redis, and reverse-proxy services were active. Local web health endpoints returned HTTP 200 and PostgreSQL accepted connections.
- Root filesystem utilization was 9%; time synchronization was enabled; package audit was clean; no error-priority platform journal entries were found in the prior 24 hours.
- The only failed unit was `NetworkManager-wait-online`, stale since 2026-06-25; NetworkManager currently reported connected.
- Three agents were enrolled and recently seen: HC-HV01, JS-DC-01, and Smooth-Operator. Retained Linux systems were not covered by TacticalRMM.
- Ports 4430, 4433, and 1024 bind on all guest interfaces for MeshCentral-related services. Their effective exposure must be verified at the firewall; this is not a confirmed external vulnerability.
- The current public certificate was valid through 2026-10-29. No credentials, tokens, or private key material were collected.

## Active Directory, DNS, and time

- `JS-DC-01` is the only domain controller for `northgate.tooling`; domain and forest functional levels are Windows Server 2016. All FSMO roles are on this DC, making it an acknowledged single point of failure.
- ADWS, DFSR, DNS, KDC, Netlogon, NTDS, and W32Time were running and automatic. SYSVOL and NETLOGON shares were present.
- Targeted `dcdiag` Advertising/Services/SysVol/NetLogons checks and the DNS basic test exited 0 with no quiet-mode failures. DC locator succeeded. Replication summary had no partners or failures, which is expected for one DC.
- No Directory Service, DNS Server, or DFS Replication error events were recorded in the prior 24 hours.
- AD-integrated zones `_msdcs.northgate.tooling`, `northgate.tooling`, and `northgateops.com` were present. Local queries for the domain, DC, and RMM name succeeded. No DNS forwarders were configured.
- The legacy `win-ukhaoru0g1r` A record still points to the DC address alongside the intended `js-dc-01` record. Treat it as a stale-alias candidate, not a proven address collision, until dependencies are checked.
- The PDC reported successful synchronization, but its active source was the Hyper-V integration provider. W32Time type is `NT5DS`; in a single-DC forest the PDC should have a deliberately configured and verified external authoritative source rather than relying on VM-host time.
- Recent System errors were limited to prior OpenSSH service terminations, TrustedInstaller/DCOM startup failures, and virtual TPM/UEFI certificate-update events. OpenSSH and core directory services were healthy at capture time.

## Deployment gates and next actions

1. **Network policy gate:** define and review least-privilege OPNsense rules for VLANs 110, 120, 130, 140, 150, 160, 240, and 250 before expecting provisioned guests to communicate. Decide whether each VLAN uses DHCP reservations or fully static addressing.
2. **Addressing gate:** convert or reserve stable management addresses for JS-BlueBench, TRMM-Tooling, and Wazuh-Machine; update DNS, TacticalRMM/Wazuh targeting, and the asset baseline from readback.
3. **Firewall gate:** remove or narrowly replace the broad WAN-to-firewall rule after preserving a tested management path and rollback configuration.
4. **Storage gate:** explicitly quarantine/exclude the unattached duplicate/remnant VHDs and exports. Every create request must use a manifest-derived unique VHD path and fail if any target path already exists.
5. **Checkpoint gate:** separately validate and then merge or retain the JS-Server checkpoint chain; never let create-only cleanup logic touch it.
6. **Monitoring gate:** restore/verify Wazuh enrollment availability and define TacticalRMM coverage policy for supported Linux guests. Canary enrollment should precede fleet rollout.
7. **Identity/time resilience:** configure and verify authoritative PDC time, review the stale DNS alias, and establish a tested backup/restore path for the single DC.
8. **Hygiene:** dismount installer media after ownership/boot checks and normalize legacy/nonstandard VM configuration roots through a separately approved migration, not during create-only deployment.

This report is a point-in-time evidence record. Re-run name, path, switch-ID, storage-free-space, firewall-policy, and guest-address checks immediately before any separately approved deployment.

## Authorized remediation record

### PDC authoritative time source

- Change time: 2026-08-02 18:34 UTC.
- Scope: `JS-DC-01` Windows Time configuration only.
- Pre-change rollback artifact: `C:\ProgramData\NorthGate\Backups\remaining-fleet-20260802T181604Z\w32time-pre-external-20260802T184000Z.reg`.
- Rollback artifact SHA-256: `fa5052f8f522b660e5d321b39145bb0753297accd665035c3c6ce895c9122a5d`.
- Change: configured the forest PDC emulator to use `time.cloudflare.com` and `time.google.com` as manual NTP peers, marked it reliable, and disabled the Hyper-V integration time provider as an input source.
- Readback: source `time.google.com,0x8`, stratum 2; both peers active and providing valid time data.
- Regression checks: `w32tm /monitor` showed the PDC advertising with the external reference; targeted AD Advertising, Services, and DNS diagnostics all passed after the change.
- Rollback: import the recorded registry export, restart Windows Time, rediscover, and verify source and AD diagnostics before closing the rollback.
