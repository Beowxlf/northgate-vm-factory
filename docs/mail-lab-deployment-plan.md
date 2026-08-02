# NorthGate internal and external SMTP deployment plan

## Status

This is the execution handoff for ADR-0002. It is **plan-only** and does not authorize a Hyper-V, OPNsense, DNS, Wazuh, TacticalRMM, mail, or guest change. The internal and simulated-external services are separate VMs and separate security zones. Neither service is exposed to the physical WAN.

## Workload baseline

| Order | Proposed VM | Role | VLAN and address | Planning resources | Required sensor |
| ---: | --- | --- | --- | --- | --- |
| 1 | `NG-MAIL-EXT01` | Simulated-external SMTP transfer, authenticated test submission, and `redteam.test` mailbox service | EXT-MAIL 240; `172.31.240.10` | 2 vCPU; dynamic 2/2/4 GiB; 40 GiB | Wazuh `default`, `ng-linux-server-baseline`, `ng-mail-base`, `ng-mail-external` |
| 2 | `NG-MAIL-INT01` | Internal authenticated submission, SMTP delivery, and `northgate.test` mailbox service | MAIL-INT 120; `10.10.120.10` | 2 vCPU; dynamic 2/4/8 GiB; 80 GiB | Wazuh `default`, `ng-linux-server-baseline`, `ng-mail-base`, `ng-mail-internal` |
| 3 | `NG-KALI-EXT01` | Simulated-external client and adversary test source | SIM-WAN 250; `172.31.250.10` | 4 vCPU; dynamic 4/4/12 GiB; 100 GiB | Optional Wazuh `ng-redteam-kali` after an exact transport exception is approved |

The names, addresses, resources, classifications, recovery tiers, and asset IDs are planning candidates until Operation-SeeSaw and the protected identity ledger approve them. The two mail servers use a promoted immutable Debian artifact; Kali uses a separately promoted immutable Kali artifact. No agent identity, account password, private key, or deployment token is baked into either image.

Together with the five Windows workstations, the proposed workload set is 22 assigned vCPUs, 38 GiB startup memory, 80 GiB configured maximum memory, and 680 GiB of virtual-disk ceilings. Those totals are design inputs, not current-capacity evidence or reservations. The final host plan must recompute memory and per-volume storage reserves, account for existing maximum-memory ceilings and checkpoints, and distribute disks only through approved opaque storage profiles.

## Network and SMTP contract

| Source | Destination | Allowed service | Purpose |
| --- | --- | --- | --- |
| USERS | `NG-MAIL-INT01` | TCP 587 with STARTTLS; TCP 993 | Authenticated internal submission and mailbox access |
| IT-ADMIN | Both mail servers | Exact approved SSH and service-management paths | Administration from one privileged source only |
| `NG-KALI-EXT01` | `NG-MAIL-EXT01` | TCP 25 for approved protocol tests; TCP 587 with STARTTLS and TCP 993 for synthetic accounts | External client and detection exercises through OPNsense |
| `NG-MAIL-EXT01` | `172.31.240.25` VIP | TCP 25 | Delivery for `northgate.test`; destination NAT only to `10.10.120.10:25` |
| `NG-MAIL-INT01` | `NG-MAIL-EXT01` | TCP 25 | Delivery for `redteam.test` |
| Each mail server | Wazuh transport | TCP 1514 after one-at-a-time enrollment | Endpoint telemetry only; no dashboard or API access |
| Each mail server | Approved DNS, time, and update services | Exact required protocols | Name resolution, synchronized time, and controlled patching |

Everything not listed is denied and logged at the routed boundary. In particular, Kali cannot directly reach MAIL-INT or the internal-mail VIP, USERS cannot reach EXT-MAIL or SIM-WAN, neither mail server can reach Hyper-V or OPNsense administration, and MAIL-INT, EXT-MAIL, and SIM-WAN cannot send TCP 25 to the physical WAN. Do not use NAT reflection, bridge mode, a physical-WAN port forward, or an alternate default route.

## Mail identity and anti-relay controls

- `NG-MAIL-INT01` is authoritative only for local `northgate.test` recipients. Authenticated clients submit on TCP 587; unauthenticated TCP 25 is accepted only from the exact external-mail edge translation and only for valid local recipients.
- `NG-MAIL-EXT01` is authoritative only for local `redteam.test` recipients. It may send `northgate.test` mail only to `mx-inbound.northgate.test`; it is never an arbitrary next-hop relay.
- On both Postfix instances, enforce relay policy before optional content policy and require `reject_unauth_destination` or the installed-version equivalent. Positive local-domain and authenticated-submission tests do not replace an open-relay negative test.
- Dovecot authentication is permitted only after TLS. Use synthetic lab accounts with unique human-controlled secrets; do not reuse Active Directory or production credentials.
- Use split-horizon `.test` DNS and a private lab CA or pinned test certificates. Verify hostname, trust chain, validity, purpose, and private-key permissions. No public MX record, public certificate claim, real external delivery, SPF reputation, or production DKIM/DMARC assertion is implied.
- Mail bodies and credentials are excluded from Git, TacticalRMM inputs, Wazuh evidence, and Operation-SeeSaw. Evidence may retain sanitized headers, queue IDs, timestamps, source/destination roles, outcomes, and hashes.

## Build and promotion sequence

1. Revalidate that the proposed names, addresses, subnets, routes, DNS zones, adapter identities, and asset IDs are collision-free. Record approved values in Operation-SeeSaw before manifest authoring.
2. Verify and consume the accepted ADR-0003 Phase 1 control-plane receipt for the shared Hyper-V Private switch, OPNsense trunk, VLANs 120, 240, and 250, native sink VLAN 4094, exact default-deny rules, logging, backup, and console recovery. The mail rollout does not recreate or independently own shared network objects.
3. Prove VLAN isolation with disposable adapters before attaching a persistent workload. Test untagged frames, spoofed source addresses, cross-zone access, management listeners, physical-WAN SMTP, and rollback.
4. Inspect the Debian and Kali installation media for provenance, digest, support status, boot behavior, and secret-like content. Promote immutable images and secret-safe role bootstrap profiles independently from consuming manifests.
5. Prove restore capability for OPNsense plus each mail server's configuration, queue, mailbox data, certificate material, and Wazuh identity. Define the approved RPO/RTO and off-host recovery evidence.
6. Build `NG-MAIL-EXT01` first through a fresh host-issued plan. Apply only EXT-MAIL access mode, guest-static addressing, test DNS, TLS, Postfix/Dovecot, host hardening, patches, and its Wazuh role. Keep cross-zone SMTP closed while local-recipient, authentication, TLS, invalid-recipient, arbitrary-relay, service, reboot, and restore tests run.
7. Build `NG-MAIL-INT01` through a separate fresh plan and acceptance window. Apply only MAIL-INT access mode, guest-static addressing, test DNS, TLS, Postfix/Dovecot/Rspamd/ClamAV, host hardening, patches, and its Wazuh role. Test local submission and retrieval before opening cross-server delivery.
8. Open one exact external-to-internal path: `172.31.240.10` to `172.31.240.25:25`, destination-translated only to `10.10.120.10:25`. Open the reverse path only from `10.10.120.10` to `172.31.240.10:25`. Verify matching firewall and Postfix queue evidence in both directions.
9. Build Kali last through its own promoted image and plan. Permit only its approved SMTP/mailbox test flows to `NG-MAIL-EXT01`; run positive delivery tests and negative boundary tests under an exercise ID.
10. Reconcile final VM IDs, adapter/MAC identities, addresses, DNS/MX records, certificates without private keys, software/configuration hashes, Wazuh agent IDs/groups, backup results, test results, and signed receipts into Operation-SeeSaw.

The first TacticalRMM Linux agent is a separate beta-agent canary because upstream labels Linux support as beta. It is not a mail-service acceptance dependency. If accepted, enroll each mail server with a short-lived token into a service-specific site, verify unique TacticalRMM and Mesh identities, run report-only health checks, and expire the token. Do not expose TacticalRMM backend listeners or weaken host security to accommodate it.

## Acceptance tests

Acceptance requires all of the following:

- immutable VM, image, disk, adapter, address, DNS, certificate, Wazuh, and evidence identities agree;
- only the documented listeners are present, with SSH limited to IT-ADMIN and Wazuh management surfaces unreachable;
- authenticated submission and mailbox retrieval require trusted TLS and reject invalid credentials;
- both servers accept their valid local recipients and reject invalid local recipients and arbitrary third-party relay attempts;
- a synthetic message travels external to internal and internal to external with matching queue IDs, timestamps, OPNsense rule/NAT evidence, and Wazuh events;
- Kali reaches only the external mail service, cannot reach the internal VIP or MAIL-INT, and cannot bypass OPNsense;
- direct physical-WAN TCP 25, cross-zone management, untagged traffic, spoofed sources, and unexpected DNS recursion are denied and logged;
- services, queues, disk, time, updates, malware scanning where installed, Wazuh transport, and reboot health are within their recorded thresholds; and
- backup and isolated restore evidence satisfies the approved recovery profile.

Stop on the first open-relay result, unexpected listener/path, identity mismatch, untrusted or expired certificate, queue growth, failed malware scanner, missing Wazuh event, capacity-reserve breach, or unsigned plan/receipt. Close the most recently opened firewall rule, quarantine only the matching new VM, and restore only the bounded configuration whose ownership and expected post-change hash still agree. Never weaken a trust boundary or delete an unrelated VM to make a test pass.

## Current blockers

- VM Factory apply and executable actions remain disabled.
- No Debian or Kali image, mail bootstrap, owner, storage, firmware, or recovery profile is approved for these workloads. The existing internal-mail and SIM-WAN network profiles remain proposed, and the new EXT-MAIL profile does not yet exist.
- The guarded control plane cannot yet add and verify the OPNsense trunk adapter or configure Hyper-V trunk/access VLAN state atomically.
- The signed planner, host plan registry, application authentication, shared writer lock, signed receipt path, and disposable canary are incomplete.
- Wazuh mail groups, one-at-a-time enrollment windows, mail configuration, test fixtures, and restore evidence require separate promotion.

Do not translate this plan into direct VM-creation calls or routine Administrator SSH. Git merge, network approval, image/profile promotion, VM deployment approval, and mail-policy activation are separate decisions.

## Authoritative references

- [Postfix SMTP relay and access control](https://www.postfix.org/SMTPD_ACCESS_README.html)
- [Postfix SASL configuration](https://www.postfix.org/SASL_README.html)
- [Dovecot TLS configuration](https://doc.dovecot.org/2.4.3/core/config/ssl.html)
- [Wazuh Linux agent deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)
- [TacticalRMM agent installation](https://docs.tacticalrmm.com/install_agent/)
