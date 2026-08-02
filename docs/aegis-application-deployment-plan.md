# Aegis Debian application deployment and readiness plan

## Status

This is the operator handoff for [ADR-0004](decision-records/ADR-0004-aegis-debian-application-services.md). It is **plan-only** and creates no deployment authority. The strict [Aegis workload provisioning proposal](../proposals/aegis-debian-workloads.proposed.json) records the selected design, but it is non-deployable, is not a standard VM manifest, and is not a host-issued plan. No manifest is included because candidate identities remain unreserved, change references remain unapproved, and every new prerequisite record is still proposed.

## Authorized design inputs and selected profiles

The owner authorized `D:\HyperV\VM-ISO` as a candidate source-media folder and specifically selected the hash-verified Debian 12.12 amd64 netinst ISO for these workloads. That is not a bulk-promotion rule: every other ISO requires its own provenance, integrity, compatibility, secret, and lifecycle review. In particular, `Win11_25H2_Unattended.iso` carries a known plaintext-credential risk and is excluded from this proposal and from automatic promotion. The machine-readable catalog records only the Debian artifact's opaque identity and observed SHA-256, never its host path. Source authorization does not replace upstream-signature, exact size, Gen 2 boot, Secure Boot, update, secret-scan, or reproducible-build evidence; the Debian image remains proposed and non-consumable until those checks pass in a separate image promotion.

The owner also authorized VLAN 150 (`BUSINESS-APPS`) and VLAN 160 (`COMMERCIAL-DMZ`) as target network design. The control-plane plan uses a new private Hyper-V trunk fabric, with planned switch identity `NorthGate-App-Trunk` and a dedicated OPNsense trunk adapter named `APP-TRUNK`. OPNsense terminates VLAN subinterfaces 150 and 160; each application VM uses one access-mode adapter on the same private switch. The opaque VM catalog profiles remain `business-apps` and `commercial-dmz`. This avoids changing or exposing the existing external LAN switch. No routine VM action may create, rebind, or alter this fabric.

The delegated storage, bootstrap, recovery, and access choices are:

| Control | Selected proposed reference | Required installed-policy behavior before promotion |
| --- | --- | --- |
| Image | `debian-12.12-amd64-netinst` | Exact artifact digest and size; Debian 12 support; Gen 2/Secure Boot proof; updated clean baseline; reproducible rebuild |
| Storage | `persistent-app-protected` | Approved persistent root; capacity reserve; integrity and encryption-at-rest eligibility; no disk reuse; 100 GiB HR and 120 GiB platform OS disks |
| Employee bootstrap | `debian12-employee-hub` | Idempotent Debian hardening, role service identities, host firewall, pinned release verification, privacy-safe logging, Wazuh, backup hooks, and rollback; no embedded secret |
| Platform bootstrap | `debian12-sentinel-atlas` | Same baseline with the independently pinned Sentinel Atlas role, database isolation, rate-limit readiness, Wazuh, backup hooks, and rollback; no embedded secret |
| Recovery | `aegis-app-protected` | Encrypted application-consistent nightly backup, pre-change recovery point, 30 daily and 12 weekly retention targets, RPO at most 24 hours, RTO at most 8 hours, and quarterly isolated restore evidence |
| Access | `debian-app-keyonly-admin` | Unique per-guest non-root administration identity; key-only, source-restricted access; password and root login disabled; separate break-glass recovery and audit trail |

TacticalRMM is not embedded in either bootstrap profile. It is added only after the Debian agent canary is explicitly accepted; Wazuh plus the key-only native-health path remains the required fallback.

## VLAN 150 and 160 control-plane plan

1. Capture and hash the OPNsense configuration and the current Hyper-V switch/adapter inventory. Reconcile both VLAN IDs, subnets, gateway addresses, routes, VPN selectors, DNS, and adapter identities; stop on any collision.
2. In a separate privileged fabric change, create the private `NorthGate-App-Trunk` switch with no external adapter or management-OS binding. Add only the dedicated `APP-TRUNK` OPNsense adapter in trunk mode, permit VLANs 150 and 160, and use the reviewed unnumbered native-sink behavior.
3. Create the OPNsense VLAN 150 and 160 subinterfaces and gateways from the approved IPAM plan. Keep DHCP disabled for both server zones and begin with default deny, logged inter-zone rules, and no physical-WAN publication.
4. Install and fingerprint the opaque `business-apps` and `commercial-dmz` host mappings. Prove VLAN separation, sole-router behavior, management-listener denial, no untagged escape, and selective rollback before catalog promotion.
5. Promote the fabric/network bundle separately. Only a later change may author the first consuming VM manifest, and each workload then receives an access-mode adapter resolved from its opaque network profile.

## Candidate manifest schema envelopes

The tables below cover every required `VirtualMachine` manifest field. They are review aids, not schema-valid manifests. Values marked pending must be resolved from approved records; placeholders must never be copied into `manifests/vms/`.

### Aegis Meridian Employee Hub

| Manifest field | Candidate value or required decision |
| --- | --- |
| `$schema`, `apiVersion`, `kind` | Canonical VM schema; `northgate/v1alpha1`; `VirtualMachine` |
| `metadata.assetId`, `metadata.name` | `NG-VM-016`; `NG-HR-APP01` — unreserved candidates pending live and ledger collision checks |
| `metadata.ownerRef` | Selected `northgate-owner`; currently proposed, not approved |
| `metadata.purpose` | Internal employee HR application on a dedicated Debian server |
| `metadata.environment` | Candidate `infrastructure`; owner approval required |
| `metadata.criticality` | Candidate `high`; owner and recovery approval required |
| `metadata.dataClassification` | Candidate `restricted`; privacy and retention approval required |
| `metadata.lifecycle` | `proposed` only until every gate passes |
| `metadata.reviewOrRetirementDate` | Candidate annual review `2027-08-01`; confirm in the approved asset record |
| `metadata.changeRef` | Pending approved, stage-specific change record; the proposal cannot create one |
| `metadata.dependencies` | Candidate empty VM dependency list after live reconciliation; non-VM shared services remain documented outside this field |
| `spec.intent`, `spec.generation` | Candidate `create`; constant `2` |
| `spec.imageRef` | Selected `debian-12.12-amd64-netinst`; proposed and digest-pinned, not promoted |
| `spec.firmwareProfileRef` | Candidate `linux-gen2`; currently proposed, not approved |
| `spec.compute` | Candidate 2 vCPU; dynamic 2048/4096/8192 MiB; recheck host reserve |
| `spec.storage` | Selected `persistent-app-protected` and 100 GiB OS disk; profile is proposed and host mapping is unapproved |
| `spec.network.profileRef` | Selected `business-apps`; proposed opaque mapping for access VLAN 150 on the private application trunk |
| `spec.bootstrapProfileRef` | Selected `debian12-employee-hub`; proposed secret-free role bootstrap |
| `spec.recoveryProfileRef` | Selected `aegis-app-protected`; proposed 24-hour RPO / 8-hour RTO protected-backup contract |
| `spec.desiredPowerState`, `spec.destroyProtection` | Candidate `running`; constant `true` |

### Sentinel Atlas Commercial

| Manifest field | Candidate value or required decision |
| --- | --- |
| `$schema`, `apiVersion`, `kind` | Canonical VM schema; `northgate/v1alpha1`; `VirtualMachine` |
| `metadata.assetId`, `metadata.name` | `NG-VM-017`; `NG-PLAT-APP01` — unreserved candidates pending live and ledger collision checks |
| `metadata.ownerRef` | Selected `northgate-owner`; currently proposed, not approved |
| `metadata.purpose` | Commercial Sentinel Atlas platform on a dedicated Debian server |
| `metadata.environment` | Candidate `infrastructure`; owner approval required |
| `metadata.criticality` | Candidate `high`; owner and recovery approval required |
| `metadata.dataClassification` | Candidate `confidential`; tenant-data and retention approval required |
| `metadata.lifecycle` | `proposed` only until every gate passes |
| `metadata.reviewOrRetirementDate` | Candidate annual review `2027-08-01`; confirm in the approved asset record |
| `metadata.changeRef` | Pending approved, stage-specific change record; the proposal cannot create one |
| `metadata.dependencies` | Candidate empty VM dependency list after live reconciliation; non-VM shared services remain documented outside this field |
| `spec.intent`, `spec.generation` | Candidate `create`; constant `2` |
| `spec.imageRef` | Selected `debian-12.12-amd64-netinst`; proposed and digest-pinned, not promoted |
| `spec.firmwareProfileRef` | Candidate `linux-gen2`; currently proposed, not approved |
| `spec.compute` | Candidate 4 vCPU; dynamic 4096/8192/16384 MiB; recheck host reserve |
| `spec.storage` | Selected `persistent-app-protected` and 120 GiB OS disk; profile is proposed and host mapping is unapproved |
| `spec.network.profileRef` | Selected `commercial-dmz`; proposed opaque mapping for access VLAN 160 on the private application trunk |
| `spec.bootstrapProfileRef` | Selected `debian12-sentinel-atlas`; proposed secret-free role bootstrap |
| `spec.recoveryProfileRef` | Selected `aegis-app-protected`; proposed 24-hour RPO / 8-hour RTO protected-backup contract |
| `spec.desiredPowerState`, `spec.destroyProtection` | Candidate `running`; constant `true` |

## Readiness gates

| Gate | Required evidence | Current design-time status |
| --- | --- | --- |
| Factory control plane | Phase 0 negative tests, signed planner/executor, host plan registry, application authentication, shared lock, signed receipt | **Blocked:** apply is disabled and executable actions are empty |
| Identity and governance | Fresh live/ledger collision check; owner, classification, criticality, lifecycle, review date, change, and dependency approval | **Blocked:** candidate identities are unreserved and governance is incomplete |
| Debian image | Official-source Debian 12 amd64 provenance, signature, exact digest and size, Gen 2/Secure Boot validation, update state, clean secret scan, rebuild and rollback evidence | **Blocked:** the authorized Debian candidate has an observed digest and size but remains proposed; signature, boot, rebuild, clean-baseline, and promotion evidence remain incomplete |
| Firmware, storage, recovery | Approved Linux firmware and `persistent-app-protected` mapping; accepted 24-hour RPO / 8-hour RTO; encrypted backup and isolated restore proof | **Blocked:** selected records are proposed, installed mappings and restore evidence do not exist |
| Bootstrap | Pinned OS/application dependencies; key-only source restriction; host firewall; service accounts; artifact verification; secret injection; Wazuh/backup hooks; idempotence and rollback | **Blocked:** both selected role profiles are proposed; only `none` is approved |
| Guest access | Unique non-root identity; key-only source restriction; password/root login disabled; per-guest audit and separate break-glass route | **Blocked:** `debian-app-keyonly-admin` is proposed and has no installed-policy/canary evidence |
| Network | Private `NorthGate-App-Trunk`; dedicated OPNsense `APP-TRUNK`; VLAN 150 and 160 uniqueness; OPNsense backup; gateways, default-deny rules, DNS, and immutable host-policy fingerprints | **Blocked:** the disconnected Private switch and hashed OPNsense rollback copy exist, but no OPNsense app-trunk adapter, VLAN subinterface, workload access port, gateway validation, or promoted opaque mapping exists |
| TLS trust and lifecycle | Private CA or explicit pinning for `.test`; distinct per-service keys; approved Windows/Kali trust distribution; renewal, revocation, expiry monitoring, and rollback tests | **Blocked:** certificate authority, trust scope, and lifecycle owner are undecided |
| Application releases | Independent private-monorepo release, tests, SBOM/dependency inventory, vulnerability review, immutable digest, migration/rollback pair, and deployment signature/provenance | **Blocked:** release promotion evidence is not part of this repository |
| Monitoring and management | Pinned Debian-compatible Wazuh agent plus either an owner-accepted TacticalRMM Linux agent or the documented key-only/native-health fallback; unique identities, enrollment closure, bounded logs, Active Response off, and evidence naming the accepted path | **Blocked:** role profiles, canaries, and management-path acceptance are not approved |
| Data protection | Synthetic-data seed, access model, encryption-at-rest design, retention/deletion behavior, backup confidentiality, recovery-key custody | **Blocked:** owner and privacy decisions are pending |

## Firewall, DNS, SMTP, and sensor contract

Rules are exact-source, exact-destination, and stateful. All other inter-zone traffic is denied and logged. Final addresses and resolvers come from live-approved IPAM rather than this document.

| Source | Destination/service | Proposed allowance and mandatory negative test |
| --- | --- | --- |
| USERS and approved manager clients | Employee Hub HTTPS 443 | Permit HTTPS; reject SSH, database, metrics, and non-HTTPS application ports; application roles still enforce least privilege |
| Approved internal clients | Sentinel Atlas HTTPS 443 | Permit HTTPS; reject database, metrics, administration, and unpublished application ports |
| Exact simulated-external canary source | Sentinel Atlas HTTPS 443 | Add only after internal acceptance; prove Employee Hub, SSH, database, admin, Wazuh, TacticalRMM, and retained infrastructure remain unreachable |
| IT-ADMIN and guarded management source | Both guests | Permit only approved key-only administration and health paths; reject password/root login and every other source |
| Each application guest | Approved DNS/time sources | Permit exact DNS and time; prove no direct query to an unauthorized resolver |
| Each application guest | Internal mail submission | Permit authenticated STARTTLS submission on TCP 587 only; reject direct TCP 25 and prove arbitrary relay remains denied |
| Each application guest | Wazuh | Permit established agent transport on TCP 1514; open TCP 1515 to one exact guest only during enrollment, then close and verify it |
| Each application guest | TacticalRMM, only when the Linux-agent path is accepted | Permit the verified Debian agent HTTPS path only; otherwise configure no TacticalRMM allowance and use the documented fallback; never expose backend listeners or reuse a deployment token |
| Each application guest | Approved package and application artifact sources | Permit only controlled update/release paths during a recorded window; reject mutable or digest-mismatched artifacts |
| Each application guest | Approved backup target | Permit only the selected encrypted backup transport after target identity is pinned; reject restore access from USERS or SIM-WAN |
| Employee Hub | Sentinel Atlas, and reverse | Deny every application, database, administration, and service path; test both directions |

Create test-only split DNS records only after address approval: `employees.aegismeridian.test` resolves solely in trusted views, while `app.sentinelatlas.test` resolves in approved trusted and simulated-external views. Forward and reverse readback must agree. No wildcard, public record, physical-WAN NAT, or direct Internet SMTP route is permitted.

Public certificate authorities cannot issue for these test-only names. Select a private CA or explicit certificate pinning as a separate security decision, issue different keys and certificates to each service, distribute trust only to approved Windows and Kali canary clients, and test renewal, revocation, expiry alerting, loss of trust, and exact rollback before acceptance.

Use the existing Wazuh `default` and `ng-linux-server-baseline` scopes plus separately reviewed role scopes for HR and commercial applications. Enroll one guest at a time, verify unique identity and indexed synthetic events, close enrollment, and keep Active Response disabled. Logs must exclude HR fields, tenant content, credentials, tokens, mail bodies, and unrestricted request bodies.

Create separate least-privilege TacticalRMM sites or equivalent scopes for the two application roles. [TacticalRMM documents its Linux agent as beta](https://docs.tacticalrmm.com/install_agent/): it becomes required on either Debian application host only after a dedicated Debian 12 canary proves its installation, upgrade, uninstall, service recovery, script execution, audit attribution, and rollback, and the owner explicitly accepts its capability limits. A reviewed report-only basic-health script checks identity, updates, pending reboot, disk, reverse proxy, application, database, backup freshness, and Wazuh state. Run against one exact canary first; never use a broad script to bootstrap its own agent. Until that acceptance, Wazuh plus source-restricted key-only administration and native system/service health readback are the fallback management path.

## Deployment and canary sequence

### Phase 0 — reconcile and promote prerequisites

1. Reconcile `NG-VM-016`, `NG-VM-017`, the disposable canary candidate `NG-VM-018` / `NG-DEB-CAN01`, all three names, candidate networks, addresses, and DNS names against live state, the protected ledger, and Operation-SeeSaw. Allocate different identities if any collision exists. The canary must use temporary VM, Wazuh, TacticalRMM, DNS, and backup identities that are never reused by either production service.
2. Approve business owner, purpose, classification, criticality, retention, RPO/RTO, dependencies, maintenance window, and change records.
3. Promote the immutable Debian image, then firmware/storage/recovery/access profiles, then the private fabric and two network profiles, then the two bootstrap profiles as separate reviewed changes. Do not deploy a consumer in the same approval.
4. Build and promote each application release independently. Verify database migrations have a tested forward and rollback path and that no secret is present in source, image layers, packages, SBOM, or logs.
5. Complete the factory control-plane and negative-test gates. Prove `NG-DEB-CAN01` can be created, secured, patched, rebooted, monitored, backed up, restored in isolation, quarantined, and retired through guarded workflows. Reconcile its decommission record; remove or revoke its exact DNS, DHCP, Wazuh, TacticalRMM, and access identities; and quarantine its disk plus recovery evidence under an approved retention deadline. Permanent disk/backup purge is a separately planned, approved, identity-checked action after retention—not a prerequisite folded into canary retirement.

### Phase 1 — Employee Hub internal canary

1. Author a manifest only after every envelope value resolves to an approved reference. Merge it separately from catalog, policy, network, and application-release changes.
2. Generate a fresh post-merge host-registered plan, approve its exact plan ID and authenticated hash, and create only `NG-HR-APP01` through the guarded factory.
3. Establish final identity, network, DNS/time, key-only administration, patch state, local firewall, Wazuh, encrypted backup, and either the accepted TacticalRMM Linux agent or documented native-health fallback before deploying the application. Record which management path was accepted.
4. Deploy the pinned Employee Hub release with synthetic employee data only. Validate TLS, authentication, authorization separation, SMTP notification, audit events, privacy-safe logging, backup, and isolated restore.
5. Observe at least 24 hours, one normal monitoring cycle, one backup, and one planned reboot. Restricted HR data remains prohibited until the owner accepts access, retention, encryption, recovery, and deletion evidence.

### Phase 2 — Sentinel Atlas internal canary

1. Repeat the independent manifest, plan, approval, VM, baseline, and evidence workflow for `NG-PLAT-APP01`; do not reuse Employee Hub identities, secrets, database, or application artifact.
2. Deploy the pinned Sentinel Atlas release with synthetic tenant data. Initially permit HTTPS only from approved trusted canary clients.
3. Validate tenant isolation, user/admin authorization, TLS, rate limiting, SMTP notification, privacy-safe audit events, backup, isolated restore, Wazuh detection, and the accepted TacticalRMM-or-fallback management path. Observe at least 24 hours and one planned reboot.

### Phase 3 — simulated-external boundary canary

1. Back up and hash OPNsense configuration. Add one exact-source SIM-WAN-to-Sentinel-Atlas HTTPS rule in a separate network change; do not expose the physical WAN.
2. Prove the positive HTTPS path and the negative matrix for Employee Hub, SSH, database, management, monitoring, retained infrastructure, direct SMTP, and all non-HTTPS platform listeners.
3. Verify OPNsense deny/allow events and the matching Sentinel Atlas synthetic security event arrive in Wazuh with the change ID. Observe at least 24 hours before promotion.

### Phase 4 — steady-state acceptance

Record VM IDs, adapter/MAC mappings, fixed addresses, DNS, package and application digests, service identities, firewall rule IDs, Wazuh agent/groups, the accepted TacticalRMM site/agent or key-only/native-health fallback, backup/restore evidence, plan/receipt hashes, and review dates in Operation-SeeSaw. Review access, updates, restore readiness, accepted management-path health, certificate expiry, and capacity at the owner-approved interval.

## Acceptance and rollback

Acceptance requires immutable identity and release readback; correct VLAN, address, DNS, and time; TLS-only client access; least-privilege application roles; database listeners confined to loopback/socket; no cross-application or unauthorized management path; direct TCP 25 blocked; successful notification through authenticated submission; a healthy Wazuh identity; either a healthy, explicitly accepted TacticalRMM Linux identity or the documented key-only/native-health fallback; current patches with no pending reboot; encrypted backup; successful isolated restore; and reconciled signed evidence naming the accepted management path.

Stop on identity collision, state drift, image or artifact digest mismatch, missing recovery material, unapproved secret exposure, broad firewall rule, cross-zone reachability, direct database listener, TLS or authorization failure, sensitive log content, duplicate agent, missing telemetry, queue/drop growth, failed backup/restore, capacity-reserve breach, or unsigned plan/receipt.

- For a new-VM failure, quarantine only artifacts carrying the matching change and asset identity. Preserve logs and the signed failure receipt; never adopt, replace, or delete an unrelated VM.
- For application failure, stop traffic, restore the last accepted immutable release, and apply only its tested migration rollback or restore the isolated verified database backup. Do not roll back the other application.
- For network failure, remove only the new exact rule or apply a reviewed selective reverse diff. Restore a full OPNsense backup only when live state matches the failed change's expected post-state and no later approved change exists.
- For Wazuh or TacticalRMM failure, close enrollment, revoke the one-time token, restore the prior role configuration, and remove only the matching new agent identity when re-enrollment requires it.
- If confidentiality cannot be assured, isolate the affected guest at the approved quarantine boundary, revoke application and SMTP credentials, preserve evidence, and treat any data introduction as an incident.

## Explicit no-live-change result

The strict proposal records the owner's selected ISO source, VLAN targets, resource envelopes, and proposed profile set without widening `applyEnabled: false` or adding executable actions. It does not convert source-media authorization into bulk image promotion and does not make either target VLAN or workload live. Separate live preparation created only the disconnected Private switch and a hashed OPNsense rollback copy; that evidence remains outside this repository and grants no workload authority.

This document does not reserve either asset ID, create a manifest, promote a catalog entry, allocate an address, create a VLAN, modify OPNsense, register DNS, enroll an agent, create a backup, deploy an application, or change a VM. Operators must not translate it into direct `hyperv_create_vm` calls or routine Administrator SSH. The next authorized action is governance and live-state reconciliation, followed by separate prerequisite promotions—not VM creation.
