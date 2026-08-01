# Aegis Debian application deployment and readiness plan

## Status

This is the operator handoff for [ADR-0004](decision-records/ADR-0004-aegis-debian-application-services.md). It is **plan-only** and creates no authorization to change Hyper-V, OPNsense, DNS, SMTP, Wazuh, TacticalRMM, backup storage, a guest, or either application. No manifest is included because required governance fields and approved catalog references do not yet exist.

## Candidate manifest schema envelopes

The tables below cover every required `VirtualMachine` manifest field. They are review aids, not schema-valid manifests. Values marked pending must be resolved from approved records; placeholders must never be copied into `manifests/vms/`.

### Aegis Meridian Employee Hub

| Manifest field | Candidate value or required decision |
| --- | --- |
| `$schema`, `apiVersion`, `kind` | Canonical VM schema; `northgate/v1alpha1`; `VirtualMachine` |
| `metadata.assetId`, `metadata.name` | `NG-VM-016`; `NG-HR-APP01` — unreserved candidates pending live and ledger collision checks |
| `metadata.ownerRef` | Pending approved owner profile |
| `metadata.purpose` | Internal employee HR application on a dedicated Debian server |
| `metadata.environment` | Candidate `infrastructure`; owner approval required |
| `metadata.criticality` | Candidate `high`; owner and recovery approval required |
| `metadata.dataClassification` | Candidate `restricted`; privacy and retention approval required |
| `metadata.lifecycle` | `proposed` only until every gate passes |
| `metadata.reviewOrRetirementDate` | Pending owner-approved date |
| `metadata.changeRef` | Pending approved change record |
| `metadata.dependencies` | Pending immutable asset-ID reconciliation for required VM dependencies; non-VM services stay outside this field |
| `spec.intent`, `spec.generation` | Candidate `create`; constant `2` |
| `spec.imageRef` | Pending promoted immutable Debian 12 image ID and verified artifact digest |
| `spec.firmwareProfileRef` | Candidate `linux-gen2`; currently proposed, not approved |
| `spec.compute` | Candidate 2 vCPU; dynamic 2048/4096/8192 MiB; recheck host reserve |
| `spec.storage` | Candidate persistent profile and 100 GiB OS disk; profile eligibility and restore design pending |
| `spec.network.profileRef` | Pending promoted lowercase opaque profile for BUSINESS-APPS (candidate `business-apps`); no catalog entry exists |
| `spec.bootstrapProfileRef` | Pending secret-safe Employee Hub Debian role profile; no profile exists |
| `spec.recoveryProfileRef` | Candidate `gold`; currently proposed, not approved, and RPO/RTO are undecided |
| `spec.desiredPowerState`, `spec.destroyProtection` | Candidate `running`; constant `true` |

### Sentinel Atlas Commercial

| Manifest field | Candidate value or required decision |
| --- | --- |
| `$schema`, `apiVersion`, `kind` | Canonical VM schema; `northgate/v1alpha1`; `VirtualMachine` |
| `metadata.assetId`, `metadata.name` | `NG-VM-017`; `NG-PLAT-APP01` — unreserved candidates pending live and ledger collision checks |
| `metadata.ownerRef` | Pending approved owner profile |
| `metadata.purpose` | Commercial Sentinel Atlas platform on a dedicated Debian server |
| `metadata.environment` | Candidate `infrastructure`; owner approval required |
| `metadata.criticality` | Candidate `high`; owner and recovery approval required |
| `metadata.dataClassification` | Candidate `confidential`; tenant-data and retention approval required |
| `metadata.lifecycle` | `proposed` only until every gate passes |
| `metadata.reviewOrRetirementDate` | Pending owner-approved date |
| `metadata.changeRef` | Pending approved change record |
| `metadata.dependencies` | Pending immutable asset-ID reconciliation for required VM dependencies; non-VM services stay outside this field |
| `spec.intent`, `spec.generation` | Candidate `create`; constant `2` |
| `spec.imageRef` | Pending promoted immutable Debian 12 image ID and verified artifact digest |
| `spec.firmwareProfileRef` | Candidate `linux-gen2`; currently proposed, not approved |
| `spec.compute` | Candidate 4 vCPU; dynamic 4096/8192/16384 MiB; recheck host reserve |
| `spec.storage` | Candidate persistent profile and 120 GiB OS disk; profile eligibility and restore design pending |
| `spec.network.profileRef` | Pending promoted lowercase opaque profile for COMMERCIAL-DMZ (candidate `commercial-dmz`); no catalog entry exists |
| `spec.bootstrapProfileRef` | Pending secret-safe Sentinel Atlas Debian role profile; no profile exists |
| `spec.recoveryProfileRef` | Candidate `gold`; currently proposed, not approved, and RPO/RTO are undecided |
| `spec.desiredPowerState`, `spec.destroyProtection` | Candidate `running`; constant `true` |

## Readiness gates

| Gate | Required evidence | Current design-time status |
| --- | --- | --- |
| Factory control plane | Phase 0 negative tests, signed planner/executor, host plan registry, application authentication, shared lock, signed receipt | **Blocked:** apply is disabled and executable actions are empty |
| Identity and governance | Fresh live/ledger collision check; owner, classification, criticality, lifecycle, review date, change, and dependency approval | **Blocked:** candidate identities are unreserved and governance is incomplete |
| Debian image | Official-source Debian 12 amd64 provenance, signature, exact digest, Gen 2/Secure Boot validation, update state, clean secret scan, rebuild and rollback evidence | **Blocked:** image catalog is empty |
| Firmware, storage, recovery | Approved Linux firmware and persistent storage mappings; owner-approved RPO/RTO; encrypted backup and isolated restore proof | **Blocked:** relevant profiles are proposed, not approved |
| Bootstrap | Pinned OS/application dependencies; key-only source restriction; host firewall; service accounts; artifact verification; secret injection; Wazuh/TRMM/backup hooks; idempotence and rollback | **Blocked:** only `none` is approved |
| Network | Private trunk capacity; VLAN 150 and 160 uniqueness; OPNsense backup; interfaces, gateways, default-deny rules, DNS, and immutable host-policy fingerprints | **Blocked:** networks are candidates and no opaque profiles exist |
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
3. Promote the immutable Debian image, then firmware/storage/recovery profiles, then the two network profiles, then the two bootstrap profiles as separate reviewed changes. Do not deploy a consumer in the same approval.
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

This document does not reserve either asset ID, create a manifest, promote a catalog entry, allocate an address, create a VLAN, modify OPNsense, register DNS, enroll an agent, create a backup, deploy an application, or change a VM. Operators must not translate it into direct `hyperv_create_vm` calls or routine Administrator SSH. The next authorized action is governance and live-state reconciliation, followed by separate prerequisite promotions—not VM creation.
