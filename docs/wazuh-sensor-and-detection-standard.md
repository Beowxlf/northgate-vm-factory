# NorthGate Wazuh sensor and detection-engineering standard

- **Status:** Proposed; plan-only
- **Applies to:** Retained NorthGate systems, the proposed Windows workstation fleet, and future mail and simulated-external workloads
- **Control owner:** NorthGate infrastructure owner

## Control statement

This standard defines the approved monitoring design. It does not install software, change a Wazuh group or rule, enable Active Response, or authorize a VM deployment. Live sensor configuration, rule files, backups, test events, and evidence remain outside Git and move through a separately reviewed Wazuh maintenance change.

The selected NorthGate endpoint-detection integration is the native Wazuh agent plus operating-system controls; no additional third-party EDR agent is introduced during the plan-only phase. The Windows stack is deliberately layered:

| Component | Security role | Boundary |
| --- | --- | --- |
| Wazuh agent | Collects selected logs, inventory, vulnerability, and file-integrity telemetry and transports it to Wazuh for correlation | Does not replace endpoint antivirus; Active Response is off by default |
| Microsoft Defender Antivirus | Provides Windows malware scanning, prevention, and quarantine | Its Operational events are collected by Wazuh; Wazuh does not manage Defender exclusions through this standard |
| Microsoft Sysmon | Adds detailed Windows Event Log telemetry | Records activity only; it does not analyze, alert, block, or quarantine |

Use either built-in or standalone Sysmon on an endpoint, never both. Pin the selected Microsoft-signed release or Windows feature state and the reviewed configuration hash. Installation or feature enablement requires its own canary, recovery path, pending-reboot check, and maintenance record.

## Sensor scopes and group model

Wazuh centralized configuration uses the following implementation units. A Windows endpoint receives `default`, one operating-system baseline, exactly one role scope, and at most one of the mutually exclusive `ng-win-sensor-canary` or `ng-win-sensor-standard` scopes. Verify the effective merged configuration and group priority before rollout.

| Scope | Assets | Required coverage |
| --- | --- | --- |
| `default` | Every enrolled agent | Agent health, labels, bounded buffering, inventory, and Active Response disabled |
| `ng-win-workstation-baseline` | Every proposed Windows workstation, in addition to `default` | Selected Security, System, Application, Defender, PowerShell, SCA, inventory, vulnerability, and conservative FIM configuration |
| `ng-win-retained` | Retained Windows clients and servers | Windows event channels, Defender events, targeted FIM, inventory, vulnerability data |
| `ng-win-sensor-canary` | Exactly one approved non-critical Windows endpoint at a time | Proposed Sysmon or Windows collection delta; highest-priority temporary overlay |
| `ng-win-sensor-standard` | Windows workstations only after the canary observation passes | Promoted bounded Windows/Sysmon source selection; no Active Response |
| `ng-win-worker` | Future `NG-WRK-01` and `NG-WRK-02`, in addition to the Windows base scope | Ordinary-user authentication, Defender, process/service, software, removable-media, and targeted user-persistence evidence |
| `ng-win-manager` | Future `NG-MGR-01`, in addition to the Windows base scope | Worker coverage plus business-application and elevated-access anomaly coverage; manager status grants no administrative response authority |
| `ng-win-it` | Future `NG-IT-01`, in addition to the Windows base scope | Privileged logon, remote administration, credential-protection, policy, service, account/group, and administrative-tool evidence |
| `ng-win-cyber` | Future `NG-CYBER-01`, in addition to the Windows base scope | Security-console access, detection content change, evidence handling, tool installation, privileged action, and sensor-health evidence |
| `ng-linux-retained` | Retained Linux systems | Authentication, privilege, service, package, audit, inventory, vulnerability, and targeted FIM data |
| `ng-linux-server-baseline` | Future managed Linux service VMs | Authentication, privilege, service, package, audit, inventory, vulnerability, conservative FIM, and Active Response disabled |
| `ng-wazuh-infra` | Wazuh server components | Local authentication plus manager, indexer, dashboard, Filebeat, storage, queue, and listener health |
| `ng-mail-base` | Both future mail servers in addition to the Linux scope | Mail transport, mailbox authentication, queue, TLS, service, and mail-configuration events |
| `ng-mail-internal` | Future `NG-MAIL-INT01` in addition to `ng-mail-base` | Internal submission, delivery, antispam, malware-scan, local-recipient, and external-edge transaction evidence |
| `ng-mail-external` | Future `NG-MAIL-EXT01` in addition to `ng-mail-base` | Simulated-external submission, local-recipient, relay-denial, Kali-source, and internal-edge transaction evidence |
| `ng-redteam-kali` | Future `NG-KALI-EXT01` in addition to the Linux scope | Agent health and host-integrity evidence after a separate transport exception is approved; expected offensive-tool activity is labeled, not auto-contained |
| `ng-opnsense-syslog` | OPNsense sender identity; not a Wazuh agent group | Source-restricted TCP syslog for firewall, NAT, DNS, DHCP, VPN, and routing evidence |

Group membership is deny-by-default: no endpoint enters a production role group until its identity, address, agent key, operating system, owner, and asset record agree. The red-team and OPNsense scopes never receive endpoint Active Response.

The desired-state table is not evidence that a group exists or is deployed. Current membership, effective configuration, and group hashes remain in Operation-SeeSaw; every proposed group is an implementation prerequisite until separate live readback proves otherwise.

The five proposed Windows workstations enroll sequentially after their final hostname, VLAN, fixed address, DNS, domain OU, TacticalRMM site, and asset identity agree. Use `NG-WRK-01` as the first production endpoint canary, followed by Worker 2, Manager, IT, and Cyber. Every endpoint receives `default`, `ng-win-workstation-baseline`, and exactly one role group; the sensor canary and standard groups are mutually exclusive. Assign in this precedence order: `default`, operating-system baseline, role group, then canary or standard sensor group last. Read back the effective group order and synchronized configuration hashes; Wazuh's most recently assigned group takes precedence for conflicting settings. Create a group before naming it during enrollment; Wazuh rejects enrollment into a nonexistent group. Enrollment TCP 1515 is opened only to the single exact endpoint being enrolled, one endpoint and maintenance window at a time, and is closed after transport on TCP 1514 and indexed telemetry are verified.

## Minimum collection profile

Collect metadata needed for detection; do not collect message bodies, credentials, private keys, tokens, or unnecessary command content.

| Platform | Minimum sources |
| --- | --- |
| Windows | Selected Security, System, Application, and Microsoft Defender Operational events; targeted inventory, vulnerability, and FIM data; Sysmon Operational events `1, 4, 6, 8, 16, 19, 20, 21, 25, 29` only after canary acceptance |
| Linux | SSH/authentication and `sudo`; service and kernel failures; package changes; reviewed `auditd` events; inventory, vulnerability, and FIM coverage for security and service configuration |
| Wazuh infrastructure | Component versions and service state; agent connectivity; listener scope; root/index/journal capacity; queue utilization and dropped-event counters; bounded error categories |
| OPNsense | `filterlog`, Unbound, DHCP, OpenVPN, IPsec/strongSwan, and WireGuard records over the existing source-restricted TCP receiver; preserve interface, action, protocol, source zone, destination zone, and rule identity |
| Mail | Postfix, Dovecot, Rspamd, ClamAV, authentication, queue, TLS, and unit health; FIM for mail and TLS configuration without key content |
| Kali | Authentication, `sudo`, service, package, route/interface, persistence, and agent-health changes; collect process detail only for an approved exercise window and never treat normal red-team tooling as automatically malicious |

For Windows role groups, collect only metadata necessary for security decisions. Do not ingest browser content, email bodies, clipboard data, passwords, tokens, private keys, or unrestricted PowerShell script-block content. Role-specific collection narrows and labels the base source set; it does not create blanket collection on privileged IT or cyber endpoints.

Every source must use synchronized UTC timestamps and stable asset and zone labels. Wazuh evidence records contain counts, rule IDs, timestamps, configuration hashes, and sanitized examples; raw alerts and private infrastructure data do not enter this repository.

Windows event selectors are allowlists, not whole-channel subscriptions. They must cover audit-log clearing, failed and privileged logon, explicit credentials, process creation when audit policy supports it, service installation, audit-policy change, local/domain account and privileged-group change, lockout, and relevant domain-controller authentication or directory change. Successful-logon and PowerShell content require narrow scoping and a privacy/secret-handling review before collection.

## Transport boundaries

- Permit an enrolled endpoint to reach only the configured Wazuh agent transport, currently TCP 1514, from its exact approved network scope. Do not expose the dashboard, API, indexer, or SSH as a sensor dependency.
- Keep enrollment on TCP 1515 closed. Before a new enrollment, back up the manager configuration and client-key state. For exactly one reserved endpoint, temporarily permit TCP 1515 at the firewall. Validate the proposed `<auth>` block against the installed Wazuh version before restart; for the current schema, require `<use_source_ip>yes</use_source_ip>`, nested `<force><enabled>no</enabled></force>`, and `<purge>no</purge>`. Enroll one exact hostname, then restore `<disabled>yes</disabled>`, validate again, restart only after validation passes, and prove TCP 1515 is absent. If enrollment uses a password, it remains human-controlled and never enters Git, TacticalRMM arguments/environment, chat, or evidence.
- Permit OPNsense to reach only the source-restricted TCP 514 receiver. Reject other senders and verify that agent transport remains unaffected.
- Each future mail agent requires a separate outbound-only exception from MAIL-INT or EXT-MAIL to agent transport. Enroll one server at a time and apply `default`, `ng-linux-server-baseline`, `ng-mail-base`, and exactly one mail-role group in that precedence order, then read back the effective configuration and synchronized hashes. A future Kali agent requires a separately approved, exact-source SIM-WAN exception to transport; without it, Kali remains agentless and OPNsense supplies network evidence. None of these exceptions grants access to Wazuh management surfaces.

## Detection engineering workflow

1. **Define:** State the hypothesis, affected assets, required source fields, expected severity, false-positive risk, owner, and rollback trigger. Allocate a unique custom rule ID from the Operation-SeeSaw rule ledger within Wazuh's `100000`-`120000` custom-rule range.
2. **Baseline:** Record component health, agent state, queue and drop counters, storage, bounded alert volume, relevant configuration hashes, and a recoverable configuration backup.
3. **Test offline:** Validate manager configuration and run one positive fixture plus at least two negative fixtures through the Wazuh rule test path. Rules must use decoded fields and the narrowest reliable parent; message-wide expressions are a last resort.
4. **Canary:** Apply only to one non-critical endpoint or one exact sender identity. Emit a synthetic event carrying the change or exercise ID. A canary rule starts at level 3, has no suppression and no response action, and must match the expected event exactly once.
5. **Observe:** Complete at least 30 minutes and one normal workload cycle. Require all agents and services to remain healthy, no increase in dropped events, queue utilization below 80%, no match on a non-target asset, and an alert-volume result within the change's recorded threshold.
6. **Promote:** Move a successful rule from canary to its exact role scope in a separate reviewed change. Record the rule/configuration hash, scope, test results, baseline comparison, approver, and rollback artifact.
7. **Review:** Revalidate after Wazuh, operating-system, Sysmon, mail, or firewall upgrades and at least quarterly. Expired tests and rules without an owner return to canary or are retired through change control.

Fail closed and roll back if configuration validation fails, a target identity is ambiguous, a non-target fires, any new event drop occurs, queues reach 80%, service or agent health degrades, the expected test does not arrive, or evidence cannot be preserved. Restore the exact pre-change configuration, verify health and ingestion, and retain the failed test evidence. Do not delete alerts or logs as part of rollback.

## Noise and suppression policy

Treat repetitive events as a diagnostic signal before treating them as noise:

1. Correct a malfunctioning or unnecessary source process, service, audit policy, or collection scope first.
2. If the source is valid, narrow collection using stable source fields while retaining the evidence needed for investigation.
3. Use a Wazuh child rule only when source correction and collection scoping are inadequate. Scope it to an exact agent or role, decoder, parent rule, field set, and documented benign condition.
4. Never deploy a broad level-zero child of a common parent, suppress an entire authentication or firewall category, or combine a new detection with its suppression.
5. Measure before/after event and alert counts, set an owner and review date, and prove that positive security fixtures still fire.

## Active Response policy

Active Response remains disabled for every initial group and rule. A future enablement is a separate, high-risk control change requiring a narrow allowlist, non-critical canary, bounded duration, idempotent action, tested rollback, protected audit trail, and explicit approval for the exact rule and target group. It remains prohibited on `ng-redteam-kali`, `ng-opnsense-syslog`, `ng-mail-base`, `ng-mail-internal`, and `ng-mail-external` so a simulation, parser error, or mail false positive cannot disrupt routing, evidence collection, or delivery.

## Future mail and Kali detection map

| Detection objective | Correlated sources | Initial disposition |
| --- | --- | --- |
| Accepted unauthenticated relay or delivery to an invalid local recipient | Postfix plus mail configuration/FIM | High; investigate immediately, no automatic response |
| Repeated SMTP or mailbox authentication failures | Postfix/Dovecot plus OPNsense source zone | Medium; raise to high when the source is SIM-WAN or crosses the recorded threshold |
| Malware or high-confidence malicious attachment verdict | ClamAV/Rspamd plus Postfix queue identity | High; preserve metadata and quarantine result, never ingest message body into evidence notes |
| Mail service, queue, TLS, or configuration failure | Unit health, Postfix/Dovecot queue and TLS events, FIM | Medium operational alert; high if delivery or trust boundary is lost |
| Direct outbound TCP 25 or access from SIM-WAN outside the mail edge policy | OPNsense `filterlog` and NAT plus endpoint network metadata | High boundary violation; distinguish an approved canary by exercise ID |
| Allowed external-to-internal SMTP transaction | External Postfix queue ID, OPNsense allow/NAT, and matching internal Postfix receipt | Informational correlation proving end-to-end visibility across the isolated servers |
| Allowed internal-to-external SMTP transaction | Internal Postfix queue ID, OPNsense allow, and matching external Postfix receipt | Informational correlation proving the reverse delivery path |
| SIM-WAN attempt toward trusted LAN, management, Wazuh, or non-mail DMZ service | OPNsense deny logs | High unless tied to an approved negative test; never auto-block because the firewall already enforces denial |
| Kali agent stop, removal, identity change, or telemetry gap | Wazuh agent status plus host service and FIM data | High sensor-tamper or availability alert |
| Kali route, interface, bridge, persistence, or privileged configuration change | Linux audit, service, package, route/interface, and FIM data | High outside an approved exercise; preserve the change/exercise ID |
| Offensive tool or process execution on Kali | Approved-window process/audit telemetry | Informational by default; elevate only when outside the authorized window or paired with a boundary violation |

Correlations use UTC time, immutable asset ID, Wazuh agent/sender identity, source and destination zones, firewall rule identity, and a synthetic exercise ID. IP address alone is not identity.

## Promotion and evidence gates

Before any current or future sensor is promoted, all of the following must be true:

- package/release, operating-system, Wazuh, and configuration compatibility is verified;
- a backup and exact rollback procedure are readable before the change;
- positive and negative tests, canary scope, health, queues, drops, storage, and alert-volume thresholds pass;
- the expected event is visible from endpoint or sender through Wazuh search with no unauthorized listener or firewall expansion;
- Active Response remains off unless a separately approved exception exists;
- the signed or hashed configuration, group membership, result counts, audit/change ID, and rollback outcome are recorded in Operation-SeeSaw; and
- the VM Factory remains plan-only until its independent control-plane, image, network, canary, and human plan-approval gates pass.

Future VM manifests reference only an approved opaque bootstrap profile. Agent enrollment, Wazuh group assignment, mail rules, OPNsense forwarding, and detection promotion remain separate guarded maintenance changes; Git merge is not deployment approval.

## Authoritative references

- [Wazuh centralized agent configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)
- [Wazuh agent grouping](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html)
- [Wazuh enrollment service configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html)
- [Wazuh Active Response configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html)
- [Postfix SMTP relay and access control](https://www.postfix.org/SMTPD_ACCESS_README.html)
- [Dovecot TLS configuration](https://doc.dovecot.org/2.4.3/core/config/ssl.html)
- [Microsoft: Enable and configure Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)
- [Microsoft: Sysmon configuration files](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)
