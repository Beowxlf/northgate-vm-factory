# Bootstrap media rollback and cleanup

## Build-stage rollback

The source ISO is immutable. On any builder failure, retain the error code and bundle manifest for analysis, delete only the bounded derivative/scratch output, and reverify the source hash. Never rename a failed derivative to an authorized source filename, overwrite an existing output, or bypass a source/architecture/UEFI check.

After evidence is retained, remove the transferred source copy, extraction tree, bundle, and failed derivative from BlueBench scratch using the approved scratch-root cleanup. Generated public-key media is not secret, but it grants temporary access and should be handled as sensitive operational material until the corresponding bootstrap identity is removed.

## Installation-stage rollback

- Do not widen OPNsense policy, enable password login, disable required Secure Boot, reuse an agent identity, or add an unmanaged NIC/disk to rescue a failed canary.
- Power off and quarantine only the new canary through the guarded VM workflow. Preserve its plan/receipt, ISO/output hashes, console result, installer logs, firewall denies, and guest status marker.
- Debian/Kali installer logs are available from the installer environment and later under `/var/log/installer`. Windows Setup evidence is under `C:\Windows\Panther`, `C:\Windows\Panther\UnattendGC`, and `%ProgramData%\NorthGate\Bootstrap`.
- If the target is disposable and recovery is not justified, retire it through the separately approved canary decommission path. Deleting a VM/disk is never implied by deleting a bundle or request.

## Removing Linux bootstrap access

The cleanup script refuses to run until the Wazuh agent and either the accepted TacticalRMM Linux agent or Mesh agent are active. From an approved root-capable path, pass the exact confirmation printed by the hostname rule:

```sh
sudo /usr/local/sbin/remove-northgate-bootstrap 'REMOVE NG-DEB-CAN01 BOOTSTRAP'
```

It removes the authorized key, sudo rule, SSH drop-in, temporary nftables service/rule, locks the account, reloads SSH, and attempts to delete the user. If deletion cannot complete because the account owns the current session, access is still disabled; finish account/home cleanup through the verified management path and record readback.

## Removing Windows bootstrap access

The cleanup script requires the exact confirmation, verified `northgate.tooling` domain membership, a running TacticalRMM/Mesh-related service, a running `WazuhSvc`, and Administrator or SYSTEM context:

```powershell
& 'C:\Windows\Setup\Scripts\Remove-NorthGateBootstrap.ps1' `
  -Confirmation 'REMOVE NG-CANARY-01 BOOTSTRAP'
```

It removes the source firewall rule and administrators public-key file, stops/disables temporary SSH, restores the pre-bootstrap sshd configuration if present, and removes the temporary local user. LAPS/domain/RMM access must be proven before this step. If cleanup happens prematurely, use the human console or already verified domain/RMM recovery path; do not re-enable password SSH or recover the unknown generated password.

## Completion readback

- Bootstrap ISO is dismounted and cannot be the next boot device.
- Temporary account is absent or disabled with no shell/logon right.
- Temporary public key, sudo/admin grant, firewall rule, and listener are absent.
- Domain/DNS/time, TacticalRMM, Wazuh, role service, backup, and recovery state remain healthy.
- Temporary DNS/DHCP/IP/canary identities are removed when the canary retires; persistent identities exactly match the approved ledger.
- Bundle, derivative, source-copy, and cleanup hashes/evidence are reconciled; no credential-bearing log or artifact was created.
