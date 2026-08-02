[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^ngcor-[a-z0-9][a-z0-9.-]{7,63}$')][string]$InstalledReleaseId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$InstalledReleaseManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$BackupReceiptSha256,
    [Parameter(Mandatory)][switch]$ConfirmRollback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $ConfirmRollback) { throw 'NGCOR-ROLLBACK-CONFIRMATION-REQUIRED' }
$null = $InstalledReleaseId
$null = $InstalledReleaseManifestSha256
$null = $BackupReceiptSha256

# Rollback remains non-operative because this candidate cannot install. A promoted
# version may restore only exact signed control-plane binaries, ACLs, service and
# SSH configuration. It must never restore or delete ledgers, journals, audit,
# receipts, consumed approvals, VMs, VHDX files, switches, or guest state.
throw 'NGCOR-ROLLBACK-BLOCKED-NO-PROMOTED-INSTALLER'
