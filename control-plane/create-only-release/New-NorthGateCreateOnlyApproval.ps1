[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^ngp-[a-f0-9]{64}$')][string]$PlanId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$PlanHash,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{40}$')][string]$ApprovalCertificateThumbprint,
    [Parameter(Mandatory)][ValidateRange(30, 300)][int]$LifetimeSeconds,
    [Parameter(Mandatory)][switch]$ConfirmApproval
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $ConfirmApproval) { throw 'NGCOR-APPROVAL-CONFIRMATION-REQUIRED' }

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'NGCOR-APPROVAL-ADMIN-IDENTITY-REQUIRED'
}

# No file is written in this release candidate. The promoted approval writer must
# read the exact authenticated plan under the admin-only identity, use a distinct
# non-exportable RSA >=3072 certificate private key from LocalMachine\My, sign the
# full canonical approval bytes, and atomically create the approval plus signature.
$null = $PlanId
$null = $PlanHash
$null = $ApprovalCertificateThumbprint
$null = $LifetimeSeconds
throw 'NGCOR-APPROVAL-BLOCKED-DURABLE-STATE-ANCHOR-NOT-IMPLEMENTED'
