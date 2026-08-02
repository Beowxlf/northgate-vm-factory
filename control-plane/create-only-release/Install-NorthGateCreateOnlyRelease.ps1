[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$PackageRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedReleaseManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedTree,
    [Parameter(Mandatory)][ValidatePattern('^ngallow-[a-z0-9-]{8,64}$')][string]$ExpectedHostAllowlistId,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$SignedHostDeploymentAuthorizationPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDeploymentAuthorizationSha256,
    [Parameter(Mandatory)][switch]$ConfirmInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This must be replaced during a separately reviewed, signed release ceremony.
# It may not be supplied as a parameter, environment value, policy value, or repo file.
$bakedDeploymentAuthorizationSignerCertificateSha256 = ''

if (-not $ConfirmInstall) { throw 'NGCOR-INSTALL-CONFIRMATION-REQUIRED' }
if ($ExpectedCommit -ceq ('0' * 40) -or $ExpectedTree -ceq ('0' * 40) -or
    $ExpectedReleaseManifestSha256 -ceq ('0' * 64) -or
    $ExpectedDeploymentAuthorizationSha256 -ceq ('0' * 64)) {
    throw 'NGCOR-INSTALL-ZERO-PIN-FORBIDDEN'
}
if ([string]::IsNullOrWhiteSpace($bakedDeploymentAuthorizationSignerCertificateSha256)) {
    throw 'NGCOR-INSTALL-BLOCKED-TRUST-ANCHOR-NOT-BAKED'
}

# Unreachable by design in this candidate. A promotable installer must verify the
# signed deployment authorization and release manifest using open, non-shareable
# handles; copy to a protected versioned directory; rehash the destination; set
# and read back ACLs/service/SSH configuration; run negative self-tests; and leave
# applyEnabled=false, executableActions=[], and canaryStage=disabled.
throw 'NGCOR-INSTALL-BLOCKED-NOT-INDEPENDENTLY-PROMOTED'
