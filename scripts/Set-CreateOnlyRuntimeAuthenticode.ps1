[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedSignerCertificateSha256,
    [string]$RepositoryRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Split-Path -Parent $PSScriptRoot }
$certificate = Get-Item -LiteralPath ("Cert:\CurrentUser\My\" + $CertificateThumbprint) -ErrorAction Stop
if (-not $certificate.HasPrivateKey) { throw 'NGCOR-AUTHENTICODE-PRIVATE-KEY-MISSING' }
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $pin = (($sha.ComputeHash($certificate.RawData) | ForEach-Object { $_.ToString('x2') }) -join '')
}
finally { $sha.Dispose() }
if ($pin -cne $ExpectedSignerCertificateSha256) { throw 'NGCOR-AUTHENTICODE-CERTIFICATE-PIN-MISMATCH' }

$releaseRoot = Join-Path $RepositoryRoot 'control-plane\create-only-release'
$files = @(
    'NorthGate.VMFactory.CreateOnlyProtocol.psd1','NorthGate.VMFactory.CreateOnlyProtocol.psm1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psd1','NorthGate.VMFactory.CreateOnlyDeployment.psm1',
    'Build-NorthGateCreateOnlyServiceHost.ps1','NorthGate.VMFactory.CreateOnlyService.psd1',
    'NorthGate.VMFactory.CreateOnlyService.psm1','backend\NorthGate.VMFactory.CreateOnlyBackend.psd1',
    'backend\NorthGate.VMFactory.CreateOnlyBackend.psm1','Invoke-NorthGateCreateOnlyForcedCommand.ps1',
    'Start-NorthGateCreateOnlyPipeService.ps1','Install-NorthGateCreateOnlyRelease.ps1',
    'New-NorthGateCreateOnlyApproval.ps1','New-NorthGateCreateOnlyRolloutPromotion.ps1',
    'Rollback-NorthGateCreateOnlyRelease.ps1','Test-NorthGateCreateOnlyHostAuthorization.ps1'
)
foreach ($relative in $files) {
    $path = Join-Path $releaseRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        (Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "NGCOR-AUTHENTICODE-FILE-INVALID:$relative"
    }
    if ($PSCmdlet.ShouldProcess($relative,'Apply SHA-256 Authenticode signature')) {
        $result = Set-AuthenticodeSignature -LiteralPath $path -Certificate $certificate `
            -HashAlgorithm SHA256 -ErrorAction Stop
        if ($result.Status -in @(
                [Management.Automation.SignatureStatus]::NotSigned,
                [Management.Automation.SignatureStatus]::HashMismatch,
                [Management.Automation.SignatureStatus]::NotSupportedFileFormat,
                [Management.Automation.SignatureStatus]::Incompatible
            )) {
            throw "NGCOR-AUTHENTICODE-SIGNING-FAILED:${relative}:$($result.Status)"
        }
    }
}
& (Join-Path $PSScriptRoot 'Test-CreateOnlyRuntimeAuthenticode.ps1') `
    -RepositoryRoot $RepositoryRoot `
    -ExpectedSignerCertificateSha256 $ExpectedSignerCertificateSha256
