[CmdletBinding()]
param(
    [string]$RepositoryRoot = '',
    [string]$ExpectedSignerCertificateSha256 = '00d58a5185b436f208a9d8b1209ede658d0b8754524fbfa2478061e2181744ef',
    [switch]$RequireTrusted
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Split-Path -Parent $PSScriptRoot }
$releaseRoot = Join-Path $RepositoryRoot 'control-plane\create-only-release'
$files = @(
    'NorthGate.VMFactory.CreateOnlyProtocol.psd1',
    'NorthGate.VMFactory.CreateOnlyProtocol.psm1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psd1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psm1',
    'Build-NorthGateCreateOnlyServiceHost.ps1',
    'NorthGate.VMFactory.CreateOnlyService.psd1',
    'NorthGate.VMFactory.CreateOnlyService.psm1',
    'backend\NorthGate.VMFactory.CreateOnlyBackend.psd1',
    'backend\NorthGate.VMFactory.CreateOnlyBackend.psm1',
    'Invoke-NorthGateCreateOnlyForcedCommand.ps1',
    'Start-NorthGateCreateOnlyPipeService.ps1',
    'Install-NorthGateCreateOnlyRelease.ps1',
    'New-NorthGateCreateOnlyApproval.ps1',
    'New-NorthGateCreateOnlyRolloutPromotion.ps1',
    'Rollback-NorthGateCreateOnlyRelease.ps1',
    'Test-NorthGateCreateOnlyHostAuthorization.ps1'
)

$sha = [Security.Cryptography.SHA256]::Create()
try {
    foreach ($relative in $files) {
        $path = Join-Path $releaseRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "NGCOR-AUTHENTICODE-FILE-INVALID:$relative"
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        if ($null -eq $signature.SignerCertificate -or
            $signature.Status -in @(
                [Management.Automation.SignatureStatus]::NotSigned,
                [Management.Automation.SignatureStatus]::HashMismatch,
                [Management.Automation.SignatureStatus]::NotSupportedFileFormat,
                [Management.Automation.SignatureStatus]::Incompatible
            )) {
            throw "NGCOR-AUTHENTICODE-SIGNATURE-INVALID:${relative}:$($signature.Status)"
        }
        if ($RequireTrusted -and $signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
            throw "NGCOR-AUTHENTICODE-SIGNER-NOT-TRUSTED:${relative}:$($signature.Status)"
        }
        $pin = (($sha.ComputeHash($signature.SignerCertificate.RawData) |
            ForEach-Object { $_.ToString('x2') }) -join '')
        if ($pin -cne $ExpectedSignerCertificateSha256) {
            throw "NGCOR-AUTHENTICODE-SIGNER-PIN-MISMATCH:$relative"
        }
        $gitPath = 'control-plane/create-only-release/' + $relative.Replace('\','/')
        $attribute = @(& git -C $RepositoryRoot check-attr text -- $gitPath 2>&1)
        if ($LASTEXITCODE -ne 0 -or (@($attribute | ForEach-Object { [string]$_ }) -join "`n") `
                -cnotmatch ': text: unset$') {
            throw "NGCOR-AUTHENTICODE-GIT-NORMALIZATION-ENABLED:$relative"
        }
    }
}
finally { $sha.Dispose() }

[pscustomobject][ordered]@{
    status = 'authenticode-verified'
    fileCount = $files.Count
    signerCertificateSha256 = $ExpectedSignerCertificateSha256
    trustRequired = [bool]$RequireTrusted
}
