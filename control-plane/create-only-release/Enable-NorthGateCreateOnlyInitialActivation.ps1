[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ReadinessEvidenceSha256,
    [Parameter(Mandatory)][ValidatePattern('^NG-CHG-[0-9]{8}-[A-Z0-9-]{3,32}$')][string]$ChangeId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ApprovalCertificateSha256,
    [Parameter(Mandatory)][ValidateRange(30,300)][int]$LifetimeSeconds,
    [Parameter(Mandatory)][switch]$ConfirmActivation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Ngca { param([string]$Code) throw [InvalidOperationException]::new($Code) }

function Get-NgcaSha256Hex {
    param([byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

if (-not $ConfirmActivation) { Stop-Ngca 'NGCOR-INITIAL-ACTIVATION-CONFIRMATION-REQUIRED' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $identity.User.Value -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {
    Stop-Ngca 'NGCOR-INITIAL-ACTIVATION-ADMIN-IDENTITY-REQUIRED'
}
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$requiredPrefix = Join-Path $programFiles 'NorthGate\VMFactory\CreateOnly\releases'
$installedRoot = [IO.Path]::GetFullPath($PSScriptRoot)
if (-not $installedRoot.StartsWith($requiredPrefix + '\',[StringComparison]::OrdinalIgnoreCase) -or
    -not (Test-Path -LiteralPath (Join-Path $installedRoot 'installed-release.json') -PathType Leaf)) {
    Stop-Ngca 'NGCOR-INITIAL-ACTIVATION-CHECKOUT-EXECUTION-FORBIDDEN'
}
$protocol = Import-Module (Join-Path $installedRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') `
    -Force -PassThru
$deployment = Import-Module (Join-Path $installedRoot 'NorthGate.VMFactory.CreateOnlyDeployment.psd1') `
    -Force -PassThru
try {
    $installedBytes = [IO.File]::ReadAllBytes((Join-Path $installedRoot 'installed-release.json'))
    $manifestBytes = [IO.File]::ReadAllBytes((Join-Path $installedRoot 'release-manifest.json'))
    $authorizationBytes = [IO.File]::ReadAllBytes((Join-Path $installedRoot 'deployment-authorization.json'))
    $backendPolicyBytes = [IO.File]::ReadAllBytes((Join-Path $installedRoot 'backend-policy.json'))
    $dataBundleBytes = [IO.File]::ReadAllBytes((Join-Path $installedRoot 'backend-data\bundle.json'))
    $installed = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
        -Bytes $installedBytes -MaximumBytes 1048576).Value
    $manifest = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
        -Bytes $manifestBytes -MaximumBytes 1048576).Value
    $authorization = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
        -Bytes $authorizationBytes -MaximumBytes 1048576).Value
}
catch { Stop-Ngca 'NGCOR-INITIAL-ACTIVATION-INSTALLED-EVIDENCE-INVALID' }
if ($installed.schema -cne 'northgate/create-only-installed-release/v1' -or
    $installed.serviceName -cne 'NorthGateCreateOnly' -or
    $manifest.releaseId -cne $installed.releaseId -or
    $authorization.repository.releaseId -cne $installed.releaseId -or
    (Get-NgcaSha256Hex $manifestBytes) -cne $installed.releaseManifestSha256 -or
    (Get-NgcaSha256Hex $authorizationBytes) -cne $installed.deploymentAuthorizationSha256 -or
    (Get-NgcaSha256Hex $backendPolicyBytes) -cne $installed.backendPolicySha256 -or
    (Get-NgcaSha256Hex $dataBundleBytes) -cne $installed.dataBundleSha256 -or
    $authorization.identity.approvalSignerCertificateSha256 -cne $ApprovalCertificateSha256) {
    Stop-Ngca 'NGCOR-INITIAL-ACTIVATION-INSTALLED-EVIDENCE-BINDING-MISMATCH'
}
try {
    $context = & $deployment { param($Authorization) Get-NgcdExistingProductionContext $Authorization } `
        $authorization
    Invoke-NorthGateCreateOnlyInitialActivationTransaction -Context $context `
        -Installed $installed -Manifest $manifest -Authorization $authorization `
        -AuthorizationSha256 ([string]$installed.deploymentAuthorizationSha256) `
        -ReadinessEvidenceSha256 $ReadinessEvidenceSha256 -ChangeId $ChangeId `
        -ApprovalCertificateSha256 $ApprovalCertificateSha256 -LifetimeSeconds $LifetimeSeconds `
        -Confirm:$false
}
catch {
    if ($_.Exception.Message -cmatch '^NGCOR-') { throw }
    Stop-Ngca 'NGCOR-INITIAL-ACTIVATION-FAILED'
}

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBpnqHM29vCTXHo
# TYuR+4MyJSN67Bfr4eCXXOrP/M/rwaCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
# sEhN7njmUsaSMA0GCSqGSIb3DQEBCwUAMDwxOjA4BgNVBAMMMU5vcnRoR2F0ZSBW
# TSBGYWN0b3J5IFJlbGVhc2UgU2lnbmVyIDIwMjYtMDgtMjEgdjIwHhcNMjYwODIx
# MDI0ODM5WhcNMjgwODIxMDc1ODM5WjA8MTowOAYDVQQDDDFOb3J0aEdhdGUgVk0g
# RmFjdG9yeSBSZWxlYXNlIFNpZ25lciAyMDI2LTA4LTIxIHYyMIIBojANBgkqhkiG
# 9w0BAQEFAAOCAY8AMIIBigKCAYEAuK2RPh+kwyLvYhpQmiHvsROwEKzmIdyEc6WV
# b1N80dzFqV4o16F7MTsoC1Xbo3VdbDurlCWifItnM+UTZ7B6xP8TLmPGRys7sGa/
# QQOm77wKKQ7OdjJlqSSXz4+efiUwoMEkhyP3YkL8G7VvS7EcKCVaspPX8ghvtCYe
# rOQQYWVFOV9EuvajfvnFPna0Y4Y4qMJAxZZEtfMVKtLejdftGHra9pZm/Vi3OiIx
# At/lfqeqK1vYu96Uyh4LhSoxSaev2EOpsznHtTIwY3KNC9dpwlogX2FYa0l1zH1k
# Kk0n/AjTYgR0mxQXMP89640xScVCb+rmY8SNG5w/YZB9uQnkTY5Zkh8z5dfHH8HM
# Fvibww5+B8nEBiMe/1RrUzpf1qOyuwyCphrAMRl2NbWR/yzdjCvUBaLbbmkVW20f
# U3X2CTd144vt2iLfCco+WEIuXaRy6g1vQxu1bYtOHuO5GwobWUCN4CVvhILf+VVt
# hPvyDnvdRZEyaJ2wmI3xWE0+QJY9AgMBAAGjVzBVMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRb
# WaTBPZZW7QhHiKCc/W2Z3DB9oTANBgkqhkiG9w0BAQsFAAOCAYEAaNP8lBhUC94L
# AUcORggLbH+yuwZ92dK4vhUVrqukaQKL0CpTouv88GOJtrocGo09vyZ1Y7T+ieZ2
# SKKMwmM+efwt+cDQ0b4HDIWYfswSQdfd/HATQX5PNSmC6uEYi6cf/yd31aHkySrN
# W2gfy82zjixp/SP/k9KmpbE+I5f8wppCZ4+ePk5/g+f7gb7a9+g66Ywua2apF76N
# gQB0LPaz0SXwWZ4QS4w/X4TUSDnluz9uHzX2NZ4oNAzT1tR7tBF7Ntu+8mEw2mot
# BcI7pQEu6CDLNGl1rSwPswnZDUWOcnImdqW3IDab4XUmN5my5pB3iLmojG2UOVXr
# SWVYZkiHWI5RGHNDBmdnbDXxK2Xy4uJMLiVEqws8QosKSTUTSAL5B3KM1/HWwQzv
# X2fiwRK2cIfTIJ34Dtlp0lewhzvauoSuVZkYxQ/43QfYxed20zWo44UnRTrScDdC
# 9UmREbQDcZjjpb04T4zAXLHmS9e0k1IwA7vXMRcs4x7Uiq5diaQdMYICgjCCAn4C
# AQEwUDA8MTowOAYDVQQDDDFOb3J0aEdhdGUgVk0gRmFjdG9yeSBSZWxlYXNlIFNp
# Z25lciAyMDI2LTA4LTIxIHYyAhAvazDvs9z4sEhN7njmUsaSMA0GCWCGSAFlAwQC
# AQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwG
# CisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZI
# hvcNAQkEMSIEILV+oW4+1ZUQ3F/5UV/N1tGWdwdciBV9nlo+5u7WXRy2MA0GCSqG
# SIb3DQEBAQUABIIBgH/lcIxBuD2nQ2dFPYoIRGERABKSk2pzVWbtBnIWQxqzCuEf
# fPxSNj43dORA3IH068lU8b/pMrWu5QtWN/1C+M1eSlW0ufwpb5E9X/I8dClxrdV7
# HqS3U/tDz/6f0HMBAb8NRoLQmcccWdbgJkOTEo/OndKZa5zRjruwTEa7FH38bFBL
# lm9pUFQRCiOpdXIwC08QJdGtl7W0Fcvx4Kuh5CE4nk9Xsv3QdwyuV7EzAL9Xj6WJ
# fjR5z5NfkD+YezHN73X34bmuKhcKcCzXQ+HY0acJLfH5p8FRAMSbuyTYRPBrXxze
# G8GcBdYwr/IwXpsJJPPWm/24FH8/6jc3P/rkbiggelMwpTN0CbNMObEkZeoAKgj9
# ODaXpRyPyHu+MVURKOVrtHKVRu+s/Mc0+y/cRNKJewgeKewHE6pQFsSMXCrvmdUD
# KB3KKMuGPb7C/cwqriZYWOlOTIbQ2nShcs8u8nktX1+t9VjRdhT0H+wdCDSnpX9G
# bP8ioxXuuf0tmZGNPQ==
# SIG # End signature block
