[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][ValidatePattern('^ngtxn-[a-f0-9]{64}$')][string]$TransactionId,
    [Parameter(Mandatory)][ValidatePattern('^ngcor-[a-z0-9][a-z0-9.-]{7,63}$')][string]$InstalledReleaseId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$InstalledReleaseManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$BackupReceiptSha256,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$BackupReceiptPath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$BackupReceiptSignaturePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$SignedHostDeploymentAuthorizationPath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$DeploymentAuthorizationSignaturePath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDeploymentAuthorizationSha256,
    [Parameter(Mandatory)][switch]$ConfirmRollback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Replaced only in the independently reviewed rollback bootstrap whose exact
# source and transport hashes are approved out of band. It is intentionally not
# caller or environment configurable.
$bakedDeploymentAuthorizationSignerCertificateSha256 = ''

function Stop-Ngcr {
    param([string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function Read-NgcrBytes {
    param([string]$Path, [int64]$MaximumBytes, [string]$Code)
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while (-not (Test-Path -LiteralPath $cursor) -and -not [string]::IsNullOrWhiteSpace($cursor)) {
        $cursor = Split-Path -Parent $cursor
    }
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and (Test-Path -LiteralPath $cursor)) {
        if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Stop-Ngcr $Code
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Stop-Ngcr $Code }
    $item = Get-Item -LiteralPath $full -Force
    if ($item.Length -le 0 -or $item.Length -gt $MaximumBytes) { Stop-Ngcr $Code }
    $stream = New-Object IO.FileStream(
        $full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None,
        65536, [IO.FileOptions]::SequentialScan
    )
    try {
        $memory = New-Object IO.MemoryStream
        try { $stream.CopyTo($memory); $memory.ToArray() }
        finally { $memory.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Get-NgcrSha256 {
    param([byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-NgcrHex {
    param([string]$Left, [string]$Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ([int][char]$Left[$index] -bxor [int][char]$Right[$index])
    }
    $difference -eq 0
}

function Test-NgcrCertificate {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$ExpectedPin)
    if ($null -eq $Certificate -or $ExpectedPin -cnotmatch '^[a-f0-9]{64}$' -or
        -not (Test-NgcrHex (Get-NgcrSha256 $Certificate.RawData) $ExpectedPin)) {
        Stop-Ngcr 'NGCOR-ROLLBACK-SIGNER-PIN-MISMATCH'
    }
    $now = [DateTimeOffset]::UtcNow
    if ($now -lt $Certificate.NotBefore.ToUniversalTime() -or $now -gt $Certificate.NotAfter.ToUniversalTime()) {
        Stop-Ngcr 'NGCOR-ROLLBACK-SIGNER-CERTIFICATE-EXPIRED'
    }
    $leaf = $false; $eku = $false; $digitalSignature = $false
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $leaf = -not $extension.CertificateAuthority
        }
        elseif ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($usage in $extension.EnhancedKeyUsages) {
                if ($usage.Value -ceq '1.3.6.1.5.5.7.3.3') { $eku = $true }
            }
        }
        elseif ($extension -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $digitalSignature = [bool]($extension.KeyUsages -band
                [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)
            if ($extension.KeyUsages -band (
                    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
                    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign)) {
                Stop-Ngcr 'NGCOR-ROLLBACK-SIGNER-KEY-USAGE-INVALID'
            }
        }
    }
    if (-not $leaf -or -not $eku -or -not $digitalSignature) {
        Stop-Ngcr 'NGCOR-ROLLBACK-SIGNER-KEY-USAGE-INVALID'
    }
}

function Test-NgcrCms {
    param([byte[]]$ContentBytes, [string]$SignaturePath, [string]$ExpectedPin)
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    $signature = Read-NgcrBytes $SignaturePath 1048576 'NGCOR-ROLLBACK-CMS-SIGNATURE-INVALID'
    try {
        $content = New-Object Security.Cryptography.Pkcs.ContentInfo(,$ContentBytes)
        $cms = New-Object Security.Cryptography.Pkcs.SignedCms($content,$true)
        $cms.Decode($signature)
        if (-not $cms.Detached -or $cms.SignerInfos.Count -ne 1 -or
            $cms.SignerInfos[0].DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1') {
            Stop-Ngcr 'NGCOR-ROLLBACK-CMS-SIGNER-COUNT-INVALID'
        }
        $cms.CheckSignature($true)
        $certificate = $cms.SignerInfos[0].Certificate
        Test-NgcrCertificate $certificate $ExpectedPin
    }
    catch {
        if ($_.Exception.Message -cmatch '^NGCOR-') { throw }
        Stop-Ngcr 'NGCOR-ROLLBACK-CMS-SIGNATURE-INVALID'
    }
}

function ConvertFrom-NgcrJson {
    param([string]$Json)
    $converter = Microsoft.PowerShell.Core\Get-Command `
        -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json -DateKind String
    }
    Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json
}

if (-not $ConfirmRollback) { Stop-Ngcr 'NGCOR-ROLLBACK-CONFIRMATION-REQUIRED' }
if ($InstalledReleaseManifestSha256 -ceq ('0' * 64) -or $BackupReceiptSha256 -ceq ('0' * 64) -or
    $ExpectedDeploymentAuthorizationSha256 -ceq ('0' * 64)) {
    Stop-Ngcr 'NGCOR-ROLLBACK-ZERO-PIN-FORBIDDEN'
}
if ($bakedDeploymentAuthorizationSignerCertificateSha256 -cnotmatch '^[a-f0-9]{64}$') {
    Stop-Ngcr 'NGCOR-ROLLBACK-BLOCKED-TRUST-ANCHOR-NOT-BAKED'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Ngcr 'NGCOR-ROLLBACK-ADMINISTRATOR-REQUIRED'
}

$authorizationBytes = Read-NgcrBytes $SignedHostDeploymentAuthorizationPath 1048576 `
    'NGCOR-ROLLBACK-AUTHORIZATION-INVALID'
if (-not (Test-NgcrHex (Get-NgcrSha256 $authorizationBytes) $ExpectedDeploymentAuthorizationSha256)) {
    Stop-Ngcr 'NGCOR-ROLLBACK-AUTHORIZATION-HASH-MISMATCH'
}
Test-NgcrCms $authorizationBytes $DeploymentAuthorizationSignaturePath `
    $bakedDeploymentAuthorizationSignerCertificateSha256
try {
    $authorizationText = (New-Object Text.UTF8Encoding($false,$true)).GetString($authorizationBytes)
    $authorizationBootstrap = ConvertFrom-NgcrJson $authorizationText
}
catch { Stop-Ngcr 'NGCOR-ROLLBACK-AUTHORIZATION-JSON-INVALID' }
if ($authorizationBootstrap.identity.deploymentAuthorizationSignerCertificateSha256 -cne
        $bakedDeploymentAuthorizationSignerCertificateSha256 -or
    $authorizationBootstrap.repository.releaseId -cne $InstalledReleaseId -or
    $authorizationBootstrap.releaseManifestSha256 -cne $InstalledReleaseManifestSha256) {
    Stop-Ngcr 'NGCOR-ROLLBACK-AUTHORIZATION-BINDING-MISMATCH'
}

$receiptBytes = Read-NgcrBytes $BackupReceiptPath 1048576 'NGCOR-ROLLBACK-RECEIPT-INVALID'
if (-not (Test-NgcrHex (Get-NgcrSha256 $receiptBytes) $BackupReceiptSha256)) {
    Stop-Ngcr 'NGCOR-ROLLBACK-RECEIPT-HASH-MISMATCH'
}
Test-NgcrCms $receiptBytes $BackupReceiptSignaturePath `
    ([string]$authorizationBootstrap.identity.receiptSignerCertificateSha256)
try {
    $receiptText = (New-Object Text.UTF8Encoding($false,$true)).GetString($receiptBytes)
    $receipt = ConvertFrom-NgcrJson $receiptText
}
catch { Stop-Ngcr 'NGCOR-ROLLBACK-RECEIPT-JSON-INVALID' }
if ($receipt.schema -cne 'northgate/create-only-backup-receipt/v1' -or
    $receipt.transactionId -cne $TransactionId -or $receipt.releaseId -cne $InstalledReleaseId -or
    $receipt.releaseManifestSha256 -cne $InstalledReleaseManifestSha256 -or
    $receipt.deploymentAuthorizationSha256 -cne $ExpectedDeploymentAuthorizationSha256 -or
    $receipt.receiptSignerCertificateSha256 -cne
        $authorizationBootstrap.identity.receiptSignerCertificateSha256) {
    Stop-Ngcr 'NGCOR-ROLLBACK-RECEIPT-BINDING-MISMATCH'
}

$releaseRoot = [IO.Path]::GetFullPath([string]$authorizationBootstrap.install.versionedReleaseRoot)
$manifestPath = Join-Path $releaseRoot 'release-manifest.json'
$manifestBytes = Read-NgcrBytes $manifestPath 1048576 'NGCOR-ROLLBACK-MANIFEST-INVALID'
if (-not (Test-NgcrHex (Get-NgcrSha256 $manifestBytes) $InstalledReleaseManifestSha256)) {
    Stop-Ngcr 'NGCOR-ROLLBACK-MANIFEST-HASH-MISMATCH'
}
try {
    $manifestText = (New-Object Text.UTF8Encoding($false,$true)).GetString($manifestBytes)
    $manifestBootstrap = ConvertFrom-NgcrJson $manifestText
}
catch { Stop-Ngcr 'NGCOR-ROLLBACK-MANIFEST-JSON-INVALID' }

foreach ($name in @(
    'NorthGate.VMFactory.CreateOnlyProtocol.psd1','NorthGate.VMFactory.CreateOnlyProtocol.psm1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psd1','NorthGate.VMFactory.CreateOnlyDeployment.psm1'
)) {
    $record = @($manifestBootstrap.files | Where-Object { $_.path -ceq $name })
    if ($record.Count -ne 1) { Stop-Ngcr 'NGCOR-ROLLBACK-MODULE-NOT-MANIFESTED' }
    $moduleFile = Join-Path $releaseRoot $name
    $moduleBytes = Read-NgcrBytes $moduleFile 16777216 'NGCOR-ROLLBACK-MODULE-INVALID'
    if (-not (Test-NgcrHex (Get-NgcrSha256 $moduleBytes) ([string]$record[0].sha256))) {
        Stop-Ngcr 'NGCOR-ROLLBACK-MODULE-HASH-MISMATCH'
    }
}

Import-Module (Join-Path $releaseRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -Force -ErrorAction Stop
$deployment = Import-Module (Join-Path $releaseRoot 'NorthGate.VMFactory.CreateOnlyDeployment.psd1') `
    -Force -PassThru -ErrorAction Stop
try {
    $authorization = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $authorizationBytes -MaximumBytes 1048576).Value
    $manifest = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $manifestBytes -MaximumBytes 1048576).Value
    $canonicalReceipt = ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $receipt
    if ($canonicalReceipt -cne $receiptText) { Stop-Ngcr 'NGCOR-ROLLBACK-RECEIPT-NONCANONICAL' }
}
catch {
    if ($_.Exception.Message -cmatch '^NGCOR-') { throw }
    Stop-Ngcr 'NGCOR-ROLLBACK-CANONICAL-EVIDENCE-INVALID'
}
if (-not $PSCmdlet.ShouldProcess($TransactionId,
        'Restore only the exact prior service/SSH/release configuration and quarantine current code')) {
    Stop-Ngcr 'NGCOR-ROLLBACK-CONFIRMATION-REQUIRED'
}
$context = & $deployment { param($Authorization) Get-NgcdExistingProductionContext $Authorization } $authorization
& $deployment {
    param($Context,$TransactionId,$ReleaseId,$ManifestHash,$ReceiptHash)
    Invoke-NgcdFileRollbackTransaction $Context $TransactionId $ReleaseId $ManifestHash $ReceiptHash
} $context $TransactionId $InstalledReleaseId $InstalledReleaseManifestSha256 $BackupReceiptSha256

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBIt+xf/SgN8eC+
# s9nBnKIUw2QklX5z1nTkuP91my7XPKCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIB97rjOCtiWNxTnmhktvPi56Mkcc5rK2A4l/Arb7Y4kgMA0GCSqG
# SIb3DQEBAQUABIIBgBlSY5GJeVbYaRApGzzLfgJW6cXCZGFiEeyAb0Wg9s6MecKS
# mMs4jcHzi4Dd9pzk3yXNLZoN8vdzeqa1ff260nOuERx78W+1vn0umzlZ+ANFShYw
# EreXi1gaz3sr8hKxtmCp76MfB830jQYm8E5q5vP+jJfODssoDpNbIUVxBU+R2q6W
# aI/wiZfxWH/MMQNCyd4dsij8SJ5CqXEQKAE7hB/m8/HTyBLmw3Va+UlByPSL0vXG
# V+9lhZnBg7VkfNyVI4S67e7GXRnlcrGfTfZycyOEVgMxUXICbQlYr3kUXm6TWRF9
# FGiBIHxeKg90w/Z9eECK0w3ObcVKigND+mmrq970Ob3s9ayPOdVh6TvGSVHwAYXm
# 65flbvz3dUCJiY84oIifugWWmAHRo6Wsctd+ubjlUDJ57w0fhRdsD24hMNT+WedW
# d9TP/I2TVqMsZ2dwwxFjf5zQTo/5cvfAFZwXCkrc+vhkR6pHMrnDh7kXJ9P06052
# XFiWj/d9fvzQaR/80w==
# SIG # End signature block
