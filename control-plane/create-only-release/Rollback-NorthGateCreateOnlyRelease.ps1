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
