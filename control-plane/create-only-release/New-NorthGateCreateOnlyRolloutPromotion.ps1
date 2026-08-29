[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('windows-canary','persistent-fleet')][string]$ToStage,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$AcceptanceEvidenceSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$RetirementEvidenceSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ApprovalCertificateSha256,
    [Parameter(Mandatory)][ValidateRange(30, 300)][int]$LifetimeSeconds,
    [Parameter(Mandatory)][switch]$ConfirmPromotion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$pipeName = 'NorthGate.VMFactory.CreateOnly.v1'
$maximumFrameBytes = 65536
$pipeResponseTimeoutMilliseconds = 120000
$exactFleetAssetIds = @(
    'NG-VM-018','NG-VM-010','NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012',
    'NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015'
)

function Stop-Ngcr {
    param([string]$Code)
    throw [InvalidOperationException]::new($Code)
}

function Get-NgcrSha256Hex {
    param([byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function New-NgcrRandomHex {
    $bytes = New-Object byte[] 32
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Assert-NgcrExactProperties {
    param([object]$Value,[string[]]$Expected,[string]$Code)
    if ($null -eq $Value) { Stop-Ngcr $Code }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    if (($actual -join '|') -cne ($expectedSorted -join '|')) { Stop-Ngcr $Code }
}

function Test-NgcrEvidenceHash {
    param([string]$Value)
    $Value -cmatch '^[a-f0-9]{64}$' -and $Value -cne ('0' * 64)
}

function Read-NgcrExact {
    param([IO.Stream]$Stream,[int]$Count,[int]$TimeoutMilliseconds)
    $bytes = New-Object byte[] $Count
    $offset = 0
    $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ($offset -lt $Count) {
        $remaining = [int][Math]::Max(1,($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
        $task = $Stream.ReadAsync($bytes,$offset,$Count-$offset)
        if (-not $task.Wait($remaining)) { Stop-Ngcr 'NGCOR-ROLLOUT-PIPE-READ-TIMEOUT' }
        if ($task.Result -le 0) { Stop-Ngcr 'NGCOR-ROLLOUT-PIPE-CLOSED' }
        $offset += $task.Result
    }
    $bytes
}

function Assert-NgcrPipeServerIdentity {
    param(
        [IO.Pipes.NamedPipeClientStream]$Pipe,
        [string]$ExpectedImagePath,
        [string]$ExpectedServiceName
    )
    $verifier = 'NorthGate.VMFactory.CreateOnly.PipeServerIdentityVerifier' -as [type]
    if ($null -eq $verifier) {
        try {
            $assembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($ExpectedImagePath))
            $verifier = $assembly.GetType(
                'NorthGate.VMFactory.CreateOnly.PipeServerIdentityVerifier', $true, $false
            )
        }
        catch { Stop-Ngcr 'NGCOR-ROLLOUT-PIPE-SERVER-VERIFIER-INVALID' }
    }
    try {
        $pipeArguments = New-Object object[] 1
        $pipeArguments[0] = $Pipe.SafePipeHandle.PSObject.BaseObject
        $pipeProcessId = [uint32]$verifier.GetMethod('GetPipeServerProcessId').Invoke(
            $null, $pipeArguments)
        $serviceArguments = New-Object object[] 1
        $serviceArguments[0] = $ExpectedServiceName
        $serviceProcessId = [uint32]$verifier.GetMethod('GetServiceProcessId').Invoke(
            $null, $serviceArguments)
    }
    catch { Stop-Ngcr 'NGCOR-ROLLOUT-PIPE-SERVER-IDENTITY-UNVERIFIABLE' }
    if ($pipeProcessId -ne $serviceProcessId) {
        Stop-Ngcr 'NGCOR-ROLLOUT-PIPE-SERVER-PROCESS-MISMATCH'
    }
}

function Invoke-NgcrPipeRequest {
    param(
        [string]$Command,
        [string]$Body,
        [string]$ExpectedServiceHostPath,
        [string]$ExpectedServiceName
    )
    $envelope = [pscustomobject][ordered]@{version=1;command=$Command;body=$Body}
    $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $envelope))
    if ($bytes.Length -gt $maximumFrameBytes) { Stop-Ngcr 'NGCOR-ROLLOUT-ENVELOPE-SIZE-INVALID' }
    $pipe = New-Object IO.Pipes.NamedPipeClientStream(
        '.', $pipeName, [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous,
        [Security.Principal.TokenImpersonationLevel]::Identification
    )
    try {
        $pipe.Connect(3000)
        Assert-NgcrPipeServerIdentity $pipe $ExpectedServiceHostPath $ExpectedServiceName
        $length = [BitConverter]::GetBytes([int]$bytes.Length)
        $pipe.Write($length,0,4); $pipe.Write($bytes,0,$bytes.Length); $pipe.Flush()
        $responseLength = [BitConverter]::ToInt32((Read-NgcrExact $pipe 4 `
            $pipeResponseTimeoutMilliseconds),0)
        if ($responseLength -le 0 -or $responseLength -gt $maximumFrameBytes) {
            Stop-Ngcr 'NGCOR-ROLLOUT-PIPE-RESPONSE-SIZE-INVALID'
        }
        $responseBytes = Read-NgcrExact $pipe $responseLength $pipeResponseTimeoutMilliseconds
        try {
            $response = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
                -Bytes $responseBytes -MaximumBytes $maximumFrameBytes).Value
        }
        catch { Stop-Ngcr 'NGCOR-ROLLOUT-PIPE-RESPONSE-INVALID' }
        $properties = @($response.PSObject.Properties.Name | Sort-Object)
        if ($response.status -ceq 'rejected') {
            if (($properties -join '|') -cne 'error|status' -or
                $response.error -cnotmatch '^NGCOR-[A-Z0-9-]{1,96}$') {
                Stop-Ngcr 'NGCOR-ROLLOUT-PIPE-RESPONSE-INVALID'
            }
            Stop-Ngcr ([string]$response.error)
        }
        if ($response.status -cne 'ok' -or ($properties -join '|') -cne 'result|status') {
            Stop-Ngcr 'NGCOR-ROLLOUT-PIPE-RESPONSE-INVALID'
        }
        $response.result
    }
    finally { $pipe.Dispose() }
}

function Get-NgcrApprovalCertificate {
    param([string]$ExpectedSha256)
    $matches = @()
    foreach ($storePath in @('Cert:\CurrentUser\My','Cert:\LocalMachine\My')) {
        foreach ($candidate in @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue)) {
            if ((Get-NgcrSha256Hex $candidate.RawData) -ceq $ExpectedSha256) {
                $matches += [pscustomobject]@{ StorePath = $storePath; Certificate = $candidate }
            }
        }
    }
    $usable = @($matches | Where-Object { $_.Certificate.HasPrivateKey })
    $unique = @($usable | Group-Object { $_.Certificate.Thumbprint.ToUpperInvariant() })
    if ($unique.Count -ne 1) { Stop-Ngcr 'NGCOR-ROLLOUT-CERTIFICATE-NOT-FOUND' }
    $certificate = $usable[0].Certificate
    $now = [DateTimeOffset]::UtcNow
    if (-not $certificate.HasPrivateKey -or $now -lt $certificate.NotBefore.ToUniversalTime() -or
        $now -gt $certificate.NotAfter.ToUniversalTime()) {
        Stop-Ngcr 'NGCOR-ROLLOUT-CERTIFICATE-INVALID'
    }
    $leaf=$false; $eku=$false; $digital=$false
    foreach ($extension in $certificate.Extensions) {
        if ($extension -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $leaf = -not $extension.CertificateAuthority
        }
        elseif ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($usage in $extension.EnhancedKeyUsages) {
                if ($usage.Value -ceq '1.3.6.1.5.5.7.3.3') { $eku=$true }
            }
        }
        elseif ($extension -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $digital=[bool]($extension.KeyUsages -band
                [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)
            if ($extension.KeyUsages -band (
                    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
                    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign)) {
                Stop-Ngcr 'NGCOR-ROLLOUT-CERTIFICATE-INVALID'
            }
        }
    }
    if (-not $leaf -or -not $eku -or -not $digital) { Stop-Ngcr 'NGCOR-ROLLOUT-CERTIFICATE-INVALID' }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    if ($null -eq $rsa -or $rsa.KeySize -lt 3072) { Stop-Ngcr 'NGCOR-ROLLOUT-PRIVATE-KEY-INVALID' }
    if ($rsa -is [Security.Cryptography.RSACng]) {
        $forbidden = [Security.Cryptography.CngExportPolicies]::AllowExport -bor
            [Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
        if (($rsa.Key.ExportPolicy -band $forbidden) -ne 0) {
            Stop-Ngcr 'NGCOR-ROLLOUT-PRIVATE-KEY-EXPORTABLE'
        }
    }
    elseif ($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) {
        if ($rsa.CspKeyContainerInfo.Exportable) { Stop-Ngcr 'NGCOR-ROLLOUT-PRIVATE-KEY-EXPORTABLE' }
    }
    else { Stop-Ngcr 'NGCOR-ROLLOUT-PRIVATE-KEY-PROVIDER-INVALID' }
    [pscustomobject]@{Certificate=$certificate;Rsa=$rsa}
}

if (-not $ConfirmPromotion) { Stop-Ngcr 'NGCOR-ROLLOUT-CONFIRMATION-REQUIRED' }
if (-not (Test-NgcrEvidenceHash $AcceptanceEvidenceSha256) -or
    -not (Test-NgcrEvidenceHash $RetirementEvidenceSha256) -or
    -not (Test-NgcrEvidenceHash $ApprovalCertificateSha256)) {
    Stop-Ngcr 'NGCOR-ROLLOUT-EVIDENCE-HASH-INVALID'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $identity.User.Value -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {
    Stop-Ngcr 'NGCOR-ROLLOUT-ADMIN-IDENTITY-REQUIRED'
}
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$requiredPrefix = Join-Path $programFiles 'NorthGate\VMFactory\CreateOnly\releases'
$installedRoot = [IO.Path]::GetFullPath($PSScriptRoot)
if (-not $installedRoot.StartsWith($requiredPrefix + '\',[StringComparison]::OrdinalIgnoreCase) -or
    -not (Test-Path -LiteralPath (Join-Path $installedRoot 'installed-release.json') -PathType Leaf)) {
    Stop-Ngcr 'NGCOR-ROLLOUT-CHECKOUT-EXECUTION-FORBIDDEN'
}
$protocol = Import-Module (Join-Path $installedRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') `
    -Force -PassThru
$deployment = Import-Module (Join-Path $installedRoot 'NorthGate.VMFactory.CreateOnlyDeployment.psd1') `
    -Force -PassThru
try {
    $installedBytes = [IO.File]::ReadAllBytes((Join-Path $installedRoot 'installed-release.json'))
    $manifestBytes = [IO.File]::ReadAllBytes((Join-Path $installedRoot 'release-manifest.json'))
    $authorizationBytes = [IO.File]::ReadAllBytes((Join-Path $installedRoot 'deployment-authorization.json'))
    $installed = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
        -Bytes $installedBytes -MaximumBytes 1048576).Value
    $manifest = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
        -Bytes $manifestBytes -MaximumBytes 1048576).Value
    $authorization = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
        -Bytes $authorizationBytes -MaximumBytes 1048576).Value
}
catch { Stop-Ngcr 'NGCOR-ROLLOUT-INSTALLED-EVIDENCE-INVALID' }
if ($installed.schema -cne 'northgate/create-only-installed-release/v1' -or
    $installed.serviceName -cne 'NorthGateCreateOnly' -or
    (Get-NgcrSha256Hex $manifestBytes) -cne $installed.releaseManifestSha256 -or
    (Get-NgcrSha256Hex $authorizationBytes) -cne $installed.deploymentAuthorizationSha256 -or
    $manifest.releaseId -cne $installed.releaseId -or
    $authorization.repository.releaseId -cne $installed.releaseId -or
    $authorization.identity.approvalSignerCertificateSha256 -cne $ApprovalCertificateSha256) {
    Stop-Ngcr 'NGCOR-ROLLOUT-INSTALLED-EVIDENCE-BINDING-MISMATCH'
}
try {
    $runtimeContext = & $deployment {
        param($Authorization) Get-NgcdExistingProductionContext $Authorization
    } $authorization
    $verified = Test-NorthGateCreateOnlyInstalledRelease -Context $runtimeContext `
        -Manifest $manifest -Authorization $authorization `
        -AuthorizationSha256 ([string]$installed.deploymentAuthorizationSha256)
}
catch { Stop-Ngcr 'NGCOR-ROLLOUT-INSTALLED-RELEASE-NOT-VERIFIED' }
if ($verified.status -cne 'verified' -or
    [IO.Path]::GetFullPath([string]$verified.releaseRoot) -cne $installedRoot) {
    Stop-Ngcr 'NGCOR-ROLLOUT-INSTALLED-RELEASE-NOT-VERIFIED'
}
$expectedServiceHostPath = Join-Path $installedRoot ([string]$installed.serviceHostFileName)
$context = Invoke-NgcrPipeRequest 'rollout-context' '' $expectedServiceHostPath `
    ([string]$installed.serviceName)
Assert-NgcrExactProperties $context @(
    'schema','nextSequence','previousAuthorizationSha256','basePolicySha256',
    'authorizationSha256','releaseManifestSha256','dataBundleSha256','repository',
    'fromStage','permittedToStage','currentRollout','requiredCanaryAssetId',
    'requiredCanaryReceiptSha256'
) 'NGCOR-ROLLOUT-CONTEXT-CONTRACT-INVALID'
Assert-NgcrExactProperties $context.repository @('identity','commit','tree') `
    'NGCOR-ROLLOUT-CONTEXT-CONTRACT-INVALID'
Assert-NgcrExactProperties $context.currentRollout @(
    'stage','exactAssetOrder','maximumConcurrentTransactions','debianCanary','windowsCanary'
) 'NGCOR-ROLLOUT-CONTEXT-CONTRACT-INVALID'
foreach ($gate in @($context.currentRollout.debianCanary,$context.currentRollout.windowsCanary)) {
    Assert-NgcrExactProperties $gate @(
        'assetId','status','receiptSha256','acceptanceEvidenceSha256','retirementEvidenceSha256'
    ) 'NGCOR-ROLLOUT-CONTEXT-CONTRACT-INVALID'
}
$sequence = [int]$context.nextSequence
$expectedFromStage = if ($sequence -eq 1) { 'debian-canary' } else { 'windows-canary' }
$expectedToStage = if ($sequence -eq 1) { 'windows-canary' } else { 'persistent-fleet' }
$expectedCanaryAssetId = if ($sequence -eq 1) { 'NG-VM-018' } else { 'NG-VM-010' }
if ($context.schema -cne 'northgate/create-only-rollout-promotion-context/v1' -or
    $sequence -notin @(1,2) -or $context.fromStage -cne $expectedFromStage -or
    $context.permittedToStage -cne $expectedToStage -or $ToStage -cne $expectedToStage -or
    $context.requiredCanaryAssetId -cne $expectedCanaryAssetId -or
    $context.requiredCanaryReceiptSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    $context.previousAuthorizationSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    $context.basePolicySha256 -cnotmatch '^[a-f0-9]{64}$' -or
    $context.authorizationSha256 -cne $installed.deploymentAuthorizationSha256 -or
    $context.releaseManifestSha256 -cne $installed.releaseManifestSha256 -or
    $context.dataBundleSha256 -cne $installed.dataBundleSha256 -or
    $context.repository.identity -cne 'Beowxlf/northgate-vm-factory' -or
    $context.repository.commit -cne $installed.repositoryCommit -or
    $context.repository.tree -cne $installed.repositoryTree -or
    $context.currentRollout.stage -cne $expectedFromStage -or
    [int]$context.currentRollout.maximumConcurrentTransactions -ne 1 -or
    (@($context.currentRollout.exactAssetOrder) -join '|') -cne ($exactFleetAssetIds -join '|')) {
    Stop-Ngcr 'NGCOR-ROLLOUT-CONTEXT-BINDING-INVALID'
}
if (($sequence -eq 1 -and
        ($context.currentRollout.debianCanary.status -cne 'pending' -or
         $context.currentRollout.windowsCanary.status -cne 'pending')) -or
    ($sequence -eq 2 -and
        ($context.currentRollout.debianCanary.status -cne 'accepted-retired' -or
         $context.currentRollout.windowsCanary.status -cne 'pending'))) {
    Stop-Ngcr 'NGCOR-ROLLOUT-CONTEXT-STAGE-INVALID'
}

$debianCanary = if ($sequence -eq 1) {
    [pscustomobject][ordered]@{
        assetId='NG-VM-018';status='accepted-retired'
        receiptSha256=[string]$context.requiredCanaryReceiptSha256
        acceptanceEvidenceSha256=$AcceptanceEvidenceSha256
        retirementEvidenceSha256=$RetirementEvidenceSha256
    }
} else {
    [pscustomobject][ordered]@{
        assetId=[string]$context.currentRollout.debianCanary.assetId
        status=[string]$context.currentRollout.debianCanary.status
        receiptSha256=[string]$context.currentRollout.debianCanary.receiptSha256
        acceptanceEvidenceSha256=[string]$context.currentRollout.debianCanary.acceptanceEvidenceSha256
        retirementEvidenceSha256=[string]$context.currentRollout.debianCanary.retirementEvidenceSha256
    }
}
$windowsCanary = if ($sequence -eq 2) {
    [pscustomobject][ordered]@{
        assetId='NG-VM-010';status='accepted-retired'
        receiptSha256=[string]$context.requiredCanaryReceiptSha256
        acceptanceEvidenceSha256=$AcceptanceEvidenceSha256
        retirementEvidenceSha256=$RetirementEvidenceSha256
    }
} else {
    [pscustomobject][ordered]@{
        assetId='NG-VM-010';status='pending';receiptSha256=''
        acceptanceEvidenceSha256='';retirementEvidenceSha256=''
    }
}
$rollout = [pscustomobject][ordered]@{
    stage=$ToStage
    exactAssetOrder=[object[]]$exactFleetAssetIds
    maximumConcurrentTransactions=1
    debianCanary=$debianCanary
    windowsCanary=$windowsCanary
}
$issued = [DateTimeOffset]::UtcNow
$expires = $issued.AddSeconds($LifetimeSeconds)
$promotion = [pscustomobject][ordered]@{
    schema='northgate/create-only-rollout-promotion/v1'
    promotionId=('ngrollout-' + (New-NgcrRandomHex))
    sequence=$sequence
    previousAuthorizationSha256=[string]$context.previousAuthorizationSha256
    basePolicySha256=[string]$context.basePolicySha256
    authorizationSha256=[string]$context.authorizationSha256
    releaseManifestSha256=[string]$context.releaseManifestSha256
    dataBundleSha256=[string]$context.dataBundleSha256
    repository=[pscustomobject][ordered]@{
        identity=[string]$context.repository.identity
        commit=[string]$context.repository.commit
        tree=[string]$context.repository.tree
    }
    fromStage=$expectedFromStage
    toStage=$ToStage
    rollout=$rollout
    issuedAtUtc=$issued.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    expiresAtUtc=$expires.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    approverSid=[string]$identity.User.Value
    nonce=(New-NgcrRandomHex)
}
$promotionJson = ConvertTo-NorthGateCreateOnlyCanonicalJson $promotion
$promotionBytes = [Text.Encoding]::UTF8.GetBytes($promotionJson)
$keyMaterial = Get-NgcrApprovalCertificate $ApprovalCertificateSha256
try {
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    $content = New-Object Security.Cryptography.Pkcs.ContentInfo(,$promotionBytes)
    $cms = New-Object Security.Cryptography.Pkcs.SignedCms($content,$true)
    $signer = New-Object Security.Cryptography.Pkcs.CmsSigner($keyMaterial.Certificate)
    $signer.DigestAlgorithm = New-Object Security.Cryptography.Oid(
        '2.16.840.1.101.3.4.2.1','SHA256'
    )
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cms.ComputeSignature($signer,$true)
    $wrapper = [pscustomobject][ordered]@{
        promotionCanonicalJson=$promotionJson
        detachedCmsSignatureBase64=[Convert]::ToBase64String($cms.Encode())
    }
    Invoke-NgcrPipeRequest 'promote-rollout' `
        (ConvertTo-NorthGateCreateOnlyCanonicalJson $wrapper) $expectedServiceHostPath `
        ([string]$installed.serviceName)
}
finally { $keyMaterial.Rsa.Dispose() }

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCZy9s+PZw/xCig
# 9tOESK9urt8AmHV+U5qWs/EvV5v3qaCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEILnaZrqjTBFTNSDZRDt3nRD0V8UvTLjJqvWhJx4lMPfIMA0GCSqG
# SIb3DQEBAQUABIIBgCu0Vh2N+zauePVtNbj4w4TUSaPDyWYTk8zx83MSV0ZSJOsC
# ArMLH5jLy5+KjnEJfWStLYBj3xnmk4T2aXTpuYKYmxNl1YwQQWcmAmfHtx2mL7kJ
# e0mNKIje31f3gCTBY4tpjQSxGTM9ypQPGzhxqrJGv6NAuCv6Yq1eQ7qL4eTs6gIv
# 7HbHYN6MhtP0BvGCeMyLWo4LVcRSRhSfIf5hCJ4jjIbYeHdaenYOJEdQpgqFGafj
# QNcTS0OW9asPYVyo0i9uyk65kmw2uRvijwf3EPNeMiBsVgEo7WZZGshiSk5JpIVj
# 0ZFN94dAXbjNew+99cnyUVZSK+olodfhZNjRyKvMzDgEFhModjWqp5/i0mIcA2AU
# qp96ICElvlnSsoN5IurPoFZBbZzh1XhCFJvBFWzGxBIMq6r4GY6OSylry2B10FwF
# ZfZVC1frY4h6QLhK/Bx8W9ViATcRrWGY0C6+6qO6Nhv8joIUrL93YrhEMYwN+pRT
# DWWZtp5dQpUGr3e6Ag==
# SIG # End signature block
