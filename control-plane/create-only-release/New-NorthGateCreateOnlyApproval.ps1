[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^ngp-[a-f0-9]{64}$')][string]$PlanId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ApprovalCertificateSha256,
    [Parameter(Mandatory)][ValidateRange(30, 300)][int]$LifetimeSeconds,
    [Parameter(Mandatory)][switch]$ConfirmApproval
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$pipeName = 'NorthGate.VMFactory.CreateOnly.v1'
$maximumFrameBytes = 65536

function Stop-Ngca {
    param([string]$Code)
    throw [InvalidOperationException]::new($Code)
}

function Get-NgcaSha256Hex {
    param([byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function New-NgcaRandomHex {
    $bytes = New-Object byte[] 32
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Read-NgcaExact {
    param([IO.Stream]$Stream,[int]$Count,[int]$TimeoutMilliseconds)
    $bytes = New-Object byte[] $Count
    $offset = 0
    $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ($offset -lt $Count) {
        $remaining = [int][Math]::Max(1,($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
        $task = $Stream.ReadAsync($bytes,$offset,$Count-$offset)
        if (-not $task.Wait($remaining)) { Stop-Ngca 'NGCOR-APPROVAL-PIPE-READ-TIMEOUT' }
        if ($task.Result -le 0) { Stop-Ngca 'NGCOR-APPROVAL-PIPE-CLOSED' }
        $offset += $task.Result
    }
    $bytes
}

function Invoke-NgcaPipeRequest {
    param([string]$Command,[string]$Body)
    $envelope = [pscustomobject][ordered]@{version=1;command=$Command;body=$Body}
    $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $envelope))
    if ($bytes.Length -gt $maximumFrameBytes) { Stop-Ngca 'NGCOR-APPROVAL-ENVELOPE-SIZE-INVALID' }
    $pipe = New-Object IO.Pipes.NamedPipeClientStream(
        '.', $pipeName, [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous,
        [Security.Principal.TokenImpersonationLevel]::Identification
    )
    try {
        $pipe.Connect(3000)
        $length = [BitConverter]::GetBytes([int]$bytes.Length)
        $pipe.Write($length,0,4); $pipe.Write($bytes,0,$bytes.Length); $pipe.Flush()
        $responseLength = [BitConverter]::ToInt32((Read-NgcaExact $pipe 4 10000),0)
        if ($responseLength -le 0 -or $responseLength -gt $maximumFrameBytes) {
            Stop-Ngca 'NGCOR-APPROVAL-PIPE-RESPONSE-SIZE-INVALID'
        }
        $responseBytes = Read-NgcaExact $pipe $responseLength 10000
        try {
            $response = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
                -Bytes $responseBytes -MaximumBytes $maximumFrameBytes).Value
        }
        catch { Stop-Ngca 'NGCOR-APPROVAL-PIPE-RESPONSE-INVALID' }
        $properties = @($response.PSObject.Properties.Name | Sort-Object)
        if ($response.status -ceq 'rejected') {
            if (($properties -join '|') -cne 'error|status' -or
                $response.error -cnotmatch '^NGCOR-[A-Z0-9-]{1,96}$') {
                Stop-Ngca 'NGCOR-APPROVAL-PIPE-RESPONSE-INVALID'
            }
            Stop-Ngca ([string]$response.error)
        }
        if ($response.status -cne 'ok' -or ($properties -join '|') -cne 'result|status') {
            Stop-Ngca 'NGCOR-APPROVAL-PIPE-RESPONSE-INVALID'
        }
        $response.result
    }
    finally { $pipe.Dispose() }
}

function Get-NgcaApprovalCertificate {
    param([string]$ExpectedSha256)
    $matches = @(Get-ChildItem -LiteralPath Cert:\CurrentUser\My | Where-Object {
        (Get-NgcaSha256Hex $_.RawData) -ceq $ExpectedSha256
    })
    if ($matches.Count -ne 1) { Stop-Ngca 'NGCOR-APPROVAL-CERTIFICATE-NOT-FOUND' }
    $certificate = $matches[0]
    $now = [DateTimeOffset]::UtcNow
    if (-not $certificate.HasPrivateKey -or $now -lt $certificate.NotBefore.ToUniversalTime() -or
        $now -gt $certificate.NotAfter.ToUniversalTime()) {
        Stop-Ngca 'NGCOR-APPROVAL-CERTIFICATE-INVALID'
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
                Stop-Ngca 'NGCOR-APPROVAL-CERTIFICATE-INVALID'
            }
        }
    }
    if (-not $leaf -or -not $eku -or -not $digital) { Stop-Ngca 'NGCOR-APPROVAL-CERTIFICATE-INVALID' }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    if ($null -eq $rsa -or $rsa.KeySize -lt 3072) { Stop-Ngca 'NGCOR-APPROVAL-PRIVATE-KEY-INVALID' }
    if ($rsa -is [Security.Cryptography.RSACng]) {
        $forbidden = [Security.Cryptography.CngExportPolicies]::AllowExport -bor
            [Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
        if (($rsa.Key.ExportPolicy -band $forbidden) -ne 0) {
            Stop-Ngca 'NGCOR-APPROVAL-PRIVATE-KEY-EXPORTABLE'
        }
    }
    elseif ($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) {
        if ($rsa.CspKeyContainerInfo.Exportable) { Stop-Ngca 'NGCOR-APPROVAL-PRIVATE-KEY-EXPORTABLE' }
    }
    else { Stop-Ngca 'NGCOR-APPROVAL-PRIVATE-KEY-PROVIDER-INVALID' }
    [pscustomobject]@{Certificate=$certificate;Rsa=$rsa}
}

if (-not $ConfirmApproval) { Stop-Ngca 'NGCOR-APPROVAL-CONFIRMATION-REQUIRED' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $identity.User.Value -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {
    Stop-Ngca 'NGCOR-APPROVAL-ADMIN-IDENTITY-REQUIRED'
}
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$requiredPrefix = Join-Path $programFiles 'NorthGate\VMFactory\CreateOnly\releases'
$installedRoot = [IO.Path]::GetFullPath($PSScriptRoot)
if (-not $installedRoot.StartsWith($requiredPrefix + '\',[StringComparison]::OrdinalIgnoreCase) -or
    -not (Test-Path -LiteralPath (Join-Path $installedRoot 'installed-release.json') -PathType Leaf)) {
    Stop-Ngca 'NGCOR-APPROVAL-CHECKOUT-EXECUTION-FORBIDDEN'
}
Import-Module (Join-Path $installedRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -Force
$authorizationBytes = [IO.File]::ReadAllBytes((Join-Path $installedRoot 'deployment-authorization.json'))
$authorization = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
    -Bytes $authorizationBytes -MaximumBytes 1048576).Value
if ($authorization.identity.approvalSignerCertificateSha256 -cne $ApprovalCertificateSha256) {
    Stop-Ngca 'NGCOR-APPROVAL-SIGNER-PIN-MISMATCH'
}

$planEvidence = Invoke-NgcaPipeRequest ('approval-context ' + $PlanId) ''
if ($planEvidence.planId -cne $PlanId -or $planEvidence.planHash -cnotmatch '^[a-f0-9]{64}$' -or
    $planEvidence.planAuthenticationHash -cnotmatch '^[a-f0-9]{64}$' -or
    $planEvidence.canonicalPlan -isnot [string]) {
    Stop-Ngca 'NGCOR-APPROVAL-PLAN-EVIDENCE-INVALID'
}
$planBytes = [Text.Encoding]::UTF8.GetBytes([string]$planEvidence.canonicalPlan)
$plan = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $planBytes -MaximumBytes 1048576).Value
if ($plan.planId -cne $PlanId) { Stop-Ngca 'NGCOR-APPROVAL-PLAN-EVIDENCE-INVALID' }
$issued = [DateTimeOffset]::UtcNow
$planExpiry = [DateTimeOffset]::ParseExact([string]$plan.expiresAtUtc,"yyyy-MM-dd'T'HH:mm:ss'Z'",
    [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)
$expires = $issued.AddSeconds($LifetimeSeconds)
if ($expires -gt $planExpiry) { $expires = $planExpiry }
if ($expires -le $issued.AddSeconds(1)) { Stop-Ngca 'NGCOR-APPROVAL-PLAN-EXPIRED' }
$approval = [pscustomobject][ordered]@{
    schema='northgate/create-only-plan-approval/v1';approvalId=('nga-' + (New-NgcaRandomHex));decision='approve'
    planId=$PlanId;planHash=[string]$planEvidence.planHash
    planAuthenticationHash=[string]$planEvidence.planAuthenticationHash
    changeId=[string]$plan.operation.changeId
    repository=[pscustomobject][ordered]@{identity=[string]$plan.repository.identity;commit=[string]$plan.repository.commit;tree=[string]$plan.repository.tree}
    releaseManifestSha256=[string]$plan.release.releaseManifestSha256
    authorizationSha256=[string]$plan.authorization.authorizationSha256
    policySha256=[string]$plan.policy.policySha256
    dataBundleSha256=[string]$plan.data.dataBundleSha256
    issuedAtUtc=$issued.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    expiresAtUtc=$expires.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    approverSid=[string]$identity.User.Value;nonce=(New-NgcaRandomHex);useLimit=1
}
$approvalJson = ConvertTo-NorthGateCreateOnlyCanonicalJson $approval
$approvalBytes = [Text.Encoding]::UTF8.GetBytes($approvalJson)
$keyMaterial = Get-NgcaApprovalCertificate $ApprovalCertificateSha256
try {
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    $content = New-Object Security.Cryptography.Pkcs.ContentInfo(,$approvalBytes)
    $cms = New-Object Security.Cryptography.Pkcs.SignedCms($content,$true)
    $signer = New-Object Security.Cryptography.Pkcs.CmsSigner($keyMaterial.Certificate)
    $signer.DigestAlgorithm = New-Object Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1','SHA256')
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cms.ComputeSignature($signer,$true)
    $wrapper = [pscustomobject][ordered]@{
        approvalCanonicalJson=$approvalJson
        detachedCmsSignatureBase64=[Convert]::ToBase64String($cms.Encode())
    }
    Invoke-NgcaPipeRequest ('approve ' + $PlanId) (ConvertTo-NorthGateCreateOnlyCanonicalJson $wrapper)
}
finally { $keyMaterial.Rsa.Dispose() }
