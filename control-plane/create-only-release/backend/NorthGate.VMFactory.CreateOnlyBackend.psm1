Set-StrictMode -Version Latest

$protocolManifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'NorthGate.VMFactory.CreateOnlyProtocol.psd1'
Import-Module $protocolManifest -ErrorAction Stop

$script:BackendVersion = '1.0.0'
$script:RepositoryIdentity = 'Beowxlf/northgate-vm-factory'
$script:GlobalMutexName = 'Global\NorthGateVmFactoryCreateOnlyBackend-v1'
$script:MaximumArtifactBytes = 1048576
$script:MaximumPlanTtlSeconds = 900
$script:MaximumApprovalTtlSeconds = 600
$script:MaximumAuthorizationLifetimeHours = 24
$script:MaximumClockSkewSeconds = 300
$script:ExactFleetAssetIds = @(
    'NG-VM-018','NG-VM-010','NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012',
    'NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015'
)
$script:WindowsFleetAssetIds = @('NG-VM-010','NG-VM-011','NG-VM-012','NG-VM-019','NG-VM-020','NG-VM-021')
$script:ProcessContextKey = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($script:ProcessContextKey)

function Throw-NgcbError {
    param([Parameter(Mandatory)][string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function ConvertFrom-NgcbJsonText {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)
    $converter = Microsoft.PowerShell.Core\Get-Command `
        -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json -DateKind String
    }
    return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json
}

function Get-NgcbSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NgcbStringSha256Hex {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    Get-NgcbSha256Hex ([System.Text.Encoding]::UTF8.GetBytes($Value))
}

function Get-NgcbHmacHex {
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )
    $algorithm = New-Object System.Security.Cryptography.HMACSHA256 (,$Key)
    try { $hash = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value)) }
    finally { $algorithm.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-NgcbFixedHexEquals {
    param([Parameter(Mandatory)][string]$Left, [Parameter(Mandatory)][string]$Right)
    if ($Left.Length -ne $Right.Length -or $Left -notmatch '^[a-f0-9]+$' -or
        $Right -notmatch '^[a-f0-9]+$') { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ([int][char]$Left[$index] -bxor [int][char]$Right[$index])
    }
    return ($difference -eq 0)
}

function New-NgcbRandomHex {
    param([ValidateRange(8, 64)][int]$ByteCount = 32)
    $bytes = New-Object byte[] $ByteCount
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Format-NgcbUtc {
    param([Parameter(Mandatory)][DateTimeOffset]$Value)
    $Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-NgcbUtc {
    param([Parameter(Mandatory)][string]$Value, [string]$Code = 'NGCB-TIMESTAMP-INVALID')
    try {
        return [DateTimeOffset]::ParseExact(
            $Value,
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal
        ).ToUniversalTime()
    }
    catch { Throw-NgcbError $Code }
}

function Assert-NgcbAuthorizationTimeCurrent {
    param(
        [Parameter(Mandatory)][object]$Authorization,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow
    )
    $issued = ConvertTo-NgcbUtc $Authorization.issuedAtUtc 'NGCB-AUTHORIZATION-TIME-INVALID'
    $expires = ConvertTo-NgcbUtc $Authorization.expiresAtUtc 'NGCB-AUTHORIZATION-TIME-INVALID'
    if ($expires -le $issued) { Throw-NgcbError 'NGCB-AUTHORIZATION-TIME-INVALID' }
    if (($expires - $issued).TotalHours -gt $script:MaximumAuthorizationLifetimeHours) {
        Throw-NgcbError 'NGCB-AUTHORIZATION-LIFETIME-INVALID'
    }
    if ($issued -gt $Now.AddSeconds($script:MaximumClockSkewSeconds)) {
        Throw-NgcbError 'NGCB-AUTHORIZATION-CLOCK-INVALID'
    }
    if ($expires -le $Now) { Throw-NgcbError 'NGCB-AUTHORIZATION-EXPIRED' }
    return [pscustomobject][ordered]@{ issued = $issued; expires = $expires }
}

function Assert-NgcbContextTimesCurrent {
    param(
        [Parameter(Mandatory)][object]$Context,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow
    )
    $authorizationTime = Assert-NgcbAuthorizationTimeCurrent $Context.Authorization $Now
    $policyIssued = ConvertTo-NgcbUtc $Context.Policy.issuedAtUtc 'NGCB-POLICY-TIME-INVALID'
    $policyExpires = ConvertTo-NgcbUtc $Context.Policy.expiresAtUtc 'NGCB-POLICY-TIME-INVALID'
    if ($policyIssued -gt $Now.AddSeconds($script:MaximumClockSkewSeconds)) {
        Throw-NgcbError 'NGCB-POLICY-CLOCK-INVALID'
    }
    if ($policyExpires -le $Now) { Throw-NgcbError 'NGCB-POLICY-EXPIRED' }
    $bundleIssued = ConvertTo-NgcbUtc $Context.DataBundle.createdAtUtc 'NGCB-DATA-BUNDLE-TIME-INVALID'
    $bundleExpires = ConvertTo-NgcbUtc $Context.DataBundle.expiresAtUtc 'NGCB-DATA-BUNDLE-TIME-INVALID'
    if ($bundleIssued -gt $Now.AddSeconds($script:MaximumClockSkewSeconds)) {
        Throw-NgcbError 'NGCB-DATA-BUNDLE-CLOCK-INVALID'
    }
    if ($bundleExpires -le $Now) { Throw-NgcbError 'NGCB-DATA-BUNDLE-EXPIRED' }
    return [pscustomobject][ordered]@{
        authorizationExpires = $authorizationTime.expires
        policyExpires = $policyExpires
        dataBundleExpires = $bundleExpires
    }
}

function Get-NgcbPlanExpiration {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][DateTimeOffset]$IssuedAt
    )
    $times = Assert-NgcbContextTimesCurrent $Context $IssuedAt
    $expiration = $IssuedAt.AddSeconds([int]$Context.Policy.planTtlSeconds)
    foreach ($anchor in @($times.authorizationExpires,$times.policyExpires,$times.dataBundleExpires)) {
        if ($anchor -lt $expiration) { $expiration = $anchor }
    }
    if ($expiration -le $IssuedAt) { Throw-NgcbError 'NGCB-PLAN-TIME-INVALID' }
    return $expiration
}

function Assert-NgcbExactProperties {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Code
    )
    $actual = @($Object.PSObject.Properties.Name)
    $expectedCopy = @($Expected)
    [array]::Sort($actual, [StringComparer]::Ordinal)
    [array]::Sort($expectedCopy, [StringComparer]::Ordinal)
    if (($actual -join '|') -cne ($expectedCopy -join '|')) { Throw-NgcbError $Code }
}

function Assert-NgcbPattern {
    param([object]$Value, [string]$Pattern, [string]$Code)
    if ($Value -isnot [string] -or [string]$Value -cnotmatch $Pattern) { Throw-NgcbError $Code }
}

function Get-NgcbCanonicalBytes {
    param([Parameter(Mandatory)][object]$Object)
    [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $Object))
}

function Read-NgcbCanonicalFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 10485760)][int]$MaximumBytes = $script:MaximumArtifactBytes,
        [string]$Code = 'NGCB-ARTIFACT-INVALID'
    )
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -and $item.Length -gt 0 -and $item.Length -le $MaximumBytes -and
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
            $bytes = [IO.File]::ReadAllBytes($item.FullName)
            $parsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $bytes -MaximumBytes $MaximumBytes
            return [pscustomobject][ordered]@{
                Path = $item.FullName
                Bytes = $bytes
                Sha256 = Get-NgcbSha256Hex $bytes
                CanonicalJson = $parsed.CanonicalJson
                Value = $parsed.Value
            }
        }
    }
    catch { }
    Throw-NgcbError $Code
}

function Read-NgcbCanonicalLineJsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaximumBytes = $script:MaximumArtifactBytes,
        [string]$Code = 'NGCB-JSON-LINE-ARTIFACT-INVALID'
    )
    try {
        $full = Assert-NgcbNoReparseAncestor $Path $Code
        $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -lt 3 -or $item.Length -gt $MaximumBytes -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Throw-NgcbError $Code }
        $bytes = [IO.File]::ReadAllBytes($item.FullName)
        $utf8 = New-Object Text.UTF8Encoding($false,$true)
        $text = $utf8.GetString($bytes)
        if (-not $text.EndsWith("`n") -or $text.EndsWith("`r`n") -or $text.TrimEnd("`n").Contains("`n")) {
            Throw-NgcbError $Code
        }
        $json = $text.Substring(0,$text.Length-1)
        $value = ConvertFrom-NgcbJsonText $json
        if ((ConvertTo-NorthGateCreateOnlyCanonicalJson $value) -cne $json) { Throw-NgcbError $Code }
        return [pscustomobject][ordered]@{
            Path=$item.FullName;Bytes=$bytes;Sha256=(Get-NgcbSha256Hex $bytes);Value=$value
        }
    }
    catch {
        if ($_.Exception.Message -ceq $Code) { throw }
        Throw-NgcbError $Code
    }
}

function Get-NgcbCertificateSha256 {
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    Get-NgcbSha256Hex $Certificate.RawData
}

function Initialize-NgcbPkcs {
    try { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security -ErrorAction Stop }
}

function Assert-NgcbSigningCertificateProfile {
    param(
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][string]$Code
    )
    $basicExtension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -ceq '2.5.29.19' })
    $ekuExtension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -ceq '2.5.29.37' })
    $keyUsageExtension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -ceq '2.5.29.15' })
    if ($basicExtension.Count -ne 1 -or $ekuExtension.Count -ne 1 -or $keyUsageExtension.Count -ne 1) {
        Throw-NgcbError $Code
    }
    try {
        $basic = New-Object Security.Cryptography.X509Certificates.X509BasicConstraintsExtension
        $basic.CopyFrom($basicExtension[0])
        $eku = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension
        $eku.CopyFrom($ekuExtension[0])
        $keyUsage = New-Object Security.Cryptography.X509Certificates.X509KeyUsageExtension
        $keyUsage.CopyFrom($keyUsageExtension[0])
    }
    catch { Throw-NgcbError $Code }
    $ekuOids = @($eku.EnhancedKeyUsages | ForEach-Object { [string]$_.Value })
    $forbiddenUsage = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
    if ($basic.CertificateAuthority -or '1.3.6.1.5.5.7.3.3' -notin $ekuOids -or
        ($keyUsage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0 -or
        ($keyUsage.KeyUsages -band $forbiddenUsage) -ne 0) {
        Throw-NgcbError $Code
    }
}

function Assert-NgcbDetachedCmsSignature {
    param(
        [Parameter(Mandatory)][byte[]]$ContentBytes,
        [Parameter(Mandatory)][byte[]]$SignatureBytes,
        [Parameter(Mandatory)][string]$ExpectedCertificateSha256,
        [string]$Code = 'NGCB-SIGNATURE-INVALID'
    )
    Assert-NgcbPattern $ExpectedCertificateSha256 '^[a-f0-9]{64}$' $Code
    try {
        Initialize-NgcbPkcs
        $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,$ContentBytes)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $content, $true
        $cms.Decode($SignatureBytes)
        if (-not [bool]$cms.Detached -or $cms.SignerInfos.Count -ne 1 -or
            $cms.SignerInfos[0].DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1') {
            Throw-NgcbError $Code
        }
        $cms.CheckSignature($true)
        $certificate = $cms.SignerInfos[0].Certificate
        if ($null -eq $certificate -or
            -not (Test-NgcbFixedHexEquals (Get-NgcbCertificateSha256 $certificate) $ExpectedCertificateSha256)) {
            Throw-NgcbError $Code
        }
        Assert-NgcbSigningCertificateProfile $certificate $Code
        $now = [DateTimeOffset]::UtcNow
        if ($now -lt [DateTimeOffset]$certificate.NotBefore.ToUniversalTime() -or
            $now -ge [DateTimeOffset]$certificate.NotAfter.ToUniversalTime()) {
            Throw-NgcbError $Code
        }
        return [pscustomobject][ordered]@{
            certificateSha256 = $ExpectedCertificateSha256
            signatureSha256 = Get-NgcbSha256Hex $SignatureBytes
        }
    }
    catch {
        if ($_.Exception.Message -ceq $Code) { throw }
        Throw-NgcbError $Code
    }
}

function New-NgcbDetachedCmsSignature {
    param(
        [Parameter(Mandatory)][byte[]]$ContentBytes,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    if (-not $Certificate.HasPrivateKey) { Throw-NgcbError 'NGCB-RECEIPT-SIGNER-NOT-USABLE' }
    try {
        Initialize-NgcbPkcs
        $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,$ContentBytes)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $content, $true
        $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner $Certificate
        $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
        $signer.DigestAlgorithm = New-Object Security.Cryptography.Oid '2.16.840.1.101.3.4.2.1'
        $cms.ComputeSignature($signer)
        return $cms.Encode()
    }
    catch { Throw-NgcbError 'NGCB-RECEIPT-SIGNING-FAILED' }
}

function Get-NgcbCertificateWithPrivateKey {
    param([Parameter(Mandatory)][string]$CertificateSha256)
    foreach ($storePath in @('Cert:\LocalMachine\My', 'Cert:\CurrentUser\My')) {
        foreach ($certificate in @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue)) {
            if ($certificate.HasPrivateKey -and
                (Test-NgcbFixedHexEquals (Get-NgcbCertificateSha256 $certificate) $CertificateSha256)) {
                return $certificate
            }
        }
    }
    Throw-NgcbError 'NGCB-RECEIPT-SIGNER-NOT-USABLE'
}

function Assert-NgcbNoReparseAncestor {
    param([Parameter(Mandatory)][string]$Path, [string]$Code = 'NGCB-REPARSE-POINT-FORBIDDEN')
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while (-not [string]::IsNullOrEmpty($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Throw-NgcbError $Code }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrEmpty($parent) -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
    return $full
}

function Assert-NgcbRestrictedAcl {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ServiceSid)
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop }
    catch { Throw-NgcbError 'NGCB-ACL-UNREADABLE' }
    $allowedWriters = @('S-1-5-18','S-1-5-32-544',$ServiceSid)
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Modify -bor
        [Security.AccessControl.FileSystemRights]::FullControl -bor
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::Delete
    foreach ($rule in @($acl.Access)) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.FileSystemRights -band $writeMask) -ne 0) {
            try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
            catch { Throw-NgcbError 'NGCB-ACL-IDENTITY-UNRESOLVED' }
            if ($sid -notin $allowedWriters) { Throw-NgcbError 'NGCB-ACL-UNAUTHORIZED-WRITER' }
        }
    }
    try {
        $ownerAccount = New-Object Security.Principal.NTAccount ([string]$acl.Owner)
        $ownerSid = $ownerAccount.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        try { $ownerSid = (New-Object Security.Principal.SecurityIdentifier($acl.Owner)).Value }
        catch { Throw-NgcbError 'NGCB-ACL-OWNER-UNRESOLVED' }
    }
    if ($ownerSid -notin $allowedWriters) { Throw-NgcbError 'NGCB-ACL-OWNER-INVALID' }
}

function Write-NgcbAtomicBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes,
        [switch]$CreateNew
    )
    $directory = Split-Path -Parent $Path
    $null = [IO.Directory]::CreateDirectory($directory)
    Assert-NgcbNoReparseAncestor $directory | Out-Null
    if ($CreateNew) {
        $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        return
    }
    $temporary = Join-Path $directory ('.ngcb-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $Path + '.previous'
    $stream = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporary, $Path, $backup, $true)
        }
        else { [IO.File]::Move($temporary, $Path) }
    }
    finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function New-NgcbEnvelope {
    param([object]$Context, [string]$RecordType, [object]$Record)
    $recordJson = ConvertTo-NorthGateCreateOnlyCanonicalJson $Record
    [pscustomobject][ordered]@{
        formatVersion = 1
        recordType = $RecordType
        record = $Record
        recordMac = Get-NgcbHmacHex $Context.StateKey ("ngcb-state-v1`n$RecordType`n$recordJson")
    }
}

function Write-NgcbEnvelope {
    param([object]$Context, [string]$RecordType, [object]$Record, [string]$Path, [switch]$CreateNew)
    $envelope = New-NgcbEnvelope $Context $RecordType $Record
    Write-NgcbAtomicBytes $Path (Get-NgcbCanonicalBytes $envelope) -CreateNew:$CreateNew
    return $envelope
}

function Read-NgcbEnvelope {
    param([object]$Context, [string]$RecordType, [string]$Path, [string]$Code = 'NGCB-STATE-CORRUPT')
    $artifact = Read-NgcbCanonicalFile $Path $script:MaximumArtifactBytes $Code
    $envelope = $artifact.Value
    Assert-NgcbExactProperties $envelope @('formatVersion','recordType','record','recordMac') $Code
    if ($envelope.formatVersion -ne 1 -or $envelope.recordType -cne $RecordType -or
        $envelope.recordMac -isnot [string] -or $envelope.recordMac -cnotmatch '^[a-f0-9]{64}$') {
        Throw-NgcbError $Code
    }
    $recordJson = ConvertTo-NorthGateCreateOnlyCanonicalJson $envelope.record
    $expected = Get-NgcbHmacHex $Context.StateKey ("ngcb-state-v1`n$RecordType`n$recordJson")
    if (-not (Test-NgcbFixedHexEquals $expected ([string]$envelope.recordMac))) { Throw-NgcbError $Code }
    return $envelope
}

function Get-NgcbContextMarker {
    param([object]$Context)
    $material = @(
        'ngcb-context-v1', [string]$Context.Mode, [string]$Context.StateRoot,
        [string]$Context.AuthorizationSha256, [string]$Context.ReleaseManifestSha256,
        [string]$Context.PolicySha256, [string]$Context.DataBundleSha256
    ) -join "`n"
    Get-NgcbHmacHex $script:ProcessContextKey $material
}

function Assert-NgcbContext {
    param([Parameter(Mandatory)][object]$Context)
    $required = @(
        'ContextVersion','Mode','StateRoot','Authorization','AuthorizationSha256','ReleaseManifest',
        'ReleaseManifestSha256','Policy','PolicySha256','DataBundle','DataBundleSha256','DataRoot',
        'StateKey','ReceiptCertificate','AnchorPaths','TestState','TestScenario','ContextMarker'
    )
    foreach ($name in $required) {
        if ($null -eq $Context.PSObject.Properties[$name]) { Throw-NgcbError 'NGCB-CONTEXT-INVALID' }
    }
    if ($Context.ContextVersion -cne 'northgate/create-only-backend-context/v1' -or
        $Context.Mode -notin @('Production','InertTest') -or $Context.StateKey -isnot [byte[]] -or
        $Context.StateKey.Length -ne 32 -or $Context.ContextMarker -cnotmatch '^[a-f0-9]{64}$' -or
        -not (Test-NgcbFixedHexEquals ([string]$Context.ContextMarker) (Get-NgcbContextMarker $Context))) {
        Throw-NgcbError 'NGCB-CONTEXT-INVALID'
    }
}

function Read-NgcbSignatureFile {
    param([Parameter(Mandatory)][string]$Path, [string]$Code = 'NGCB-SIGNATURE-INVALID')
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -lt 64 -or $item.Length -gt 262144 -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Throw-NgcbError $Code }
        return [IO.File]::ReadAllBytes($item.FullName)
    }
    catch {
        if ($_.Exception.Message -ceq $Code) { throw }
        Throw-NgcbError $Code
    }
}

function Assert-NgcbReleaseManifest {
    param([object]$Release, [string]$ExpectedSha256)
    Assert-NgcbExactProperties $Release @('schema','releaseId','repository','sourceProof','packageSemantics','files') `
        'NGCB-RELEASE-CONTRACT-INVALID'
    Assert-NgcbExactProperties $Release.repository @(
        'identity','origin','commit','tree','objectFormat','commitSignatureStatus','hostAllowlistId',
        'packageAllowlistSha256','governanceExceptionId'
    ) 'NGCB-RELEASE-CONTRACT-INVALID'
    if ($Release.schema -cne 'northgate/create-only-release-manifest/v2' -or
        $Release.repository.identity -cne $script:RepositoryIdentity -or
        $Release.repository.commit -cnotmatch '^[a-f0-9]{40}$' -or
        $Release.repository.tree -cnotmatch '^[a-f0-9]{40}$' -or
        $ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$') { Throw-NgcbError 'NGCB-RELEASE-CONTRACT-INVALID' }
}

function Assert-NgcbHostAuthorization {
    param([object]$Authorization, [object]$Release, [string]$AuthorizationSha256)
    Assert-NgcbExactProperties $Authorization @(
        'schema','authorizationId','sequence','issuedAtUtc','expiresAtUtc','repository',
        'releaseManifestSha256','host','install','identity','switch','volumes','images','bootstrapMedia',
        'protectedAssets','accessIsolation','initialPolicy'
    ) 'NGCB-AUTHORIZATION-CONTRACT-INVALID'
    if ($Authorization.schema -cne 'northgate/create-only-host-deployment-authorization/v2' -or
        $AuthorizationSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $Authorization.repository.identity -cne $script:RepositoryIdentity -or
        $Authorization.repository.releaseId -cne $Release.releaseId -or
        $Authorization.repository.commit -cne $Release.repository.commit -or
        $Authorization.repository.tree -cne $Release.repository.tree -or
        $Authorization.repository.hostAllowlistId -cne $Release.repository.hostAllowlistId -or
        $Authorization.releaseManifestSha256 -cnotmatch '^[a-f0-9]{64}$') {
        Throw-NgcbError 'NGCB-AUTHORIZATION-RELEASE-BINDING-INVALID'
    }
    $null = Assert-NgcbAuthorizationTimeCurrent $Authorization
    Assert-NgcbPattern $Authorization.identity.serviceIdentitySid '^S-1-[0-9-]+$' 'NGCB-AUTHORIZATION-IDENTITY-INVALID'
    foreach ($pinName in @(
        'releaseSignerCertificateSha256','deploymentAuthorizationSignerCertificateSha256',
        'approvalSignerCertificateSha256','receiptSignerCertificateSha256'
    )) {
        Assert-NgcbPattern $Authorization.identity.$pinName '^[a-f0-9]{64}$' 'NGCB-AUTHORIZATION-IDENTITY-INVALID'
    }
    $signerPins = @(
        $Authorization.identity.releaseSignerCertificateSha256,
        $Authorization.identity.deploymentAuthorizationSignerCertificateSha256,
        $Authorization.identity.approvalSignerCertificateSha256,
        $Authorization.identity.receiptSignerCertificateSha256
    )
    if (@($signerPins | Select-Object -Unique).Count -ne 4) {
        Throw-NgcbError 'NGCB-AUTHORIZATION-SIGNER-SEPARATION-INVALID'
    }
    if ($Authorization.initialPolicy.applyEnabled -ne $false -or
        @($Authorization.initialPolicy.executableActions).Count -ne 0 -or
        $Authorization.initialPolicy.canaryStage -cne 'disabled') {
        Throw-NgcbError 'NGCB-AUTHORIZATION-INSTALL-STATE-INVALID'
    }
    if (@($Authorization.protectedAssets).Count -ne 5 -or @($Authorization.volumes).Count -ne 2 -or
        @($Authorization.images).Count -ne 3 -or @($Authorization.bootstrapMedia).Count -ne 12) {
        Throw-NgcbError 'NGCB-AUTHORIZATION-HOST-BOUNDARY-INVALID'
    }
    $expectedImages = @('debian-12.12-amd64-netinst','kali-2026.2-installer-netinst-amd64','windows-11-25h2-english-x64')
    $observedImages = @($Authorization.images | ForEach-Object { [string]$_.imageId } | Sort-Object)
    if (($observedImages -join '|') -cne (($expectedImages | Sort-Object) -join '|')) {
        Throw-NgcbError 'NGCB-AUTHORIZATION-IMAGE-IDENTITY-INVALID'
    }
    foreach ($image in @($Authorization.images)) {
        Assert-NgcbExactProperties $image @('imageId','path','sha256','sizeBytes') 'NGCB-AUTHORIZATION-IMAGE-INVALID'
        if ($image.sha256 -cnotmatch '^[a-f0-9]{64}$' -or [int64]$image.sizeBytes -lt 1 -or
            [IO.Path]::GetExtension([string]$image.path) -ine '.iso') {
            Throw-NgcbError 'NGCB-AUTHORIZATION-IMAGE-INVALID'
        }
    }
    $observedAssets = @($Authorization.bootstrapMedia | ForEach-Object { [string]$_.assetId } | Sort-Object)
    if (($observedAssets -join '|') -cne (($script:ExactFleetAssetIds | Sort-Object) -join '|')) {
        Throw-NgcbError 'NGCB-AUTHORIZATION-BOOTSTRAP-MEDIA-SCOPE-INVALID'
    }
    $mediaIds = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $mediaPaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $mediaHashes = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $provenancePaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $provenanceHashes = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $bundleManifestHashes = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $payloadHashes = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($media in @($Authorization.bootstrapMedia)) {
        Assert-NgcbExactProperties $media @(
            'assetId','mediaId','mode','path','sha256','sizeBytes','sourceImageId','sourceImageSha256',
            'provenancePath','provenanceSha256','bundleManifestSha256','builderId','builderReleaseSha256',
            'recipeSha256','unattendedPayloadSha256','sourceCommit','sourceTree'
        ) 'NGCB-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID'
        $expectedSourceImageId = if ($media.assetId -in $script:WindowsFleetAssetIds) {
            'windows-11-25h2-english-x64'
        } elseif ($media.assetId -ceq 'NG-VM-015') {
            'kali-2026.2-installer-netinst-amd64'
        } else { 'debian-12.12-amd64-netinst' }
        $sourceImage = @($Authorization.images | Where-Object { $_.imageId -ceq $expectedSourceImageId })
        try {
            $fullMediaPath = [IO.Path]::GetFullPath([string]$media.path)
            $fullProvenancePath = [IO.Path]::GetFullPath([string]$media.provenancePath)
        }
        catch { Throw-NgcbError 'NGCB-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID' }
        if ($media.mediaId -cne ('ngmedia-' + ([string]$media.assetId).ToLowerInvariant()) -or
            $media.mode -cne 'asset-bound-derivative-iso' -or $media.sourceImageId -cne $expectedSourceImageId -or
            $sourceImage.Count -ne 1 -or $media.sourceImageSha256 -cne $sourceImage[0].sha256 -or
            $media.builderId -cne 'northgate-unattended-media-v1' -or
            $media.builderReleaseSha256 -cne $Authorization.releaseManifestSha256 -or
            $media.sourceCommit -cne $Authorization.repository.commit -or $media.sourceTree -cne $Authorization.repository.tree -or
            $media.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $media.provenanceSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $media.bundleManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or $media.recipeSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $media.unattendedPayloadSha256 -cnotmatch '^[a-f0-9]{64}$' -or [int64]$media.sizeBytes -lt 1 -or
            [IO.Path]::GetExtension($fullMediaPath) -ine '.iso' -or [IO.Path]::GetExtension($fullProvenancePath) -ine '.json' -or
            $fullMediaPath -ieq [IO.Path]::GetFullPath([string]$sourceImage[0].path) -or
            -not $mediaIds.Add([string]$media.mediaId) -or -not $mediaPaths.Add($fullMediaPath) -or
            -not $mediaHashes.Add([string]$media.sha256) -or -not $provenancePaths.Add($fullProvenancePath) -or
            -not $provenanceHashes.Add([string]$media.provenanceSha256) -or
            -not $bundleManifestHashes.Add([string]$media.bundleManifestSha256) -or
            -not $payloadHashes.Add([string]$media.unattendedPayloadSha256)) {
            Throw-NgcbError 'NGCB-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID'
        }
    }
    if ($bundleManifestHashes.Count -ne 12) { Throw-NgcbError 'NGCB-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID' }
}

function Assert-NgcbRolloutPolicy {
    param([object]$Rollout)
    Assert-NgcbExactProperties $Rollout @(
        'stage','exactAssetOrder','maximumConcurrentTransactions','debianCanary','windowsCanary'
    ) 'NGCB-POLICY-ROLLOUT-INVALID'
    if ($Rollout.stage -notin @('debian-canary','windows-canary','persistent-fleet') -or
        [int]$Rollout.maximumConcurrentTransactions -ne 1 -or
        (@($Rollout.exactAssetOrder) -join '|') -cne ($script:ExactFleetAssetIds -join '|')) {
        Throw-NgcbError 'NGCB-POLICY-ROLLOUT-INVALID'
    }
    foreach ($record in @($Rollout.debianCanary,$Rollout.windowsCanary)) {
        Assert-NgcbExactProperties $record @(
            'assetId','status','receiptSha256','acceptanceEvidenceSha256','retirementEvidenceSha256'
        ) 'NGCB-POLICY-ROLLOUT-INVALID'
        if ($record.status -notin @('pending','accepted-retired')) { Throw-NgcbError 'NGCB-POLICY-ROLLOUT-INVALID' }
        if ($record.status -ceq 'pending') {
            if ($record.receiptSha256 -cne '' -or $record.acceptanceEvidenceSha256 -cne '' -or
                $record.retirementEvidenceSha256 -cne '') { Throw-NgcbError 'NGCB-POLICY-ROLLOUT-INVALID' }
        }
        elseif ($record.receiptSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $record.acceptanceEvidenceSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $record.retirementEvidenceSha256 -cnotmatch '^[a-f0-9]{64}$') {
            Throw-NgcbError 'NGCB-POLICY-ROLLOUT-INVALID'
        }
    }
    if ($Rollout.debianCanary.assetId -cne 'NG-VM-018' -or $Rollout.windowsCanary.assetId -cne 'NG-VM-010') {
        Throw-NgcbError 'NGCB-POLICY-ROLLOUT-INVALID'
    }
    if (($Rollout.stage -ceq 'debian-canary' -and
            ($Rollout.debianCanary.status -cne 'pending' -or $Rollout.windowsCanary.status -cne 'pending')) -or
        ($Rollout.stage -ceq 'windows-canary' -and
            ($Rollout.debianCanary.status -cne 'accepted-retired' -or $Rollout.windowsCanary.status -cne 'pending')) -or
        ($Rollout.stage -ceq 'persistent-fleet' -and
            ($Rollout.debianCanary.status -cne 'accepted-retired' -or $Rollout.windowsCanary.status -cne 'accepted-retired'))) {
        Throw-NgcbError 'NGCB-POLICY-ROLLOUT-INVALID'
    }
}

function Assert-NgcbRolloutPromotionContract {
    param([object]$Context,[object]$Promotion,[switch]$RequireCurrent)
    Assert-NgcbExactProperties $Promotion @(
        'schema','promotionId','sequence','previousAuthorizationSha256','basePolicySha256',
        'authorizationSha256','releaseManifestSha256','dataBundleSha256','repository',
        'fromStage','toStage','rollout','issuedAtUtc','expiresAtUtc','approverSid','nonce'
    ) 'NGCB-ROLLOUT-PROMOTION-CONTRACT-INVALID'
    Assert-NgcbExactProperties $Promotion.repository @('identity','commit','tree') `
        'NGCB-ROLLOUT-PROMOTION-CONTRACT-INVALID'
    if ($Promotion.schema -cne 'northgate/create-only-rollout-promotion/v1' -or
        $Promotion.promotionId -cnotmatch '^ngrollout-[a-f0-9]{64}$' -or
        $Promotion.sequence -isnot [int] -and $Promotion.sequence -isnot [long] -or
        [int]$Promotion.sequence -notin @(1,2) -or
        $Promotion.previousAuthorizationSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $Promotion.basePolicySha256 -cne $Context.PolicySha256 -or
        $Promotion.authorizationSha256 -cne $Context.AuthorizationSha256 -or
        $Promotion.releaseManifestSha256 -cne $Context.ReleaseManifestSha256 -or
        $Promotion.dataBundleSha256 -cne $Context.DataBundleSha256 -or
        $Promotion.repository.identity -cne $script:RepositoryIdentity -or
        $Promotion.repository.commit -cne $Context.ReleaseManifest.repository.commit -or
        $Promotion.repository.tree -cne $Context.ReleaseManifest.repository.tree -or
        $Promotion.fromStage -notin @('debian-canary','windows-canary') -or
        $Promotion.toStage -notin @('windows-canary','persistent-fleet') -or
        $Promotion.rollout.stage -cne $Promotion.toStage -or
        $Promotion.approverSid -cnotmatch '^S-1-[0-9-]+$' -or
        $Promotion.approverSid -in @(
            'S-1-5-18','S-1-5-19','S-1-5-20',
            [string]$Context.Authorization.identity.sshIdentitySid,
            [string]$Context.Authorization.identity.serviceIdentitySid
        ) -or $Promotion.nonce -cnotmatch '^[a-f0-9]{64}$') {
        Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-CONTRACT-INVALID'
    }
    if (([int]$Promotion.sequence -eq 1 -and
            ($Promotion.fromStage -cne 'debian-canary' -or $Promotion.toStage -cne 'windows-canary')) -or
        ([int]$Promotion.sequence -eq 2 -and
            ($Promotion.fromStage -cne 'windows-canary' -or $Promotion.toStage -cne 'persistent-fleet'))) {
        Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-TRANSITION-INVALID'
    }
    Assert-NgcbRolloutPolicy $Promotion.rollout
    $issued = ConvertTo-NgcbUtc $Promotion.issuedAtUtc 'NGCB-ROLLOUT-PROMOTION-TIME-INVALID'
    $expires = ConvertTo-NgcbUtc $Promotion.expiresAtUtc 'NGCB-ROLLOUT-PROMOTION-TIME-INVALID'
    if ($expires -le $issued -or $expires -gt $issued.AddSeconds($script:MaximumApprovalTtlSeconds)) {
        Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-TIME-INVALID'
    }
    if ($RequireCurrent) {
        $now = [DateTimeOffset]::UtcNow
        if ($issued -gt $now.AddSeconds($script:MaximumClockSkewSeconds) -or $expires -le $now) {
            Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-TIME-INVALID'
        }
    }
}

function Assert-NgcbBackendPolicy {
    param([object]$Policy, [object]$Authorization, [string]$AuthorizationSha256, [string]$PolicySha256)
    Assert-NgcbExactProperties $Policy @(
        'schema','policyId','policyVersion','authorizationSha256','releaseManifestSha256',
        'hostId','issuedAtUtc','expiresAtUtc','applyEnabled','executableActions','planTtlSeconds',
        'approvalTtlSeconds','stateKeyId','limits','rollout','storageProfiles','networkProfiles','images','bootstrapMedia',
        'firmwareProfiles','bootstrapProfiles','recoveryProfiles','allowedAssets'
    ) 'NGCB-POLICY-CONTRACT-INVALID'
    if ($Policy.schema -cne 'northgate/create-only-backend-policy/v1' -or
        $Policy.authorizationSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $Policy.authorizationSha256 -cne $AuthorizationSha256 -or
        $Policy.releaseManifestSha256 -cne $Authorization.releaseManifestSha256 -or
        $Policy.hostId -cne $Authorization.host.hostId -or
        $PolicySha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $Policy.applyEnabled -isnot [bool] -or
        (@($Policy.executableActions) -join '|') -cne 'Create' -or
        $Policy.planTtlSeconds -isnot [int] -or $Policy.planTtlSeconds -lt 30 -or
        $Policy.planTtlSeconds -gt $script:MaximumPlanTtlSeconds -or
        $Policy.approvalTtlSeconds -isnot [int] -or $Policy.approvalTtlSeconds -lt 30 -or
        $Policy.approvalTtlSeconds -gt $script:MaximumApprovalTtlSeconds -or
        $Policy.stateKeyId -cnotmatch '^ngkey-[a-z0-9-]{8,64}$') {
        Throw-NgcbError 'NGCB-POLICY-CONTRACT-INVALID'
    }
    $issued = ConvertTo-NgcbUtc $Policy.issuedAtUtc 'NGCB-POLICY-TIME-INVALID'
    $expires = ConvertTo-NgcbUtc $Policy.expiresAtUtc 'NGCB-POLICY-TIME-INVALID'
    $now = [DateTimeOffset]::UtcNow
    if ($expires -le $issued) { Throw-NgcbError 'NGCB-POLICY-TIME-INVALID' }
    if ($issued -gt $now.AddSeconds($script:MaximumClockSkewSeconds)) { Throw-NgcbError 'NGCB-POLICY-CLOCK-INVALID' }
    if ($expires -le $now) { Throw-NgcbError 'NGCB-POLICY-EXPIRED' }
    Assert-NgcbExactProperties $Policy.limits @(
        'hostReserveMemoryMiB','hostProcessorReserveCount','maximumVcpuToLogicalRatio','minimumVolumeFreeBytes',
        'minimumVolumeFreePercent','maximumProcessorCount','maximumStartupMemoryMiB',
        'maximumDynamicMemoryMiB','maximumOsDiskGiB'
    ) 'NGCB-POLICY-LIMITS-INVALID'
    if ($Policy.limits.maximumVcpuToLogicalRatio -isnot [int] -or
        [int]$Policy.limits.maximumVcpuToLogicalRatio -lt 1 -or
        [int]$Policy.limits.maximumVcpuToLogicalRatio -gt 2 -or
        [int]$Policy.limits.hostProcessorReserveCount -lt 1) {
        Throw-NgcbError 'NGCB-POLICY-LIMITS-INVALID'
    }
    Assert-NgcbRolloutPolicy $Policy.rollout
    if ($Policy.rollout.stage -cne 'debian-canary') {
        Throw-NgcbError 'NGCB-POLICY-ROLLOUT-INITIAL-STAGE-INVALID'
    }
    $collections = @('storageProfiles','networkProfiles','images','bootstrapMedia','firmwareProfiles','bootstrapProfiles','recoveryProfiles','allowedAssets')
    foreach ($collection in $collections) {
        if (@($Policy.$collection).Count -lt 1) { Throw-NgcbError 'NGCB-POLICY-CONTRACT-INVALID' }
    }
    foreach ($entry in @($Policy.storageProfiles)) {
        Assert-NgcbExactProperties $entry @(
            'profileRef','catalogServerPolicyId','volumeId','root','reserveBytes','maximumOsDiskGiB','workloadClass'
        ) 'NGCB-POLICY-STORAGE-INVALID'
    }
    foreach ($entry in @($Policy.networkProfiles)) {
        Assert-NgcbExactProperties $entry @('profileRef','catalogServerPolicyId','switchPolicyId','vlanId') `
            'NGCB-POLICY-NETWORK-INVALID'
        if ($entry.switchPolicyId -cne $Authorization.switch.switchPolicyId -or
            [int]$entry.vlanId -notin @(110,120,130,140,150,160,240,250)) {
            Throw-NgcbError 'NGCB-POLICY-NETWORK-INVALID'
        }
    }
    foreach ($entry in @($Policy.images)) {
        Assert-NgcbExactProperties $entry @(
            'imageRef','authorizationImageId','path','sha256','sizeBytes','guestFamily',
            'firmwareProfileRef','secureBootEnabled','secureBootTemplate','secureBootExceptionId','vtpmRequired'
        ) 'NGCB-POLICY-IMAGE-INVALID'
        $isKali = $entry.authorizationImageId -ceq 'kali-2026.2-installer-netinst-amd64'
        $validFirmwareSecurity = if ($isKali) {
            $entry.imageRef -ceq 'kali-2026.2-installer-netinst-amd64' -and
            $entry.guestFamily -ceq 'linux' -and $entry.firmwareProfileRef -ceq 'kali-gen2-unsigned' -and
            $entry.secureBootEnabled -eq $false -and
            $entry.secureBootTemplate -ceq 'None' -and
            $entry.secureBootExceptionId -ceq 'NG-FW-20260802-KALI-UNSIGNED' -and
            $entry.vtpmRequired -eq $false
        }
        elseif ($entry.guestFamily -ceq 'windows') {
            $entry.firmwareProfileRef -ceq 'windows-gen2' -and $entry.secureBootEnabled -eq $true -and
            $entry.secureBootTemplate -ceq 'MicrosoftWindows' -and
            $entry.secureBootExceptionId -ceq 'none' -and $entry.vtpmRequired -eq $true
        }
        else {
            $entry.guestFamily -ceq 'linux' -and $entry.firmwareProfileRef -ceq 'linux-gen2' -and
            $entry.secureBootEnabled -eq $true -and
            $entry.secureBootTemplate -ceq 'MicrosoftUEFICertificateAuthority' -and
            $entry.secureBootExceptionId -ceq 'none' -and $entry.vtpmRequired -eq $false
        }
        if ($entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $entry.guestFamily -notin @('windows','linux') -or
            $entry.secureBootEnabled -isnot [bool] -or $entry.vtpmRequired -isnot [bool] -or
            -not $validFirmwareSecurity) {
            Throw-NgcbError 'NGCB-POLICY-IMAGE-INVALID'
        }
    }
    if (@($Policy.bootstrapMedia).Count -ne 12) { Throw-NgcbError 'NGCB-POLICY-BOOTSTRAP-MEDIA-INVALID' }
    foreach ($entry in @($Policy.bootstrapMedia)) {
        $authorized = @($Authorization.bootstrapMedia | Where-Object { $_.mediaId -ceq $entry.mediaId })
        if ($authorized.Count -ne 1 -or
            (ConvertTo-NorthGateCreateOnlyCanonicalJson $entry) -cne
                (ConvertTo-NorthGateCreateOnlyCanonicalJson $authorized[0])) {
            Throw-NgcbError 'NGCB-POLICY-BOOTSTRAP-MEDIA-AUTHORIZATION-MISMATCH'
        }
    }
    foreach ($entry in @($Policy.allowedAssets)) {
        Assert-NgcbExactProperties $entry @(
            'assetId','name','allowedImageRefs','allowedStorageProfileRefs','allowedNetworkProfileRefs',
            'allowedFirmwareProfileRefs','allowedBootstrapProfileRefs','allowedRecoveryProfileRefs',
            'maximumProcessors','maximumMemoryMiB','maximumOsDiskGiB','adapterPolicyId','staticMacAddress','bootstrapMediaId'
        ) 'NGCB-POLICY-ASSET-INVALID'
        if ($entry.adapterPolicyId -cnotmatch '^ngnic-[a-z0-9-]{8,64}$' -or
            $entry.staticMacAddress -cnotmatch '^02[0-9A-F]{10}$' -or
            @($Policy.bootstrapMedia | Where-Object {
                $_.mediaId -ceq $entry.bootstrapMediaId -and $_.assetId -ceq $entry.assetId
            }).Count -ne 1) { Throw-NgcbError 'NGCB-POLICY-ASSET-MAC-INVALID' }
    }
    $macs = @($Policy.allowedAssets | ForEach-Object { [string]$_.staticMacAddress })
    if (@($macs | Select-Object -Unique).Count -ne $macs.Count) { Throw-NgcbError 'NGCB-POLICY-DUPLICATE-MAC' }
    foreach ($collection in $collections) {
        $identityProperty = if ($collection -ceq 'allowedAssets') { 'assetId' }
            elseif ($collection -ceq 'images') { 'imageRef' }
            elseif ($collection -ceq 'bootstrapMedia') { 'mediaId' }
            else { 'profileRef' }
        $values = @($Policy.$collection | ForEach-Object { [string]$_.$identityProperty })
        if (@($values | Where-Object { $_ -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{1,63}$' }).Count -gt 0 -or
            @($values | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique).Count -ne $values.Count) {
            Throw-NgcbError 'NGCB-POLICY-DUPLICATE-IDENTITY'
        }
    }
}

function Assert-NgcbDataBundle {
    param([object]$Bundle, [object]$Release)
    Assert-NgcbExactProperties $Bundle @('schema','bundleId','repository','createdAtUtc','expiresAtUtc','files') `
        'NGCB-DATA-BUNDLE-CONTRACT-INVALID'
    Assert-NgcbExactProperties $Bundle.repository @('identity','commit','tree') 'NGCB-DATA-BUNDLE-CONTRACT-INVALID'
    if ($Bundle.schema -cne 'northgate/create-only-data-bundle/v1' -or
        $Bundle.bundleId -cnotmatch '^ngdata-[a-f0-9]{64}$' -or
        $Bundle.repository.identity -cne $script:RepositoryIdentity -or
        $Bundle.repository.commit -cne $Release.repository.commit -or
        $Bundle.repository.tree -cne $Release.repository.tree -or @($Bundle.files).Count -lt 7) {
        Throw-NgcbError 'NGCB-DATA-BUNDLE-CONTRACT-INVALID'
    }
    $created = ConvertTo-NgcbUtc $Bundle.createdAtUtc 'NGCB-DATA-BUNDLE-TIME-INVALID'
    $expires = ConvertTo-NgcbUtc $Bundle.expiresAtUtc 'NGCB-DATA-BUNDLE-TIME-INVALID'
    $now = [DateTimeOffset]::UtcNow
    if ($expires -le $created) { Throw-NgcbError 'NGCB-DATA-BUNDLE-TIME-INVALID' }
    if ($created -gt $now.AddSeconds($script:MaximumClockSkewSeconds)) { Throw-NgcbError 'NGCB-DATA-BUNDLE-CLOCK-INVALID' }
    if ($expires -le $now) { Throw-NgcbError 'NGCB-DATA-BUNDLE-EXPIRED' }
    $relativePaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $sourcePaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($Bundle.files)) {
        $expected = if ($entry.role -ceq 'manifest') {
            @('role','assetId','sourcePath','gitBlobOid','gitMode','sourceSha256','canonicalRelativePath','canonicalSha256','sizeBytes')
        }
        else { @('role','sourcePath','gitBlobOid','gitMode','sourceSha256','canonicalRelativePath','canonicalSha256','sizeBytes') }
        Assert-NgcbExactProperties $entry $expected 'NGCB-DATA-BUNDLE-FILE-INVALID'
        if ($entry.role -notin @('manifest','imageCatalog','networkCatalog','storageCatalog','firmwareCatalog','bootstrapCatalog','recoveryCatalog','schema','policy') -or
            $entry.sourcePath -cnotmatch '^(?:schemas|manifests|catalog|policy)/[A-Za-z0-9._/-]{1,180}\.json$' -or
            $entry.sourcePath -match '(?:^|/)\.\.(?:/|$)' -or
            $entry.canonicalRelativePath -cnotmatch '^files/[A-Za-z0-9._/-]{1,180}\.json$' -or
            $entry.canonicalRelativePath -match '(?:^|/)\.\.(?:/|$)' -or
            $entry.gitBlobOid -cnotmatch '^[a-f0-9]{40}$' -or $entry.gitMode -cne '100644' -or
            $entry.sourceSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $entry.canonicalSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $entry.sizeBytes -isnot [long] -and $entry.sizeBytes -isnot [int] -or
            [int64]$entry.sizeBytes -lt 2 -or [int64]$entry.sizeBytes -gt $script:MaximumArtifactBytes -or
            -not $relativePaths.Add([string]$entry.canonicalRelativePath) -or
            -not $sourcePaths.Add([string]$entry.sourcePath)) {
            Throw-NgcbError 'NGCB-DATA-BUNDLE-FILE-INVALID'
        }
        if ($entry.role -ceq 'manifest') {
            Assert-NgcbPattern $entry.assetId '^NG-VM-[0-9]{3,}$' 'NGCB-DATA-BUNDLE-FILE-INVALID'
        }
    }
    foreach ($role in @('imageCatalog','networkCatalog','storageCatalog','firmwareCatalog','bootstrapCatalog','recoveryCatalog')) {
        if (@($Bundle.files | Where-Object { $_.role -ceq $role }).Count -ne 1) {
            Throw-NgcbError 'NGCB-DATA-BUNDLE-ROLE-INVALID'
        }
    }
}

function Get-NgcbDataArtifact {
    param([object]$Context, [string]$Role, [string]$AssetId = '')
    $matches = @($Context.DataBundle.files | Where-Object {
        $_.role -ceq $Role -and ($Role -cne 'manifest' -or $_.assetId -ceq $AssetId)
    })
    if ($matches.Count -ne 1) { Throw-NgcbError 'NGCB-DATA-ARTIFACT-NOT-UNIQUE' }
    $entry = $matches[0]
    $path = [IO.Path]::GetFullPath((Join-Path $Context.DataRoot ([string]$entry.canonicalRelativePath)))
    $rootPrefix = [IO.Path]::GetFullPath($Context.DataRoot).TrimEnd('\') + '\'
    if (-not $path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Throw-NgcbError 'NGCB-DATA-ARTIFACT-PATH-INVALID'
    }
    Assert-NgcbNoReparseAncestor $path 'NGCB-DATA-ARTIFACT-REPARSE-FORBIDDEN' | Out-Null
    $artifact = Read-NgcbCanonicalFile $path $script:MaximumArtifactBytes 'NGCB-DATA-ARTIFACT-INVALID'
    if (-not (Test-NgcbFixedHexEquals $artifact.Sha256 ([string]$entry.canonicalSha256)) -or
        $artifact.Bytes.Length -ne [int64]$entry.sizeBytes) { Throw-NgcbError 'NGCB-DATA-ARTIFACT-HASH-MISMATCH' }
    return [pscustomobject][ordered]@{ Entry = $entry; Artifact = $artifact }
}

function New-NorthGateCreateOnlyBackendContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StateRoot,
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][string]$StateKeyPath,
        [Parameter(Mandatory)][string]$ReleaseManifestPath,
        [Parameter(Mandatory)][string]$ReleaseManifestSignaturePath,
        [Parameter(Mandatory)][string]$ExpectedReleaseManifestSha256,
        [Parameter(Mandatory)][string]$ExpectedReleaseSignerCertificateSha256,
        [Parameter(Mandatory)][string]$HostAuthorizationPath,
        [Parameter(Mandatory)][string]$HostAuthorizationSignaturePath,
        [Parameter(Mandatory)][string]$ExpectedHostAuthorizationSha256,
        [Parameter(Mandatory)][string]$ExpectedHostAuthorizationSignerCertificateSha256,
        [Parameter(Mandatory)][string]$BackendPolicyPath,
        [Parameter(Mandatory)][string]$BackendPolicySignaturePath,
        [Parameter(Mandatory)][string]$ExpectedBackendPolicySha256,
        [Parameter(Mandatory)][string]$DataBundlePath,
        [Parameter(Mandatory)][string]$DataBundleSignaturePath,
        [Parameter(Mandatory)][string]$ExpectedDataBundleSha256
    )

    if ($env:OS -cne 'Windows_NT') { Throw-NgcbError 'NGCB-PRODUCTION-WINDOWS-REQUIRED' }
    foreach ($hash in @(
        $ExpectedReleaseManifestSha256,$ExpectedReleaseSignerCertificateSha256,
        $ExpectedHostAuthorizationSha256,$ExpectedHostAuthorizationSignerCertificateSha256,
        $ExpectedBackendPolicySha256,$ExpectedDataBundleSha256
    )) { Assert-NgcbPattern $hash '^[a-f0-9]{64}$' 'NGCB-TRUST-ANCHOR-INVALID' }

    $releaseArtifact = Read-NgcbCanonicalFile $ReleaseManifestPath $script:MaximumArtifactBytes 'NGCB-RELEASE-INVALID'
    if (-not (Test-NgcbFixedHexEquals $releaseArtifact.Sha256 $ExpectedReleaseManifestSha256)) {
        Throw-NgcbError 'NGCB-RELEASE-HASH-MISMATCH'
    }
    $null = Assert-NgcbDetachedCmsSignature $releaseArtifact.Bytes `
        (Read-NgcbSignatureFile $ReleaseManifestSignaturePath) $ExpectedReleaseSignerCertificateSha256 `
        'NGCB-RELEASE-SIGNATURE-INVALID'
    Assert-NgcbReleaseManifest $releaseArtifact.Value $ExpectedReleaseManifestSha256

    $authorizationArtifact = Read-NgcbCanonicalFile $HostAuthorizationPath $script:MaximumArtifactBytes `
        'NGCB-AUTHORIZATION-INVALID'
    if (-not (Test-NgcbFixedHexEquals $authorizationArtifact.Sha256 $ExpectedHostAuthorizationSha256)) {
        Throw-NgcbError 'NGCB-AUTHORIZATION-HASH-MISMATCH'
    }
    $null = Assert-NgcbDetachedCmsSignature $authorizationArtifact.Bytes `
        (Read-NgcbSignatureFile $HostAuthorizationSignaturePath) `
        $ExpectedHostAuthorizationSignerCertificateSha256 'NGCB-AUTHORIZATION-SIGNATURE-INVALID'
    Assert-NgcbHostAuthorization $authorizationArtifact.Value $releaseArtifact.Value $authorizationArtifact.Sha256
    $authorization = $authorizationArtifact.Value
    if ($authorization.releaseManifestSha256 -cne $releaseArtifact.Sha256 -or
        $authorization.identity.releaseSignerCertificateSha256 -cne $ExpectedReleaseSignerCertificateSha256 -or
        $authorization.identity.deploymentAuthorizationSignerCertificateSha256 -cne
            $ExpectedHostAuthorizationSignerCertificateSha256) {
        Throw-NgcbError 'NGCB-AUTHORIZATION-TRUST-PIN-MISMATCH'
    }

    $policyArtifact = Read-NgcbCanonicalFile $BackendPolicyPath $script:MaximumArtifactBytes 'NGCB-POLICY-INVALID'
    if (-not (Test-NgcbFixedHexEquals $policyArtifact.Sha256 $ExpectedBackendPolicySha256)) {
        Throw-NgcbError 'NGCB-POLICY-HASH-MISMATCH'
    }
    $null = Assert-NgcbDetachedCmsSignature $policyArtifact.Bytes `
        (Read-NgcbSignatureFile $BackendPolicySignaturePath) `
        $ExpectedReleaseSignerCertificateSha256 'NGCB-POLICY-SIGNATURE-INVALID'
    Assert-NgcbBackendPolicy $policyArtifact.Value $authorization $authorizationArtifact.Sha256 $policyArtifact.Sha256

    $bundleArtifact = Read-NgcbCanonicalFile $DataBundlePath 10485760 'NGCB-DATA-BUNDLE-INVALID'
    if (-not (Test-NgcbFixedHexEquals $bundleArtifact.Sha256 $ExpectedDataBundleSha256)) {
        Throw-NgcbError 'NGCB-DATA-BUNDLE-HASH-MISMATCH'
    }
    $null = Assert-NgcbDetachedCmsSignature $bundleArtifact.Bytes `
        (Read-NgcbSignatureFile $DataBundleSignaturePath) `
        $ExpectedReleaseSignerCertificateSha256 'NGCB-DATA-BUNDLE-SIGNATURE-INVALID'
    Assert-NgcbDataBundle $bundleArtifact.Value $releaseArtifact.Value

    $stateRootFull = Assert-NgcbNoReparseAncestor $StateRoot
    $dataRootFull = Assert-NgcbNoReparseAncestor $DataRoot
    if (-not (Test-Path -LiteralPath $stateRootFull -PathType Container) -or
        -not (Test-Path -LiteralPath $dataRootFull -PathType Container)) {
        Throw-NgcbError 'NGCB-INSTALLED-ROOT-MISSING'
    }
    $authorizedInstallStateRoot = [IO.Path]::GetFullPath([string]$authorization.install.stateRoot).TrimEnd('\')
    $authorizedStateRoot = [IO.Path]::GetFullPath((Join-Path $authorizedInstallStateRoot `
        ('backend\' + [string]$releaseArtifact.Value.releaseId))).TrimEnd('\')
    $authorizedDataRoot = [IO.Path]::GetFullPath((Join-Path `
        ([string]$authorization.install.versionedReleaseRoot) 'backend-data')).TrimEnd('\')
    if ($stateRootFull.TrimEnd('\') -ine $authorizedStateRoot) {
        Throw-NgcbError 'NGCB-STATE-ROOT-NOT-AUTHORIZED'
    }
    if ($dataRootFull.TrimEnd('\') -ine $authorizedDataRoot) {
        Throw-NgcbError 'NGCB-DATA-ROOT-NOT-AUTHORIZED'
    }
    if ([IO.Path]::GetFullPath($StateKeyPath) -ine (Join-Path $authorizedStateRoot 'state-key.dpapi') -or
        [IO.Path]::GetFullPath($DataBundlePath) -ine (Join-Path $authorizedDataRoot 'bundle.json') -or
        [IO.Path]::GetFullPath($DataBundleSignaturePath) -ine (Join-Path $authorizedDataRoot 'bundle.p7s')) {
        Throw-NgcbError 'NGCB-INSTALLED-ARTIFACT-PATH-NOT-AUTHORIZED'
    }
    $releaseRoot = [IO.Path]::GetFullPath([string]$authorization.install.versionedReleaseRoot).TrimEnd('\') + '\'
    $modulePath = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    if (-not $modulePath.StartsWith($releaseRoot, [StringComparison]::OrdinalIgnoreCase)) {
        Throw-NgcbError 'NGCB-MODULE-NOT-IN-AUTHORIZED-RELEASE'
    }
    Assert-NgcbRestrictedAcl $stateRootFull ([string]$authorization.identity.serviceIdentitySid)
    Assert-NgcbRestrictedAcl $dataRootFull ([string]$authorization.identity.serviceIdentitySid)

    try {
        $stateKeyItem = Get-Item -LiteralPath $StateKeyPath -Force -ErrorAction Stop
        if ($stateKeyItem.PSIsContainer -or $stateKeyItem.Length -lt 48 -or $stateKeyItem.Length -gt 4096 -or
            ($stateKeyItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-NgcbError 'NGCB-STATE-KEY-INVALID'
        }
        $protectedKey = [IO.File]::ReadAllBytes($stateKeyItem.FullName)
        $entropy = [Text.Encoding]::UTF8.GetBytes('northgate-vm-factory|' + [string]$policyArtifact.Value.stateKeyId)
        $stateKey = [Security.Cryptography.ProtectedData]::Unprotect(
            $protectedKey, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        if ($stateKey.Length -ne 32) { Throw-NgcbError 'NGCB-STATE-KEY-INVALID' }
    }
    catch {
        if ($_.Exception.Message -ceq 'NGCB-STATE-KEY-INVALID') { throw }
        Throw-NgcbError 'NGCB-STATE-KEY-INVALID'
    }

    foreach ($directoryName in @('plans','approvals','receipts','journals','ledger','locks','audit')) {
        $directory = Join-Path $stateRootFull $directoryName
        $null = [IO.Directory]::CreateDirectory($directory)
        Assert-NgcbNoReparseAncestor $directory | Out-Null
    }
    $rolloutPromotions = Join-Path $stateRootFull 'rollout\promotions'
    $null = [IO.Directory]::CreateDirectory($rolloutPromotions)
    Assert-NgcbNoReparseAncestor $rolloutPromotions | Out-Null
    $receiptCertificate = Get-NgcbCertificateWithPrivateKey `
        ([string]$authorization.identity.receiptSignerCertificateSha256)
    $context = [pscustomobject][ordered]@{
        ContextVersion = 'northgate/create-only-backend-context/v1'
        Mode = 'Production'
        StateRoot = $stateRootFull
        Authorization = $authorization
        AuthorizationSha256 = $authorizationArtifact.Sha256
        ReleaseManifest = $releaseArtifact.Value
        ReleaseManifestSha256 = $releaseArtifact.Sha256
        Policy = $policyArtifact.Value
        PolicySha256 = $policyArtifact.Sha256
        DataBundle = $bundleArtifact.Value
        DataBundleSha256 = $bundleArtifact.Sha256
        DataRoot = $dataRootFull
        StateKey = $stateKey
        ReceiptCertificate = $receiptCertificate
        AnchorPaths = [pscustomobject][ordered]@{
            release = [IO.Path]::GetFullPath($ReleaseManifestPath)
            authorization = [IO.Path]::GetFullPath($HostAuthorizationPath)
            policy = [IO.Path]::GetFullPath($BackendPolicyPath)
            dataBundle = [IO.Path]::GetFullPath($DataBundlePath)
        }
        TestState = [pscustomobject]@{}
        TestScenario = 'None'
        ContextMarker = ''
    }
    $context.ContextMarker = Get-NgcbContextMarker $context
    Assert-NgcbContext $context
    return $context
}

function New-NgcbInertTestContext {
    param(
        [Parameter(Mandatory)][string]$StateRoot,
        [Parameter(Mandatory)][object]$Authorization,
        [Parameter(Mandatory)][string]$AuthorizationSha256,
        [Parameter(Mandatory)][object]$ReleaseManifest,
        [Parameter(Mandatory)][string]$ReleaseManifestSha256,
        [Parameter(Mandatory)][object]$Policy,
        [Parameter(Mandatory)][string]$PolicySha256,
        [Parameter(Mandatory)][object]$DataBundle,
        [Parameter(Mandatory)][string]$DataBundleSha256,
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][object]$TestState,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$ReceiptCertificate
    )
    Assert-NgcbReleaseManifest $ReleaseManifest $ReleaseManifestSha256
    Assert-NgcbHostAuthorization $Authorization $ReleaseManifest $AuthorizationSha256
    if ($Authorization.releaseManifestSha256 -cne $ReleaseManifestSha256) {
        Throw-NgcbError 'NGCB-AUTHORIZATION-RELEASE-BINDING-INVALID'
    }
    Assert-NgcbBackendPolicy $Policy $Authorization $AuthorizationSha256 $PolicySha256
    Assert-NgcbDataBundle $DataBundle $ReleaseManifest
    $null = [IO.Directory]::CreateDirectory($StateRoot)
    foreach ($directoryName in @('plans','approvals','receipts','journals','ledger','locks','audit')) {
        $null = [IO.Directory]::CreateDirectory((Join-Path $StateRoot $directoryName))
    }
    $null = [IO.Directory]::CreateDirectory((Join-Path $StateRoot 'rollout\promotions'))
    $key = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    $context = [pscustomobject][ordered]@{
        ContextVersion = 'northgate/create-only-backend-context/v1'
        Mode = 'InertTest'
        StateRoot = [IO.Path]::GetFullPath($StateRoot)
        Authorization = $Authorization
        AuthorizationSha256 = $AuthorizationSha256
        ReleaseManifest = $ReleaseManifest
        ReleaseManifestSha256 = $ReleaseManifestSha256
        Policy = $Policy
        PolicySha256 = $PolicySha256
        DataBundle = $DataBundle
        DataBundleSha256 = $DataBundleSha256
        DataRoot = [IO.Path]::GetFullPath($DataRoot)
        StateKey = $key
        ReceiptCertificate = $ReceiptCertificate
        AnchorPaths = [pscustomobject]@{}
        TestState = $TestState
        TestScenario = 'None'
        ContextMarker = ''
    }
    $context.ContextMarker = Get-NgcbContextMarker $context
    Assert-NgcbContext $context
    return $context
}

function Assert-NgcbContextAnchorsCurrent {
    param([object]$Context)
    Assert-NgcbContext $Context
    $null = Assert-NgcbContextTimesCurrent $Context
    if ($Context.Mode -ne 'Production') { return }
    foreach ($record in @(
        @([string]$Context.AnchorPaths.release,[string]$Context.ReleaseManifestSha256,'NGCB-RELEASE-HASH-MISMATCH'),
        @([string]$Context.AnchorPaths.authorization,[string]$Context.AuthorizationSha256,'NGCB-AUTHORIZATION-HASH-MISMATCH'),
        @([string]$Context.AnchorPaths.policy,[string]$Context.PolicySha256,'NGCB-POLICY-HASH-MISMATCH'),
        @([string]$Context.AnchorPaths.dataBundle,[string]$Context.DataBundleSha256,'NGCB-DATA-BUNDLE-HASH-MISMATCH')
    )) {
        $artifact = Read-NgcbCanonicalFile $record[0] 10485760 $record[2]
        if (-not (Test-NgcbFixedHexEquals $artifact.Sha256 $record[1])) { Throw-NgcbError $record[2] }
    }
}

function Get-NgcbUniqueEntry {
    param([object[]]$Entries, [string]$Property, [string]$Value, [string]$Code)
    $matches = @($Entries | Where-Object { [string]$_.$Property -ceq $Value })
    if ($matches.Count -ne 1) { Throw-NgcbError $Code }
    return $matches[0]
}

function Assert-NgcbCatalogProfile {
    param([object]$Catalog, [string]$Kind, [string]$ProfileRef, [string]$ExpectedServerPolicyId)
    if ($Catalog.apiVersion -cne 'northgate/v1alpha1' -or $Catalog.kind -cne $Kind) {
        Throw-NgcbError 'NGCB-CATALOG-CONTRACT-INVALID'
    }
    $profile = Get-NgcbUniqueEntry @($Catalog.profiles) 'id' $ProfileRef 'NGCB-CATALOG-PROFILE-NOT-APPROVED'
    if ($profile.approvalStatus -cne 'approved' -or
        $profile.serverPolicyId -cne $ExpectedServerPolicyId) {
        Throw-NgcbError 'NGCB-CATALOG-PROFILE-NOT-APPROVED'
    }
    return $profile
}

function Resolve-NgcbManifest {
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$AssetId)
    $manifestData = Get-NgcbDataArtifact $Context 'manifest' $AssetId
    $manifest = $manifestData.Artifact.Value
    Assert-NgcbExactProperties $manifest @('$schema','apiVersion','kind','metadata','spec') `
        'NGCB-MANIFEST-PROPERTIES-INVALID'
    Assert-NgcbExactProperties $manifest.metadata @(
        'assetId','name','ownerRef','purpose','environment','criticality','dataClassification',
        'lifecycle','reviewOrRetirementDate','changeRef','dependencies'
    ) 'NGCB-MANIFEST-PROPERTIES-INVALID'
    Assert-NgcbExactProperties $manifest.spec @(
        'intent','generation','imageRef','firmwareProfileRef','compute','storage','network',
        'bootstrapProfileRef','recoveryProfileRef','desiredPowerState','destroyProtection'
    ) 'NGCB-MANIFEST-PROPERTIES-INVALID'
    Assert-NgcbExactProperties $manifest.spec.compute @('processors','memory') 'NGCB-MANIFEST-COMPUTE-INVALID'
    Assert-NgcbExactProperties $manifest.spec.storage @('profileRef','osDiskGiB') 'NGCB-MANIFEST-STORAGE-INVALID'
    Assert-NgcbExactProperties $manifest.spec.network @('profileRef') 'NGCB-MANIFEST-NETWORK-INVALID'
    if ($manifest.spec.compute.memory.mode -ceq 'static') {
        Assert-NgcbExactProperties $manifest.spec.compute.memory @('mode','startupMiB') 'NGCB-MANIFEST-MEMORY-INVALID'
        $minimumMemory = [int]$manifest.spec.compute.memory.startupMiB
        $maximumMemory = [int]$manifest.spec.compute.memory.startupMiB
    }
    elseif ($manifest.spec.compute.memory.mode -ceq 'dynamic') {
        Assert-NgcbExactProperties $manifest.spec.compute.memory @('mode','minimumMiB','startupMiB','maximumMiB') `
            'NGCB-MANIFEST-MEMORY-INVALID'
        $minimumMemory = [int]$manifest.spec.compute.memory.minimumMiB
        $maximumMemory = [int]$manifest.spec.compute.memory.maximumMiB
        if ($minimumMemory -gt [int]$manifest.spec.compute.memory.startupMiB -or
            [int]$manifest.spec.compute.memory.startupMiB -gt $maximumMemory) {
            Throw-NgcbError 'NGCB-MANIFEST-MEMORY-INVALID'
        }
    }
    else { Throw-NgcbError 'NGCB-MANIFEST-MEMORY-INVALID' }
    if ($manifest.'$schema' -cne '../../schemas/vm-manifest.schema.json' -or
        $manifest.apiVersion -cne 'northgate/v1alpha1' -or $manifest.kind -cne 'VirtualMachine' -or
        $manifest.metadata.assetId -cne $AssetId -or $manifest.metadata.assetId -cnotmatch '^NG-VM-[0-9]{3,}$' -or
        $manifest.metadata.name -cnotmatch '^[A-Z](?:[A-Z0-9-]{0,13}[A-Z0-9])?$' -or
        $manifest.metadata.lifecycle -notin @('approved','active') -or
        $manifest.metadata.changeRef -cnotmatch '^NG-CHG-[0-9]{8}-[0-9]{3,}$' -or
        $manifest.spec.intent -cne 'create' -or $manifest.spec.generation -ne 2 -or
        $manifest.spec.destroyProtection -ne $true -or
        $manifest.spec.desiredPowerState -notin @('off','running') -or
        $manifest.spec.compute.processors -isnot [int] -or
        $manifest.spec.storage.osDiskGiB -isnot [int]) {
        Throw-NgcbError 'NGCB-MANIFEST-CONTRACT-INVALID'
    }
    foreach ($profile in @(
        $manifest.spec.imageRef,$manifest.spec.firmwareProfileRef,$manifest.spec.storage.profileRef,
        $manifest.spec.network.profileRef,$manifest.spec.bootstrapProfileRef,$manifest.spec.recoveryProfileRef
    )) {
        Assert-NgcbPattern $profile '^[a-z0-9][a-z0-9.-]{1,63}$' 'NGCB-MANIFEST-PROFILE-INVALID'
    }

    $allowed = Get-NgcbUniqueEntry @($Context.Policy.allowedAssets) 'assetId' $AssetId `
        'NGCB-ASSET-NOT-IN-HOST-POLICY'
    if ($allowed.name -cne $manifest.metadata.name -or
        $manifest.spec.imageRef -cnotin @($allowed.allowedImageRefs) -or
        $manifest.spec.storage.profileRef -cnotin @($allowed.allowedStorageProfileRefs) -or
        $manifest.spec.network.profileRef -cnotin @($allowed.allowedNetworkProfileRefs) -or
        $manifest.spec.firmwareProfileRef -cnotin @($allowed.allowedFirmwareProfileRefs) -or
        $manifest.spec.bootstrapProfileRef -cnotin @($allowed.allowedBootstrapProfileRefs) -or
        $manifest.spec.recoveryProfileRef -cnotin @($allowed.allowedRecoveryProfileRefs) -or
        [int]$manifest.spec.compute.processors -gt [int]$allowed.maximumProcessors -or
        $maximumMemory -gt [int]$allowed.maximumMemoryMiB -or
        [int]$manifest.spec.storage.osDiskGiB -gt [int]$allowed.maximumOsDiskGiB) {
        Throw-NgcbError 'NGCB-MANIFEST-EXCEEDS-ASSET-POLICY'
    }
    $limits = $Context.Policy.limits
    if ([int]$manifest.spec.compute.processors -lt 1 -or
        [int]$manifest.spec.compute.processors -gt [int]$limits.maximumProcessorCount -or
        [int]$manifest.spec.compute.memory.startupMiB -lt 1024 -or
        [int]$manifest.spec.compute.memory.startupMiB -gt [int]$limits.maximumStartupMemoryMiB -or
        $maximumMemory -gt [int]$limits.maximumDynamicMemoryMiB -or
        [int]$manifest.spec.storage.osDiskGiB -lt 20 -or
        [int]$manifest.spec.storage.osDiskGiB -gt [int]$limits.maximumOsDiskGiB) {
        Throw-NgcbError 'NGCB-MANIFEST-EXCEEDS-GLOBAL-POLICY'
    }

    $imagePolicy = Get-NgcbUniqueEntry @($Context.Policy.images) 'imageRef' ([string]$manifest.spec.imageRef) `
        'NGCB-IMAGE-NOT-IN-HOST-POLICY'
    if ($imagePolicy.firmwareProfileRef -cne $manifest.spec.firmwareProfileRef) {
        Throw-NgcbError 'NGCB-IMAGE-FIRMWARE-INCOMPATIBLE'
    }
    $authorizedImage = Get-NgcbUniqueEntry @($Context.Authorization.images) 'imageId' `
        ([string]$imagePolicy.authorizationImageId) 'NGCB-IMAGE-NOT-AUTHORIZED'
    if ([IO.Path]::GetFullPath([string]$authorizedImage.path) -ine
            [IO.Path]::GetFullPath([string]$imagePolicy.path) -or
        $authorizedImage.sha256 -cne $imagePolicy.sha256 -or
        [int64]$authorizedImage.sizeBytes -ne [int64]$imagePolicy.sizeBytes) {
        Throw-NgcbError 'NGCB-IMAGE-AUTHORIZATION-MISMATCH'
    }
    $bootstrapMedia = Get-NgcbUniqueEntry @($Context.Policy.bootstrapMedia) 'mediaId' `
        ([string]$allowed.bootstrapMediaId) 'NGCB-BOOTSTRAP-MEDIA-NOT-IN-HOST-POLICY'
    $authorizedBootstrapMedia = Get-NgcbUniqueEntry @($Context.Authorization.bootstrapMedia) 'mediaId' `
        ([string]$allowed.bootstrapMediaId) 'NGCB-BOOTSTRAP-MEDIA-NOT-AUTHORIZED'
    if ($bootstrapMedia.assetId -cne $AssetId -or $authorizedBootstrapMedia.assetId -cne $AssetId -or
        $bootstrapMedia.sourceImageId -cne $imagePolicy.authorizationImageId -or
        $bootstrapMedia.sourceImageSha256 -cne $imagePolicy.sha256 -or
        (ConvertTo-NorthGateCreateOnlyCanonicalJson $bootstrapMedia) -cne
            (ConvertTo-NorthGateCreateOnlyCanonicalJson $authorizedBootstrapMedia)) {
        Throw-NgcbError 'NGCB-BOOTSTRAP-MEDIA-ASSET-BINDING-INVALID'
    }
    $storagePolicy = Get-NgcbUniqueEntry @($Context.Policy.storageProfiles) 'profileRef' `
        ([string]$manifest.spec.storage.profileRef) 'NGCB-STORAGE-NOT-IN-HOST-POLICY'
    $authorizedVolume = Get-NgcbUniqueEntry @($Context.Authorization.volumes) 'volumeId' `
        ([string]$storagePolicy.volumeId) 'NGCB-STORAGE-NOT-AUTHORIZED'
    if ([IO.Path]::GetFullPath([string]$authorizedVolume.root).TrimEnd('\') -ine
        [IO.Path]::GetFullPath([string]$storagePolicy.root).TrimEnd('\')) {
        Throw-NgcbError 'NGCB-STORAGE-AUTHORIZATION-MISMATCH'
    }
    $networkPolicy = Get-NgcbUniqueEntry @($Context.Policy.networkProfiles) 'profileRef' `
        ([string]$manifest.spec.network.profileRef) 'NGCB-NETWORK-NOT-IN-HOST-POLICY'
    $firmwarePolicy = Get-NgcbUniqueEntry @($Context.Policy.firmwareProfiles) 'profileRef' `
        ([string]$manifest.spec.firmwareProfileRef) 'NGCB-FIRMWARE-NOT-IN-HOST-POLICY'
    $bootstrapPolicy = Get-NgcbUniqueEntry @($Context.Policy.bootstrapProfiles) 'profileRef' `
        ([string]$manifest.spec.bootstrapProfileRef) 'NGCB-BOOTSTRAP-NOT-IN-HOST-POLICY'
    $recoveryPolicy = Get-NgcbUniqueEntry @($Context.Policy.recoveryProfiles) 'profileRef' `
        ([string]$manifest.spec.recoveryProfileRef) 'NGCB-RECOVERY-NOT-IN-HOST-POLICY'

    $catalogArtifacts = [ordered]@{}
    foreach ($role in @('imageCatalog','networkCatalog','storageCatalog','firmwareCatalog','bootstrapCatalog','recoveryCatalog')) {
        $catalogArtifacts[$role] = Get-NgcbDataArtifact $Context $role
    }
    $imageCatalog = $catalogArtifacts.imageCatalog.Artifact.Value
    if ($imageCatalog.kind -cne 'ImageCatalog' -or $imageCatalog.promotedOnly -ne $true -or
        $imageCatalog.status -cne 'active') { Throw-NgcbError 'NGCB-IMAGE-CATALOG-NOT-ACTIVE' }
    $catalogImage = Get-NgcbUniqueEntry @($imageCatalog.images) 'id' ([string]$manifest.spec.imageRef) `
        'NGCB-IMAGE-NOT-PROMOTED'
    if ($catalogImage.approvalStatus -cne 'promoted' -or $catalogImage.retirementStatus -cne 'active' -or
        $catalogImage.sha256 -cne $imagePolicy.sha256 -or
        [int64]$catalogImage.sizeBytes -ne [int64]$imagePolicy.sizeBytes -or
        $catalogImage.architecture -cne 'x86_64' -or 2 -cnotin @($catalogImage.allowedGenerations) -or
        $manifest.spec.firmwareProfileRef -cnotin @($catalogImage.allowedFirmwareProfiles)) {
        Throw-NgcbError 'NGCB-IMAGE-NOT-PROMOTED'
    }
    $networkCatalogProfile = Assert-NgcbCatalogProfile $catalogArtifacts.networkCatalog.Artifact.Value `
        'NetworkCatalog' ([string]$manifest.spec.network.profileRef) ([string]$networkPolicy.catalogServerPolicyId)
    if ($networkCatalogProfile.allowAttach -ne $true -or $networkCatalogProfile.allowCreate -ne $false -or
        $networkCatalogProfile.allowRebind -ne $false) { Throw-NgcbError 'NGCB-NETWORK-CATALOG-INVALID' }
    $storageCatalogProfile = Assert-NgcbCatalogProfile $catalogArtifacts.storageCatalog.Artifact.Value `
        'StorageCatalog' ([string]$manifest.spec.storage.profileRef) ([string]$storagePolicy.catalogServerPolicyId)
    if ($storageCatalogProfile.allowProvision -ne $true) { Throw-NgcbError 'NGCB-STORAGE-CATALOG-INVALID' }
    $null = Assert-NgcbCatalogProfile $catalogArtifacts.firmwareCatalog.Artifact.Value `
        'FirmwareCatalog' ([string]$manifest.spec.firmwareProfileRef) ([string]$firmwarePolicy.catalogServerPolicyId)
    $null = Assert-NgcbCatalogProfile $catalogArtifacts.bootstrapCatalog.Artifact.Value `
        'BootstrapCatalog' ([string]$manifest.spec.bootstrapProfileRef) ([string]$bootstrapPolicy.catalogServerPolicyId)
    $null = Assert-NgcbCatalogProfile $catalogArtifacts.recoveryCatalog.Artifact.Value `
        'RecoveryCatalog' ([string]$manifest.spec.recoveryProfileRef) ([string]$recoveryPolicy.catalogServerPolicyId)

    $catalogEvidence = @()
    foreach ($role in $catalogArtifacts.Keys) {
        $catalogEvidence += [pscustomobject][ordered]@{
            role = $role
            canonicalSha256 = $catalogArtifacts[$role].Artifact.Sha256
            sourceSha256 = [string]$catalogArtifacts[$role].Entry.sourceSha256
            gitBlobOid = [string]$catalogArtifacts[$role].Entry.gitBlobOid
        }
    }
    $storageRoot = [IO.Path]::GetFullPath([string]$storagePolicy.root).TrimEnd('\')
    $assetRoot = Join-Path $storageRoot $AssetId
    $vhdPath = Join-Path (Join-Path $assetRoot 'Virtual Hard Disks') ($AssetId + '-os.vhdx')
    return [pscustomobject][ordered]@{
        Manifest = $manifest
        ManifestSha256 = $manifestData.Artifact.Sha256
        ManifestSourceSha256 = [string]$manifestData.Entry.sourceSha256
        ManifestGitBlobOid = [string]$manifestData.Entry.gitBlobOid
        CatalogEvidence = @($catalogEvidence)
        CatalogHash = Get-NgcbStringSha256Hex (ConvertTo-NorthGateCreateOnlyCanonicalJson @($catalogEvidence))
        AllowedAsset = $allowed
        Image = $imagePolicy
        BootstrapMedia = $bootstrapMedia
        Storage = $storagePolicy
        AuthorizedVolume = $authorizedVolume
        Network = $networkPolicy
        Firmware = $firmwarePolicy
        Bootstrap = $bootstrapPolicy
        Recovery = $recoveryPolicy
        MinimumMemoryMiB = $minimumMemory
        MaximumMemoryMiB = $maximumMemory
        StorageRoot = $storageRoot
        AssetRoot = $assetRoot
        VhdPath = $vhdPath
    }
}

function Get-NgcbOwnershipNote {
    param([string]$AssetId, [string]$ChangeId, [string]$ReservationId, [string]$PlanId, [bool]$Quarantined)
    'NorthGateFactory=v1;assetId={0};changeId={1};reservationId={2};planId={3};destroyProtection=true;quarantine={4}' -f `
        $AssetId,$ChangeId,$ReservationId,$PlanId,($(if ($Quarantined) { 'true' } else { 'false' }))
}

function Normalize-NgcbVlanList {
    param([AllowEmptyString()][string]$Value)
    (@($Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } | Sort-Object) -join ',')
}

function Get-NgcbAdapterIdentity {
    param([object]$Adapter, [Parameter(Mandatory)][string]$VmId)
    $normalizedVmId = $VmId.ToLowerInvariant()
    $adapterId = ([string]$Adapter.AdapterId).ToLowerInvariant()
    if ($adapterId -cmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$') {
        return $adapterId
    }
    $compositeId = [string]$Adapter.Id
    if ($compositeId -cnotmatch '^Microsoft:(?<vm>[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12})\\(?<adapter>[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12})$' -or
        $Matches.vm.ToLowerInvariant() -cne $normalizedVmId) {
        Throw-NgcbError 'NGCB-ADAPTER-IDENTITY-INVALID'
    }
    return $Matches.adapter.ToLowerInvariant()
}

function Get-NgcbSwitchFingerprint {
    param([object]$Switch)
    $record = [pscustomobject][ordered]@{
        id = ([string]$Switch.Id).ToLowerInvariant()
        name = [string]$Switch.Name
        switchType = [string]$Switch.SwitchType
        netAdapterInterfaceDescription = [string]$Switch.NetAdapterInterfaceDescription
        allowManagementOS = [bool]$Switch.AllowManagementOS
    }
    Get-NgcbStringSha256Hex (ConvertTo-NorthGateCreateOnlyCanonicalJson $record)
}

function Get-NgcbTrunkFingerprint {
    param([object]$Adapter, [object]$Vlan, [string]$VmId, [string]$SwitchId)
    $record = [pscustomobject][ordered]@{
        adapterId = Get-NgcbAdapterIdentity $Adapter $VmId
        vmId = $VmId.ToLowerInvariant()
        switchId = $SwitchId.ToLowerInvariant()
        operationMode = ([string]$Vlan.OperationMode).ToLowerInvariant()
        nativeVlanId = [int]$Vlan.NativeVlanId
        allowedVlanIdList = Normalize-NgcbVlanList ([string]$Vlan.AllowedVlanIdList)
    }
    Get-NgcbStringSha256Hex (ConvertTo-NorthGateCreateOnlyCanonicalJson $record)
}

function Get-NgcbProductionSnapshot {
    param([object]$Context, [object]$Resolved)
    foreach ($commandName in @(
        'Hyper-V\Get-VM','Hyper-V\Get-VMSwitch','Hyper-V\Get-VMHardDiskDrive',
        'Hyper-V\Get-VMNetworkAdapter','Hyper-V\Get-VMNetworkAdapterVlan','Hyper-V\Get-VMMemory',
        'Hyper-V\Get-VMProcessor','Hyper-V\Get-VHD'
    )) { $null = Get-Command $commandName -ErrorAction Stop }
    $authorization = $Context.Authorization
    try {
        $machineGuid = [string](Get-ItemPropertyValue `
            -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop)
        $machineGuidHash = Get-NgcbStringSha256Hex $machineGuid.ToLowerInvariant()
        $hostProducts = @(Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop)
        if ($hostProducts.Count -ne 1 -or [string]$hostProducts[0].UUID -cnotmatch
            '^[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$' -or
            [string]$hostProducts[0].UUID -in @(
                '00000000-0000-0000-0000-000000000000','FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'
            )) { Throw-NgcbError 'NGCB-HOST-IDENTITY-READ-FAILED' }
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hostId = ([string]$hostProducts[0].UUID).ToLowerInvariant()
        $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $osBuild = [string]$os.CurrentBuildNumber + '.' + [string]$os.UBR
    }
    catch { Throw-NgcbError 'NGCB-HOST-IDENTITY-READ-FAILED' }
    if ($env:COMPUTERNAME -cne [string]$authorization.host.computerName -or
        $machineGuidHash -cne [string]$authorization.host.machineGuidSha256 -or
        $hostId -cne ([string]$authorization.host.hyperVHostId).ToLowerInvariant() -or
        $osBuild -cne [string]$authorization.host.osBuild) {
        Throw-NgcbError 'NGCB-HOST-IDENTITY-MISMATCH'
    }

    $allVms = @(Hyper-V\Get-VM -ErrorAction Stop | Sort-Object Id)
    $vmRecords = @()
    $diskRecords = @()
    $adapterRecords = @()
    $existingProcessorCount = 0
    $existingMemoryMiB = 0
    foreach ($vm in $allVms) {
        $processor = Hyper-V\Get-VMProcessor -VM $vm -ErrorAction Stop
        $memory = Hyper-V\Get-VMMemory -VM $vm -ErrorAction Stop
        $existingProcessorCount += [int]$processor.Count
        $memoryReservation = if ($memory.DynamicMemoryEnabled) { [int64]$memory.Maximum } else { [int64]$memory.Startup }
        $existingMemoryMiB += [int64][Math]::Ceiling($memoryReservation / 1MB)
        $vmRecords += [pscustomobject][ordered]@{
            vmId = ([string]$vm.Id).ToLowerInvariant()
            name = [string]$vm.Name
            generation = [int]$vm.Generation
            state = [string]$vm.State
            path = [IO.Path]::GetFullPath([string]$vm.Path)
            notes = [string]$vm.Notes
        }
        foreach ($adapter in @(Hyper-V\Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)) {
            $adapterRecords += [pscustomobject][ordered]@{
                vmId = ([string]$vm.Id).ToLowerInvariant()
                adapterId = Get-NgcbAdapterIdentity $adapter ([string]$vm.Id)
                macAddress = ([string]$adapter.MacAddress).ToUpperInvariant()
                dynamicMacAddressEnabled = [bool]$adapter.DynamicMacAddressEnabled
                switchId = ([string]$adapter.SwitchId).ToLowerInvariant()
            }
        }
        foreach ($drive in @(Hyper-V\Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)) {
            $vhd = Hyper-V\Get-VHD -Path $drive.Path -ErrorAction Stop
            $diskRecords += [pscustomobject][ordered]@{
                vmId = ([string]$vm.Id).ToLowerInvariant()
                controllerType = [string]$drive.ControllerType
                controllerNumber = [int]$drive.ControllerNumber
                controllerLocation = [int]$drive.ControllerLocation
                path = [IO.Path]::GetFullPath([string]$drive.Path)
                diskIdentifier = ([string]$vhd.DiskIdentifier).ToLowerInvariant()
            }
        }
    }
    $vmRecords = @($vmRecords | Sort-Object vmId)
    $diskRecords = @($diskRecords | Sort-Object vmId,controllerType,controllerNumber,controllerLocation)

    $protectedRecords = @()
    foreach ($protected in @($authorization.protectedAssets | Sort-Object name)) {
        $matches = @($allVms | Where-Object { $_.Name -ceq [string]$protected.name })
        if ($matches.Count -ne 1 -or ([string]$matches[0].Id).ToLowerInvariant() -cne
            ([string]$protected.vmId).ToLowerInvariant()) { Throw-NgcbError 'NGCB-PROTECTED-ASSET-IDENTITY-DRIFT' }
        $vm = $matches[0]
        $actualDiskIds = @()
        foreach ($drive in @(Hyper-V\Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)) {
            $actualDiskIds += ([string](Hyper-V\Get-VHD -Path $drive.Path -ErrorAction Stop).DiskIdentifier).ToLowerInvariant()
        }
        $actualAdapterIds = @(Hyper-V\Get-VMNetworkAdapter -VM $vm -ErrorAction Stop |
            ForEach-Object { Get-NgcbAdapterIdentity $_ ([string]$vm.Id) })
        if ((@($actualDiskIds | Sort-Object) -join '|') -cne
                (@($protected.diskUniqueIds | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object) -join '|') -or
            (@($actualAdapterIds | Sort-Object) -join '|') -cne
                (@($protected.adapterIds | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object) -join '|')) {
            Throw-NgcbError 'NGCB-PROTECTED-ASSET-COMPONENT-DRIFT'
        }
        $protectedRecords += [pscustomobject][ordered]@{
            name = [string]$protected.name
            vmId = ([string]$protected.vmId).ToLowerInvariant()
            diskUniqueIds = @($actualDiskIds | Sort-Object)
            adapterIds = @($actualAdapterIds | Sort-Object)
        }
    }

    $switches = @(Hyper-V\Get-VMSwitch -Name ([string]$authorization.switch.name) -ErrorAction Stop)
    if ($switches.Count -ne 1 -or ([string]$switches[0].Id).ToLowerInvariant() -cne
        ([string]$authorization.switch.id).ToLowerInvariant()) { Throw-NgcbError 'NGCB-SWITCH-IDENTITY-MISMATCH' }
    $switch = $switches[0]
    $switchFingerprint = Get-NgcbSwitchFingerprint $switch
    if ($switchFingerprint -cne [string]$authorization.switch.fingerprint) {
        Throw-NgcbError 'NGCB-SWITCH-FINGERPRINT-MISMATCH'
    }
    $opnsense = @($allVms | Where-Object { $_.Name -ceq 'OPNsense-Tooling' })[0]
    $trunkAdapters = @(Hyper-V\Get-VMNetworkAdapter -VM $opnsense -ErrorAction Stop | Where-Object {
        (Get-NgcbAdapterIdentity $_ ([string]$opnsense.Id)) -ceq ([string]$authorization.switch.trunkAdapterId).ToLowerInvariant()
    })
    if ($trunkAdapters.Count -ne 1 -or ([string]$trunkAdapters[0].SwitchId).ToLowerInvariant() -cne
        ([string]$authorization.switch.id).ToLowerInvariant()) { Throw-NgcbError 'NGCB-TRUNK-IDENTITY-MISMATCH' }
    $trunkVlan = Hyper-V\Get-VMNetworkAdapterVlan -VMNetworkAdapter $trunkAdapters[0] -ErrorAction Stop
    $trunkFingerprint = Get-NgcbTrunkFingerprint $trunkAdapters[0] $trunkVlan `
        ([string]$opnsense.Id) ([string]$switch.Id)
    if ($trunkFingerprint -cne [string]$authorization.switch.trunkAdapterFingerprint) {
        Throw-NgcbError 'NGCB-TRUNK-FINGERPRINT-MISMATCH'
    }

    $volumeRecords = @()
    foreach ($volumePolicy in @($authorization.volumes | Sort-Object volumeId)) {
        $driveLetter = ([IO.Path]::GetPathRoot([string]$volumePolicy.root)).Substring(0,1)
        $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
        if ([string]$volume.UniqueId -cne [string]$volumePolicy.uniqueId) {
            Throw-NgcbError 'NGCB-VOLUME-IDENTITY-MISMATCH'
        }
        $volumeRecords += [pscustomobject][ordered]@{
            volumeId = [string]$volumePolicy.volumeId
            uniqueId = [string]$volume.UniqueId
            root = [IO.Path]::GetFullPath([string]$volumePolicy.root).TrimEnd('\')
            sizeBytes = [int64]$volume.Size
            freeBytes = [int64]$volume.SizeRemaining
        }
    }
    $imageItem = Get-Item -LiteralPath ([string]$Resolved.Image.path) -Force -ErrorAction Stop
    if ($imageItem.PSIsContainer -or ($imageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $imageItem.Length -ne [int64]$Resolved.Image.sizeBytes) { Throw-NgcbError 'NGCB-IMAGE-ARTIFACT-MISMATCH' }
    $imageHash = (Get-FileHash -LiteralPath $imageItem.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($imageHash -cne [string]$Resolved.Image.sha256) { Throw-NgcbError 'NGCB-IMAGE-ARTIFACT-MISMATCH' }
    try {
        $bootstrapMediaItem = Get-Item -LiteralPath ([string]$Resolved.BootstrapMedia.path) -Force -ErrorAction Stop
        if ($bootstrapMediaItem.PSIsContainer -or
            ($bootstrapMediaItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $bootstrapMediaItem.Length -ne [int64]$Resolved.BootstrapMedia.sizeBytes) {
            Throw-NgcbError 'NGCB-BOOTSTRAP-MEDIA-ARTIFACT-MISMATCH'
        }
        $bootstrapMediaHash = (Get-FileHash -LiteralPath $bootstrapMediaItem.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($bootstrapMediaHash -cne [string]$Resolved.BootstrapMedia.sha256) {
            Throw-NgcbError 'NGCB-BOOTSTRAP-MEDIA-ARTIFACT-MISMATCH'
        }
    }
    catch {
        if ($_.Exception.Message -ceq 'NGCB-BOOTSTRAP-MEDIA-ARTIFACT-MISMATCH') { throw }
        Throw-NgcbError 'NGCB-BOOTSTRAP-MEDIA-ARTIFACT-MISMATCH'
    }
    $provenanceArtifact = Read-NgcbCanonicalLineJsonFile ([string]$Resolved.BootstrapMedia.provenancePath) `
        $script:MaximumArtifactBytes 'NGCB-BOOTSTRAP-MEDIA-PROVENANCE-INVALID'
    if ($provenanceArtifact.Sha256 -cne [string]$Resolved.BootstrapMedia.provenanceSha256) {
        Throw-NgcbError 'NGCB-BOOTSTRAP-MEDIA-PROVENANCE-MISMATCH'
    }
    $provenance = $provenanceArtifact.Value
    Assert-NgcbExactProperties $provenance @(
        'assetId','buildEpochUtc','builder','bundleManifestSha256','family','firmware','output','schema','source'
    ) 'NGCB-BOOTSTRAP-MEDIA-PROVENANCE-INVALID'
    Assert-NgcbExactProperties $provenance.builder @('name','version') 'NGCB-BOOTSTRAP-MEDIA-PROVENANCE-INVALID'
    Assert-NgcbExactProperties $provenance.firmware @('profile','secureBoot','template') 'NGCB-BOOTSTRAP-MEDIA-PROVENANCE-INVALID'
    Assert-NgcbExactProperties $provenance.output @('fileName','sha256','sizeBytes') 'NGCB-BOOTSTRAP-MEDIA-PROVENANCE-INVALID'
    Assert-NgcbExactProperties $provenance.source @('sha256','sizeBytes') 'NGCB-BOOTSTRAP-MEDIA-PROVENANCE-INVALID'
    $expectedFamily = if ($Resolved.BootstrapMedia.sourceImageId -ceq 'windows-11-25h2-english-x64') {
        'windows'
    } elseif ($Resolved.BootstrapMedia.sourceImageId -ceq 'kali-2026.2-installer-netinst-amd64') {
        'kali'
    } else { 'debian' }
    $expectedFirmwareTemplate = if ([bool]$Resolved.Image.secureBootEnabled) {
        [string]$Resolved.Image.secureBootTemplate
    } else { 'Disabled' }
    if ($provenance.schema -cne 'northgate/bootstrap-media-output-provenance/v1' -or
        $provenance.assetId -cne $Resolved.Manifest.metadata.assetId -or $provenance.family -cne $expectedFamily -or
        $provenance.buildEpochUtc -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' -or
        $provenance.builder.name -notin @('genisoimage','xorriso') -or [string]::IsNullOrWhiteSpace([string]$provenance.builder.version) -or
        $provenance.bundleManifestSha256 -cne $Resolved.BootstrapMedia.bundleManifestSha256 -or
        $provenance.source.sha256 -cne $Resolved.BootstrapMedia.sourceImageSha256 -or
        [int64]$provenance.source.sizeBytes -ne [int64]$Resolved.Image.sizeBytes -or
        $provenance.output.fileName -cne [IO.Path]::GetFileName([string]$Resolved.BootstrapMedia.path) -or
        $provenance.output.sha256 -cne $Resolved.BootstrapMedia.sha256 -or
        [int64]$provenance.output.sizeBytes -ne [int64]$Resolved.BootstrapMedia.sizeBytes -or
        $provenance.firmware.profile -cne $Resolved.Manifest.spec.firmwareProfileRef -or
        [bool]$provenance.firmware.secureBoot -ne [bool]$Resolved.Image.secureBootEnabled -or
        $provenance.firmware.template -cne $expectedFirmwareTemplate) {
        Throw-NgcbError 'NGCB-BOOTSTRAP-MEDIA-PROVENANCE-INVALID'
    }
    return [pscustomobject][ordered]@{
        host = [pscustomobject][ordered]@{
            computerName = $env:COMPUTERNAME
            machineGuidSha256 = $machineGuidHash
            hyperVHostId = $hostId
            osBuild = $osBuild
            logicalProcessorCount = [int][Environment]::ProcessorCount
            memoryCapacityMiB = [int64][Math]::Floor([int64]$computerSystem.TotalPhysicalMemory / 1MB)
        }
        protectedAssets = @($protectedRecords)
        switch = [pscustomobject][ordered]@{
            id = ([string]$switch.Id).ToLowerInvariant()
            fingerprint = $switchFingerprint
            trunkAdapterId = Get-NgcbAdapterIdentity $trunkAdapters[0] ([string]$opnsense.Id)
            trunkAdapterFingerprint = $trunkFingerprint
        }
        volumes = @($volumeRecords)
        selectedImage = [pscustomobject][ordered]@{
            path = [IO.Path]::GetFullPath($imageItem.FullName)
            sizeBytes = [int64]$imageItem.Length
            sha256 = $imageHash
        }
        selectedBootstrapMedia = [pscustomobject][ordered]@{
            mediaId = [string]$Resolved.BootstrapMedia.mediaId
            path = [IO.Path]::GetFullPath($bootstrapMediaItem.FullName)
            sizeBytes = [int64]$bootstrapMediaItem.Length
            sha256 = $bootstrapMediaHash
        }
        selectedBootstrapProvenance = [pscustomobject][ordered]@{
            path = [IO.Path]::GetFullPath($provenanceArtifact.Path)
            sha256 = [string]$provenanceArtifact.Sha256
            bundleManifestSha256 = [string]$Resolved.BootstrapMedia.bundleManifestSha256
        }
        vms = @($vmRecords)
        disks = @($diskRecords)
        adapters = @($adapterRecords | Sort-Object vmId,adapterId)
        existingProcessorCount = $existingProcessorCount
        existingMemoryMiB = $existingMemoryMiB
    }
}

function Get-NgcbInertSnapshot {
    param([object]$Context, [object]$Resolved)
    $null = $Resolved
    $state = $Context.TestState
    return [pscustomobject][ordered]@{
        host = $state.host
        protectedAssets = @($state.protectedAssets)
        switch = $state.switch
        volumes = @($state.volumes)
        selectedImage = $state.selectedImage
        selectedBootstrapMedia = $state.selectedBootstrapMedia
        selectedBootstrapProvenance = $state.selectedBootstrapProvenance
        vms = @($state.vms)
        disks = @($state.disks)
        adapters = @($state.adapters)
        existingProcessorCount = [int]$state.existingProcessorCount
        existingMemoryMiB = [int64]$state.existingMemoryMiB
    }
}

function Get-NgcbLedgerPath { param([object]$Context) Join-Path $Context.StateRoot 'ledger\identity-ledger.json' }

function Read-NgcbLedger {
    param([object]$Context)
    $path = Get-NgcbLedgerPath $Context
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            schema = 'northgate/create-only-identity-ledger/v1'
            sequence = 0
            entries = [object[]]@()
        }
    }
    $envelope = Read-NgcbEnvelope $Context 'identity-ledger' $path 'NGCB-LEDGER-CORRUPT'
    $ledger = $envelope.record
    Assert-NgcbExactProperties $ledger @('schema','sequence','entries') 'NGCB-LEDGER-CORRUPT'
    if ($ledger.schema -cne 'northgate/create-only-identity-ledger/v1' -or
        $ledger.sequence -isnot [int] -and $ledger.sequence -isnot [long]) { Throw-NgcbError 'NGCB-LEDGER-CORRUPT' }
    $activeAssetSet = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $activeNameSet = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $reservationSet = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $planSet = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $vmIdSet = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($ledger.entries)) {
        Assert-NgcbExactProperties $entry @(
            'assetId','name','reservationId','changeId','planId','vmId','state','assetRoot','vhdPath','updatedAtUtc'
        ) 'NGCB-LEDGER-CORRUPT'
        if ($entry.state -notin @('Reserved','Applying','Bound','Quarantined','OutcomeUnknown','AbortedNoArtifacts') -or
            $entry.reservationId -cnotmatch '^ngrsv-[a-f0-9]{64}$' -or
            $entry.planId -cnotmatch '^ngp-[a-f0-9]{64}$' -or
            -not $reservationSet.Add([string]$entry.reservationId) -or
            -not $planSet.Add([string]$entry.planId) -or
            ($entry.vmId -ne '' -and -not $vmIdSet.Add([string]$entry.vmId)) -or
            ($entry.state -ceq 'AbortedNoArtifacts' -and $entry.vmId -ne '')) {
            Throw-NgcbError 'NGCB-LEDGER-CORRUPT'
        }
        # Finalized no-artifact attempts remain immutable history.  They do not
        # reserve the asset identity forever, but every other state does.
        if ($entry.state -cne 'AbortedNoArtifacts' -and
            (-not $activeAssetSet.Add([string]$entry.assetId) -or
             -not $activeNameSet.Add([string]$entry.name))) {
            Throw-NgcbError 'NGCB-LEDGER-CORRUPT'
        }
    }
    return $ledger
}

function Save-NgcbLedger {
    param([object]$Context, [object]$Ledger)
    $Ledger.sequence = [int64]$Ledger.sequence + 1
    $null = Write-NgcbEnvelope $Context 'identity-ledger' $Ledger (Get-NgcbLedgerPath $Context)
}

function Get-NgcbRolloutRoot { param([object]$Context) Join-Path $Context.StateRoot 'rollout' }
function Get-NgcbRolloutCurrentPath { param([object]$Context) Join-Path (Get-NgcbRolloutRoot $Context) 'current.json' }
function Get-NgcbRolloutPromotionPath {
    param([object]$Context,[int]$Sequence,[string]$PromotionId)
    if ($Sequence -notin @(1,2) -or $PromotionId -cnotmatch '^ngrollout-[a-f0-9]{64}$') {
        Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-ID-INVALID'
    }
    Join-Path (Join-Path (Get-NgcbRolloutRoot $Context) 'promotions') `
        (('{0:d2}-{1}.json' -f $Sequence,$PromotionId))
}

function Read-NgcbRolloutPromotionRecord {
    param([object]$Context,[string]$Path)
    $envelope = Read-NgcbEnvelope $Context 'rollout-promotion-record' $Path `
        'NGCB-ROLLOUT-PROMOTION-STATE-CORRUPT'
    $record = $envelope.record
    Assert-NgcbExactProperties $record @(
        'schema','promotion','promotionSha256','detachedCmsSignatureBase64',
        'detachedCmsSignatureSha256','signerCertificateSha256','registeredAtUtc'
    ) 'NGCB-ROLLOUT-PROMOTION-STATE-CORRUPT'
    if ($record.schema -cne 'northgate/create-only-rollout-promotion-record/v1' -or
        $record.promotionSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $record.detachedCmsSignatureSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $record.signerCertificateSha256 -cne
            [string]$Context.Authorization.identity.approvalSignerCertificateSha256) {
        Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-STATE-CORRUPT'
    }
    Assert-NgcbRolloutPromotionContract $Context $record.promotion
    $promotionBytes = Get-NgcbCanonicalBytes $record.promotion
    if ((Get-NgcbSha256Hex $promotionBytes) -cne $record.promotionSha256) {
        Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-STATE-CORRUPT'
    }
    try { $signatureBytes = [Convert]::FromBase64String([string]$record.detachedCmsSignatureBase64) }
    catch { Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-STATE-CORRUPT' }
    $signatureEvidence = Assert-NgcbDetachedCmsSignature $promotionBytes $signatureBytes `
        ([string]$Context.Authorization.identity.approvalSignerCertificateSha256) `
        'NGCB-ROLLOUT-PROMOTION-SIGNATURE-INVALID'
    if ($signatureEvidence.signatureSha256 -cne $record.detachedCmsSignatureSha256 -or
        $signatureEvidence.certificateSha256 -cne $record.signerCertificateSha256) {
        Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-STATE-CORRUPT'
    }
    return $record
}

function Get-NgcbEffectiveRolloutState {
    param([object]$Context)
    $currentPath = Get-NgcbRolloutCurrentPath $Context
    if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            sequence = 0
            promotionId = ''
            authorizationSha256 = [string]$Context.PolicySha256
            stage = [string]$Context.Policy.rollout.stage
            rollout = $Context.Policy.rollout
        }
    }
    $currentEnvelope = Read-NgcbEnvelope $Context 'rollout-promotion-anchor' $currentPath `
        'NGCB-ROLLOUT-PROMOTION-ANCHOR-CORRUPT'
    $anchor = $currentEnvelope.record
    Assert-NgcbExactProperties $anchor @(
        'schema','sequence','promotionId','promotionSha256','stage','registeredAtUtc'
    ) 'NGCB-ROLLOUT-PROMOTION-ANCHOR-CORRUPT'
    if ($anchor.schema -cne 'northgate/create-only-rollout-promotion-anchor/v1' -or
        $anchor.sequence -isnot [int] -and $anchor.sequence -isnot [long] -or
        [int]$anchor.sequence -notin @(1,2) -or
        $anchor.promotionId -cnotmatch '^ngrollout-[a-f0-9]{64}$' -or
        $anchor.promotionSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $anchor.stage -notin @('windows-canary','persistent-fleet')) {
        Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-ANCHOR-CORRUPT'
    }
    $expectedPrevious = [string]$Context.PolicySha256
    $expectedStage = [string]$Context.Policy.rollout.stage
    $lastRecord = $null
    for ($sequence = 1; $sequence -le [int]$anchor.sequence; $sequence++) {
        $matches = @(Get-ChildItem -LiteralPath (Join-Path (Get-NgcbRolloutRoot $Context) 'promotions') `
            -Filter (('{0:d2}-*.json' -f $sequence)) -File -ErrorAction SilentlyContinue)
        if ($matches.Count -ne 1) { Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-CHAIN-CORRUPT' }
        $record = Read-NgcbRolloutPromotionRecord $Context $matches[0].FullName
        $promotion = $record.promotion
        if ([int]$promotion.sequence -ne $sequence -or
            $promotion.previousAuthorizationSha256 -cne $expectedPrevious -or
            $promotion.fromStage -cne $expectedStage) {
            Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-CHAIN-CORRUPT'
        }
        $expectedPrevious = [string]$record.promotionSha256
        $expectedStage = [string]$promotion.toStage
        $lastRecord = $record
    }
    if ($null -eq $lastRecord -or $anchor.promotionId -cne $lastRecord.promotion.promotionId -or
        $anchor.promotionSha256 -cne $lastRecord.promotionSha256 -or
        $anchor.stage -cne $lastRecord.promotion.toStage) {
        Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-CHAIN-CORRUPT'
    }
    return [pscustomobject][ordered]@{
        sequence = [int]$anchor.sequence
        promotionId = [string]$anchor.promotionId
        authorizationSha256 = [string]$anchor.promotionSha256
        stage = [string]$anchor.stage
        rollout = $lastRecord.promotion.rollout
    }
}

function Assert-NgcbCanaryRolloutEvidence {
    param([object]$Context,[object]$Gate,[object]$Ledger,[object]$Identity)
    $entries = @($Ledger.entries | Where-Object { $_.assetId -ceq $Gate.assetId })
    if ($entries.Count -ne 1 -or $entries[0].state -cne 'Bound') {
        Throw-NgcbError 'NGCB-ROLLOUT-CANARY-RECEIPT-MISSING'
    }
    $receiptEnvelope = Read-NgcbEnvelope $Context 'signed-receipt-record' `
        (Get-NgcbReceiptPath $Context ([string]$entries[0].planId)) 'NGCB-ROLLOUT-CANARY-RECEIPT-MISSING'
    $record = $receiptEnvelope.record
    $receiptBytes = Get-NgcbCanonicalBytes $record.receipt
    if ((Get-NgcbSha256Hex $receiptBytes) -cne $record.receiptSha256 -or
        $record.receiptSha256 -cne $Gate.receiptSha256 -or $record.receipt.outcome -cne 'Succeeded' -or
        $record.receipt.afterStateVerified -ne $true -or $record.receipt.operation.assetId -cne $Gate.assetId) {
        Throw-NgcbError 'NGCB-ROLLOUT-CANARY-RECEIPT-MISMATCH'
    }
    try { $signatureBytes = [Convert]::FromBase64String([string]$record.detachedCmsSignatureBase64) }
    catch { Throw-NgcbError 'NGCB-ROLLOUT-CANARY-RECEIPT-MISMATCH' }
    $signatureEvidence = Assert-NgcbDetachedCmsSignature $receiptBytes $signatureBytes `
        ([string]$Context.Authorization.identity.receiptSignerCertificateSha256) `
        'NGCB-ROLLOUT-CANARY-RECEIPT-MISMATCH'
    if ($signatureEvidence.signatureSha256 -cne $record.detachedCmsSignatureSha256 -or
        $signatureEvidence.certificateSha256 -cne $record.signerCertificateSha256) {
        Throw-NgcbError 'NGCB-ROLLOUT-CANARY-RECEIPT-MISMATCH'
    }
    $matches = @($Identity.vms | Where-Object {
        $_.notes -match ('(?:^|;)assetId=' + [regex]::Escape([string]$Gate.assetId) + '(?:;|$)')
    })
    if ($matches.Count -gt 1) { Throw-NgcbError 'NGCB-ROLLOUT-CANARY-NOT-RETIRED' }
    if ($matches.Count -eq 1) {
        if ([string]$matches[0].state -cne 'Off' -or
            @($Identity.adapters | Where-Object { $_.vmId -ceq $matches[0].vmId -and $_.switchId -ne '' }).Count -ne 0) {
            Throw-NgcbError 'NGCB-ROLLOUT-CANARY-NOT-RETIRED'
        }
    }
}

function Get-NgcbAuthoritativeLedgerEntries {
    param([object]$Context,[object]$Ledger)
    if ($null -eq $Ledger) { $Ledger = Read-NgcbLedger $Context }
    $authoritative = @()
    foreach ($entry in @($Ledger.entries)) {
        if ($entry.state -cne 'AbortedNoArtifacts') {
            $authoritative += $entry
            continue
        }

        # An AbortedNoArtifacts ledger state alone is not enough to release an
        # identity.  Crash recovery must re-observe the host, then authenticate
        # both the terminal plan state and its chained journal event.
        $parsedPlan = Read-NgcbPlanRecord $Context ([string]$entry.planId)
        $lastJournal = Read-NgcbLastJournalEvent $Context `
            ([string]$entry.assetId) ([string]$entry.reservationId)
        if ($parsedPlan.Plan.planId -cne $entry.planId -or
            $parsedPlan.Plan.reservationId -cne $entry.reservationId -or
            $parsedPlan.Plan.operation.assetId -cne $entry.assetId -or
            $parsedPlan.Plan.operation.name -cne $entry.name -or
            $parsedPlan.Record.state -cne 'RecoveredNoArtifacts' -or
            $parsedPlan.Record.quarantineState -cne 'not-required' -or
            $parsedPlan.Record.evidenceState -cne 'recovery-journal-complete' -or
            $entry.vmId -ne '' -or $null -eq $lastJournal -or
            $lastJournal.planId -cne $entry.planId -or
            $lastJournal.state -cne 'RecoveredNoArtifacts' -or
            $lastJournal.vmId -ne '' -or
            $lastJournal.detailCode -cne 'NGCB-RECOVERY-NO-ARTIFACTS') {
            Throw-NgcbError 'NGCB-RETRY-RECOVERY-FINALIZATION-REQUIRED'
        }
    }
    return @($authoritative)
}

function Assert-NgcbRolloutState {
    param([object]$Context,[string]$AssetId,[object]$Identity)
    $rolloutState = Get-NgcbEffectiveRolloutState $Context
    $rollout = $rolloutState.rollout
    $ledger = Read-NgcbLedger $Context
    $entries = @(Get-NgcbAuthoritativeLedgerEntries $Context $ledger)
    if (@($entries | Where-Object { $_.state -ne 'Bound' }).Count -ne 0) {
        Throw-NgcbError 'NGCB-ROLLOUT-TRANSACTION-INCOMPLETE'
    }
    if ($entries.Count -ge $script:ExactFleetAssetIds.Count) { Throw-NgcbError 'NGCB-ROLLOUT-COMPLETE' }
    for ($index=0;$index-lt $entries.Count;$index++) {
        if ($entries[$index].assetId -cne $script:ExactFleetAssetIds[$index]) {
            Throw-NgcbError 'NGCB-ROLLOUT-ORDER-INVALID'
        }
    }
    if ($AssetId -cne $script:ExactFleetAssetIds[$entries.Count]) {
        Throw-NgcbError 'NGCB-ROLLOUT-ORDER-INVALID'
    }
    $stage = [string]$rolloutState.stage
    if ($entries.Count -eq 0) {
        if ($stage -cne 'debian-canary') { Throw-NgcbError 'NGCB-ROLLOUT-STAGE-INVALID' }
        return $rolloutState
    }
    if ($entries.Count -eq 1) {
        if ($stage -cne 'windows-canary') { Throw-NgcbError 'NGCB-ROLLOUT-STAGE-ADVANCE-REQUIRED' }
        Assert-NgcbCanaryRolloutEvidence $Context $rollout.debianCanary `
            ([pscustomobject]@{ entries = [object[]]$entries }) $Identity
        return $rolloutState
    }
    if ($stage -cne 'persistent-fleet') { Throw-NgcbError 'NGCB-ROLLOUT-STAGE-ADVANCE-REQUIRED' }
    $authoritativeLedger = [pscustomobject]@{ entries = [object[]]$entries }
    Assert-NgcbCanaryRolloutEvidence $Context $rollout.debianCanary $authoritativeLedger $Identity
    Assert-NgcbCanaryRolloutEvidence $Context $rollout.windowsCanary $authoritativeLedger $Identity
    return $rolloutState
}

function Enter-NgcbLockSet {
    param([object]$Context, [string]$AssetId)
    $globalMutex = New-Object Threading.Mutex($false, $script:GlobalMutexName)
    $assetMutexName = 'Global\NorthGateVmFactoryCreateOnlyAsset-' + `
        (Get-NgcbStringSha256Hex $AssetId).Substring(0,32)
    $assetMutex = New-Object Threading.Mutex($false, $assetMutexName)
    $acquiredGlobal = $false
    $acquiredAsset = $false
    $fileStream = $null
    try {
        $acquiredGlobal = $globalMutex.WaitOne([TimeSpan]::FromSeconds(15))
        if (-not $acquiredGlobal) { Throw-NgcbError 'NGCB-GLOBAL-WRITER-LOCK-BUSY' }
        $acquiredAsset = $assetMutex.WaitOne([TimeSpan]::FromSeconds(15))
        if (-not $acquiredAsset) { Throw-NgcbError 'NGCB-ASSET-WRITER-LOCK-BUSY' }
        $lockPath = Join-Path $Context.StateRoot ('locks\' + $AssetId + '.lck')
        $fileStream = New-Object IO.FileStream(
            $lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None
        )
        return [pscustomobject]@{
            GlobalMutex = $globalMutex; AssetMutex = $assetMutex; FileStream = $fileStream
            AcquiredGlobal = $acquiredGlobal; AcquiredAsset = $acquiredAsset
        }
    }
    catch {
        if ($null -ne $fileStream) { $fileStream.Dispose() }
        if ($acquiredAsset) { $assetMutex.ReleaseMutex() }
        if ($acquiredGlobal) { $globalMutex.ReleaseMutex() }
        $assetMutex.Dispose(); $globalMutex.Dispose()
        throw
    }
}

function Exit-NgcbLockSet {
    param([object]$Lock)
    if ($null -eq $Lock) { return }
    if ($null -ne $Lock.FileStream) { $Lock.FileStream.Dispose() }
    if ($Lock.AcquiredAsset) { $Lock.AssetMutex.ReleaseMutex() }
    if ($Lock.AcquiredGlobal) { $Lock.GlobalMutex.ReleaseMutex() }
    $Lock.AssetMutex.Dispose(); $Lock.GlobalMutex.Dispose()
}

function Get-NgcbObservedState {
    param([object]$Context, [object]$Resolved, [string]$ReservationId = '')
    Assert-NgcbContext $Context
    $snapshot = if ($Context.Mode -ceq 'Production') {
        Get-NgcbProductionSnapshot $Context $Resolved
    } else { Get-NgcbInertSnapshot $Context $Resolved }
    $authorization = $Context.Authorization
    if ($snapshot.host.computerName -cne $authorization.host.computerName -or
        $snapshot.host.machineGuidSha256 -cne $authorization.host.machineGuidSha256 -or
        $snapshot.host.hyperVHostId -cne $authorization.host.hyperVHostId -or
        $snapshot.host.osBuild -cne $authorization.host.osBuild -or
        $snapshot.switch.id -cne ([string]$authorization.switch.id).ToLowerInvariant() -or
        $snapshot.switch.fingerprint -cne $authorization.switch.fingerprint -or
        $snapshot.switch.trunkAdapterId -cne ([string]$authorization.switch.trunkAdapterId).ToLowerInvariant() -or
        $snapshot.switch.trunkAdapterFingerprint -cne $authorization.switch.trunkAdapterFingerprint) {
        Throw-NgcbError 'NGCB-LIVE-AUTHORIZATION-DRIFT'
    }
    if ((ConvertTo-NorthGateCreateOnlyCanonicalJson @($snapshot.protectedAssets | Sort-Object name)) -cne
        (ConvertTo-NorthGateCreateOnlyCanonicalJson @($authorization.protectedAssets | ForEach-Object {
            [pscustomobject][ordered]@{
                name = [string]$_.name
                vmId = ([string]$_.vmId).ToLowerInvariant()
                diskUniqueIds = @($_.diskUniqueIds | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object)
                adapterIds = @($_.adapterIds | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object)
            }
        } | Sort-Object name))) {
        Throw-NgcbError 'NGCB-PROTECTED-ASSET-IDENTITY-DRIFT'
    }
    $assetId = [string]$Resolved.Manifest.metadata.assetId
    $name = [string]$Resolved.Manifest.metadata.name
    $assetVmCollisions = @($snapshot.vms | Where-Object {
        $_.notes -match ('(?:^|;)assetId=' + [regex]::Escape($assetId) + '(?:;|$)')
    })
    $nameVmCollisions = @($snapshot.vms | Where-Object { $_.name -ieq $name })
    $diskCollisions = @($snapshot.disks | Where-Object {
        [IO.Path]::GetFullPath([string]$_.path) -ieq [IO.Path]::GetFullPath($Resolved.VhdPath)
    })
    $macCollisions = @($snapshot.adapters | Where-Object {
        ([string]$_.macAddress).ToUpperInvariant() -ceq ([string]$Resolved.AllowedAsset.staticMacAddress).ToUpperInvariant()
    })
    $ledger = Read-NgcbLedger $Context
    $authoritativeLedgerEntries = @(Get-NgcbAuthoritativeLedgerEntries $Context $ledger)
    $ledgerCollisions = @($authoritativeLedgerEntries | Where-Object {
        ($_.assetId -ieq $assetId -or $_.name -ieq $name) -and
        ($ReservationId -eq '' -or $_.reservationId -cne $ReservationId)
    })
    $assetRootExists = Test-Path -LiteralPath $Resolved.AssetRoot
    $vhdPathExists = Test-Path -LiteralPath $Resolved.VhdPath
    Assert-NgcbNoReparseAncestor $Resolved.StorageRoot | Out-Null
    Assert-NgcbNoReparseAncestor $Resolved.AssetRoot | Out-Null
    $volume = Get-NgcbUniqueEntry @($snapshot.volumes) 'volumeId' ([string]$Resolved.Storage.volumeId) `
        'NGCB-LIVE-VOLUME-NOT-FOUND'
    if ($volume.uniqueId -cne $Resolved.AuthorizedVolume.uniqueId -or
        [IO.Path]::GetFullPath([string]$volume.root).TrimEnd('\') -ine $Resolved.StorageRoot) {
        Throw-NgcbError 'NGCB-LIVE-VOLUME-IDENTITY-MISMATCH'
    }
    if ($snapshot.selectedImage.sha256 -cne $Resolved.Image.sha256 -or
        [int64]$snapshot.selectedImage.sizeBytes -ne [int64]$Resolved.Image.sizeBytes -or
        [IO.Path]::GetFullPath([string]$snapshot.selectedImage.path) -ine
            [IO.Path]::GetFullPath([string]$Resolved.Image.path)) {
        Throw-NgcbError 'NGCB-LIVE-IMAGE-MISMATCH'
    }
    if ($snapshot.selectedBootstrapMedia.mediaId -cne $Resolved.BootstrapMedia.mediaId -or
        $snapshot.selectedBootstrapMedia.sha256 -cne $Resolved.BootstrapMedia.sha256 -or
        [int64]$snapshot.selectedBootstrapMedia.sizeBytes -ne [int64]$Resolved.BootstrapMedia.sizeBytes -or
        [IO.Path]::GetFullPath([string]$snapshot.selectedBootstrapMedia.path) -ine
            [IO.Path]::GetFullPath([string]$Resolved.BootstrapMedia.path)) {
        Throw-NgcbError 'NGCB-LIVE-BOOTSTRAP-MEDIA-MISMATCH'
    }
    if ($snapshot.selectedBootstrapProvenance.sha256 -cne $Resolved.BootstrapMedia.provenanceSha256 -or
        $snapshot.selectedBootstrapProvenance.bundleManifestSha256 -cne $Resolved.BootstrapMedia.bundleManifestSha256 -or
        [IO.Path]::GetFullPath([string]$snapshot.selectedBootstrapProvenance.path) -ine
            [IO.Path]::GetFullPath([string]$Resolved.BootstrapMedia.provenancePath)) {
        Throw-NgcbError 'NGCB-LIVE-BOOTSTRAP-PROVENANCE-MISMATCH'
    }
    $reservationMemory = [int64]$Resolved.MaximumMemoryMiB
    $reservationProcessors = [int]$Resolved.Manifest.spec.compute.processors
    $reservationStorageBytes = [int64]$Resolved.Manifest.spec.storage.osDiskGiB * 1GB
    $availableMemory = [int64]$snapshot.host.memoryCapacityMiB - [int64]$snapshot.existingMemoryMiB -
        [int64]$Context.Policy.limits.hostReserveMemoryMiB
    $logicalProcessors = [int]$snapshot.host.logicalProcessorCount
    $physicalProcessorReserve = [int]$Context.Policy.limits.hostProcessorReserveCount
    $vcpuRatio = [int]$Context.Policy.limits.maximumVcpuToLogicalRatio
    if ($physicalProcessorReserve -ge $logicalProcessors) { Throw-NgcbError 'NGCB-CAPACITY-POLICY-INVALID' }
    $maximumConfiguredProcessors = ($logicalProcessors - $physicalProcessorReserve) * $vcpuRatio
    $availableProcessors = $maximumConfiguredProcessors - [int]$snapshot.existingProcessorCount
    $minimumFree = [Math]::Max(
        [int64]$Context.Policy.limits.minimumVolumeFreeBytes,
        [int64][Math]::Ceiling([int64]$volume.sizeBytes * ([double]$Context.Policy.limits.minimumVolumeFreePercent / 100.0))
    )
    $capacityPass = $availableMemory -ge $reservationMemory -and
        $availableProcessors -ge $reservationProcessors -and
        ([int64]$volume.freeBytes - $reservationStorageBytes) -ge $minimumFree
    $identityRecord = [pscustomobject][ordered]@{
        host = [pscustomobject][ordered]@{
            computerName = [string]$snapshot.host.computerName
            machineGuidSha256 = [string]$snapshot.host.machineGuidSha256
            hyperVHostId = [string]$snapshot.host.hyperVHostId
            osBuild = [string]$snapshot.host.osBuild
        }
        protectedAssets = @($snapshot.protectedAssets)
        switch = $snapshot.switch
        volumes = @($snapshot.volumes | ForEach-Object {
            [pscustomobject][ordered]@{ volumeId=$_.volumeId; uniqueId=$_.uniqueId; root=$_.root; sizeBytes=[int64]$_.sizeBytes }
        })
        selectedImage = $snapshot.selectedImage
        selectedBootstrapMedia = $snapshot.selectedBootstrapMedia
        selectedBootstrapProvenance = $snapshot.selectedBootstrapProvenance
        vms = @($snapshot.vms)
        disks = @($snapshot.disks)
        adapters = @($snapshot.adapters)
        target = [pscustomobject][ordered]@{
            assetId = $assetId; name = $name; assetRoot = $Resolved.AssetRoot; vhdPath = $Resolved.VhdPath
            assetCollisionCount = $assetVmCollisions.Count
            nameCollisionCount = $nameVmCollisions.Count
            diskCollisionCount = $diskCollisions.Count
            macCollisionCount = $macCollisions.Count
            ledgerCollisionCount = $ledgerCollisions.Count
            assetRootExists = [bool]$assetRootExists
            vhdPathExists = [bool]$vhdPathExists
        }
    }
    $capacityRecord = [pscustomobject][ordered]@{
        logicalProcessorCount = [int]$snapshot.host.logicalProcessorCount
        existingProcessorCount = [int]$snapshot.existingProcessorCount
        processorReserveCount = [int]$Context.Policy.limits.hostProcessorReserveCount
        maximumVcpuToLogicalRatio = $vcpuRatio
        maximumConfiguredProcessorCount = $maximumConfiguredProcessors
        configuredProcessorHeadroom = $availableProcessors
        requestedProcessorCount = $reservationProcessors
        memoryCapacityMiB = [int64]$snapshot.host.memoryCapacityMiB
        existingMemoryMiB = [int64]$snapshot.existingMemoryMiB
        memoryReserveMiB = [int64]$Context.Policy.limits.hostReserveMemoryMiB
        requestedMemoryMiB = $reservationMemory
        volumeSizeBytes = [int64]$volume.sizeBytes
        volumeFreeBytes = [int64]$volume.freeBytes
        minimumFreeBytes = $minimumFree
        requestedStorageBytes = $reservationStorageBytes
        pass = [bool]$capacityPass
    }
    return [pscustomobject][ordered]@{
        Identity = $identityRecord
        IdentityHash = Get-NgcbStringSha256Hex (ConvertTo-NorthGateCreateOnlyCanonicalJson $identityRecord)
        Capacity = $capacityRecord
        CapacityHash = Get-NgcbStringSha256Hex (ConvertTo-NorthGateCreateOnlyCanonicalJson $capacityRecord)
        CollisionFree = ($assetVmCollisions.Count -eq 0 -and $nameVmCollisions.Count -eq 0 -and
            $diskCollisions.Count -eq 0 -and $macCollisions.Count -eq 0 -and $ledgerCollisions.Count -eq 0 -and
            -not $assetRootExists -and -not $vhdPathExists)
    }
}

function Get-NgcbPlanPath { param([object]$Context, [string]$PlanId) Join-Path $Context.StateRoot ('plans\' + $PlanId + '.json') }
function Get-NgcbApprovalPath { param([object]$Context, [string]$PlanId) Join-Path $Context.StateRoot ('approvals\' + $PlanId + '.json') }
function Get-NgcbReceiptPath { param([object]$Context, [string]$PlanId) Join-Path $Context.StateRoot ('receipts\' + $PlanId + '.json') }

function Get-NgcbJournalDirectory {
    param([object]$Context, [string]$AssetId, [string]$ReservationId)
    Join-Path $Context.StateRoot ('journals\' + $AssetId + '\' + $ReservationId)
}

function Write-NgcbJournalEvent {
    param(
        [object]$Context, [string]$AssetId, [string]$ReservationId, [string]$PlanId,
        [string]$State, [string]$VmId = '', [string]$DetailCode = 'NGCB-JOURNAL-TRANSITION',
        [string]$AdapterId = '', [string]$StaticMacAddress = ''
    )
    $directory = Get-NgcbJournalDirectory $Context $AssetId $ReservationId
    $null = [IO.Directory]::CreateDirectory($directory)
    $existing = @(Get-ChildItem -LiteralPath $directory -Filter '*.json' -File -ErrorAction Stop | Sort-Object Name)
    $sequence = $existing.Count + 1
    $previousHash = if ($existing.Count -eq 0) { '0' * 64 } else {
        (Get-FileHash -LiteralPath $existing[-1].FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
    $event = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-journal-event/v1'
        sequence = $sequence
        recordedAtUtc = Format-NgcbUtc ([DateTimeOffset]::UtcNow)
        assetId = $AssetId
        reservationId = $ReservationId
        planId = $PlanId
        state = $State
        vmId = $VmId
        adapterId = $AdapterId
        staticMacAddress = $StaticMacAddress
        detailCode = $DetailCode
        previousEventSha256 = $previousHash
    }
    $path = Join-Path $directory ('{0:d8}.json' -f $sequence)
    $null = Write-NgcbEnvelope $Context 'journal-event' $event $path -CreateNew
    return $event
}

function Read-NgcbLastJournalEvent {
    param([object]$Context, [string]$AssetId, [string]$ReservationId)
    $directory = Get-NgcbJournalDirectory $Context $AssetId $ReservationId
    $files = @(Get-ChildItem -LiteralPath $directory -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)
    if ($files.Count -eq 0) { return $null }
    $previousHash = '0' * 64
    $expectedSequence = 1
    $last = $null
    foreach ($file in $files) {
        if ($file.Name -cne ('{0:d8}.json' -f $expectedSequence)) { Throw-NgcbError 'NGCB-JOURNAL-SEQUENCE-CORRUPT' }
        $envelope = Read-NgcbEnvelope $Context 'journal-event' $file.FullName 'NGCB-JOURNAL-CORRUPT'
        $event = $envelope.record
        Assert-NgcbExactProperties $event @(
            'schema','sequence','recordedAtUtc','assetId','reservationId','planId','state','vmId','adapterId','staticMacAddress',
            'detailCode','previousEventSha256'
        ) 'NGCB-JOURNAL-CORRUPT'
        if ($event.schema -cne 'northgate/create-only-journal-event/v1' -or
            $event.sequence -ne $expectedSequence -or $event.assetId -cne $AssetId -or
            $event.reservationId -cne $ReservationId -or $event.previousEventSha256 -cne $previousHash) {
            Throw-NgcbError 'NGCB-JOURNAL-CORRUPT'
        }
        $previousHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $last = $event
        $expectedSequence++
    }
    return $last
}

function Write-NgcbAuditEvent {
    param([object]$Context, [string]$Event, [string]$Outcome, [string]$Code, [string]$PlanId = '', [string]$AssetId = '')
    $record = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-audit-event/v1'
        eventId = 'ngaudit-' + (New-NgcbRandomHex 16)
        recordedAtUtc = Format-NgcbUtc ([DateTimeOffset]::UtcNow)
        event = $Event
        outcome = $Outcome
        reasonCode = $Code
        planId = $PlanId
        assetId = $AssetId
        processId = [int]$PID
    }
    $path = Join-Path $Context.StateRoot ('audit\' + $record.eventId + '.json')
    $null = Write-NgcbEnvelope $Context 'audit-event' $record $path -CreateNew
}

function Assert-NgcbPlanId {
    param([string]$PlanId)
    if ($PlanId -cnotmatch '^ngp-[a-f0-9]{64}$') { Throw-NgcbError 'NGCB-PLAN-ID-INVALID' }
}

function Read-NgcbPlanRecord {
    param([object]$Context, [string]$PlanId)
    Assert-NgcbPlanId $PlanId
    $envelope = Read-NgcbEnvelope $Context 'host-plan-record' (Get-NgcbPlanPath $Context $PlanId) `
        'NGCB-PLAN-RECORD-CORRUPT'
    $record = $envelope.record
    Assert-NgcbExactProperties $record @(
        'schema','planId','planHash','planAuthenticationHash','canonicalPlan','state','approvalState',
        'approvalId','approvalSha256','executionId','quarantineState','evidenceState'
    ) 'NGCB-PLAN-RECORD-CORRUPT'
    if ($record.schema -cne 'northgate/create-only-host-plan-record/v1' -or
        $record.planId -cne $PlanId -or $record.planHash -cnotmatch '^[a-f0-9]{64}$' -or
        $record.planAuthenticationHash -cnotmatch '^[a-f0-9]{64}$' -or
        (Get-NgcbStringSha256Hex ([string]$record.canonicalPlan)) -cne [string]$record.planHash) {
        Throw-NgcbError 'NGCB-PLAN-RECORD-CORRUPT'
    }
    $expectedAuthentication = Get-NgcbHmacHex $Context.StateKey `
        ("ngcb-host-plan-v1`n$PlanId`n$($record.planHash)")
    if (-not (Test-NgcbFixedHexEquals $expectedAuthentication ([string]$record.planAuthenticationHash))) {
        Throw-NgcbError 'NGCB-PLAN-RECORD-CORRUPT'
    }
    try { $plan = ConvertFrom-NgcbJsonText ([string]$record.canonicalPlan) }
    catch { Throw-NgcbError 'NGCB-PLAN-RECORD-CORRUPT' }
    return [pscustomobject][ordered]@{ Record = $record; Plan = $plan; Envelope = $envelope }
}

function Save-NgcbPlanRecord {
    param([object]$Context, [object]$Record, [switch]$CreateNew)
    $null = Write-NgcbEnvelope $Context 'host-plan-record' $Record `
        (Get-NgcbPlanPath $Context ([string]$Record.planId)) -CreateNew:$CreateNew
}

function Get-NorthGateCreateOnlyBackendState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)
    Assert-NgcbContext $Context
    $incomplete = 0
    foreach ($entry in @((Read-NgcbLedger $Context).entries)) {
        if ($entry.state -in @('Reserved','Applying','OutcomeUnknown')) { $incomplete++ }
    }
    $rolloutState = Get-NgcbEffectiveRolloutState $Context
    [pscustomobject][ordered]@{
        backendVersion = $script:BackendVersion
        mode = $Context.Mode
        repositoryIdentity = $script:RepositoryIdentity
        releaseManifestSha256 = $Context.ReleaseManifestSha256
        authorizationSha256 = $Context.AuthorizationSha256
        policySha256 = $Context.PolicySha256
        rolloutAuthorizationSha256 = [string]$rolloutState.authorizationSha256
        rolloutSequence = [int]$rolloutState.sequence
        rolloutStage = [string]$rolloutState.stage
        dataBundleSha256 = $Context.DataBundleSha256
        applyEnabled = [bool]$Context.Policy.applyEnabled
        executableActions = @($Context.Policy.executableActions)
        createOnly = $true
        generation = 2
        destructiveOperationsExposed = $false
        incompleteTransactionCount = $incomplete
    }
}

function Get-NgcbRolloutIdentitySnapshot {
    param([object]$Context)
    if ($Context.Mode -ne 'Production') {
        return [pscustomobject][ordered]@{
            vms = [object[]]@($Context.TestState.vms)
            adapters = [object[]]@($Context.TestState.adapters)
        }
    }
    $vms = @()
    $adapters = @()
    foreach ($vm in @(Hyper-V\Get-VM -ErrorAction Stop | Sort-Object Id)) {
        $vmId = ([string]$vm.Id).ToLowerInvariant()
        $vms += [pscustomobject][ordered]@{
            vmId = $vmId
            name = [string]$vm.Name
            state = [string]$vm.State
            notes = [string]$vm.Notes
        }
        foreach ($adapter in @(Hyper-V\Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)) {
            $adapters += [pscustomobject][ordered]@{
                vmId = $vmId
                adapterId = Get-NgcbAdapterIdentity $adapter $vmId
                switchId = if ([string]$adapter.SwitchId -eq '') { '' } `
                    else { ([string]$adapter.SwitchId).ToLowerInvariant() }
            }
        }
    }
    return [pscustomobject][ordered]@{ vms=[object[]]$vms; adapters=[object[]]$adapters }
}

function Get-NgcbRolloutPromotionContextCore {
    param([object]$Context)
    $effective = Get-NgcbEffectiveRolloutState $Context
    if ([int]$effective.sequence -ge 2) { Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-COMPLETE' }
    $nextSequence = [int]$effective.sequence + 1
    $requiredCanaryAssetId = if ($nextSequence -eq 1) { 'NG-VM-018' } else { 'NG-VM-010' }
    $toStage = if ($nextSequence -eq 1) { 'windows-canary' } else { 'persistent-fleet' }
    $ledger = Read-NgcbLedger $Context
    $entries = @(Get-NgcbAuthoritativeLedgerEntries $Context $ledger)
    if (@($entries | Where-Object { $_.state -cne 'Bound' }).Count -ne 0 -or
        $entries.Count -ne $nextSequence) {
        Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-LEDGER-NOT-READY'
    }
    for ($index=0;$index-lt $entries.Count;$index++) {
        if ($entries[$index].assetId -cne $script:ExactFleetAssetIds[$index]) {
            Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-LEDGER-NOT-READY'
        }
    }
    $canaryEntry = @($entries | Where-Object { $_.assetId -ceq $requiredCanaryAssetId })
    if ($canaryEntry.Count -ne 1) { Throw-NgcbError 'NGCB-ROLLOUT-CANARY-RECEIPT-MISSING' }
    $receiptEnvelope = Read-NgcbEnvelope $Context 'signed-receipt-record' `
        (Get-NgcbReceiptPath $Context ([string]$canaryEntry[0].planId)) `
        'NGCB-ROLLOUT-CANARY-RECEIPT-MISSING'
    $parsedPlan = Read-NgcbPlanRecord $Context ([string]$canaryEntry[0].planId)
    Assert-NgcbReceiptRecord $Context $receiptEnvelope.record $parsedPlan
    $identity = Get-NgcbRolloutIdentitySnapshot $Context
    $receiptGate = [pscustomobject][ordered]@{
        assetId = $requiredCanaryAssetId
        status = 'accepted-retired'
        receiptSha256 = [string]$receiptEnvelope.record.receiptSha256
        acceptanceEvidenceSha256 = '0' * 64
        retirementEvidenceSha256 = '0' * 64
    }
    Assert-NgcbCanaryRolloutEvidence $Context $receiptGate `
        ([pscustomobject]@{entries=[object[]]$entries}) $identity
    return [pscustomobject][ordered]@{
        schema = 'northgate/create-only-rollout-promotion-context/v1'
        nextSequence = $nextSequence
        previousAuthorizationSha256 = [string]$effective.authorizationSha256
        basePolicySha256 = [string]$Context.PolicySha256
        authorizationSha256 = [string]$Context.AuthorizationSha256
        releaseManifestSha256 = [string]$Context.ReleaseManifestSha256
        dataBundleSha256 = [string]$Context.DataBundleSha256
        repository = [pscustomobject][ordered]@{
            identity = $script:RepositoryIdentity
            commit = [string]$Context.ReleaseManifest.repository.commit
            tree = [string]$Context.ReleaseManifest.repository.tree
        }
        fromStage = [string]$effective.stage
        permittedToStage = $toStage
        currentRollout = $effective.rollout
        requiredCanaryAssetId = $requiredCanaryAssetId
        requiredCanaryReceiptSha256 = [string]$receiptEnvelope.record.receiptSha256
    }
}

function Get-NorthGateCreateOnlyRolloutPromotionContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)
    Assert-NgcbContext $Context
    Assert-NgcbProductionServiceIdentity $Context
    $lock = Enter-NgcbLockSet $Context 'rollout-promotion'
    try {
        Assert-NgcbContextAnchorsCurrent $Context
        return Get-NgcbRolloutPromotionContextCore $Context
    }
    finally { Exit-NgcbLockSet $lock }
}

function Register-NorthGateCreateOnlyRolloutPromotion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][byte[]]$PromotionBytes,
        [Parameter(Mandatory)][byte[]]$DetachedCmsSignatureBytes
    )
    Assert-NgcbContext $Context
    Assert-NgcbProductionServiceIdentity $Context
    $parsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $PromotionBytes -MaximumBytes 65536
    $promotion = $parsed.Value
    Assert-NgcbRolloutPromotionContract $Context $promotion -RequireCurrent
    $promotionSha256 = Get-NgcbSha256Hex $PromotionBytes
    $signatureEvidence = Assert-NgcbDetachedCmsSignature $PromotionBytes $DetachedCmsSignatureBytes `
        ([string]$Context.Authorization.identity.approvalSignerCertificateSha256) `
        'NGCB-ROLLOUT-PROMOTION-SIGNATURE-INVALID'
    $lock = Enter-NgcbLockSet $Context 'rollout-promotion'
    try {
        Assert-NgcbContextAnchorsCurrent $Context
        $effective = Get-NgcbEffectiveRolloutState $Context
        $historyRoot = Join-Path (Get-NgcbRolloutRoot $Context) 'promotions'
        $existingRecords = @()
        foreach ($file in @(Get-ChildItem -LiteralPath $historyRoot -Filter '*.json' -File -ErrorAction Stop)) {
            $existingRecords += Read-NgcbRolloutPromotionRecord $Context $file.FullName
        }
        $exact = @($existingRecords | Where-Object {
            $_.promotionSha256 -ceq $promotionSha256 -and
            $_.promotion.promotionId -ceq $promotion.promotionId
        })
        if ([int]$effective.sequence -eq [int]$promotion.sequence -and
            $effective.authorizationSha256 -ceq $promotionSha256) {
            if ($exact.Count -ne 1) { Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-STATE-CORRUPT' }
            return [pscustomobject][ordered]@{
                status='already-registered';promotionId=[string]$promotion.promotionId
                sequence=[int]$effective.sequence;stage=[string]$effective.stage
                rolloutAuthorizationSha256=[string]$effective.authorizationSha256
            }
        }
        foreach ($record in $existingRecords) {
            if (($record.promotion.promotionId -ceq $promotion.promotionId -or
                 $record.promotion.nonce -ceq $promotion.nonce -or
                 [int]$record.promotion.sequence -eq [int]$promotion.sequence) -and
                $record.promotionSha256 -cne $promotionSha256) {
                Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-REPLAY'
            }
        }
        if ([int]$promotion.sequence -ne ([int]$effective.sequence + 1) -or
            $promotion.previousAuthorizationSha256 -cne $effective.authorizationSha256 -or
            $promotion.fromStage -cne $effective.stage) {
            Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-MONOTONICITY-INVALID'
        }
        $promotionContext = Get-NgcbRolloutPromotionContextCore $Context
        if ([int]$promotion.sequence -ne [int]$promotionContext.nextSequence -or
            $promotion.previousAuthorizationSha256 -cne $promotionContext.previousAuthorizationSha256 -or
            $promotion.fromStage -cne $promotionContext.fromStage -or
            $promotion.toStage -cne $promotionContext.permittedToStage) {
            Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-BINDING-INVALID'
        }
        $expectedReceipt = [string]$promotionContext.requiredCanaryReceiptSha256
        if ([int]$promotion.sequence -eq 1) {
            if ($promotion.rollout.debianCanary.receiptSha256 -cne $expectedReceipt -or
                (ConvertTo-NorthGateCreateOnlyCanonicalJson $promotion.rollout.windowsCanary) -cne
                    (ConvertTo-NorthGateCreateOnlyCanonicalJson $promotionContext.currentRollout.windowsCanary)) {
                Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-EVIDENCE-INVALID'
            }
        }
        else {
            if ($promotion.rollout.windowsCanary.receiptSha256 -cne $expectedReceipt -or
                (ConvertTo-NorthGateCreateOnlyCanonicalJson $promotion.rollout.debianCanary) -cne
                    (ConvertTo-NorthGateCreateOnlyCanonicalJson $promotionContext.currentRollout.debianCanary)) {
                Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-EVIDENCE-INVALID'
            }
        }
        $historyPath = Get-NgcbRolloutPromotionPath $Context ([int]$promotion.sequence) `
            ([string]$promotion.promotionId)
        $registeredAt = Format-NgcbUtc ([DateTimeOffset]::UtcNow)
        if ($exact.Count -eq 1) {
            if ($exact[0].detachedCmsSignatureSha256 -cne $signatureEvidence.signatureSha256) {
                Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-REPLAY'
            }
            $registeredAt = [string]$exact[0].registeredAtUtc
        }
        else {
            $historyRecord = [pscustomobject][ordered]@{
                schema = 'northgate/create-only-rollout-promotion-record/v1'
                promotion = $promotion
                promotionSha256 = $promotionSha256
                detachedCmsSignatureBase64 = [Convert]::ToBase64String($DetachedCmsSignatureBytes)
                detachedCmsSignatureSha256 = [string]$signatureEvidence.signatureSha256
                signerCertificateSha256 = [string]$signatureEvidence.certificateSha256
                registeredAtUtc = $registeredAt
            }
            $null = Write-NgcbEnvelope $Context 'rollout-promotion-record' $historyRecord $historyPath -CreateNew
        }
        $anchor = [pscustomobject][ordered]@{
            schema = 'northgate/create-only-rollout-promotion-anchor/v1'
            sequence = [int]$promotion.sequence
            promotionId = [string]$promotion.promotionId
            promotionSha256 = $promotionSha256
            stage = [string]$promotion.toStage
            registeredAtUtc = $registeredAt
        }
        $null = Write-NgcbEnvelope $Context 'rollout-promotion-anchor' $anchor `
            (Get-NgcbRolloutCurrentPath $Context)
        $verified = Get-NgcbEffectiveRolloutState $Context
        if ($verified.authorizationSha256 -cne $promotionSha256 -or
            [int]$verified.sequence -ne [int]$promotion.sequence) {
            Throw-NgcbError 'NGCB-ROLLOUT-PROMOTION-COMMIT-VERIFY-FAILED'
        }
        Write-NgcbAuditEvent $Context 'rollout-promotion-registered' 'succeeded' `
            'NGCB-ROLLOUT-PROMOTION-REGISTERED' '' $promotionContext.requiredCanaryAssetId
        return [pscustomobject][ordered]@{
            status='registered';promotionId=[string]$promotion.promotionId
            sequence=[int]$verified.sequence;stage=[string]$verified.stage
            rolloutAuthorizationSha256=[string]$verified.authorizationSha256
        }
    }
    finally { Exit-NgcbLockSet $lock }
}

function New-NorthGateCreateOnlyHostPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][byte[]]$PlanRequestBytes
    )
    Assert-NgcbContext $Context
    if (-not [bool]$Context.Policy.applyEnabled -or
        (@($Context.Policy.executableActions) -join '|') -cne 'Create') {
        Throw-NgcbError 'NGCB-POLICY-APPLY-NOT-ENABLED'
    }
    $parsedRequest = ConvertFrom-NorthGateCreateOnlyPlanRequestBytes $PlanRequestBytes
    $request = $parsedRequest.Request
    if ($request.repository.identity -cne $script:RepositoryIdentity -or
        $request.repository.commit -cne $Context.ReleaseManifest.repository.commit -or
        $request.repository.tree -cne $Context.ReleaseManifest.repository.tree -or
        $request.repository.commit -cne $Context.DataBundle.repository.commit -or
        $request.repository.tree -cne $Context.DataBundle.repository.tree -or
        $request.repository.signedReleaseSha256 -cne $Context.ReleaseManifestSha256 -or
        $request.repository.hostAllowlistId -cne $Context.ReleaseManifest.repository.hostAllowlistId) {
        Throw-NgcbError 'NGCB-REQUEST-PROVENANCE-MISMATCH'
    }
    $resolved = Resolve-NgcbManifest $Context ([string]$request.assetId)
    if ($resolved.Manifest.metadata.changeRef -cne $request.changeId) {
        Throw-NgcbError 'NGCB-REQUEST-MANIFEST-CHANGE-MISMATCH'
    }
    $lock = Enter-NgcbLockSet $Context ([string]$request.assetId)
    try {
        Assert-NgcbContextAnchorsCurrent $Context
        $observed = Get-NgcbObservedState $Context $resolved
        if (-not $observed.CollisionFree) { Throw-NgcbError 'NGCB-CREATE-COLLISION' }
        $rolloutState = Assert-NgcbRolloutState $Context ([string]$request.assetId) $observed.Identity
        if (-not $observed.Capacity.pass) { Throw-NgcbError 'NGCB-CAPACITY-INSUFFICIENT' }
        $planId = 'ngp-' + (New-NgcbRandomHex 32)
        $reservationId = 'ngrsv-' + (New-NgcbRandomHex 32)
        $issued = [DateTimeOffset]::UtcNow
        $expires = Get-NgcbPlanExpiration $Context $issued
        $plan = [pscustomobject][ordered]@{
            schema = 'northgate/create-only-host-plan/v1'
            planId = $planId
            reservationId = $reservationId
            issuedAtUtc = Format-NgcbUtc $issued
            expiresAtUtc = Format-NgcbUtc $expires
            repository = [pscustomobject][ordered]@{
                identity = $script:RepositoryIdentity
                commit = [string]$request.repository.commit
                tree = [string]$request.repository.tree
            }
            release = [pscustomobject][ordered]@{
                releaseId = [string]$Context.ReleaseManifest.releaseId
                releaseManifestSha256 = $Context.ReleaseManifestSha256
                packageAllowlistSha256 = [string]$Context.ReleaseManifest.repository.packageAllowlistSha256
                backendVersion = $script:BackendVersion
            }
            authorization = [pscustomobject][ordered]@{
                authorizationId = [string]$Context.Authorization.authorizationId
                authorizationSha256 = $Context.AuthorizationSha256
                hostAllowlistId = [string]$request.repository.hostAllowlistId
                hostId = [string]$Context.Authorization.host.hostId
            }
            policy = [pscustomobject][ordered]@{
                policyId = [string]$Context.Policy.policyId
                policyVersion = [string]$Context.Policy.policyVersion
                policySha256 = $Context.PolicySha256
                rolloutAuthorizationSha256 = [string]$rolloutState.authorizationSha256
                rolloutSequence = [int]$rolloutState.sequence
                rolloutStage = [string]$rolloutState.stage
            }
            data = [pscustomobject][ordered]@{
                bundleId = [string]$Context.DataBundle.bundleId
                dataBundleSha256 = $Context.DataBundleSha256
                manifestSha256 = $resolved.ManifestSha256
                manifestSourceSha256 = $resolved.ManifestSourceSha256
                manifestGitBlobOid = $resolved.ManifestGitBlobOid
                catalogHash = $resolved.CatalogHash
                catalogEvidence = @($resolved.CatalogEvidence)
            }
            liveState = [pscustomobject][ordered]@{
                identityHash = $observed.IdentityHash
                capacityHash = $observed.CapacityHash
                capacity = $observed.Capacity
            }
            operation = [pscustomobject][ordered]@{
                action = 'Create'
                assetId = [string]$resolved.Manifest.metadata.assetId
                name = [string]$resolved.Manifest.metadata.name
                changeId = [string]$resolved.Manifest.metadata.changeRef
                generation = 2
                processors = [int]$resolved.Manifest.spec.compute.processors
                memoryMode = [string]$resolved.Manifest.spec.compute.memory.mode
                minimumMemoryMiB = [int]$resolved.MinimumMemoryMiB
                startupMemoryMiB = [int]$resolved.Manifest.spec.compute.memory.startupMiB
                maximumMemoryMiB = [int]$resolved.MaximumMemoryMiB
                storageProfileRef = [string]$resolved.Manifest.spec.storage.profileRef
                storageRoot = $resolved.StorageRoot
                assetRoot = $resolved.AssetRoot
                vhdPath = $resolved.VhdPath
                osDiskGiB = [int]$resolved.Manifest.spec.storage.osDiskGiB
                imageRef = [string]$resolved.Manifest.spec.imageRef
                imagePath = [IO.Path]::GetFullPath([string]$resolved.Image.path)
                imageSha256 = [string]$resolved.Image.sha256
                bootstrapMediaId = [string]$resolved.BootstrapMedia.mediaId
                bootstrapMediaMode = [string]$resolved.BootstrapMedia.mode
                bootstrapMediaPath = [IO.Path]::GetFullPath([string]$resolved.BootstrapMedia.path)
                bootstrapMediaSha256 = [string]$resolved.BootstrapMedia.sha256
                bootstrapMediaSizeBytes = [int64]$resolved.BootstrapMedia.sizeBytes
                bootstrapMediaSourceImageId = [string]$resolved.BootstrapMedia.sourceImageId
                bootstrapMediaSourceImageSha256 = [string]$resolved.BootstrapMedia.sourceImageSha256
                bootstrapMediaProvenancePath = [IO.Path]::GetFullPath([string]$resolved.BootstrapMedia.provenancePath)
                bootstrapMediaProvenanceSha256 = [string]$resolved.BootstrapMedia.provenanceSha256
                bootstrapMediaBundleManifestSha256 = [string]$resolved.BootstrapMedia.bundleManifestSha256
                bootstrapMediaBuilderId = [string]$resolved.BootstrapMedia.builderId
                bootstrapMediaBuilderReleaseSha256 = [string]$resolved.BootstrapMedia.builderReleaseSha256
                bootstrapMediaRecipeSha256 = [string]$resolved.BootstrapMedia.recipeSha256
                bootstrapMediaUnattendedPayloadSha256 = [string]$resolved.BootstrapMedia.unattendedPayloadSha256
                bootstrapMediaSourceCommit = [string]$resolved.BootstrapMedia.sourceCommit
                bootstrapMediaSourceTree = [string]$resolved.BootstrapMedia.sourceTree
                installationMediaBindingMode = 'asset-bound-immutable-unattended'
                expectedDvdCount = 1
                firmwareProfileRef = [string]$resolved.Manifest.spec.firmwareProfileRef
                secureBootEnabled = [bool]$resolved.Image.secureBootEnabled
                secureBootTemplate = [string]$resolved.Image.secureBootTemplate
                secureBootExceptionId = [string]$resolved.Image.secureBootExceptionId
                vtpmRequired = [bool]$resolved.Image.vtpmRequired
                networkProfileRef = [string]$resolved.Manifest.spec.network.profileRef
                switchId = ([string]$Context.Authorization.switch.id).ToLowerInvariant()
                switchName = [string]$Context.Authorization.switch.name
                vlanId = [int]$resolved.Network.vlanId
                adapterPolicyId = [string]$resolved.AllowedAsset.adapterPolicyId
                adapterReservationId = 'ngnicr-' + (New-NgcbRandomHex 32)
                staticMacAddress = ([string]$resolved.AllowedAsset.staticMacAddress).ToUpperInvariant()
                adapterIdBindingMode = 'hyperv-issued-journal-before-first-boot'
                expectedAdapterCount = 1
                bootstrapProfileRef = [string]$resolved.Manifest.spec.bootstrapProfileRef
                recoveryProfileRef = [string]$resolved.Manifest.spec.recoveryProfileRef
                desiredPowerState = [string]$resolved.Manifest.spec.desiredPowerState
                destroyProtection = $true
            }
            approval = [pscustomobject][ordered]@{
                required = $true
                oneTime = $true
                signerCertificateSha256 = [string]$Context.Authorization.identity.approvalSignerCertificateSha256
            }
            failure = [pscustomobject][ordered]@{
                deleteOnFailure = $false
                quarantineOnlyWhenOwnershipProven = $true
                identityReuseBlockedOnUnknown = $true
            }
        }
        $canonicalPlan = ConvertTo-NorthGateCreateOnlyCanonicalJson $plan
        $planHash = Get-NgcbStringSha256Hex $canonicalPlan
        $planAuthenticationHash = Get-NgcbHmacHex $Context.StateKey `
            ("ngcb-host-plan-v1`n$planId`n$planHash")
        $record = [pscustomobject][ordered]@{
            schema = 'northgate/create-only-host-plan-record/v1'
            planId = $planId
            planHash = $planHash
            planAuthenticationHash = $planAuthenticationHash
            canonicalPlan = $canonicalPlan
            state = 'Registered'
            approvalState = 'Pending'
            approvalId = ''
            approvalSha256 = ''
            executionId = ''
            quarantineState = 'not-required'
            evidenceState = 'pending'
        }
        $ledger = Read-NgcbLedger $Context
        $ledger.entries = [object[]]@($ledger.entries) + [pscustomobject][ordered]@{
            assetId = [string]$plan.operation.assetId
            name = [string]$plan.operation.name
            reservationId = $reservationId
            changeId = [string]$plan.operation.changeId
            planId = $planId
            vmId = ''
            state = 'Reserved'
            assetRoot = [string]$plan.operation.assetRoot
            vhdPath = [string]$plan.operation.vhdPath
            updatedAtUtc = Format-NgcbUtc ([DateTimeOffset]::UtcNow)
        }
        $null = Write-NgcbJournalEvent $Context $plan.operation.assetId $reservationId $planId `
            'PlanValidated' '' 'NGCB-HOST-PLAN-VALIDATED'
        Save-NgcbLedger $Context $ledger
        Save-NgcbPlanRecord $Context $record -CreateNew
        Write-NgcbAuditEvent $Context 'plan-registered' 'succeeded' 'NGCB-HOST-PLAN-REGISTERED' $planId $plan.operation.assetId
        return [pscustomobject][ordered]@{
            planId = $planId
            planHash = $planHash
            planAuthenticationHash = $planAuthenticationHash
            issuedAtUtc = $plan.issuedAtUtc
            expiresAtUtc = $plan.expiresAtUtc
            assetId = $plan.operation.assetId
            name = $plan.operation.name
            action = 'Create'
            liveIdentityHash = $plan.liveState.identityHash
            capacityHash = $plan.liveState.capacityHash
            canonicalPlan = $canonicalPlan
        }
    }
    finally { Exit-NgcbLockSet $lock }
}

function Get-NorthGateCreateOnlyHostPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$PlanId)
    Assert-NgcbContext $Context
    $parsed = Read-NgcbPlanRecord $Context $PlanId
    [pscustomobject][ordered]@{
        planId = $parsed.Record.planId
        planHash = $parsed.Record.planHash
        planAuthenticationHash = $parsed.Record.planAuthenticationHash
        state = $parsed.Record.state
        approvalState = $parsed.Record.approvalState
        expiresAtUtc = $parsed.Plan.expiresAtUtc
        assetId = $parsed.Plan.operation.assetId
        name = $parsed.Plan.operation.name
        action = 'Create'
        canonicalPlan = $parsed.Record.canonicalPlan
    }
}

function Assert-NgcbApprovalContract {
    param([object]$Approval, [object]$PlanRecord, [object]$Plan, [object]$Context)
    Assert-NgcbExactProperties $Approval @(
        'schema','approvalId','decision','planId','planHash','planAuthenticationHash','changeId',
        'repository','releaseManifestSha256','authorizationSha256','policySha256','dataBundleSha256','issuedAtUtc','expiresAtUtc',
        'approverSid','nonce','useLimit'
    ) 'NGCB-APPROVAL-CONTRACT-INVALID'
    Assert-NgcbExactProperties $Approval.repository @('identity','commit','tree') 'NGCB-APPROVAL-CONTRACT-INVALID'
    if ($Approval.schema -cne 'northgate/create-only-plan-approval/v1' -or
        $Approval.approvalId -cnotmatch '^nga-[a-f0-9]{64}$' -or $Approval.decision -cne 'approve' -or
        $Approval.planId -cne $PlanRecord.planId -or $Approval.planHash -cne $PlanRecord.planHash -or
        $Approval.planAuthenticationHash -cne $PlanRecord.planAuthenticationHash -or
        $Approval.changeId -cne $Plan.operation.changeId -or
        $Approval.repository.identity -cne $script:RepositoryIdentity -or
        $Approval.repository.commit -cne $Plan.repository.commit -or
        $Approval.repository.tree -cne $Plan.repository.tree -or
        $Approval.releaseManifestSha256 -cne $Context.ReleaseManifestSha256 -or
        $Approval.authorizationSha256 -cne $Context.AuthorizationSha256 -or
        $Approval.policySha256 -cne $Context.PolicySha256 -or
        $Approval.dataBundleSha256 -cne $Context.DataBundleSha256 -or
        $Approval.approverSid -cnotmatch '^S-1-[0-9-]+$' -or
        $Approval.approverSid -in @(
            [string]$Context.Authorization.identity.sshIdentitySid,
            [string]$Context.Authorization.identity.serviceIdentitySid
        ) -or $Approval.nonce -cnotmatch '^[a-f0-9]{64}$' -or $Approval.useLimit -ne 1) {
        Throw-NgcbError 'NGCB-APPROVAL-BINDING-INVALID'
    }
    $issued = ConvertTo-NgcbUtc $Approval.issuedAtUtc 'NGCB-APPROVAL-TIME-INVALID'
    $expires = ConvertTo-NgcbUtc $Approval.expiresAtUtc 'NGCB-APPROVAL-TIME-INVALID'
    $planExpiry = ConvertTo-NgcbUtc $Plan.expiresAtUtc 'NGCB-PLAN-TIME-INVALID'
    $now = [DateTimeOffset]::UtcNow
    if ($issued -gt $now.AddMinutes(1) -or $expires -le $now -or $expires -le $issued -or
        $expires -gt $issued.AddSeconds([int]$Context.Policy.approvalTtlSeconds) -or
        $expires -gt $planExpiry) { Throw-NgcbError 'NGCB-APPROVAL-TIME-INVALID' }
}

function Register-NorthGateCreateOnlyApproval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][byte[]]$ApprovalBytes,
        [Parameter(Mandatory)][byte[]]$DetachedCmsSignatureBytes
    )
    Assert-NgcbContext $Context
    Assert-NgcbProductionServiceIdentity $Context
    $parsedApproval = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
        -Bytes $ApprovalBytes -MaximumBytes 32768
    $approval = $parsedApproval.Value
    if ($approval.PSObject.Properties['planId'] -eq $null -or $approval.planId -isnot [string]) {
        Throw-NgcbError 'NGCB-APPROVAL-CONTRACT-INVALID'
    }
    Assert-NgcbPlanId ([string]$approval.planId)
    $parsedPlan = Read-NgcbPlanRecord $Context ([string]$approval.planId)
    $assetId = [string]$parsedPlan.Plan.operation.assetId
    $lock = Enter-NgcbLockSet $Context $assetId
    try {
        $parsedPlan = Read-NgcbPlanRecord $Context ([string]$approval.planId)
        Assert-NgcbApprovalContract $approval $parsedPlan.Record $parsedPlan.Plan $Context
        $signatureEvidence = Assert-NgcbDetachedCmsSignature $ApprovalBytes $DetachedCmsSignatureBytes `
            ([string]$Context.Authorization.identity.approvalSignerCertificateSha256) `
            'NGCB-APPROVAL-SIGNATURE-INVALID'
        foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $Context.StateRoot 'approvals') -Filter '*.json' -File)) {
            $other = Read-NgcbEnvelope $Context 'plan-approval-record' $file.FullName 'NGCB-APPROVAL-STATE-CORRUPT'
            if ($other.record.approval.approvalId -ceq $approval.approvalId -or
                $other.record.approval.nonce -ceq $approval.nonce) {
                Throw-NgcbError 'NGCB-APPROVAL-REPLAY'
            }
        }
        if ($parsedPlan.Record.state -cne 'Registered' -or $parsedPlan.Record.approvalState -cne 'Pending') {
            Throw-NgcbError 'NGCB-PLAN-NOT-AWAITING-APPROVAL'
        }
        $approvalSha = Get-NgcbSha256Hex $ApprovalBytes
        $approvalRecord = [pscustomobject][ordered]@{
            schema = 'northgate/create-only-plan-approval-record/v1'
            approval = $approval
            approvalSha256 = $approvalSha
            detachedCmsSignatureBase64 = [Convert]::ToBase64String($DetachedCmsSignatureBytes)
            detachedCmsSignatureSha256 = [string]$signatureEvidence.signatureSha256
            signerCertificateSha256 = [string]$signatureEvidence.certificateSha256
            state = 'Registered'
            consumedAtUtc = ''
            executionId = ''
        }
        $null = Write-NgcbEnvelope $Context 'plan-approval-record' $approvalRecord `
            (Get-NgcbApprovalPath $Context ([string]$approval.planId)) -CreateNew
        $parsedPlan.Record.approvalState = 'Registered'
        $parsedPlan.Record.approvalId = [string]$approval.approvalId
        $parsedPlan.Record.approvalSha256 = $approvalSha
        Save-NgcbPlanRecord $Context $parsedPlan.Record
        $null = Write-NgcbJournalEvent $Context $assetId $parsedPlan.Plan.reservationId `
            $parsedPlan.Plan.planId 'ApprovalRegistered' '' 'NGCB-EXACT-APPROVAL-REGISTERED'
        Write-NgcbAuditEvent $Context 'approval-registered' 'succeeded' `
            'NGCB-EXACT-APPROVAL-REGISTERED' $parsedPlan.Plan.planId $assetId
        return [pscustomobject][ordered]@{
            planId = $parsedPlan.Plan.planId
            approvalId = $approval.approvalId
            approvalSha256 = $approvalSha
            signatureSha256 = $signatureEvidence.signatureSha256
            state = 'Registered'
            expiresAtUtc = $approval.expiresAtUtc
        }
    }
    finally { Exit-NgcbLockSet $lock }
}

function Read-NgcbApprovalRecord {
    param([object]$Context, [object]$ParsedPlan)
    $path = Get-NgcbApprovalPath $Context ([string]$ParsedPlan.Record.planId)
    $envelope = Read-NgcbEnvelope $Context 'plan-approval-record' $path 'NGCB-APPROVAL-STATE-CORRUPT'
    $record = $envelope.record
    Assert-NgcbExactProperties $record @(
        'schema','approval','approvalSha256','detachedCmsSignatureBase64','detachedCmsSignatureSha256',
        'signerCertificateSha256','state','consumedAtUtc','executionId'
    ) 'NGCB-APPROVAL-STATE-CORRUPT'
    if ($record.schema -cne 'northgate/create-only-plan-approval-record/v1' -or
        $record.approvalSha256 -cne $ParsedPlan.Record.approvalSha256 -or
        $record.approval.approvalId -cne $ParsedPlan.Record.approvalId -or
        $record.state -notin @('Registered','Consumed')) { Throw-NgcbError 'NGCB-APPROVAL-STATE-CORRUPT' }
    $approvalBytes = Get-NgcbCanonicalBytes $record.approval
    if ((Get-NgcbSha256Hex $approvalBytes) -cne $record.approvalSha256) {
        Throw-NgcbError 'NGCB-APPROVAL-STATE-CORRUPT'
    }
    try { $signatureBytes = [Convert]::FromBase64String([string]$record.detachedCmsSignatureBase64) }
    catch { Throw-NgcbError 'NGCB-APPROVAL-STATE-CORRUPT' }
    $evidence = Assert-NgcbDetachedCmsSignature $approvalBytes $signatureBytes `
        ([string]$Context.Authorization.identity.approvalSignerCertificateSha256) `
        'NGCB-APPROVAL-SIGNATURE-INVALID'
    if ($evidence.signatureSha256 -cne $record.detachedCmsSignatureSha256 -or
        $evidence.certificateSha256 -cne $record.signerCertificateSha256) {
        Throw-NgcbError 'NGCB-APPROVAL-STATE-CORRUPT'
    }
    Assert-NgcbApprovalContract $record.approval $ParsedPlan.Record $ParsedPlan.Plan $Context
    return [pscustomobject][ordered]@{ Record = $record; Envelope = $envelope }
}

function Assert-NgcbPlanContract {
    param([object]$Context, [object]$Record, [object]$Plan, [object]$Resolved)
    $effectiveRollout = Get-NgcbEffectiveRolloutState $Context
    Assert-NgcbExactProperties $Plan @(
        'schema','planId','reservationId','issuedAtUtc','expiresAtUtc','repository','release',
        'authorization','policy','data','liveState','operation','approval','failure'
    ) 'NGCB-PLAN-CONTRACT-INVALID'
    Assert-NgcbExactProperties $Plan.policy @(
        'policyId','policyVersion','policySha256','rolloutAuthorizationSha256','rolloutSequence','rolloutStage'
    ) 'NGCB-PLAN-CONTRACT-INVALID'
    Assert-NgcbExactProperties $Plan.operation @(
        'action','assetId','name','changeId','generation','processors','memoryMode','minimumMemoryMiB',
        'startupMemoryMiB','maximumMemoryMiB','storageProfileRef','storageRoot','assetRoot','vhdPath',
        'osDiskGiB','imageRef','imagePath','imageSha256','bootstrapMediaId','bootstrapMediaMode',
        'bootstrapMediaPath','bootstrapMediaSha256','bootstrapMediaSizeBytes','bootstrapMediaSourceImageId',
        'bootstrapMediaSourceImageSha256','bootstrapMediaProvenancePath','bootstrapMediaProvenanceSha256',
        'bootstrapMediaBundleManifestSha256','bootstrapMediaBuilderId','bootstrapMediaBuilderReleaseSha256',
        'bootstrapMediaRecipeSha256','bootstrapMediaUnattendedPayloadSha256','bootstrapMediaSourceCommit',
        'bootstrapMediaSourceTree','installationMediaBindingMode','expectedDvdCount','firmwareProfileRef','secureBootEnabled',
        'secureBootTemplate','secureBootExceptionId','vtpmRequired',
        'networkProfileRef','switchId','switchName','vlanId','adapterPolicyId','adapterReservationId','staticMacAddress',
        'adapterIdBindingMode','expectedAdapterCount','bootstrapProfileRef','recoveryProfileRef',
        'desiredPowerState','destroyProtection'
    ) 'NGCB-PLAN-OPERATION-INVALID'
    if ($Plan.schema -cne 'northgate/create-only-host-plan/v1' -or $Plan.planId -cne $Record.planId -or
        $Plan.reservationId -cnotmatch '^ngrsv-[a-f0-9]{64}$' -or
        $Plan.repository.identity -cne $script:RepositoryIdentity -or
        $Plan.repository.commit -cne $Context.ReleaseManifest.repository.commit -or
        $Plan.repository.tree -cne $Context.ReleaseManifest.repository.tree -or
        $Plan.release.releaseManifestSha256 -cne $Context.ReleaseManifestSha256 -or
        $Plan.release.backendVersion -cne $script:BackendVersion -or
        $Plan.authorization.authorizationSha256 -cne $Context.AuthorizationSha256 -or
        $Plan.authorization.hostId -cne $Context.Authorization.host.hostId -or
        $Plan.policy.policySha256 -cne $Context.PolicySha256 -or
        $Plan.policy.rolloutAuthorizationSha256 -cne $effectiveRollout.authorizationSha256 -or
        [int]$Plan.policy.rolloutSequence -ne [int]$effectiveRollout.sequence -or
        $Plan.policy.rolloutStage -cne $effectiveRollout.stage -or
        $Plan.data.dataBundleSha256 -cne $Context.DataBundleSha256 -or
        $Plan.data.manifestSha256 -cne $Resolved.ManifestSha256 -or
        $Plan.data.catalogHash -cne $Resolved.CatalogHash -or
        $Plan.operation.action -cne 'Create' -or $Plan.operation.assetId -cne $Resolved.Manifest.metadata.assetId -or
        $Plan.operation.name -cne $Resolved.Manifest.metadata.name -or
        $Plan.operation.changeId -cne $Resolved.Manifest.metadata.changeRef -or
        $Plan.operation.generation -ne 2 -or $Plan.operation.destroyProtection -ne $true -or
        $Plan.operation.storageRoot -cne $Resolved.StorageRoot -or
        $Plan.operation.assetRoot -cne $Resolved.AssetRoot -or $Plan.operation.vhdPath -cne $Resolved.VhdPath -or
        $Plan.operation.imageRef -cne $Resolved.Image.imageRef -or
        [IO.Path]::GetFullPath([string]$Plan.operation.imagePath) -ine [IO.Path]::GetFullPath([string]$Resolved.Image.path) -or
        $Plan.operation.imageSha256 -cne $Resolved.Image.sha256 -or
        $Plan.operation.bootstrapMediaId -cne $Resolved.BootstrapMedia.mediaId -or
        $Plan.operation.bootstrapMediaMode -cne $Resolved.BootstrapMedia.mode -or
        [IO.Path]::GetFullPath([string]$Plan.operation.bootstrapMediaPath) -ine [IO.Path]::GetFullPath([string]$Resolved.BootstrapMedia.path) -or
        $Plan.operation.bootstrapMediaSha256 -cne $Resolved.BootstrapMedia.sha256 -or
        [int64]$Plan.operation.bootstrapMediaSizeBytes -ne [int64]$Resolved.BootstrapMedia.sizeBytes -or
        $Plan.operation.bootstrapMediaSourceImageId -cne $Resolved.BootstrapMedia.sourceImageId -or
        $Plan.operation.bootstrapMediaSourceImageSha256 -cne $Resolved.BootstrapMedia.sourceImageSha256 -or
        [IO.Path]::GetFullPath([string]$Plan.operation.bootstrapMediaProvenancePath) -ine
            [IO.Path]::GetFullPath([string]$Resolved.BootstrapMedia.provenancePath) -or
        $Plan.operation.bootstrapMediaProvenanceSha256 -cne $Resolved.BootstrapMedia.provenanceSha256 -or
        $Plan.operation.bootstrapMediaBundleManifestSha256 -cne $Resolved.BootstrapMedia.bundleManifestSha256 -or
        $Plan.operation.bootstrapMediaBuilderId -cne $Resolved.BootstrapMedia.builderId -or
        $Plan.operation.bootstrapMediaBuilderReleaseSha256 -cne $Resolved.BootstrapMedia.builderReleaseSha256 -or
        $Plan.operation.bootstrapMediaRecipeSha256 -cne $Resolved.BootstrapMedia.recipeSha256 -or
        $Plan.operation.bootstrapMediaUnattendedPayloadSha256 -cne $Resolved.BootstrapMedia.unattendedPayloadSha256 -or
        $Plan.operation.bootstrapMediaSourceCommit -cne $Resolved.BootstrapMedia.sourceCommit -or
        $Plan.operation.bootstrapMediaSourceTree -cne $Resolved.BootstrapMedia.sourceTree -or
        $Plan.operation.installationMediaBindingMode -cne 'asset-bound-immutable-unattended' -or
        [int]$Plan.operation.expectedDvdCount -ne 1 -or
        $Plan.operation.secureBootEnabled -ne $Resolved.Image.secureBootEnabled -or
        $Plan.operation.secureBootTemplate -cne $Resolved.Image.secureBootTemplate -or
        $Plan.operation.secureBootExceptionId -cne $Resolved.Image.secureBootExceptionId -or
        $Plan.operation.vtpmRequired -ne $Resolved.Image.vtpmRequired -or
        $Plan.operation.switchId -cne ([string]$Context.Authorization.switch.id).ToLowerInvariant() -or
        $Plan.operation.switchName -cne $Context.Authorization.switch.name -or
        $Plan.operation.vlanId -ne $Resolved.Network.vlanId -or
        $Plan.operation.adapterPolicyId -cne $Resolved.AllowedAsset.adapterPolicyId -or
        $Plan.operation.adapterReservationId -cnotmatch '^ngnicr-[a-f0-9]{64}$' -or
        $Plan.operation.staticMacAddress -cne $Resolved.AllowedAsset.staticMacAddress -or
        $Plan.operation.adapterIdBindingMode -cne 'hyperv-issued-journal-before-first-boot' -or
        $Plan.operation.expectedAdapterCount -ne 1 -or
        $Plan.approval.required -ne $true -or $Plan.approval.oneTime -ne $true -or
        $Plan.approval.signerCertificateSha256 -cne $Context.Authorization.identity.approvalSignerCertificateSha256 -or
        $Plan.failure.deleteOnFailure -ne $false -or
        $Plan.failure.quarantineOnlyWhenOwnershipProven -ne $true -or
        $Plan.failure.identityReuseBlockedOnUnknown -ne $true) {
        Throw-NgcbError 'NGCB-PLAN-BINDING-INVALID'
    }
    $issued = ConvertTo-NgcbUtc $Plan.issuedAtUtc 'NGCB-PLAN-TIME-INVALID'
    $expires = ConvertTo-NgcbUtc $Plan.expiresAtUtc 'NGCB-PLAN-TIME-INVALID'
    $maximumExpiry = $issued.AddSeconds([int]$Context.Policy.planTtlSeconds)
    foreach ($anchorExpiry in @(
        (ConvertTo-NgcbUtc $Context.Authorization.expiresAtUtc 'NGCB-AUTHORIZATION-TIME-INVALID'),
        (ConvertTo-NgcbUtc $Context.Policy.expiresAtUtc 'NGCB-POLICY-TIME-INVALID'),
        (ConvertTo-NgcbUtc $Context.DataBundle.expiresAtUtc 'NGCB-DATA-BUNDLE-TIME-INVALID')
    )) { if ($anchorExpiry -lt $maximumExpiry) { $maximumExpiry = $anchorExpiry } }
    if ($expires -le $issued -or $expires -gt $maximumExpiry) {
        Throw-NgcbError 'NGCB-PLAN-TIME-INVALID'
    }
}

function Update-NgcbLedgerEntry {
    param([object]$Context, [string]$ReservationId, [string]$State, [string]$VmId = '')
    $ledger = Read-NgcbLedger $Context
    $matches = @($ledger.entries | Where-Object { $_.reservationId -ceq $ReservationId })
    if ($matches.Count -ne 1) { Throw-NgcbError 'NGCB-LEDGER-RESERVATION-MISSING' }
    $matches[0].state = $State
    if ($VmId -ne '') { $matches[0].vmId = $VmId.ToLowerInvariant() }
    $matches[0].updatedAtUtc = Format-NgcbUtc ([DateTimeOffset]::UtcNow)
    Save-NgcbLedger $Context $ledger
}

function Assert-NgcbProductionServiceIdentity {
    param([object]$Context)
    if ($Context.Mode -ne 'Production') { return }
    try { $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
    catch { Throw-NgcbError 'NGCB-SERVICE-IDENTITY-INVALID' }
    if ($sid -cne [string]$Context.Authorization.identity.serviceIdentitySid) {
        Throw-NgcbError 'NGCB-SERVICE-IDENTITY-INVALID'
    }
}

function Assert-NgcbProductionVmReadback {
    param([object]$Plan, [string]$VmId, [bool]$ExpectRunning)
    $operation = $Plan.operation
    $vm = Hyper-V\Get-VM -Id ([guid]$VmId) -ErrorAction Stop
    if ($vm.Name -cne $operation.name -or $vm.Generation -ne 2 -or $vm.Notes -cne
        (Get-NgcbOwnershipNote $operation.assetId $operation.changeId $Plan.reservationId $Plan.planId $false)) {
        Throw-NgcbError 'NGCB-VM-READBACK-MISMATCH'
    }
    $processor = Hyper-V\Get-VMProcessor -VM $vm -ErrorAction Stop
    $memory = Hyper-V\Get-VMMemory -VM $vm -ErrorAction Stop
    if ([int]$processor.Count -ne [int]$operation.processors -or
        [int64]$memory.Startup -ne [int64]$operation.startupMemoryMiB * 1MB -or
        [bool]$memory.DynamicMemoryEnabled -ne ($operation.memoryMode -ceq 'dynamic')) {
        Throw-NgcbError 'NGCB-VM-READBACK-MISMATCH'
    }
    if ($operation.memoryMode -ceq 'dynamic' -and
        ([int64]$memory.Minimum -ne [int64]$operation.minimumMemoryMiB * 1MB -or
         [int64]$memory.Maximum -ne [int64]$operation.maximumMemoryMiB * 1MB)) {
        Throw-NgcbError 'NGCB-VM-READBACK-MISMATCH'
    }
    $drives = @(Hyper-V\Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)
    if ($drives.Count -ne 1 -or [IO.Path]::GetFullPath([string]$drives[0].Path) -ine
        [IO.Path]::GetFullPath([string]$operation.vhdPath)) { Throw-NgcbError 'NGCB-VM-READBACK-MISMATCH' }
    $dvds = @(Hyper-V\Get-VMDvdDrive -VM $vm -ErrorAction Stop | Sort-Object ControllerNumber,ControllerLocation)
    $expectedDvdPaths = @([IO.Path]::GetFullPath([string]$operation.bootstrapMediaPath))
    $actualDvdPaths = @($dvds | ForEach-Object { [IO.Path]::GetFullPath([string]$_.Path) })
    if ($dvds.Count -ne [int]$operation.expectedDvdCount -or
        ($actualDvdPaths -join '|') -ine ($expectedDvdPaths -join '|')) {
        Throw-NgcbError 'NGCB-VM-INSTALLATION-MEDIA-READBACK-MISMATCH'
    }
    $firmware = Hyper-V\Get-VMFirmware -VM $vm -ErrorAction Stop
    $security = Hyper-V\Get-VMSecurity -VM $vm -ErrorAction Stop
    $secureBootObserved = [string]$firmware.SecureBoot -ceq 'On'
    if ($secureBootObserved -ne [bool]$operation.secureBootEnabled -or
        [bool]$security.TpmEnabled -ne [bool]$operation.vtpmRequired -or
        ($operation.secureBootEnabled -and [string]$firmware.SecureBootTemplate -cne
            [string]$operation.secureBootTemplate)) {
        Throw-NgcbError 'NGCB-VM-FIRMWARE-SECURITY-READBACK-MISMATCH'
    }
    $adapters = @(Hyper-V\Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
    if ($adapters.Count -ne 1 -or $adapters[0].SwitchId.ToString().ToLowerInvariant() -cne $operation.switchId) {
        Throw-NgcbError 'NGCB-VM-READBACK-MISMATCH'
    }
    if (([string]$adapters[0].MacAddress).ToUpperInvariant() -cne $operation.staticMacAddress -or
        [bool]$adapters[0].DynamicMacAddressEnabled) { Throw-NgcbError 'NGCB-VM-ADAPTER-IDENTITY-DRIFT' }
    $vlan = Hyper-V\Get-VMNetworkAdapterVlan -VMNetworkAdapter $adapters[0] -ErrorAction Stop
    if ([string]$vlan.OperationMode -cne 'Access' -or [int]$vlan.AccessVlanId -ne [int]$operation.vlanId) {
        Throw-NgcbError 'NGCB-VM-READBACK-MISMATCH'
    }
    if ($ExpectRunning -and [string]$vm.State -cne 'Running') { Throw-NgcbError 'NGCB-VM-POWER-READBACK-MISMATCH' }
    if (-not $ExpectRunning -and [string]$vm.State -cne 'Off') { Throw-NgcbError 'NGCB-VM-POWER-READBACK-MISMATCH' }
    $after = [pscustomobject][ordered]@{
        vmId = $VmId.ToLowerInvariant(); name = [string]$vm.Name; generation = [int]$vm.Generation
        state = [string]$vm.State; processorCount = [int]$processor.Count
        startupMemoryBytes = [int64]$memory.Startup; dynamicMemoryEnabled = [bool]$memory.DynamicMemoryEnabled
        vhdPath = [IO.Path]::GetFullPath([string]$drives[0].Path)
        imagePath = [IO.Path]::GetFullPath([string]$operation.imagePath)
        bootstrapMediaId = [string]$operation.bootstrapMediaId
        bootstrapMediaMode = [string]$operation.bootstrapMediaMode
        bootstrapMediaSha256 = [string]$operation.bootstrapMediaSha256
        bootstrapMediaProvenanceSha256 = [string]$operation.bootstrapMediaProvenanceSha256
        bootstrapMediaBundleManifestSha256 = [string]$operation.bootstrapMediaBundleManifestSha256
        bootstrapMediaUnattendedPayloadSha256 = [string]$operation.bootstrapMediaUnattendedPayloadSha256
        installationMediaPaths = @($actualDvdPaths)
        switchId = $adapters[0].SwitchId.ToString().ToLowerInvariant(); vlanId = [int]$vlan.AccessVlanId
        adapterPolicyId = [string]$operation.adapterPolicyId
        adapterId = Get-NgcbAdapterIdentity $adapters[0] $VmId
        staticMacAddress = ([string]$adapters[0].MacAddress).ToUpperInvariant()
        dynamicMacAddressEnabled = [bool]$adapters[0].DynamicMacAddressEnabled
        secureBootEnabled = $secureBootObserved
        secureBootTemplate = if ($secureBootObserved) { [string]$firmware.SecureBootTemplate } else { 'None' }
        secureBootExceptionId = [string]$operation.secureBootExceptionId
        vtpmEnabled = [bool]$security.TpmEnabled
        ownershipNoteSha256 = Get-NgcbStringSha256Hex ([string]$vm.Notes)
    }
    return [pscustomobject][ordered]@{
        VmId = $VmId.ToLowerInvariant()
        AfterState = $after
        AfterStateHash = Get-NgcbStringSha256Hex (ConvertTo-NorthGateCreateOnlyCanonicalJson $after)
    }
}

function Invoke-NgcbQuarantineProductionVm {
    param([object]$Context, [object]$Plan, [string]$VmId)
    if ($VmId -cnotmatch '^[a-f0-9-]{36}$') { return $false }
    try {
        $vm = Hyper-V\Get-VM -Id ([guid]$VmId) -ErrorAction Stop
        $expectedNote = Get-NgcbOwnershipNote $Plan.operation.assetId $Plan.operation.changeId `
            $Plan.reservationId $Plan.planId $false
        $quarantineNote = Get-NgcbOwnershipNote $Plan.operation.assetId $Plan.operation.changeId `
            $Plan.reservationId $Plan.planId $true
        if ($vm.Name -cne $Plan.operation.name -or [string]$vm.Notes -notin @($expectedNote,$quarantineNote)) { return $false }
        if ([string]$vm.State -ne 'Off') { Hyper-V\Stop-VM -VM $vm -TurnOff -Force -ErrorAction Stop }
        foreach ($adapter in @(Hyper-V\Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)) {
            Hyper-V\Disconnect-VMNetworkAdapter -VMNetworkAdapter $adapter -ErrorAction Stop
        }
        Hyper-V\Set-VM -VM $vm -Notes (Get-NgcbOwnershipNote $Plan.operation.assetId `
            $Plan.operation.changeId $Plan.reservationId $Plan.planId $true) -ErrorAction Stop
        return $true
    }
    catch { return $false }
}

function Invoke-NgcbProductionCreate {
    param([object]$Context, [object]$Plan)
    foreach ($commandName in @(
        'Hyper-V\New-VM','Hyper-V\Set-VM','Hyper-V\Set-VMProcessor','Hyper-V\Set-VMMemory',
        'Hyper-V\Add-VMDvdDrive','Hyper-V\Get-VMDvdDrive','Hyper-V\Get-VMFirmware','Hyper-V\Set-VMFirmware',
        'Hyper-V\Get-VMSecurity','Hyper-V\Set-VMKeyProtector','Hyper-V\Enable-VMTPM',
        'Hyper-V\Add-VMNetworkAdapter','Hyper-V\Set-VMNetworkAdapter','Hyper-V\Connect-VMNetworkAdapter','Hyper-V\Set-VMNetworkAdapterVlan','Hyper-V\Start-VM',
        'Hyper-V\Stop-VM','Hyper-V\Disconnect-VMNetworkAdapter'
    )) { $null = Get-Command $commandName -ErrorAction Stop }
    $operation = $Plan.operation
    $vmId = ''
    try {
        $null = [IO.Directory]::CreateDirectory([string]$operation.assetRoot)
        $null = [IO.Directory]::CreateDirectory((Split-Path -Parent ([string]$operation.vhdPath)))
        Assert-NgcbNoReparseAncestor ([string]$operation.assetRoot) | Out-Null
        $null = Write-NgcbJournalEvent $Context $operation.assetId $Plan.reservationId $Plan.planId `
            'OwnedDirectoriesCreated' '' 'NGCB-OWNED-DIRECTORIES-CREATED'
        $vm = Hyper-V\New-VM -Name ([string]$operation.name) -Generation 2 `
            -Path ([string]$operation.assetRoot) -MemoryStartupBytes ([int64]$operation.startupMemoryMiB * 1MB) `
            -NewVHDPath ([string]$operation.vhdPath) -NewVHDSizeBytes ([int64]$operation.osDiskGiB * 1GB) `
            -ErrorAction Stop
        $vmId = ([string]$vm.Id).ToLowerInvariant()
        $null = Write-NgcbJournalEvent $Context $operation.assetId $Plan.reservationId $Plan.planId `
            'VmCreated' $vmId 'NGCB-HYPERV-VM-ID-ISSUED'
        Update-NgcbLedgerEntry $Context $Plan.reservationId 'Applying' $vmId
        Hyper-V\Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing `
            -AutomaticStopAction ShutDown -CheckpointType Production `
            -Notes (Get-NgcbOwnershipNote $operation.assetId $operation.changeId $Plan.reservationId $Plan.planId $false) `
            -ErrorAction Stop
        Hyper-V\Set-VMProcessor -VM $vm -Count ([int]$operation.processors) -ErrorAction Stop
        if ($operation.memoryMode -ceq 'dynamic') {
            Hyper-V\Set-VMMemory -VM $vm -DynamicMemoryEnabled $true `
                -MinimumBytes ([int64]$operation.minimumMemoryMiB * 1MB) `
                -StartupBytes ([int64]$operation.startupMemoryMiB * 1MB) `
                -MaximumBytes ([int64]$operation.maximumMemoryMiB * 1MB) -ErrorAction Stop
        }
        else {
            Hyper-V\Set-VMMemory -VM $vm -DynamicMemoryEnabled $false `
                -StartupBytes ([int64]$operation.startupMemoryMiB * 1MB) -ErrorAction Stop
        }
        if ($operation.bootstrapMediaMode -cne 'asset-bound-derivative-iso' -or
            [int]$operation.expectedDvdCount -ne 1 -or
            [IO.Path]::GetFullPath([string]$operation.bootstrapMediaPath) -ieq
                [IO.Path]::GetFullPath([string]$operation.imagePath)) {
            Throw-NgcbError 'NGCB-DERIVATIVE-MEDIA-BINDING-INVALID'
        }
        $dvd = Hyper-V\Add-VMDvdDrive -VM $vm -Path ([string]$operation.bootstrapMediaPath) -Passthru -ErrorAction Stop
        if ([bool]$operation.secureBootEnabled) {
            Hyper-V\Set-VMFirmware -VM $vm -EnableSecureBoot On `
                -SecureBootTemplate ([string]$operation.secureBootTemplate) -FirstBootDevice $dvd -ErrorAction Stop
        }
        else {
            if ($operation.imageRef -cne 'kali-2026.2-installer-netinst-amd64' -or
                $operation.secureBootExceptionId -cne 'NG-FW-20260802-KALI-UNSIGNED' -or
                [bool]$operation.vtpmRequired) { Throw-NgcbError 'NGCB-SECURE-BOOT-EXCEPTION-NOT-AUTHORIZED' }
            Hyper-V\Set-VMFirmware -VM $vm -EnableSecureBoot Off -FirstBootDevice $dvd -ErrorAction Stop
        }
        if ([bool]$operation.vtpmRequired) {
            if ($operation.secureBootTemplate -cne 'MicrosoftWindows' -or
                -not [bool]$operation.secureBootEnabled) { Throw-NgcbError 'NGCB-VTPM-POLICY-INVALID' }
            Hyper-V\Set-VMKeyProtector -VM $vm -NewLocalKeyProtector -ErrorAction Stop
            Hyper-V\Enable-VMTPM -VM $vm -ErrorAction Stop
        }
        $adapters = @(Hyper-V\Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
        if ($adapters.Count -eq 0) {
            $null = Hyper-V\Add-VMNetworkAdapter -VM $vm -Name 'NorthGate-Primary' `
                -StaticMacAddress ([string]$operation.staticMacAddress) -Passthru -ErrorAction Stop
            $adapters = @(Hyper-V\Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
        }
        if ($adapters.Count -ne 1 -or [string]$adapters[0].SwitchId -ne '') {
            Throw-NgcbError 'NGCB-NEW-VM-ADAPTER-NOT-QUARANTINED'
        }
        Hyper-V\Set-VMNetworkAdapter -VMNetworkAdapter $adapters[0] `
            -StaticMacAddress ([string]$operation.staticMacAddress) -ErrorAction Stop
        $adapters = @(Hyper-V\Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
        if ($adapters.Count -ne 1 -or ([string]$adapters[0].MacAddress).ToUpperInvariant() -cne
            [string]$operation.staticMacAddress -or [bool]$adapters[0].DynamicMacAddressEnabled) {
            Throw-NgcbError 'NGCB-VM-ADAPTER-IDENTITY-DRIFT'
        }
        $adapterId = Get-NgcbAdapterIdentity $adapters[0] $vmId
        $null = Write-NgcbJournalEvent $Context $operation.assetId $Plan.reservationId $Plan.planId `
            'AdapterIdentityBound' $vmId 'NGCB-STATIC-MAC-AND-ADAPTER-BOUND' $adapterId $operation.staticMacAddress
        Hyper-V\Connect-VMNetworkAdapter -VMNetworkAdapter $adapters[0] `
            -SwitchName ([string]$operation.switchName) -ErrorAction Stop
        Hyper-V\Set-VMNetworkAdapterVlan -VMNetworkAdapter $adapters[0] -Access `
            -VlanId ([int]$operation.vlanId) -ErrorAction Stop
        $null = Write-NgcbJournalEvent $Context $operation.assetId $Plan.reservationId $Plan.planId `
            'ConfiguredOff' $vmId 'NGCB-VM-CONFIGURED-OFF'
        $null = Assert-NgcbProductionVmReadback $Plan $vmId $false
        if ($operation.desiredPowerState -ceq 'running') {
            Hyper-V\Start-VM -VM $vm -ErrorAction Stop
        }
        $verified = Assert-NgcbProductionVmReadback $Plan $vmId ($operation.desiredPowerState -ceq 'running')
        return [pscustomobject][ordered]@{
            status = 'Created'; vmId = $vmId; afterState = $verified.AfterState
            afterStateHash = $verified.AfterStateHash; quarantineState = 'not-required'
            reasonCode = 'NGCB-CREATE-VERIFIED'
        }
    }
    catch {
        $quarantined = if ($vmId -ne '') { Invoke-NgcbQuarantineProductionVm $Context $Plan $vmId } else { $false }
        $artifactExists = (Test-Path -LiteralPath ([string]$operation.assetRoot)) -or $vmId -ne ''
        return [pscustomobject][ordered]@{
            status = if ($artifactExists -and -not $quarantined) { 'OutcomeUnknown' } else { 'Failed' }
            vmId = $vmId
            afterState = [pscustomobject][ordered]@{ vmId=$vmId; verified=$false }
            afterStateHash = Get-NgcbStringSha256Hex ("failed|$($Plan.planId)|$vmId")
            quarantineState = if ($quarantined) { 'completed' } elseif ($artifactExists) { 'required' } else { 'not-required' }
            reasonCode = if ($quarantined) { 'NGCB-PARTIAL-CREATE-QUARANTINED' } `
                elseif ($artifactExists) { 'NGCB-CREATE-OUTCOME-UNKNOWN' } else { 'NGCB-CREATE-FAILED-NO-ARTIFACTS' }
        }
    }
}

function Invoke-NgcbInertCreate {
    param([object]$Context, [object]$Plan)
    $operation = $Plan.operation
    if ($Context.TestScenario -ceq 'FailBeforeCreate') {
        return [pscustomobject][ordered]@{
            status='Failed'; vmId=''; afterState=[pscustomobject][ordered]@{vmId='';verified=$false}
            afterStateHash=Get-NgcbStringSha256Hex ("failed|$($Plan.planId)"); quarantineState='not-required'
            reasonCode='NGCB-CREATE-FAILED-NO-ARTIFACTS'
        }
    }
    $vmId = [guid]::NewGuid().ToString().ToLowerInvariant()
    $note = Get-NgcbOwnershipNote $operation.assetId $operation.changeId $Plan.reservationId $Plan.planId $false
    $Context.TestState.vms = [object[]]@($Context.TestState.vms) + [pscustomobject][ordered]@{
        vmId=$vmId; name=$operation.name; generation=2
        state=$(if ($operation.desiredPowerState -ceq 'running') {'Running'} else {'Off'})
        path=$operation.assetRoot; notes=$note
    }
    $Context.TestState.disks = [object[]]@($Context.TestState.disks) + [pscustomobject][ordered]@{
        vmId=$vmId; controllerType='SCSI'; controllerNumber=0; controllerLocation=0
        path=$operation.vhdPath; diskIdentifier=[guid]::NewGuid().ToString().ToLowerInvariant()
    }
    $adapterId = [guid]::NewGuid().ToString().ToLowerInvariant()
    $Context.TestState.adapters = [object[]]@($Context.TestState.adapters) + [pscustomobject][ordered]@{
        vmId=$vmId; adapterId=$adapterId; macAddress=$operation.staticMacAddress
        dynamicMacAddressEnabled=$false; switchId=$operation.switchId
    }
    $null = Write-NgcbJournalEvent $Context $operation.assetId $Plan.reservationId $Plan.planId `
        'VmCreated' $vmId 'NGCB-HYPERV-VM-ID-ISSUED'
    Update-NgcbLedgerEntry $Context $Plan.reservationId 'Applying' $vmId
    $null = Write-NgcbJournalEvent $Context $operation.assetId $Plan.reservationId $Plan.planId `
        'AdapterIdentityBound' $vmId 'NGCB-STATIC-MAC-AND-ADAPTER-BOUND' $adapterId $operation.staticMacAddress
    if ($Context.TestScenario -in @('CrashAfterCreate','UnknownAfterCreate')) {
        if ($Context.TestScenario -ceq 'CrashAfterCreate') {
            $Context.TestState.vms[-1].notes = Get-NgcbOwnershipNote $operation.assetId $operation.changeId `
                $Plan.reservationId $Plan.planId $true
            $status = 'Failed'; $quarantine = 'completed'; $code = 'NGCB-PARTIAL-CREATE-QUARANTINED'
        }
        else {
            $Context.TestState.vms[-1].notes = ''
            $status = 'OutcomeUnknown'; $quarantine = 'required'; $code = 'NGCB-CREATE-OUTCOME-UNKNOWN'
        }
        return [pscustomobject][ordered]@{
            status=$status; vmId=$vmId; afterState=[pscustomobject][ordered]@{vmId=$vmId;verified=$false}
            afterStateHash=Get-NgcbStringSha256Hex ("failed|$($Plan.planId)|$vmId")
            quarantineState=$quarantine; reasonCode=$code
        }
    }
    $after = [pscustomobject][ordered]@{
        vmId=$vmId; name=$operation.name; generation=2; state=$(if ($operation.desiredPowerState -ceq 'running') {'Running'} else {'Off'})
        processorCount=[int]$operation.processors; startupMemoryBytes=[int64]$operation.startupMemoryMiB*1MB
        dynamicMemoryEnabled=($operation.memoryMode -ceq 'dynamic'); vhdPath=$operation.vhdPath
        imagePath=$operation.imagePath
        bootstrapMediaId=$operation.bootstrapMediaId; bootstrapMediaMode=$operation.bootstrapMediaMode
        bootstrapMediaSha256=$operation.bootstrapMediaSha256
        bootstrapMediaProvenanceSha256=$operation.bootstrapMediaProvenanceSha256
        bootstrapMediaBundleManifestSha256=$operation.bootstrapMediaBundleManifestSha256
        bootstrapMediaUnattendedPayloadSha256=$operation.bootstrapMediaUnattendedPayloadSha256
        installationMediaPaths=[object[]]@($operation.bootstrapMediaPath)
        switchId=$operation.switchId; vlanId=[int]$operation.vlanId
        adapterPolicyId=$operation.adapterPolicyId; adapterId=$adapterId; staticMacAddress=$operation.staticMacAddress
        dynamicMacAddressEnabled=$false
        secureBootEnabled=[bool]$operation.secureBootEnabled; secureBootTemplate=$operation.secureBootTemplate
        secureBootExceptionId=$operation.secureBootExceptionId; vtpmEnabled=[bool]$operation.vtpmRequired
        ownershipNoteSha256=Get-NgcbStringSha256Hex $note
    }
    return [pscustomobject][ordered]@{
        status='Created'; vmId=$vmId; afterState=$after
        afterStateHash=Get-NgcbStringSha256Hex (ConvertTo-NorthGateCreateOnlyCanonicalJson $after)
        quarantineState='not-required'; reasonCode='NGCB-CREATE-VERIFIED'
    }
}

function New-NgcbSignedReceiptRecord {
    param(
        [object]$Context, [object]$ParsedPlan, [object]$ApprovalRecord,
        [object]$ProviderResult, [string]$ExecutionId
    )
    $plan = $ParsedPlan.Plan
    $outcome = if ($ProviderResult.status -ceq 'Created') { 'Succeeded' }
        elseif ($ProviderResult.status -ceq 'OutcomeUnknown') { 'OutcomeUnknown' } else { 'Failed' }
    $receipt = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-signed-receipt/v1'
        receiptId = 'ngr-' + (New-NgcbRandomHex 32)
        completedAtUtc = Format-NgcbUtc ([DateTimeOffset]::UtcNow)
        executionId = $ExecutionId
        planId = [string]$plan.planId
        planHash = [string]$ParsedPlan.Record.planHash
        planAuthenticationHash = [string]$ParsedPlan.Record.planAuthenticationHash
        approvalId = [string]$ApprovalRecord.approval.approvalId
        approvalSha256 = [string]$ApprovalRecord.approvalSha256
        repository = $plan.repository
        releaseManifestSha256 = [string]$Context.ReleaseManifestSha256
        authorizationSha256 = [string]$Context.AuthorizationSha256
        policySha256 = [string]$Context.PolicySha256
        rolloutAuthorizationSha256 = [string]$plan.policy.rolloutAuthorizationSha256
        rolloutSequence = [int]$plan.policy.rolloutSequence
        rolloutStage = [string]$plan.policy.rolloutStage
        dataBundleSha256 = [string]$Context.DataBundleSha256
        manifestSha256 = [string]$plan.data.manifestSha256
        catalogHash = [string]$plan.data.catalogHash
        beforeIdentityHash = [string]$plan.liveState.identityHash
        beforeCapacityHash = [string]$plan.liveState.capacityHash
        afterStateHash = [string]$ProviderResult.afterStateHash
        afterStateVerified = ($ProviderResult.status -ceq 'Created')
        outcome = $outcome
        reasonCode = [string]$ProviderResult.reasonCode
        quarantineState = [string]$ProviderResult.quarantineState
        rollbackState = 'not-applicable-create-only'
        operation = [pscustomobject][ordered]@{
            action = 'Create'
            assetId = [string]$plan.operation.assetId
            name = [string]$plan.operation.name
            changeId = [string]$plan.operation.changeId
            reservationId = [string]$plan.reservationId
            vmId = [string]$ProviderResult.vmId
            adapterPolicyId = [string]$plan.operation.adapterPolicyId
            adapterReservationId = [string]$plan.operation.adapterReservationId
            adapterId = if ($ProviderResult.afterState.PSObject.Properties['adapterId']) {
                [string]$ProviderResult.afterState.adapterId
            } else { '' }
            staticMacAddress = [string]$plan.operation.staticMacAddress
            dynamicMacAddressEnabled = if ($ProviderResult.afterState.PSObject.Properties['dynamicMacAddressEnabled']) {
                [bool]$ProviderResult.afterState.dynamicMacAddressEnabled
            } else { $false }
            secureBootEnabled = [bool]$plan.operation.secureBootEnabled
            secureBootTemplate = [string]$plan.operation.secureBootTemplate
            secureBootExceptionId = [string]$plan.operation.secureBootExceptionId
            vtpmRequired = [bool]$plan.operation.vtpmRequired
            vtpmEnabled = if ($ProviderResult.afterState.PSObject.Properties['vtpmEnabled']) {
                [bool]$ProviderResult.afterState.vtpmEnabled
            } else { $false }
            bootstrapMediaId = [string]$plan.operation.bootstrapMediaId
            bootstrapMediaMode = [string]$plan.operation.bootstrapMediaMode
            bootstrapMediaSha256 = [string]$plan.operation.bootstrapMediaSha256
            bootstrapMediaSourceImageSha256 = [string]$plan.operation.bootstrapMediaSourceImageSha256
            bootstrapMediaProvenanceSha256 = [string]$plan.operation.bootstrapMediaProvenanceSha256
            bootstrapMediaBundleManifestSha256 = [string]$plan.operation.bootstrapMediaBundleManifestSha256
            bootstrapMediaUnattendedPayloadSha256 = [string]$plan.operation.bootstrapMediaUnattendedPayloadSha256
            installationMediaPaths = [object[]]@([string]$plan.operation.bootstrapMediaPath)
            storageRoot = [string]$plan.operation.storageRoot
            assetRoot = [string]$plan.operation.assetRoot
            vhdPath = [string]$plan.operation.vhdPath
            switchId = [string]$plan.operation.switchId
            vlanId = [int]$plan.operation.vlanId
            desiredPowerState = [string]$plan.operation.desiredPowerState
            destroyProtection = $true
        }
        controls = [pscustomobject][ordered]@{
            existingAssetsMutated = $false
            existingDisksMutated = $false
            switchesMutated = $false
            deletePathUsed = $false
            identityReuseBlocked = ($outcome -ne 'Succeeded')
            approvalUseCount = 1
            testOnly = ($Context.Mode -ne 'Production')
        }
    }
    $receiptBytes = Get-NgcbCanonicalBytes $receipt
    $signature = New-NgcbDetachedCmsSignature $receiptBytes $Context.ReceiptCertificate
    $signerSha = Get-NgcbCertificateSha256 $Context.ReceiptCertificate
    if ($signerSha -cne [string]$Context.Authorization.identity.receiptSignerCertificateSha256) {
        Throw-NgcbError 'NGCB-RECEIPT-SIGNER-PIN-MISMATCH'
    }
    $record = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-signed-receipt-record/v1'
        receipt = $receipt
        receiptSha256 = Get-NgcbSha256Hex $receiptBytes
        detachedCmsSignatureBase64 = [Convert]::ToBase64String($signature)
        detachedCmsSignatureSha256 = Get-NgcbSha256Hex $signature
        signerCertificateSha256 = $signerSha
    }
    $null = Assert-NgcbDetachedCmsSignature $receiptBytes $signature $signerSha 'NGCB-RECEIPT-SIGNATURE-INVALID'
    return $record
}

function Assert-NgcbReceiptRecord {
    param([object]$Context, [object]$Record, [object]$ParsedPlan)
    Assert-NgcbExactProperties $Record @(
        'schema','receipt','receiptSha256','detachedCmsSignatureBase64','detachedCmsSignatureSha256',
        'signerCertificateSha256'
    ) 'NGCB-RECEIPT-CORRUPT'
    if ($Record.schema -cne 'northgate/create-only-signed-receipt-record/v1') { Throw-NgcbError 'NGCB-RECEIPT-CORRUPT' }
    $bytes = Get-NgcbCanonicalBytes $Record.receipt
    if ((Get-NgcbSha256Hex $bytes) -cne $Record.receiptSha256 -or
        $Record.receipt.planId -cne $ParsedPlan.Record.planId -or
        $Record.receipt.planHash -cne $ParsedPlan.Record.planHash -or
        $Record.receipt.planAuthenticationHash -cne $ParsedPlan.Record.planAuthenticationHash -or
        $Record.receipt.repository.identity -cne $script:RepositoryIdentity -or
        $Record.receipt.repository.commit -cne $Context.ReleaseManifest.repository.commit -or
        $Record.receipt.repository.tree -cne $Context.ReleaseManifest.repository.tree -or
        $Record.receipt.releaseManifestSha256 -cne $Context.ReleaseManifestSha256 -or
        $Record.receipt.authorizationSha256 -cne $Context.AuthorizationSha256 -or
        $Record.receipt.policySha256 -cne $Context.PolicySha256 -or
        $Record.receipt.rolloutAuthorizationSha256 -cne $ParsedPlan.Plan.policy.rolloutAuthorizationSha256 -or
        [int]$Record.receipt.rolloutSequence -ne [int]$ParsedPlan.Plan.policy.rolloutSequence -or
        $Record.receipt.rolloutStage -cne $ParsedPlan.Plan.policy.rolloutStage -or
        $Record.receipt.dataBundleSha256 -cne $Context.DataBundleSha256 -or
        $Record.receipt.operation.adapterPolicyId -cne $ParsedPlan.Plan.operation.adapterPolicyId -or
        $Record.receipt.operation.adapterReservationId -cne $ParsedPlan.Plan.operation.adapterReservationId -or
        $Record.receipt.operation.staticMacAddress -cne $ParsedPlan.Plan.operation.staticMacAddress -or
        $Record.receipt.operation.secureBootEnabled -ne $ParsedPlan.Plan.operation.secureBootEnabled -or
        $Record.receipt.operation.secureBootExceptionId -cne $ParsedPlan.Plan.operation.secureBootExceptionId -or
        $Record.receipt.operation.vtpmRequired -ne $ParsedPlan.Plan.operation.vtpmRequired -or
        $Record.receipt.operation.bootstrapMediaId -cne $ParsedPlan.Plan.operation.bootstrapMediaId -or
        $Record.receipt.operation.bootstrapMediaMode -cne $ParsedPlan.Plan.operation.bootstrapMediaMode -or
        $Record.receipt.operation.bootstrapMediaSha256 -cne $ParsedPlan.Plan.operation.bootstrapMediaSha256 -or
        $Record.receipt.operation.bootstrapMediaSourceImageSha256 -cne $ParsedPlan.Plan.operation.bootstrapMediaSourceImageSha256 -or
        $Record.receipt.operation.bootstrapMediaProvenanceSha256 -cne $ParsedPlan.Plan.operation.bootstrapMediaProvenanceSha256 -or
        $Record.receipt.operation.bootstrapMediaBundleManifestSha256 -cne $ParsedPlan.Plan.operation.bootstrapMediaBundleManifestSha256 -or
        $Record.receipt.operation.bootstrapMediaUnattendedPayloadSha256 -cne
            $ParsedPlan.Plan.operation.bootstrapMediaUnattendedPayloadSha256) {
        Throw-NgcbError 'NGCB-RECEIPT-PLAN-BINDING-INVALID'
    }
    try { $signature = [Convert]::FromBase64String([string]$Record.detachedCmsSignatureBase64) }
    catch { Throw-NgcbError 'NGCB-RECEIPT-CORRUPT' }
    $evidence = Assert-NgcbDetachedCmsSignature $bytes $signature `
        ([string]$Context.Authorization.identity.receiptSignerCertificateSha256) `
        'NGCB-RECEIPT-SIGNATURE-INVALID'
    if ($evidence.signatureSha256 -cne $Record.detachedCmsSignatureSha256 -or
        $evidence.certificateSha256 -cne $Record.signerCertificateSha256) {
        Throw-NgcbError 'NGCB-RECEIPT-CORRUPT'
    }
}

function Get-NorthGateCreateOnlyReceipt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$PlanId)
    Assert-NgcbContext $Context
    $parsedPlan = Read-NgcbPlanRecord $Context $PlanId
    $envelope = Read-NgcbEnvelope $Context 'signed-receipt-record' (Get-NgcbReceiptPath $Context $PlanId) `
        'NGCB-RECEIPT-NOT-AVAILABLE'
    Assert-NgcbReceiptRecord $Context $envelope.record $parsedPlan
    return [pscustomobject][ordered]@{
        receipt = $envelope.record.receipt
        receiptSha256 = $envelope.record.receiptSha256
        detachedCmsSignatureBase64 = $envelope.record.detachedCmsSignatureBase64
        detachedCmsSignatureSha256 = $envelope.record.detachedCmsSignatureSha256
        signerCertificateSha256 = $envelope.record.signerCertificateSha256
    }
}

function Invoke-NorthGateCreateOnlyApply {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$PlanId)
    Assert-NgcbContext $Context
    Assert-NgcbPlanId $PlanId
    Assert-NgcbProductionServiceIdentity $Context
    $initialPlan = Read-NgcbPlanRecord $Context $PlanId
    $assetId = [string]$initialPlan.Plan.operation.assetId
    $lock = Enter-NgcbLockSet $Context $assetId
    try {
        Assert-NgcbContextAnchorsCurrent $Context
        if (Test-Path -LiteralPath (Get-NgcbReceiptPath $Context $PlanId) -PathType Leaf) {
            return Get-NorthGateCreateOnlyReceipt $Context $PlanId
        }
        $parsedPlan = Read-NgcbPlanRecord $Context $PlanId
        if ($parsedPlan.Record.state -cne 'Registered' -or $parsedPlan.Record.approvalState -cne 'Registered') {
            Throw-NgcbError 'NGCB-PLAN-NOT-APPLICABLE'
        }
        $applyNow = [DateTimeOffset]::UtcNow
        if ((ConvertTo-NgcbUtc $parsedPlan.Plan.issuedAtUtc 'NGCB-PLAN-TIME-INVALID') -gt
            $applyNow.AddSeconds($script:MaximumClockSkewSeconds)) {
            Throw-NgcbError 'NGCB-PLAN-CLOCK-INVALID'
        }
        if ((ConvertTo-NgcbUtc $parsedPlan.Plan.expiresAtUtc 'NGCB-PLAN-TIME-INVALID') -le $applyNow) {
            Throw-NgcbError 'NGCB-PLAN-EXPIRED'
        }
        if (-not [bool]$Context.Policy.applyEnabled -or
            (@($Context.Policy.executableActions) -join '|') -cne 'Create') {
            Throw-NgcbError 'NGCB-POLICY-APPLY-NOT-ENABLED'
        }
        $resolved = Resolve-NgcbManifest $Context $assetId
        Assert-NgcbPlanContract $Context $parsedPlan.Record $parsedPlan.Plan $resolved
        $approvalEnvelope = Read-NgcbApprovalRecord $Context $parsedPlan
        if ($approvalEnvelope.Record.state -cne 'Registered') { Throw-NgcbError 'NGCB-APPROVAL-ALREADY-CONSUMED' }
        $observed = Get-NgcbObservedState $Context $resolved ([string]$parsedPlan.Plan.reservationId)
        if (-not $observed.CollisionFree) { Throw-NgcbError 'NGCB-APPLY-COLLISION' }
        if ($observed.IdentityHash -cne [string]$parsedPlan.Plan.liveState.identityHash) {
            Throw-NgcbError 'NGCB-LIVE-STATE-DRIFT'
        }
        if (-not $observed.Capacity.pass) { Throw-NgcbError 'NGCB-CAPACITY-INSUFFICIENT' }
        if (-not $Context.ReceiptCertificate.HasPrivateKey -or
            (Get-NgcbCertificateSha256 $Context.ReceiptCertificate) -cne
                [string]$Context.Authorization.identity.receiptSignerCertificateSha256) {
            Throw-NgcbError 'NGCB-RECEIPT-SIGNER-NOT-USABLE'
        }
        $executionId = 'ngx-' + (New-NgcbRandomHex 32)
        $approvalEnvelope.Record.state = 'Consumed'
        $approvalEnvelope.Record.consumedAtUtc = Format-NgcbUtc ([DateTimeOffset]::UtcNow)
        $approvalEnvelope.Record.executionId = $executionId
        $null = Write-NgcbEnvelope $Context 'plan-approval-record' $approvalEnvelope.Record `
            (Get-NgcbApprovalPath $Context $PlanId)
        $parsedPlan.Record.approvalState = 'Consumed'
        $parsedPlan.Record.state = 'Applying'
        $parsedPlan.Record.executionId = $executionId
        Save-NgcbPlanRecord $Context $parsedPlan.Record
        Update-NgcbLedgerEntry $Context $parsedPlan.Plan.reservationId 'Applying'
        $null = Write-NgcbJournalEvent $Context $assetId $parsedPlan.Plan.reservationId $PlanId `
            'ApprovalConsumed' '' 'NGCB-ONE-TIME-APPROVAL-CONSUMED'
        Write-NgcbAuditEvent $Context 'approval-consumed' 'succeeded' `
            'NGCB-ONE-TIME-APPROVAL-CONSUMED' $PlanId $assetId

        $providerResult = if ($Context.Mode -ceq 'Production') {
            Invoke-NgcbProductionCreate $Context $parsedPlan.Plan
        } else { Invoke-NgcbInertCreate $Context $parsedPlan.Plan }
        if ($providerResult.status -ceq 'Created') {
            Update-NgcbLedgerEntry $Context $parsedPlan.Plan.reservationId 'Bound' $providerResult.vmId
            $terminalState = 'Applied'
            $journalState = 'CreateVerified'
        }
        elseif ($providerResult.status -ceq 'OutcomeUnknown') {
            Update-NgcbLedgerEntry $Context $parsedPlan.Plan.reservationId 'OutcomeUnknown' $providerResult.vmId
            $terminalState = 'OutcomeUnknownReconciliationRequired'
            $journalState = 'OutcomeUnknown'
        }
        elseif ($providerResult.quarantineState -ceq 'completed') {
            Update-NgcbLedgerEntry $Context $parsedPlan.Plan.reservationId 'Quarantined' $providerResult.vmId
            $terminalState = 'FailedQuarantined'
            $journalState = 'Quarantined'
        }
        else {
            Update-NgcbLedgerEntry $Context $parsedPlan.Plan.reservationId 'AbortedNoArtifacts' $providerResult.vmId
            $terminalState = 'FailedNoArtifacts'
            $journalState = 'AbortedNoArtifacts'
        }
        $null = Write-NgcbJournalEvent $Context $assetId $parsedPlan.Plan.reservationId $PlanId `
            $journalState $providerResult.vmId $providerResult.reasonCode `
            $(if ($providerResult.afterState.PSObject.Properties['adapterId']) { [string]$providerResult.afterState.adapterId } else { '' }) `
            ([string]$parsedPlan.Plan.operation.staticMacAddress)

        try {
            $receiptRecord = New-NgcbSignedReceiptRecord $Context $parsedPlan $approvalEnvelope.Record `
                $providerResult $executionId
            $null = Write-NgcbEnvelope $Context 'signed-receipt-record' $receiptRecord `
                (Get-NgcbReceiptPath $Context $PlanId) -CreateNew
            $parsedPlan.Record.evidenceState = 'signed-receipt-complete'
        }
        catch {
            $parsedPlan.Record.state = $terminalState + 'EvidencePending'
            $parsedPlan.Record.quarantineState = [string]$providerResult.quarantineState
            $parsedPlan.Record.evidenceState = 'receipt-signing-failed'
            Save-NgcbPlanRecord $Context $parsedPlan.Record
            $null = Write-NgcbJournalEvent $Context $assetId $parsedPlan.Plan.reservationId $PlanId `
                'EvidenceReconciliationPending' $providerResult.vmId 'NGCB-RECEIPT-SIGNING-FAILED'
            Write-NgcbAuditEvent $Context 'apply-completed-receipt-failed' 'failed' `
                'NGCB-RECEIPT-SIGNING-FAILED' $PlanId $assetId
            Throw-NgcbError 'NGCB-RECEIPT-SIGNING-FAILED'
        }
        $parsedPlan.Record.state = $terminalState
        $parsedPlan.Record.quarantineState = [string]$providerResult.quarantineState
        Save-NgcbPlanRecord $Context $parsedPlan.Record
        Write-NgcbAuditEvent $Context 'apply-completed' `
            $(if ($providerResult.status -ceq 'Created') {'succeeded'} else {'failed'}) `
            $providerResult.reasonCode $PlanId $assetId
        return Get-NorthGateCreateOnlyReceipt $Context $PlanId
    }
    finally { Exit-NgcbLockSet $lock }
}

function Invoke-NorthGateCreateOnlyCrashRecovery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [string]$AssetId = ''
    )
    Assert-NgcbContext $Context
    Assert-NgcbProductionServiceIdentity $Context
    $ledger = Read-NgcbLedger $Context
    $candidates = @($ledger.entries | Where-Object {
        $_.state -in @('Reserved','Applying','OutcomeUnknown','AbortedNoArtifacts') -and
        ($AssetId -eq '' -or $_.assetId -ceq $AssetId)
    })
    $results = @()
    foreach ($candidate in $candidates) {
        $lock = Enter-NgcbLockSet $Context ([string]$candidate.assetId)
        try {
            $parsedPlan = Read-NgcbPlanRecord $Context ([string]$candidate.planId)
            $lastJournal = Read-NgcbLastJournalEvent $Context $candidate.assetId $candidate.reservationId
            if ($candidate.state -ceq 'AbortedNoArtifacts' -and
                $parsedPlan.Record.state -ceq 'RecoveredNoArtifacts' -and
                $parsedPlan.Record.quarantineState -ceq 'not-required' -and
                $parsedPlan.Record.evidenceState -ceq 'recovery-journal-complete' -and
                $candidate.vmId -eq '' -and $null -ne $lastJournal -and
                $lastJournal.planId -ceq $candidate.planId -and
                $lastJournal.state -ceq 'RecoveredNoArtifacts' -and
                $lastJournal.vmId -eq '' -and
                $lastJournal.detailCode -ceq 'NGCB-RECOVERY-NO-ARTIFACTS') {
                continue
            }
            if ($parsedPlan.Record.state -eq 'Registered' -and
                (ConvertTo-NgcbUtc $parsedPlan.Plan.expiresAtUtc) -gt [DateTimeOffset]::UtcNow) {
                continue
            }
            $ownedVmId = ''
            $owned = $false
            $artifactExists = Test-Path -LiteralPath ([string]$candidate.assetRoot)
            if ($Context.Mode -ceq 'Production') {
                $matches = @()
                if ($candidate.vmId -ne '') {
                    $matches = @(Hyper-V\Get-VM -Id ([guid]$candidate.vmId) -ErrorAction SilentlyContinue)
                }
                if ($matches.Count -eq 0) {
                    $matches = @(Hyper-V\Get-VM -Name ([string]$candidate.name) -ErrorAction SilentlyContinue)
                }
                if ($matches.Count -eq 1) {
                    $normalNote = Get-NgcbOwnershipNote $parsedPlan.Plan.operation.assetId `
                        $parsedPlan.Plan.operation.changeId $parsedPlan.Plan.reservationId $parsedPlan.Plan.planId $false
                    $quarantineNote = Get-NgcbOwnershipNote $parsedPlan.Plan.operation.assetId `
                        $parsedPlan.Plan.operation.changeId $parsedPlan.Plan.reservationId $parsedPlan.Plan.planId $true
                    if ([string]$matches[0].Notes -in @($normalNote,$quarantineNote)) {
                        $owned = $true
                        $ownedVmId = ([string]$matches[0].Id).ToLowerInvariant()
                    }
                    else { $artifactExists = $true }
                }
                if ($owned) {
                    $quarantined = Invoke-NgcbQuarantineProductionVm $Context $parsedPlan.Plan $ownedVmId
                }
                else { $quarantined = $false }
            }
            else {
                $matches = @($Context.TestState.vms | Where-Object {
                    ($candidate.vmId -ne '' -and $_.vmId -ceq $candidate.vmId) -or $_.name -ceq $candidate.name
                })
                if ($matches.Count -eq 1) {
                    $normalNote = Get-NgcbOwnershipNote $parsedPlan.Plan.operation.assetId `
                        $parsedPlan.Plan.operation.changeId $parsedPlan.Plan.reservationId $parsedPlan.Plan.planId $false
                    $quarantineNote = Get-NgcbOwnershipNote $parsedPlan.Plan.operation.assetId `
                        $parsedPlan.Plan.operation.changeId $parsedPlan.Plan.reservationId $parsedPlan.Plan.planId $true
                    if ([string]$matches[0].notes -in @($normalNote,$quarantineNote)) {
                        $owned = $true
                        $ownedVmId = [string]$matches[0].vmId
                        $matches[0].notes = $quarantineNote
                    }
                    else { $artifactExists = $true }
                }
                $quarantined = $owned
            }
            if ($quarantined) {
                $state = 'Quarantined'; $planState = 'RecoveredQuarantined'; $code = 'NGCB-RECOVERY-QUARANTINED'
            }
            elseif (-not $artifactExists -and -not $owned) {
                $state = 'AbortedNoArtifacts'; $planState = 'RecoveredNoArtifacts'; $code = 'NGCB-RECOVERY-NO-ARTIFACTS'
            }
            else {
                $state = 'OutcomeUnknown'; $planState = 'OutcomeUnknownReconciliationRequired'; $code = 'NGCB-RECOVERY-OWNERSHIP-UNCERTAIN'
            }
            Update-NgcbLedgerEntry $Context $candidate.reservationId $state $ownedVmId
            $parsedPlan.Record.state = $planState
            $parsedPlan.Record.quarantineState = if ($state -eq 'Quarantined') { 'completed' } `
                elseif ($state -eq 'OutcomeUnknown') { 'required' } else { 'not-required' }
            $parsedPlan.Record.evidenceState = 'recovery-journal-complete'
            Save-NgcbPlanRecord $Context $parsedPlan.Record
            $null = Write-NgcbJournalEvent $Context $candidate.assetId $candidate.reservationId `
                $candidate.planId $planState $ownedVmId $code
            Write-NgcbAuditEvent $Context 'crash-recovery' `
                $(if ($state -eq 'OutcomeUnknown') {'failed'} else {'succeeded'}) $code `
                $candidate.planId $candidate.assetId
            $results += [pscustomobject][ordered]@{
                assetId = [string]$candidate.assetId
                planId = [string]$candidate.planId
                state = $state
                vmId = $ownedVmId
                quarantineState = [string]$parsedPlan.Record.quarantineState
                reasonCode = $code
                approvalReusable = $false
            }
        }
        finally { Exit-NgcbLockSet $lock }
    }
    return @($results)
}

Export-ModuleMember -Function @(
    'New-NorthGateCreateOnlyBackendContext',
    'Get-NorthGateCreateOnlyBackendState',
    'New-NorthGateCreateOnlyHostPlan',
    'Get-NorthGateCreateOnlyHostPlan',
    'Get-NorthGateCreateOnlyRolloutPromotionContext',
    'Register-NorthGateCreateOnlyRolloutPromotion',
    'Register-NorthGateCreateOnlyApproval',
    'Invoke-NorthGateCreateOnlyApply',
    'Get-NorthGateCreateOnlyReceipt',
    'Invoke-NorthGateCreateOnlyCrashRecovery'
)

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBERQpK4W9TsxxB
# wkhZqfRRgxIWR+i6Vj5wrWnCgUWCraCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIDlKFBatfFrEH9s1+VEMihQ7dKfWPmSiLBavo4cBsF+hMA0GCSqG
# SIb3DQEBAQUABIIBgElLYtmoDeQaYRj1DxNtnMi5F85RNRXN6kZtSdbhkzBZuvVN
# BZqRNFXczYl8+xXNHphWtCyxIFBsnjFdyZSQre2d7gek+wvAmpyOwAf0umnGQGrV
# H+uUBL+jmXBfOCCxdLB3wu1diCyvWOLgNF91y6S5BuwOu8u/0+yijgNifgnVhQp6
# ic53dd+P/EV7WhzMIQyT54xRrPkTaxxVlCdADqszprTm9VizpW3secU/Uodbuby3
# iUEhuJ8UKo3lnUOAfuBwfpFhLOMsz+PKY8QTzuVI3cwrPlVH9YlfhXi7ucOQany6
# kKdj9dLtx9/s3ktmxOGIuhcxAIWxsTDFe/fEKnvr4Oe2Oo3eZH3eCsLgxBMKqm4+
# 7NzzBVPob6G0IJP9zvg13EZ70kiZIBzwE4GwS7OvyyYDEcnltDDjSm+WwY/GavaB
# SetdXL5aJVCwH0LKdoWdJz6g0MGZG+ThaLmk/713YwT+twQBH5DH4pa/caMxKS0N
# ayA5fEvCtGLHbAnEBg==
# SIG # End signature block
