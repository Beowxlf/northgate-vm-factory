[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$PackageRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedReleaseManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedTree,
    [Parameter(Mandatory)][ValidatePattern('^ngallow-[a-z0-9-]{8,64}$')][string]$ExpectedHostAllowlistId,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$ReleaseManifestSignaturePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$SignedHostDeploymentAuthorizationPath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$DeploymentAuthorizationSignaturePath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDeploymentAuthorizationSha256,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$BackendPolicyPath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$BackendPolicySignaturePath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedBackendPolicySha256,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$DataBundleRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDataBundleSha256,
    [Parameter(Mandatory)][switch]$ConfirmInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# These two independent public-certificate pins are replaced only in the
# separately reviewed bootstrap artifact whose exact source and transport hashes
# are approved out of band. They are never parameters, environment values,
# policy values, or repository data.
$bakedReleaseSignerCertificateSha256 = ''
$bakedDeploymentAuthorizationSignerCertificateSha256 = ''
$requiredServiceHostFileName = 'NorthGate.CreateOnly.ServiceHost.exe'

function Stop-Ngci {
    param([string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function Read-NgciExclusiveBytes {
    param([string]$Path, [int64]$MaximumBytes, [string]$Code)
    $full = [System.IO.Path]::GetFullPath($Path)
    $cursor = $full
    while (-not (Test-Path -LiteralPath $cursor) -and -not [string]::IsNullOrWhiteSpace($cursor)) {
        $cursor = Split-Path -Parent $cursor
    }
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and (Test-Path -LiteralPath $cursor)) {
        if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            Stop-Ngci $Code
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Stop-Ngci $Code }
    $item = Get-Item -LiteralPath $full -Force
    if ($item.Length -le 0 -or $item.Length -gt $MaximumBytes) { Stop-Ngci $Code }
    $stream = New-Object System.IO.FileStream(
        $full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::None, 65536, [System.IO.FileOptions]::SequentialScan
    )
    try {
        $memory = New-Object System.IO.MemoryStream
        try {
            $stream.CopyTo($memory)
            $bytes = $memory.ToArray()
            return ,$bytes
        }
        finally { $memory.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Get-NgciSha256Hex {
    param([byte[]]$Bytes)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-NgciHexEquals {
    param([string]$Left, [string]$Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ([int][char]$Left[$index] -bxor [int][char]$Right[$index])
    }
    $difference -eq 0
}

function Test-NgciCertificatePin {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$ExpectedPin)
    if ($null -eq $Certificate -or $ExpectedPin -cnotmatch '^[a-f0-9]{64}$' -or $ExpectedPin -ceq ('0' * 64)) {
        Stop-Ngci 'NGCOR-INSTALL-SIGNER-PIN-INVALID'
    }
    if (-not (Test-NgciHexEquals (Get-NgciSha256Hex $Certificate.RawData) $ExpectedPin)) {
        Stop-Ngci 'NGCOR-INSTALL-SIGNER-PIN-MISMATCH'
    }
    $now = [DateTimeOffset]::UtcNow
    if ($now -lt $Certificate.NotBefore.ToUniversalTime() -or $now -gt $Certificate.NotAfter.ToUniversalTime()) {
        Stop-Ngci 'NGCOR-INSTALL-SIGNER-CERTIFICATE-EXPIRED'
    }
    $hasLeafConstraint = $false
    $hasCodeSigningEku = $false
    $hasDigitalSignatureUsage = $false
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $hasLeafConstraint = $true
            if ($extension.CertificateAuthority) { Stop-Ngci 'NGCOR-INSTALL-SIGNER-CA-FORBIDDEN' }
        }
        elseif ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($usage in $extension.EnhancedKeyUsages) {
                if ($usage.Value -ceq '1.3.6.1.5.5.7.3.3') { $hasCodeSigningEku = $true }
            }
        }
        elseif ($extension -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $hasDigitalSignatureUsage = [bool]($extension.KeyUsages -band
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)
            if ($extension.KeyUsages -band (
                    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
                    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign)) {
                Stop-Ngci 'NGCOR-INSTALL-SIGNER-KEY-USAGE-INVALID'
            }
        }
    }
    if (-not $hasLeafConstraint -or -not $hasCodeSigningEku -or -not $hasDigitalSignatureUsage) {
        Stop-Ngci 'NGCOR-INSTALL-SIGNER-KEY-USAGE-INVALID'
    }
}

function Test-NgciDetachedCms {
    param([byte[]]$ContentBytes, [string]$SignaturePath, [string]$ExpectedPin)
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    $signatureBytes = Read-NgciExclusiveBytes $SignaturePath 1048576 'NGCOR-INSTALL-CMS-SIGNATURE-INVALID'
    try {
        $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo(,$ContentBytes)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms($content, $true)
        $cms.Decode($signatureBytes)
        if (-not $cms.Detached -or $cms.SignerInfos.Count -ne 1) {
            Stop-Ngci 'NGCOR-INSTALL-CMS-SIGNER-COUNT-INVALID'
        }
        if ($cms.SignerInfos[0].DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1') {
            Stop-Ngci 'NGCOR-INSTALL-CMS-DIGEST-INVALID'
        }
        $cms.CheckSignature($true)
        $certificate = $cms.SignerInfos[0].Certificate
        Test-NgciCertificatePin $certificate $ExpectedPin
    }
    catch {
        if ($_.Exception.Message -cmatch '^NGCOR-') { throw }
        Stop-Ngci 'NGCOR-INSTALL-CMS-SIGNATURE-INVALID'
    }
}

function Test-NgciAuthenticodeFile {
    param([string]$Path, [string]$ExpectedPin)
    try { $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop }
    catch { Stop-Ngci 'NGCOR-INSTALL-AUTHENTICODE-INVALID' }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        Stop-Ngci 'NGCOR-INSTALL-AUTHENTICODE-INVALID'
    }
    Test-NgciCertificatePin $signature.SignerCertificate $ExpectedPin
}

function ConvertFrom-NgciJson {
    param([string]$Json)
    $converter = Microsoft.PowerShell.Core\Get-Command `
        -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json -DateKind String
    }
    Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json
}

function Assert-NgciNotRepositoryPath {
    param([string]$Path)
    $cursor = New-Object System.IO.DirectoryInfo([System.IO.Path]::GetFullPath($Path))
    while ($null -ne $cursor) {
        if (Test-Path -LiteralPath (Join-Path $cursor.FullName '.git')) {
            Stop-Ngci 'NGCOR-INSTALL-PACKAGE-IN-REPOSITORY-FORBIDDEN'
        }
        $cursor = $cursor.Parent
    }
}

function Assert-NgciPathWithin {
    param([string]$Path,[string]$Parent,[string]$Code)
    $full=[IO.Path]::GetFullPath($Path)
    $root=[IO.Path]::GetFullPath($Parent).TrimEnd('\')
    if (-not $full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) { Stop-Ngci $Code }
    $full
}

function Test-NgciTargetGroupMembership {
    param([string]$MemberSid, [string]$GroupSid)
    try {
        $groupAccount = (New-Object System.Security.Principal.SecurityIdentifier($GroupSid)).Translate(
            [System.Security.Principal.NTAccount]
        ).Value
        $groupName = ($groupAccount -split '\\')[-1]
        $group = [ADSI]('WinNT://./' + $groupName + ',group')
        foreach ($member in @($group.psbase.Invoke('Members'))) {
            $bytes = [byte[]]$member.GetType().InvokeMember(
                'objectSid', 'GetProperty', $null, $member, $null
            )
            if ((New-Object System.Security.Principal.SecurityIdentifier($bytes,0)).Value -ceq $MemberSid) {
                return $true
            }
        }
        $false
    }
    catch { Stop-Ngci 'NGCOR-INSTALL-IDENTITY-MEMBERSHIP-UNVERIFIABLE' }
}

if (-not $ConfirmInstall) { Stop-Ngci 'NGCOR-INSTALL-CONFIRMATION-REQUIRED' }
if ($ExpectedCommit -ceq ('0' * 40) -or $ExpectedTree -ceq ('0' * 40) -or
    $ExpectedReleaseManifestSha256 -ceq ('0' * 64) -or
    $ExpectedDeploymentAuthorizationSha256 -ceq ('0' * 64) -or
    $ExpectedBackendPolicySha256 -ceq ('0' * 64) -or $ExpectedDataBundleSha256 -ceq ('0' * 64)) {
    Stop-Ngci 'NGCOR-INSTALL-ZERO-PIN-FORBIDDEN'
}
if ($bakedReleaseSignerCertificateSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    $bakedDeploymentAuthorizationSignerCertificateSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    $bakedReleaseSignerCertificateSha256 -ceq $bakedDeploymentAuthorizationSignerCertificateSha256) {
    Stop-Ngci 'NGCOR-INSTALL-BLOCKED-TRUST-ANCHOR-NOT-BAKED'
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Ngci 'NGCOR-INSTALL-ADMINISTRATOR-REQUIRED'
}

$package = [System.IO.Path]::GetFullPath($PackageRoot).TrimEnd('\','/')
Assert-NgciNotRepositoryPath $package
$manifestPath = Join-Path $package 'release-manifest.json'
$manifestBytes = Read-NgciExclusiveBytes $manifestPath 1048576 'NGCOR-INSTALL-MANIFEST-INVALID'
$manifestHash = Get-NgciSha256Hex $manifestBytes
if (-not (Test-NgciHexEquals $manifestHash $ExpectedReleaseManifestSha256)) {
    Stop-Ngci 'NGCOR-INSTALL-MANIFEST-HASH-MISMATCH'
}
Test-NgciDetachedCms $manifestBytes $ReleaseManifestSignaturePath $bakedReleaseSignerCertificateSha256

try {
    $manifestText = (New-Object System.Text.UTF8Encoding($false,$true)).GetString($manifestBytes)
    $manifestBootstrap = ConvertFrom-NgciJson $manifestText
}
catch { Stop-Ngci 'NGCOR-INSTALL-MANIFEST-JSON-INVALID' }
if ($manifestBootstrap.schema -cne 'northgate/create-only-release-manifest/v2' -or
    $manifestBootstrap.repository.identity -cne 'Beowxlf/northgate-vm-factory' -or
    $manifestBootstrap.repository.commit -cne $ExpectedCommit -or
    $manifestBootstrap.repository.tree -cne $ExpectedTree -or
    $manifestBootstrap.repository.hostAllowlistId -cne $ExpectedHostAllowlistId) {
    Stop-Ngci 'NGCOR-INSTALL-MANIFEST-PIN-MISMATCH'
}

$authenticodeFiles = @($manifestBootstrap.files | Where-Object {
    [IO.Path]::GetExtension([string]$_.path) -cin @('.ps1','.psm1','.psd1')
})
if ($authenticodeFiles.Count -lt 10) { Stop-Ngci 'NGCOR-INSTALL-AUTHENTICODE-INVENTORY-INVALID' }
foreach ($record in $authenticodeFiles) {
    $authenticodePath = Join-Path $package ([string]$record.path)
    Test-NgciAuthenticodeFile $authenticodePath $bakedReleaseSignerCertificateSha256
}

$bootstrapFiles = @(
    'NorthGate.VMFactory.CreateOnlyProtocol.psd1',
    'NorthGate.VMFactory.CreateOnlyProtocol.psm1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psd1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psm1'
)
foreach ($name in $bootstrapFiles) {
    $record = @($manifestBootstrap.files | Where-Object { $_.path -ceq $name })
    if ($record.Count -ne 1 -or $record[0].sha256 -cnotmatch '^[a-f0-9]{64}$') {
        Stop-Ngci 'NGCOR-INSTALL-BOOTSTRAP-FILE-NOT-MANIFESTED'
    }
    $path = Join-Path $package $name
    $bytes = Read-NgciExclusiveBytes $path 16777216 'NGCOR-INSTALL-BOOTSTRAP-FILE-INVALID'
    if (-not (Test-NgciHexEquals (Get-NgciSha256Hex $bytes) ([string]$record[0].sha256))) {
        Stop-Ngci 'NGCOR-INSTALL-BOOTSTRAP-FILE-HASH-MISMATCH'
    }
}

$protocolPath = Join-Path $package 'NorthGate.VMFactory.CreateOnlyProtocol.psd1'
$deploymentPath = Join-Path $package 'NorthGate.VMFactory.CreateOnlyDeployment.psd1'
Import-Module $protocolPath -Force -ErrorAction Stop
$deployment = Import-Module $deploymentPath -Force -PassThru -ErrorAction Stop
try { $manifest = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $manifestBytes -MaximumBytes 1048576).Value }
catch { Stop-Ngci 'NGCOR-INSTALL-MANIFEST-NONCANONICAL' }

$authorizationBytes = Read-NgciExclusiveBytes $SignedHostDeploymentAuthorizationPath 1048576 `
    'NGCOR-INSTALL-AUTHORIZATION-INVALID'
if (-not (Test-NgciHexEquals (Get-NgciSha256Hex $authorizationBytes) $ExpectedDeploymentAuthorizationSha256)) {
    Stop-Ngci 'NGCOR-INSTALL-AUTHORIZATION-HASH-MISMATCH'
}
Test-NgciDetachedCms $authorizationBytes $DeploymentAuthorizationSignaturePath `
    $bakedDeploymentAuthorizationSignerCertificateSha256
try {
    $authorization = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $authorizationBytes -MaximumBytes 1048576).Value
}
catch { Stop-Ngci 'NGCOR-INSTALL-AUTHORIZATION-NONCANONICAL' }
if ($authorization.identity.releaseSignerCertificateSha256 -cne $bakedReleaseSignerCertificateSha256 -or
    $authorization.identity.deploymentAuthorizationSignerCertificateSha256 -cne
        $bakedDeploymentAuthorizationSignerCertificateSha256) {
    Stop-Ngci 'NGCOR-INSTALL-AUTHORIZATION-SIGNER-PIN-MISMATCH'
}

$backendPolicyBytes = Read-NgciExclusiveBytes $BackendPolicyPath 1048576 'NGCOR-INSTALL-BACKEND-POLICY-INVALID'
if (-not (Test-NgciHexEquals (Get-NgciSha256Hex $backendPolicyBytes) $ExpectedBackendPolicySha256)) {
    Stop-Ngci 'NGCOR-INSTALL-BACKEND-POLICY-HASH-MISMATCH'
}
Test-NgciDetachedCms $backendPolicyBytes $BackendPolicySignaturePath $bakedReleaseSignerCertificateSha256
try {
    $backendPolicy = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
        -Bytes $backendPolicyBytes -MaximumBytes 1048576).Value
}
catch { Stop-Ngci 'NGCOR-INSTALL-BACKEND-POLICY-NONCANONICAL' }
if ($backendPolicy.schema -cne 'northgate/create-only-backend-policy/v1' -or
    $backendPolicy.authorizationSha256 -cne $ExpectedDeploymentAuthorizationSha256 -or
    $backendPolicy.releaseManifestSha256 -cne $ExpectedReleaseManifestSha256 -or
    $backendPolicy.hostId -cne $authorization.host.hostId -or
    $backendPolicy.applyEnabled -ne $true -or
    (@($backendPolicy.executableActions) -join '|') -cne 'Create' -or
    $backendPolicy.stateKeyId -cnotmatch '^ngkey-[a-z0-9-]{8,64}$') {
    Stop-Ngci 'NGCOR-INSTALL-BACKEND-POLICY-BINDING-MISMATCH'
}

$dataBundleSourceRoot = [IO.Path]::GetFullPath($DataBundleRoot).TrimEnd('\')
Assert-NgciNotRepositoryPath $dataBundleSourceRoot
$dataBundlePath = Join-Path $dataBundleSourceRoot 'bundle.json'
$dataBundleSignaturePath = Join-Path $dataBundleSourceRoot 'bundle.p7s'
$dataBundleBytes = Read-NgciExclusiveBytes $dataBundlePath 10485760 'NGCOR-INSTALL-DATA-BUNDLE-INVALID'
if (-not (Test-NgciHexEquals (Get-NgciSha256Hex $dataBundleBytes) $ExpectedDataBundleSha256)) {
    Stop-Ngci 'NGCOR-INSTALL-DATA-BUNDLE-HASH-MISMATCH'
}
Test-NgciDetachedCms $dataBundleBytes $dataBundleSignaturePath $bakedReleaseSignerCertificateSha256
try {
    $dataBundle = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
        -Bytes $dataBundleBytes -MaximumBytes 10485760).Value
}
catch { Stop-Ngci 'NGCOR-INSTALL-DATA-BUNDLE-NONCANONICAL' }
if ($dataBundle.schema -cne 'northgate/create-only-data-bundle/v1' -or
    $dataBundle.bundleId -cnotmatch '^ngdata-[a-f0-9]{64}$' -or
    $dataBundle.repository.identity -cne 'Beowxlf/northgate-vm-factory' -or
    $dataBundle.repository.commit -cne $ExpectedCommit -or $dataBundle.repository.tree -cne $ExpectedTree -or
    @($dataBundle.files).Count -lt 7) { Stop-Ngci 'NGCOR-INSTALL-DATA-BUNDLE-BINDING-MISMATCH' }
$dataFiles = @()
$expectedDataInventory = @('bundle.json','bundle.p7s')
$seenDataPaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($record in @($dataBundle.files)) {
    $relative = [string]$record.canonicalRelativePath
    if ($relative -cnotmatch '^files/[A-Za-z0-9._/-]{1,180}\.json$' -or
        $relative -match '(?:^|/)\.\.(?:/|$)' -or -not $seenDataPaths.Add($relative) -or
        $record.canonicalSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        -not ($record.sizeBytes -is [int] -or $record.sizeBytes -is [long])) {
        Stop-Ngci 'NGCOR-INSTALL-DATA-BUNDLE-FILE-INVALID'
    }
    $source = Assert-NgciPathWithin (Join-Path $dataBundleSourceRoot $relative.Replace('/','\')) `
        $dataBundleSourceRoot 'NGCOR-INSTALL-DATA-BUNDLE-FILE-INVALID'
    $bytes = Read-NgciExclusiveBytes $source 1048576 'NGCOR-INSTALL-DATA-BUNDLE-FILE-INVALID'
    if ($bytes.Length -ne [int64]$record.sizeBytes -or
        -not (Test-NgciHexEquals (Get-NgciSha256Hex $bytes) ([string]$record.canonicalSha256))) {
        Stop-Ngci 'NGCOR-INSTALL-DATA-BUNDLE-FILE-HASH-MISMATCH'
    }
    $dataFiles += [pscustomobject][ordered]@{relativePath=$relative;bytes=$bytes}
    $expectedDataInventory += $relative
}
$actualDataInventory = @(Get-ChildItem -LiteralPath $dataBundleSourceRoot -Recurse -File | ForEach-Object {
    $_.FullName.Substring($dataBundleSourceRoot.Length).TrimStart('\').Replace('\','/')
} | Sort-Object)
if (($actualDataInventory -join '|') -cne (@($expectedDataInventory | Sort-Object) -join '|')) {
    Stop-Ngci 'NGCOR-INSTALL-DATA-BUNDLE-INVENTORY-MISMATCH'
}

$null = & $deployment {
    param($Root,$Files)
    Test-NgcdPackageFiles $Root @($Files)
} $package @($manifest.files)
$serviceHostRecords = @($manifest.files | Where-Object {
    $_.artifactKind -ceq 'derived-signed-artifact' -and $_.path -ceq $requiredServiceHostFileName
})
if ($serviceHostRecords.Count -ne 1 -or
    $serviceHostRecords[0].detachedCms.signerCertificateSha256 -cne $bakedReleaseSignerCertificateSha256) {
    Stop-Ngci 'NGCOR-INSTALL-SIGNED-SERVICE-HOST-MISSING'
}
$serviceHostRecord = $serviceHostRecords[0]
$serviceHostBytes = Read-NgciExclusiveBytes (Join-Path $package $requiredServiceHostFileName) 67108864 `
    'NGCOR-INSTALL-SERVICE-HOST-INVALID'
$serviceHostCmsPath = Join-Path $package ([string]$serviceHostRecord.detachedCms.path)
$serviceHostCmsBytes = Read-NgciExclusiveBytes $serviceHostCmsPath 1048576 `
    'NGCOR-INSTALL-SERVICE-HOST-CMS-INVALID'
$serviceHostCmsHash = Get-NgciSha256Hex $serviceHostCmsBytes
if ([int64]$serviceHostCmsBytes.Length -ne [int64]$serviceHostRecord.detachedCms.sizeBytes -or
    -not (Test-NgciHexEquals $serviceHostCmsHash ([string]$serviceHostRecord.detachedCms.sha256))) {
    Stop-Ngci 'NGCOR-INSTALL-SERVICE-HOST-CMS-HASH-MISMATCH'
}
Test-NgciDetachedCms $serviceHostBytes $serviceHostCmsPath $bakedReleaseSignerCertificateSha256

$validator = Join-Path $package 'Test-NorthGateCreateOnlyHostAuthorization.ps1'
$authorizationResult = & $validator -AuthorizationPath $SignedHostDeploymentAuthorizationPath `
    -ExpectedReleaseId ([string]$manifest.releaseId) `
    -ExpectedReleaseManifestSha256 $ExpectedReleaseManifestSha256 `
    -ExpectedCommit $ExpectedCommit -ExpectedTree $ExpectedTree `
    -ExpectedHostAllowlistId $ExpectedHostAllowlistId `
    -ExpectedGovernanceExceptionId ([string]$manifest.repository.governanceExceptionId)
if ($authorizationResult.status -cne 'semantic-validation-passed-signature-not-verified') {
    Stop-Ngci 'NGCOR-INSTALL-AUTHORIZATION-SEMANTIC-VALIDATION-FAILED'
}

$machineGuid = [string](Get-ItemPropertyValue -LiteralPath `
    'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop)
$machineGuidHash = Get-NgciSha256Hex ([System.Text.Encoding]::UTF8.GetBytes($machineGuid.ToLowerInvariant()))
$currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
$osBuild = [string]$currentVersion.CurrentBuildNumber + '.' + [string]$currentVersion.UBR
if ($authorization.host.computerName -cne $env:COMPUTERNAME -or
    -not (Test-NgciHexEquals ([string]$authorization.host.machineGuidSha256) $machineGuidHash) -or
    $authorization.host.osBuild -cne $osBuild) {
    Stop-Ngci 'NGCOR-INSTALL-HOST-IDENTITY-MISMATCH'
}
try {
    $hostSystem = @(Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop)
}
catch { Stop-Ngci 'NGCOR-INSTALL-HYPERV-HOST-IDENTITY-UNVERIFIABLE' }
if ($hostSystem.Count -ne 1 -or [string]$hostSystem[0].UUID -cnotmatch
    '^[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$' -or
    [string]$hostSystem[0].UUID -in @(
        '00000000-0000-0000-0000-000000000000','FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'
    ) -or ([string]$hostSystem[0].UUID).ToLowerInvariant() -cne
    ([string]$authorization.host.hyperVHostId).ToLowerInvariant()) {
    Stop-Ngci 'NGCOR-INSTALL-HYPERV-HOST-IDENTITY-MISMATCH'
}

$serviceSid = & $deployment { Get-NgcdServiceSid }
if ($serviceSid -cne $authorization.identity.serviceIdentitySid) {
    Stop-Ngci 'NGCOR-INSTALL-SERVICE-IDENTITY-MISMATCH'
}
$sshSid = [string]$authorization.identity.sshIdentitySid
foreach ($forbiddenGroup in @('S-1-5-32-544','S-1-5-32-578','S-1-5-32-580')) {
    if (Test-NgciTargetGroupMembership $sshSid $forbiddenGroup) {
        Stop-Ngci 'NGCOR-INSTALL-SSH-IDENTITY-PRIVILEGED'
    }
}
try {
    $sshAccount = (New-Object System.Security.Principal.SecurityIdentifier($sshSid)).Translate(
        [System.Security.Principal.NTAccount]
    ).Value
}
catch { Stop-Ngci 'NGCOR-INSTALL-SSH-IDENTITY-UNRESOLVED' }
$sshUser = ($sshAccount -split '\\')[-1]

$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$sshdConfigPath = Join-Path $programData 'ssh\sshd_config'
$authorizedKeysPath = Join-Path $programData 'ssh\northgate-create-only-authorized_keys'
$existingSshBytes = Read-NgciExclusiveBytes $sshdConfigPath 1048576 'NGCOR-INSTALL-SSHD-CONFIG-INVALID'
$null = Read-NgciExclusiveBytes $authorizedKeysPath 1048576 'NGCOR-INSTALL-AUTHORIZED-KEYS-INVALID'
$existingSsh = (New-Object System.Text.UTF8Encoding($false,$true)).GetString($existingSshBytes)
$newSsh = & $deployment {
    param($Existing,$User,$ReleaseRoot)
    New-NgcdManagedSshConfiguration $Existing $User $ReleaseRoot
} $existingSsh $sshUser ([string]$authorization.install.versionedReleaseRoot)
$newSshBytes = [System.Text.Encoding]::UTF8.GetBytes($newSsh)

$preflightRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-install-preflight-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($preflightRoot)
try {
    $candidateSshPath = Join-Path $preflightRoot 'sshd_config'
    [IO.File]::WriteAllBytes($candidateSshPath, $newSshBytes)
    $null = & $deployment { param($Path,$User) Test-NgcdSshConfiguration $Path $User } `
        $candidateSshPath $sshUser
}
finally {
    if (Test-Path -LiteralPath $candidateSshPath) { [IO.File]::Delete($candidateSshPath) }
    if (Test-Path -LiteralPath $preflightRoot) { [IO.Directory]::Delete($preflightRoot) }
}

$policy = & $deployment {
    param($Authorization,$ReleaseId,$ManifestHash,$BackendPolicyHash,$DataBundleHash)
    New-NgcdInstalledPolicy $Authorization $ReleaseId $ManifestHash $BackendPolicyHash $DataBundleHash
} $authorization ([string]$manifest.releaseId) $ExpectedReleaseManifestSha256 `
    $ExpectedBackendPolicySha256 $ExpectedDataBundleSha256
$policyBytes = [System.Text.Encoding]::UTF8.GetBytes(
    (ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $policy)
)

if (-not $PSCmdlet.ShouldProcess([string]$authorization.host.hostId,
        'Install the verified create-only release, service, and confined SSH configuration')) {
    Stop-Ngci 'NGCOR-INSTALL-CONFIRMATION-REQUIRED'
}
$null = & $deployment {
    param($ReceiptSignerSha256,$ServiceSid)
    Set-NgcdReceiptSignerKeyAccess $ReceiptSignerSha256 $ServiceSid
} ([string]$authorization.identity.receiptSignerCertificateSha256) $serviceSid
$context = & $deployment { param($Authorization) New-NgcdProductionContext $Authorization } $authorization
$runtimeArtifacts = [pscustomobject][ordered]@{
    releaseManifestSignature = Read-NgciExclusiveBytes $ReleaseManifestSignaturePath 1048576 'NGCOR-INSTALL-CMS-SIGNATURE-INVALID'
    deploymentAuthorizationSignature = Read-NgciExclusiveBytes $DeploymentAuthorizationSignaturePath 1048576 'NGCOR-INSTALL-CMS-SIGNATURE-INVALID'
    backendPolicy = $backendPolicyBytes
    backendPolicySignature = Read-NgciExclusiveBytes $BackendPolicySignaturePath 1048576 'NGCOR-INSTALL-CMS-SIGNATURE-INVALID'
    backendPolicySha256 = $ExpectedBackendPolicySha256
    dataBundle = $dataBundleBytes
    dataBundleSignature = Read-NgciExclusiveBytes $dataBundleSignaturePath 1048576 'NGCOR-INSTALL-CMS-SIGNATURE-INVALID'
    dataBundleSha256 = $ExpectedDataBundleSha256
    dataBundleId = [string]$dataBundle.bundleId
    stateKeyId = [string]$backendPolicy.stateKeyId
    deploymentAuthorizationSignerCertificateSha256 = $bakedDeploymentAuthorizationSignerCertificateSha256
    dataFiles = [object[]]$dataFiles
}
& $deployment {
    param($Context,$Package,$Manifest,$Authorization,$AuthorizationHash,$Policy,$Ssh,$RuntimeArtifacts)
    Invoke-NgcdFileInstallTransaction $Context $Package $Manifest $Authorization $AuthorizationHash `
        $Policy $Ssh 'None' $RuntimeArtifacts
} $context $package $manifest $authorization $ExpectedDeploymentAuthorizationSha256 $policyBytes $newSshBytes `
    $runtimeArtifacts

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD3taQ+kKyssK8Z
# ifgiFf9M1V/EUQrEaS+fJxRgny1jIKCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIKVjUSLvZrtfKO7jrgFwDV2YOq88nRLuD9hN6ZZhueNyMA0GCSqG
# SIb3DQEBAQUABIIBgC8E/hRBzmb6dxiFiBbq79PBrBm+qriOH+H8jWSZHEAyMLZW
# BfpAhc+78DEwtfT+3JOmYOpEtZrhZabT0GAVJkfVsSSCOi7SS9qoRx1jHibN1XWr
# 6D15ytMnZ/qePyAZ8LyYj9D2olc8IR/U1VdLpuDBJga+w8Aa8d/FbzAFsCS7a7bc
# EX2XnLQoXcfq3yGxaxj6PXVoxzML4EizRxqGZg0ZBK4CIDYpKuQAj9/Vk++kDNAJ
# 8oAS9DfQph/kbl+W5LropOkJJZj3UyUr6zFF88nsYLT4PSd+KX7YPrt7Eo08549c
# CQYLTqPkP7qFCagrHuA5RjzY8siH9s9N3QJuQGscDgcTIk+FNaNXP+IHT1TPMi6e
# owcU90DgGH7ufBVRdUl/t/ug3fDJOqsPxp53hcS8CHWs9/NWmjlsgESZ9Rws/mLv
# uBYS/4TLjp4FsJOPVo3yblE7B0TF4h7FuaanRO+LDIO2Cd4S9oii85BQ45JrqgeN
# 0QGiWtdvUye6ExQDxQ==
# SIG # End signature block
