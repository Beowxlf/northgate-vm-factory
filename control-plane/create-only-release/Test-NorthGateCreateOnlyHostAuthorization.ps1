[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$AuthorizationPath,
    [Parameter(Mandatory)][ValidatePattern('^ngcor-[a-z0-9][a-z0-9.-]{7,63}$')][string]$ExpectedReleaseId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedReleaseManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedTree,
    [Parameter(Mandatory)][ValidatePattern('^ngallow-[a-z0-9-]{8,64}$')][string]$ExpectedHostAllowlistId,
    [Parameter(Mandatory)][ValidatePattern('^NG-GOV-[0-9]{8}-[A-Z0-9-]{3,32}$')][string]$ExpectedGovernanceExceptionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$maximumAuthorizationBytes = 262144
$expectedVlanProfiles = [ordered]@{
    'business-apps' = 150
    'commercial-dmz' = 160
    'cyber-workstations' = 140
    'external-mail' = 240
    'it-admin-workstations' = 130
    'mail-internal' = 120
    'sim-wan' = 250
    'users-workstations' = 110
}
$expectedVolumes = [ordered]@{
    'volume-d' = [pscustomobject][ordered]@{ drive = 'D'; persistentCeilingGiB = 440; canaryCeilingGiB = 40 }
    'volume-f' = [pscustomobject][ordered]@{ drive = 'F'; persistentCeilingGiB = 460; canaryCeilingGiB = 80 }
}
$expectedImages = [ordered]@{
    'debian-12.12-amd64-netinst' = [pscustomobject][ordered]@{
        sha256 = 'dfc30e04fd095ac2c07e998f145e94bb8f7d3a8eca3a631d2eb012398deae531'
        sizeBytes = 704643072
    }
    'kali-2026.2-installer-netinst-amd64' = [pscustomobject][ordered]@{
        sha256 = 'd32f929dacc48134a31461a09f2160d13ad1d26b820cee920446813ca979b39b'
        sizeBytes = 779091968
    }
    'windows-11-25h2-english-x64' = [pscustomobject][ordered]@{
        sha256 = 'd141f6030fed50f75e2b03e1eb2e53646c4b21e5386047cb860af5223f102a32'
        sizeBytes = 7736125440
    }
}
$expectedProtectedNames = @(
    'JS-BlueBench', 'JS-Server-01', 'OPNsense-Tooling', 'TRMM-Tooling', 'Wazuh-Machine'
)
$zeroGuid = '00000000-0000-0000-0000-000000000000'
$fixedPackageFiles = @(
    'NorthGate.VMFactory.CreateOnlyProtocol.psd1',
    'NorthGate.VMFactory.CreateOnlyProtocol.psm1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psd1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psm1',
    'NorthGate.CreateOnly.ServiceHost.cs',
    'Build-NorthGateCreateOnlyServiceHost.ps1',
    'NorthGate.VMFactory.CreateOnlyService.psd1',
    'NorthGate.VMFactory.CreateOnlyService.psm1',
    'backend/NorthGate.VMFactory.CreateOnlyBackend.psd1',
    'backend/NorthGate.VMFactory.CreateOnlyBackend.psm1',
    'backend/schemas/create-only-backend-policy.schema.json',
    'backend/schemas/create-only-data-bundle.schema.json',
    'backend/schemas/create-only-host-plan.schema.json',
    'backend/schemas/create-only-journal-event.schema.json',
    'backend/schemas/create-only-plan-approval.schema.json',
    'backend/schemas/create-only-rollout-promotion.schema.json',
    'backend/schemas/create-only-signed-receipt.schema.json',
    'Invoke-NorthGateCreateOnlyForcedCommand.ps1',
    'Start-NorthGateCreateOnlyPipeService.ps1',
    'Install-NorthGateCreateOnlyRelease.ps1',
    'Enable-NorthGateCreateOnlyInitialActivation.ps1',
    'New-NorthGateCreateOnlyApproval.ps1',
    'New-NorthGateCreateOnlyRolloutPromotion.ps1',
    'Rollback-NorthGateCreateOnlyRelease.ps1',
    'Test-NorthGateCreateOnlyHostAuthorization.ps1',
    'host-deployment-authorization.schema.json',
    'initial-activation.schema.json',
    'release-manifest.schema.json',
    'sshd_config.create-only.example',
    'README.md',
    'NorthGate.CreateOnly.ServiceHost.exe',
    'NorthGate.CreateOnly.ServiceHost.exe.p7s'
)
$allowlistAlgorithm = [System.Security.Cryptography.SHA256]::Create()
try {
    $expectedPackageAllowlistSha256 = (($allowlistAlgorithm.ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes(($fixedPackageFiles -join "`n"))
    ) | ForEach-Object { $_.ToString('x2') }) -join '')
}
finally { $allowlistAlgorithm.Dispose() }

function Stop-NgcorAuthorization {
    param([Parameter(Mandatory)][string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function Assert-NgcorExactProperties {
    param([object]$Object, [string[]]$Expected, [string]$Code)
    if ($null -eq $Object -or $Object -isnot [System.Management.Automation.PSCustomObject]) {
        Stop-NgcorAuthorization $Code
    }
    $actual = @($Object.PSObject.Properties.Name)
    $wanted = @($Expected)
    [array]::Sort($actual, [System.StringComparer]::Ordinal)
    [array]::Sort($wanted, [System.StringComparer]::Ordinal)
    if (($actual -join '|') -cne ($wanted -join '|')) { Stop-NgcorAuthorization $Code }
}

function Assert-NgcorExactStringSet {
    param([object[]]$Values, [string[]]$Expected, [string]$Code)
    if (@($Values | Where-Object { $_ -isnot [string] }).Count -ne 0) { Stop-NgcorAuthorization $Code }
    $actual = @($Values | ForEach-Object { [string]$_ })
    if (@($actual | Sort-Object -Unique).Count -ne $actual.Count) { Stop-NgcorAuthorization $Code }
    $wanted = @($Expected)
    [array]::Sort($actual, [System.StringComparer]::Ordinal)
    [array]::Sort($wanted, [System.StringComparer]::Ordinal)
    if (($actual -join '|') -cne ($wanted -join '|')) { Stop-NgcorAuthorization $Code }
}

function Assert-NgcorNonzeroLowerHex {
    param([object]$Value, [int]$Length, [string]$Code)
    if ($Value -isnot [string]) { Stop-NgcorAuthorization $Code }
    $text = [string]$Value
    if ($text -cnotmatch ('^[a-f0-9]{' + $Length + '}$') -or $text -ceq ('0' * $Length)) {
        Stop-NgcorAuthorization $Code
    }
}

function Test-NgcorIntegerValue {
    param([object]$Value)
    $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64]
}

function Test-NgcorBooleanValue {
    param([object]$Value)
    $Value -is [bool]
}

function Get-NgcorCanonicalLocalPath {
    param([object]$Value, [string]$Code)
    if ($Value -isnot [string]) { Stop-NgcorAuthorization $Code }
    $path = [string]$Value
    if ($path.Length -lt 3 -or $path.Length -gt 240 -or $path -cnotmatch '^[A-Za-z]:\\' -or
        $path -match '[\x00-\x1f"<>|*?%$]' -or $path.Substring(2) -match ':' -or
        $path -match '(?:^|\\)\.{1,2}(?:\\|$)' -or $path -match '(?:^|\\)[^\\]*[ .](?:\\|$)') {
        Stop-NgcorAuthorization $Code
    }
    try { $full = [System.IO.Path]::GetFullPath($path).TrimEnd('\') }
    catch { Stop-NgcorAuthorization $Code }
    if ($full -cne $path.TrimEnd('\') -or $full.Length -lt 4) { Stop-NgcorAuthorization $Code }
    $full
}

function Test-NgcorPathsOverlap {
    param([string]$Left, [string]$Right)
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $Left.Equals($Right, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Left.StartsWith($Right + $separator, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Right.StartsWith($Left + $separator, [System.StringComparison]::OrdinalIgnoreCase)
}

$item = Get-Item -LiteralPath $AuthorizationPath -Force
if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-REPARSE-FORBIDDEN'
}
if ($item.Length -le 0 -or $item.Length -gt $maximumAuthorizationBytes) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-SIZE-INVALID'
}
$stream = New-Object System.IO.FileStream(
    $item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read, 65536, [System.IO.FileOptions]::SequentialScan
)
try {
    $memory = New-Object System.IO.MemoryStream
    try { $stream.CopyTo($memory); $bytes = $memory.ToArray() }
    finally { $memory.Dispose() }
}
finally { $stream.Dispose() }

Import-Module (Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -Force -ErrorAction Stop
$parsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $bytes -MaximumBytes $maximumAuthorizationBytes
$authorization = $parsed.Value

Assert-NgcorExactProperties $authorization @(
    'schema','authorizationId','sequence','issuedAtUtc','expiresAtUtc','repository',
    'releaseManifestSha256','host','install','identity','switch','volumes','images',
    'bootstrapMedia','protectedAssets','accessIsolation','initialPolicy'
) 'NGCOR-AUTHORIZATION-PROPERTIES-INVALID'
if ($authorization.schema -cne 'northgate/create-only-host-deployment-authorization/v2' -or
    $authorization.schema -isnot [string] -or $authorization.authorizationId -isnot [string] -or
    $authorization.authorizationId -cnotmatch '^ngdeploy-[a-z0-9-]{8,64}$' -or
    -not (Test-NgcorIntegerValue $authorization.sequence) -or [int64]$authorization.sequence -lt 1) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-CONTRACT-INVALID'
}

$issued = [DateTimeOffset]::MinValue
$expires = [DateTimeOffset]::MinValue
$timestampFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
$timestampStyle = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
    [System.Globalization.DateTimeStyles]::AdjustToUniversal
if ($authorization.issuedAtUtc -isnot [string] -or $authorization.expiresAtUtc -isnot [string] -or
    -not [DateTimeOffset]::TryParseExact([string]$authorization.issuedAtUtc, $timestampFormat,
        [System.Globalization.CultureInfo]::InvariantCulture, $timestampStyle, [ref]$issued) -or
    -not [DateTimeOffset]::TryParseExact([string]$authorization.expiresAtUtc, $timestampFormat,
        [System.Globalization.CultureInfo]::InvariantCulture, $timestampStyle, [ref]$expires)) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-TIME-INVALID'
}
$now = [DateTimeOffset]::UtcNow
if ($issued -gt $now.AddMinutes(5) -or $expires -le $now -or $expires -le $issued -or
    ($expires - $issued).TotalHours -gt 24) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-TIME-WINDOW-INVALID'
}

Assert-NgcorExactProperties $authorization.repository @(
    'identity','releaseId','commit','tree','hostAllowlistId','packageAllowlistSha256',
    'governanceExceptionId'
) 'NGCOR-AUTHORIZATION-REPOSITORY-PROPERTIES-INVALID'
if ($authorization.repository.identity -cne 'Beowxlf/northgate-vm-factory' -or
    $authorization.repository.releaseId -cne $ExpectedReleaseId -or
    $authorization.repository.commit -cne $ExpectedCommit -or
    $authorization.repository.tree -cne $ExpectedTree -or
    $authorization.repository.hostAllowlistId -cne $ExpectedHostAllowlistId -or
    $authorization.repository.packageAllowlistSha256 -cne $expectedPackageAllowlistSha256 -or
    $authorization.repository.governanceExceptionId -cne $ExpectedGovernanceExceptionId -or
    $authorization.releaseManifestSha256 -cne $ExpectedReleaseManifestSha256) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-REPOSITORY-PIN-MISMATCH'
}
Assert-NgcorNonzeroLowerHex $authorization.repository.commit 40 'NGCOR-AUTHORIZATION-COMMIT-INVALID'
Assert-NgcorNonzeroLowerHex $authorization.repository.tree 40 'NGCOR-AUTHORIZATION-TREE-INVALID'
Assert-NgcorNonzeroLowerHex $authorization.releaseManifestSha256 64 'NGCOR-AUTHORIZATION-MANIFEST-HASH-INVALID'

Assert-NgcorExactProperties $authorization.host @(
    'hostId','computerName','machineGuidSha256','hyperVHostId','osBuild'
) 'NGCOR-AUTHORIZATION-HOST-PROPERTIES-INVALID'
if ($authorization.host.hostId -cnotmatch '^nghost-[a-z0-9-]{8,64}$' -or
    $authorization.host.hostId -isnot [string] -or
    $authorization.host.computerName -isnot [string] -or
    $authorization.host.hyperVHostId -isnot [string] -or
    $authorization.host.osBuild -isnot [string] -or
    $authorization.host.computerName -cnotmatch '^[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?$' -or
    $authorization.host.hyperVHostId -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
    $authorization.host.hyperVHostId -ceq $zeroGuid -or
    $authorization.host.osBuild -cnotmatch '^[0-9]{5}(?:\.[0-9]{1,6})?$') {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-HOST-INVALID'
}
Assert-NgcorNonzeroLowerHex $authorization.host.machineGuidSha256 64 'NGCOR-AUTHORIZATION-HOST-INVALID'

Assert-NgcorExactProperties $authorization.install @(
    'versionedReleaseRoot','stateRoot','quarantineRoot'
) 'NGCOR-AUTHORIZATION-INSTALL-PROPERTIES-INVALID'
$releaseRoot = Get-NgcorCanonicalLocalPath $authorization.install.versionedReleaseRoot 'NGCOR-AUTHORIZATION-INSTALL-PATH-INVALID'
$stateRoot = Get-NgcorCanonicalLocalPath $authorization.install.stateRoot 'NGCOR-AUTHORIZATION-INSTALL-PATH-INVALID'
$quarantineRoot = Get-NgcorCanonicalLocalPath $authorization.install.quarantineRoot 'NGCOR-AUTHORIZATION-INSTALL-PATH-INVALID'
$expectedReleaseRoot = 'C:\Program Files\NorthGate\VMFactory\CreateOnly\releases\' + $ExpectedReleaseId
$expectedStateRoot = 'C:\ProgramData\NorthGate\VMFactory\CreateOnly\state'
$expectedQuarantineRoot = 'C:\ProgramData\NorthGate\VMFactory\CreateOnly\quarantine'
if ($releaseRoot -cne $expectedReleaseRoot -or $stateRoot -cne $expectedStateRoot -or
    $quarantineRoot -cne $expectedQuarantineRoot -or
    (Test-NgcorPathsOverlap $releaseRoot $stateRoot) -or
    (Test-NgcorPathsOverlap $releaseRoot $quarantineRoot) -or
    (Test-NgcorPathsOverlap $stateRoot $quarantineRoot)) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-INSTALL-PATH-INVALID'
}

Assert-NgcorExactProperties $authorization.identity @(
    'sshIdentitySid','serviceIdentitySid','releaseSignerCertificateSha256',
    'deploymentAuthorizationSignerCertificateSha256','approvalSignerCertificateSha256',
    'receiptSignerCertificateSha256'
) 'NGCOR-AUTHORIZATION-IDENTITY-PROPERTIES-INVALID'
$forbiddenSids = @('S-1-5-18','S-1-5-19','S-1-5-20','S-1-5-32-544','S-1-5-32-578')
if ($authorization.identity.sshIdentitySid -cnotmatch '^S-1-[0-9-]+$' -or
    $authorization.identity.sshIdentitySid -isnot [string] -or
    $authorization.identity.serviceIdentitySid -isnot [string] -or
    $authorization.identity.serviceIdentitySid -cnotmatch '^S-1-[0-9-]+$' -or
    $authorization.identity.sshIdentitySid -ceq $authorization.identity.serviceIdentitySid -or
    $authorization.identity.sshIdentitySid -in $forbiddenSids -or
    $authorization.identity.serviceIdentitySid -in $forbiddenSids) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-IDENTITY-SEPARATION-INVALID'
}
$signerPins = @(
    [string]$authorization.identity.releaseSignerCertificateSha256,
    [string]$authorization.identity.deploymentAuthorizationSignerCertificateSha256,
    [string]$authorization.identity.approvalSignerCertificateSha256,
    [string]$authorization.identity.receiptSignerCertificateSha256
)
if ($authorization.identity.releaseSignerCertificateSha256 -isnot [string] -or
    $authorization.identity.deploymentAuthorizationSignerCertificateSha256 -isnot [string] -or
    $authorization.identity.approvalSignerCertificateSha256 -isnot [string] -or
    $authorization.identity.receiptSignerCertificateSha256 -isnot [string]) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-SIGNER-PIN-INVALID'
}
foreach ($pin in $signerPins) { Assert-NgcorNonzeroLowerHex $pin 64 'NGCOR-AUTHORIZATION-SIGNER-PIN-INVALID' }
if (@($signerPins | Sort-Object -Unique).Count -ne 4) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-SIGNER-SEPARATION-INVALID'
}

Assert-NgcorExactProperties $authorization.switch @(
    'switchPolicyId','name','id','fingerprint','trunkAdapterId','trunkAdapterFingerprint',
    'mode','allowCreate','vlanProfiles'
) 'NGCOR-AUTHORIZATION-SWITCH-PROPERTIES-INVALID'
if ($authorization.switch.switchPolicyId -cne 'northgate-app-trunk' -or
    $authorization.switch.switchPolicyId -isnot [string] -or
    $authorization.switch.name -isnot [string] -or
    $authorization.switch.id -isnot [string] -or
    $authorization.switch.trunkAdapterId -isnot [string] -or
    [string]::IsNullOrWhiteSpace([string]$authorization.switch.name) -or
    ([string]$authorization.switch.name).Length -gt 128 -or
    $authorization.switch.id -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
    $authorization.switch.trunkAdapterId -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
    $authorization.switch.id -ceq $zeroGuid -or $authorization.switch.trunkAdapterId -ceq $zeroGuid -or
    $authorization.switch.id -ceq $authorization.switch.trunkAdapterId -or
    $authorization.switch.mode -isnot [string] -or
    $authorization.switch.mode -cne 'existing-only' -or
    -not (Test-NgcorBooleanValue $authorization.switch.allowCreate) -or
    $authorization.switch.allowCreate -ne $false) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-SWITCH-INVALID'
}
Assert-NgcorNonzeroLowerHex $authorization.switch.fingerprint 64 'NGCOR-AUTHORIZATION-SWITCH-INVALID'
Assert-NgcorNonzeroLowerHex $authorization.switch.trunkAdapterFingerprint 64 'NGCOR-AUTHORIZATION-SWITCH-INVALID'
Assert-NgcorExactProperties $authorization.switch.vlanProfiles @($expectedVlanProfiles.Keys) `
    'NGCOR-AUTHORIZATION-VLAN-PROFILES-INVALID'
foreach ($name in $expectedVlanProfiles.Keys) {
    $vlanValue = $authorization.switch.vlanProfiles.PSObject.Properties[$name].Value
    if (-not (Test-NgcorIntegerValue $vlanValue) -or
        [int64]$vlanValue -ne [int64]$expectedVlanProfiles[$name]) {
        Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-VLAN-PROFILES-INVALID'
    }
}

if ($authorization.volumes -isnot [System.Array] -or @($authorization.volumes).Count -ne 2) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-VOLUMES-INVALID'
}
Assert-NgcorExactStringSet @($authorization.volumes.volumeId) @($expectedVolumes.Keys) 'NGCOR-AUTHORIZATION-VOLUMES-INVALID'
$volumeRoots = @()
$volumeUniqueIds = @()
foreach ($volume in @($authorization.volumes)) {
    Assert-NgcorExactProperties $volume @(
        'volumeId','uniqueId','root','persistentCeilingGiB','canaryCeilingGiB'
    ) 'NGCOR-AUTHORIZATION-VOLUME-PROPERTIES-INVALID'
    $expectedVolume = $expectedVolumes[[string]$volume.volumeId]
    $root = Get-NgcorCanonicalLocalPath $volume.root 'NGCOR-AUTHORIZATION-VOLUME-PATH-INVALID'
    if ($root.Substring(0,1) -cne $expectedVolume.drive -or
        $volume.volumeId -isnot [string] -or $volume.uniqueId -isnot [string] -or
        -not (Test-NgcorIntegerValue $volume.persistentCeilingGiB) -or
        -not (Test-NgcorIntegerValue $volume.canaryCeilingGiB) -or
        [int64]$volume.persistentCeilingGiB -ne $expectedVolume.persistentCeilingGiB -or
        [int64]$volume.canaryCeilingGiB -ne $expectedVolume.canaryCeilingGiB -or
        ([string]$volume.uniqueId).Length -lt 8 -or ([string]$volume.uniqueId).Length -gt 128) {
        Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-VOLUME-INVALID'
    }
    $volumeRoots += $root
    $volumeUniqueIds += [string]$volume.uniqueId
}
if (@($volumeRoots | Sort-Object -Unique).Count -ne 2 -or
    @($volumeUniqueIds | Sort-Object -Unique).Count -ne 2 -or
    (Test-NgcorPathsOverlap $volumeRoots[0] $volumeRoots[1])) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-VOLUME-SEPARATION-INVALID'
}

if ($authorization.images -isnot [System.Array] -or @($authorization.images).Count -ne 3) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-IMAGES-INVALID'
}
Assert-NgcorExactStringSet @($authorization.images.imageId) @($expectedImages.Keys) 'NGCOR-AUTHORIZATION-IMAGES-INVALID'
$imagePaths = @()
foreach ($image in @($authorization.images)) {
    Assert-NgcorExactProperties $image @('imageId','path','sha256','sizeBytes') `
        'NGCOR-AUTHORIZATION-IMAGE-PROPERTIES-INVALID'
    $expectedImage = $expectedImages[[string]$image.imageId]
    $path = Get-NgcorCanonicalLocalPath $image.path 'NGCOR-AUTHORIZATION-IMAGE-PATH-INVALID'
    if (-not $path.StartsWith('D:\HyperV\VM-ISO\', [System.StringComparison]::OrdinalIgnoreCase) -or
        $image.imageId -isnot [string] -or $image.sha256 -isnot [string] -or
        [System.IO.Path]::GetExtension($path) -cne '.iso' -or
        $image.sha256 -cne $expectedImage.sha256 -or
        -not (Test-NgcorIntegerValue $image.sizeBytes) -or
        [int64]$image.sizeBytes -ne [int64]$expectedImage.sizeBytes) {
        Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-IMAGE-INVALID'
    }
    $imagePaths += $path.ToLowerInvariant()
}
if (@($imagePaths | Sort-Object -Unique).Count -ne 3) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-IMAGE-PATH-COLLISION'
}

$expectedFleetAssets = @(
    'NG-VM-018','NG-VM-010','NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012',
    'NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015'
)
$windowsAssets = @('NG-VM-010','NG-VM-011','NG-VM-012','NG-VM-019','NG-VM-020','NG-VM-021')
if ($authorization.bootstrapMedia -isnot [System.Array] -or @($authorization.bootstrapMedia).Count -ne 12) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID'
}
Assert-NgcorExactStringSet @($authorization.bootstrapMedia.assetId) $expectedFleetAssets `
    'NGCOR-AUTHORIZATION-BOOTSTRAP-MEDIA-SCOPE-INVALID'
$mediaIds=@();$mediaPaths=@();$mediaHashes=@();$provenancePaths=@();$provenanceHashes=@()
$bundleManifestHashes=@();$payloadHashes=@()
foreach($media in @($authorization.bootstrapMedia)) {
    Assert-NgcorExactProperties $media @(
        'assetId','mediaId','mode','path','sha256','sizeBytes','sourceImageId','sourceImageSha256',
        'provenancePath','provenanceSha256','bundleManifestSha256','builderId','builderReleaseSha256',
        'recipeSha256','unattendedPayloadSha256','sourceCommit','sourceTree'
    ) 'NGCOR-AUTHORIZATION-BOOTSTRAP-MEDIA-PROPERTIES-INVALID'
    $expectedSource = if($media.assetId -in $windowsAssets){'windows-11-25h2-english-x64'}
        elseif($media.assetId -ceq 'NG-VM-015'){'kali-2026.2-installer-netinst-amd64'}else{'debian-12.12-amd64-netinst'}
    $source=@($authorization.images|Where-Object{$_.imageId -ceq $expectedSource})
    $path=Get-NgcorCanonicalLocalPath $media.path 'NGCOR-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID'
    $provenancePath=Get-NgcorCanonicalLocalPath $media.provenancePath `
        'NGCOR-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID'
    if(-not $path.StartsWith('D:\HyperV\VM-ISO\',[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetExtension($path) -cne '.iso' -or
        -not $provenancePath.StartsWith('D:\HyperV\VM-ISO\',[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetExtension($provenancePath) -cne '.json' -or $path -ieq $provenancePath -or
        $media.mediaId -cne ('ngmedia-'+([string]$media.assetId).ToLowerInvariant()) -or
        $media.mode -cne 'asset-bound-derivative-iso' -or
        $media.sourceImageId -cne $expectedSource -or $source.Count -ne 1 -or
        $media.sourceImageSha256 -cne $source[0].sha256 -or
        $media.builderId -cne 'northgate-unattended-media-v1' -or
        $media.builderReleaseSha256 -cne $ExpectedReleaseManifestSha256 -or
        $media.sourceCommit -cne $ExpectedCommit -or $media.sourceTree -cne $ExpectedTree -or
        $media.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $media.sha256 -ceq ('0'*64) -or
        $media.provenanceSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $media.provenanceSha256 -ceq ('0'*64) -or
        $media.bundleManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $media.bundleManifestSha256 -ceq ('0'*64) -or
        $media.recipeSha256 -cnotmatch '^[a-f0-9]{64}$' -or $media.recipeSha256 -ceq ('0'*64) -or
        $media.unattendedPayloadSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $media.unattendedPayloadSha256 -ceq ('0'*64) -or
        -not(Test-NgcorIntegerValue $media.sizeBytes) -or [int64]$media.sizeBytes -lt 1 -or
        $path -ieq [IO.Path]::GetFullPath([string]$source[0].path)) {
        Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID'
    }
    $mediaIds+=[string]$media.mediaId;$mediaPaths+=$path;$mediaHashes+=[string]$media.sha256
    $provenancePaths+=$provenancePath;$provenanceHashes+=[string]$media.provenanceSha256
    $bundleManifestHashes+=[string]$media.bundleManifestSha256
    $payloadHashes+=[string]$media.unattendedPayloadSha256
}
if(@($mediaIds|Sort-Object -Unique).Count-ne12-or @($mediaPaths|Sort-Object -Unique).Count-ne12-or
   @($mediaHashes|Sort-Object -Unique).Count-ne12-or
   @($provenancePaths|Sort-Object -Unique).Count-ne12-or
   @($provenanceHashes|Sort-Object -Unique).Count-ne12-or
   @($bundleManifestHashes|Sort-Object -Unique).Count-ne12-or
   @($payloadHashes|Sort-Object -Unique).Count-ne12){
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-BOOTSTRAP-MEDIA-COLLISION'
}

if ($authorization.protectedAssets -isnot [System.Array] -or @($authorization.protectedAssets).Count -ne 5) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-PROTECTED-ASSETS-INVALID'
}
Assert-NgcorExactStringSet @($authorization.protectedAssets.name) $expectedProtectedNames `
    'NGCOR-AUTHORIZATION-PROTECTED-ASSETS-INVALID'
$vmIds = @()
$allDiskIds = @()
$allAdapterIds = @()
foreach ($asset in @($authorization.protectedAssets)) {
    Assert-NgcorExactProperties $asset @('name','vmId','diskUniqueIds','adapterIds') `
        'NGCOR-AUTHORIZATION-PROTECTED-ASSET-PROPERTIES-INVALID'
    if ($asset.vmId -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
        $asset.name -isnot [string] -or $asset.vmId -isnot [string] -or
        $asset.vmId -ceq $zeroGuid -or
        $asset.diskUniqueIds -isnot [System.Array] -or @($asset.diskUniqueIds).Count -lt 1 -or
        $asset.adapterIds -isnot [System.Array] -or @($asset.adapterIds).Count -lt 1) {
        Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-PROTECTED-ASSET-INVALID'
    }
    $vmIds += [string]$asset.vmId
    foreach ($diskId in @($asset.diskUniqueIds)) {
        if ($diskId -isnot [string] -or ([string]$diskId).Length -lt 8 -or
            ([string]$diskId).Length -gt 128) {
            Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-PROTECTED-ASSET-INVALID'
        }
        $allDiskIds += [string]$diskId
    }
    foreach ($adapterId in @($asset.adapterIds)) {
        if ($adapterId -isnot [string] -or
            $adapterId -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
            $adapterId -ceq $zeroGuid) {
            Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-PROTECTED-ASSET-INVALID'
        }
        $allAdapterIds += [string]$adapterId
    }
}
if (@($vmIds | Sort-Object -Unique).Count -ne $vmIds.Count -or
    @($allDiskIds | Sort-Object -Unique).Count -ne $allDiskIds.Count -or
    @($allAdapterIds | Sort-Object -Unique).Count -ne $allAdapterIds.Count) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-PROTECTED-ASSET-IDENTITY-COLLISION'
}

Assert-NgcorExactProperties $authorization.accessIsolation @(
    'routineSshIsLocalAdministrator','routineSshIsHyperVAdministrator',
    'routineSshCanUsePowerShellRemoting','routineSshCanReachLegacyMcp'
) 'NGCOR-AUTHORIZATION-ACCESS-ISOLATION-PROPERTIES-INVALID'
if ($authorization.accessIsolation.routineSshIsLocalAdministrator -ne $false -or
    -not (Test-NgcorBooleanValue $authorization.accessIsolation.routineSshIsLocalAdministrator) -or
    -not (Test-NgcorBooleanValue $authorization.accessIsolation.routineSshIsHyperVAdministrator) -or
    -not (Test-NgcorBooleanValue $authorization.accessIsolation.routineSshCanUsePowerShellRemoting) -or
    -not (Test-NgcorBooleanValue $authorization.accessIsolation.routineSshCanReachLegacyMcp) -or
    $authorization.accessIsolation.routineSshIsHyperVAdministrator -ne $false -or
    $authorization.accessIsolation.routineSshCanUsePowerShellRemoting -ne $false -or
    $authorization.accessIsolation.routineSshCanReachLegacyMcp -ne $false) {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-ACCESS-ISOLATION-INVALID'
}

Assert-NgcorExactProperties $authorization.initialPolicy @('applyEnabled','executableActions','canaryStage') `
    'NGCOR-AUTHORIZATION-INITIAL-POLICY-PROPERTIES-INVALID'
if ($authorization.initialPolicy.applyEnabled -ne $false -or
    -not (Test-NgcorBooleanValue $authorization.initialPolicy.applyEnabled) -or
    $authorization.initialPolicy.executableActions -isnot [System.Array] -or
    @($authorization.initialPolicy.executableActions).Count -ne 0 -or
    $authorization.initialPolicy.canaryStage -cne 'disabled') {
    Stop-NgcorAuthorization 'NGCOR-AUTHORIZATION-INITIAL-POLICY-INVALID'
}

$algorithm = [System.Security.Cryptography.SHA256]::Create()
try { $authorizationHash = (($algorithm.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '') }
finally { $algorithm.Dispose() }
[pscustomobject][ordered]@{
    status = 'semantic-validation-passed-signature-not-verified'
    authorizationId = [string]$authorization.authorizationId
    authorizationSha256 = $authorizationHash
    releaseId = [string]$authorization.repository.releaseId
    repositoryCommit = [string]$authorization.repository.commit
    repositoryTree = [string]$authorization.repository.tree
    hostId = [string]$authorization.host.hostId
    applyEnabled = $false
    executableActions = @()
    installable = $false
    nextGate = 'reviewed-bootstrap-installer-exact-cms-verification'
}

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD+G66ea6GCAgJI
# iVy38254/CQtLadBOqIfJPGFDBFNmaCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEINAbrak1sWMIAX6mAnK/+UlbrBWAWxJwEzhXWcjpnrFvMA0GCSqG
# SIb3DQEBAQUABIIBgKwUiZsXhy1GJxFVpry0Q3bU7O2cAPZw16pdDZXYzvbBQw3N
# WQbcuzAcGtT00adly3mQu3YWVidjZXpoZXmik34DAI5ClcJOZfRoc6Jc6PsV/+Y9
# 8yigwqRI8WMvFb5qkhkHsiOc70L8G0glxrfA9D1zj3Tps4y8C3lYkT67xtsUp6Ir
# Q7hijlik4y2xXIg1NJl/0F1VdPgwtPUsKrS6UYK5Ii1nHNeNSr63nE1htKu0xAu9
# euiTBj8OiNomZNBKucoOv2K0LjR7Vowbo8VenX/IrWapEsjn+xvYnI5GgZJzCOHF
# 0VFNHDA/WP0ir2tM0t1BTJuJGLYahHuE81E8CBzph2Y/0y/w3WsaEBhVEwHeom9i
# Dv3kfT8OVnj+AM4uvLt8Ch9aEyPTbAU4F3EpRpF2HWAhRcBvXYTu217B8v8gsDbB
# 4PJkdVPmgQLDevtbsPS4WXQM9HQKDLHsCJUHZJTAwNLySPHq6AE2FWLTR5YOQHmg
# ZkPAV0rzlQt4XDDn1w==
# SIG # End signature block
