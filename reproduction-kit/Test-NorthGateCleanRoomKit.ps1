[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$KitRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedKitManifestSha256,
    [switch]$RequireCurrentlyInstallable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Ngcrkv { param([string]$Code) throw [InvalidOperationException]::new($Code) }
function Get-NgcrkvSha256 {
    param([string]$Path)
    $stream = New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Read-NgcrkvJson {
    param([string]$Path,[int64]$MaximumBytes)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -le 0 -or $item.Length -gt $MaximumBytes -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Stop-Ngcrkv 'NGCRK-FILE-INVALID' }
    try { ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($item.FullName,[Text.Encoding]::UTF8)) }
    catch { Stop-Ngcrkv 'NGCRK-JSON-INVALID' }
}
function Assert-NgcrkvExactProperties {
    param([object]$Value,[string[]]$Names,[string]$Code)
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (($actual -join '|') -cne ($expected -join '|')) { Stop-Ngcrkv $Code }
}
function Resolve-NgcrkvRelativePath {
    param([string]$Root,[string]$Relative,[string]$Code)
    if ($Relative -cnotmatch '^[A-Za-z0-9._/-]{1,240}$' -or $Relative -match '(?:^|/)\.\.(?:/|$)' -or
        [IO.Path]::IsPathRooted($Relative)) { Stop-Ngcrkv $Code }
    $candidate = [IO.Path]::GetFullPath((Join-Path $Root $Relative.Replace('/','\')))
    $prefix = $Root.TrimEnd('\') + '\'
    if (-not $candidate.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { Stop-Ngcrkv $Code }
    $candidate
}

$root = [IO.Path]::GetFullPath($KitRoot).TrimEnd('\')
$manifestPath = Join-Path $root 'clean-room-kit.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { Stop-Ngcrkv 'NGCRK-MANIFEST-MISSING' }
if ((Get-NgcrkvSha256 $manifestPath) -cne $ExpectedKitManifestSha256) {
    Stop-Ngcrkv 'NGCRK-MANIFEST-HASH-MISMATCH'
}
$manifest = Read-NgcrkvJson $manifestPath 4194304
Assert-NgcrkvExactProperties $manifest @(
    'schema','kitId','createdAtUtc','repository','release','targetHost','disabledInstallation',
    'trustPins','installInputs','files'
) 'NGCRK-MANIFEST-PROPERTIES-INVALID'
if ($manifest.schema -cne 'northgate/vm-factory-clean-room-kit/v1' -or
    $manifest.kitId -cnotmatch '^ngcrk-[a-z0-9.-]{8,96}$') { Stop-Ngcrkv 'NGCRK-MANIFEST-IDENTITY-INVALID' }

Assert-NgcrkvExactProperties $manifest.repository @(
    'identity','origin','commit','tree','hostAllowlistId','governanceExceptionId'
) 'NGCRK-REPOSITORY-PROPERTIES-INVALID'
if ($manifest.repository.identity -cne 'Beowxlf/northgate-vm-factory' -or
    $manifest.repository.commit -cnotmatch '^[a-f0-9]{40}$' -or
    $manifest.repository.tree -cnotmatch '^[a-f0-9]{40}$') { Stop-Ngcrkv 'NGCRK-REPOSITORY-BINDING-INVALID' }

Assert-NgcrkvExactProperties $manifest.release @('releaseId','manifestSha256') `
    'NGCRK-RELEASE-PROPERTIES-INVALID'
if ($manifest.release.releaseId -cnotmatch '^ngcor-[a-z0-9.-]{3,64}$' -or
    $manifest.release.manifestSha256 -cnotmatch '^[a-f0-9]{64}$') {
    Stop-Ngcrkv 'NGCRK-RELEASE-BINDING-INVALID'
}
Assert-NgcrkvExactProperties $manifest.targetHost @(
    'computerName','hostId','hyperVHostId','osBuild','authorizationId','authorizationExpiresAtUtc'
) 'NGCRK-TARGET-HOST-PROPERTIES-INVALID'

Assert-NgcrkvExactProperties $manifest.disabledInstallation @(
    'applyEnabled','executableActions','canaryStage','serviceStartMode','serviceState','activationIncluded'
) 'NGCRK-DISABLED-PROPERTIES-INVALID'
if ($manifest.disabledInstallation.applyEnabled -ne $false -or
    @($manifest.disabledInstallation.executableActions).Count -ne 0 -or
    $manifest.disabledInstallation.canaryStage -cne 'disabled' -or
    $manifest.disabledInstallation.serviceStartMode -cne 'Disabled' -or
    $manifest.disabledInstallation.serviceState -cne 'Stopped' -or
    $manifest.disabledInstallation.activationIncluded -ne $false) {
    Stop-Ngcrkv 'NGCRK-DISABLED-CONTRACT-INVALID'
}

$hashNames = @(
    'releaseSignerCertificateSha256','deploymentAuthorizationSignerCertificateSha256',
    'approvalSignerCertificateSha256','receiptSignerCertificateSha256'
)
Assert-NgcrkvExactProperties $manifest.trustPins $hashNames 'NGCRK-TRUST-PINS-INVALID'
$pins = @()
foreach ($name in $hashNames) {
    $pin = [string]$manifest.trustPins.$name
    if ($pin -cnotmatch '^[a-f0-9]{64}$' -or $pin -ceq ('0' * 64)) { Stop-Ngcrkv 'NGCRK-TRUST-PINS-INVALID' }
    $pins += $pin
}
if (@($pins | Select-Object -Unique).Count -ne 4) { Stop-Ngcrkv 'NGCRK-TRUST-ROLES-NOT-DISTINCT' }

$inputNames = @(
    'bootstrapInstallerPath','bootstrapRollbackPath','packageRoot','releaseManifestSignaturePath',
    'releaseManifestSha256','signedHostDeploymentAuthorizationPath','deploymentAuthorizationSignaturePath',
    'deploymentAuthorizationSha256','backendPolicyPath','backendPolicySignaturePath','backendPolicySha256',
    'dataBundleRoot','dataBundleSha256'
)
Assert-NgcrkvExactProperties $manifest.installInputs $inputNames 'NGCRK-INSTALL-INPUTS-INVALID'
foreach ($hashName in @('releaseManifestSha256','deploymentAuthorizationSha256','backendPolicySha256','dataBundleSha256')) {
    if ([string]$manifest.installInputs.$hashName -cnotmatch '^[a-f0-9]{64}$') { Stop-Ngcrkv 'NGCRK-INSTALL-HASH-INVALID' }
}
foreach ($pathName in @($inputNames | Where-Object { $_ -match '(Path|Root)$' })) {
    $null = Resolve-NgcrkvRelativePath $root ([string]$manifest.installInputs.$pathName) 'NGCRK-INSTALL-PATH-INVALID'
}
$fixedInputs = [ordered]@{
    bootstrapInstallerPath='bootstrap/Install-NorthGateCreateOnlyRelease.ps1'
    bootstrapRollbackPath='bootstrap/Rollback-NorthGateCreateOnlyRelease.ps1'
    packageRoot='release';releaseManifestSignaturePath='signatures/release-manifest.p7s'
    signedHostDeploymentAuthorizationPath='authorization/host-deployment-authorization.json'
    deploymentAuthorizationSignaturePath='signatures/host-deployment-authorization.p7s'
    backendPolicyPath='policy/backend-policy.json';backendPolicySignaturePath='signatures/backend-policy.p7s'
    dataBundleRoot='data-bundle'
}
foreach ($entry in $fixedInputs.GetEnumerator()) {
    if ([string]$manifest.installInputs.($entry.Key) -cne [string]$entry.Value) {
        Stop-Ngcrkv 'NGCRK-INSTALL-PATH-NOT-FIXED'
    }
}

$seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$expectedInventory = @('clean-room-kit.json','clean-room-kit.sha256')
foreach ($record in @($manifest.files)) {
    Assert-NgcrkvExactProperties $record @('path','sha256','sizeBytes') 'NGCRK-FILE-RECORD-INVALID'
    $relative = [string]$record.path
    if (-not $seen.Add($relative) -or [string]$record.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        -not ($record.sizeBytes -is [int] -or $record.sizeBytes -is [long])) {
        Stop-Ngcrkv 'NGCRK-FILE-RECORD-INVALID'
    }
    $path = Resolve-NgcrkvRelativePath $root $relative 'NGCRK-FILE-PATH-INVALID'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Stop-Ngcrkv 'NGCRK-FILE-MISSING' }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        [int64]$item.Length -ne [int64]$record.sizeBytes -or
        (Get-NgcrkvSha256 $path) -cne [string]$record.sha256) { Stop-Ngcrkv 'NGCRK-FILE-HASH-MISMATCH' }
    if ($item.Name -match '(?i)(^id_rsa$|^id_ed25519$|\.pfx$|\.p12$|\.p8$|\.key$|\.pem$|unattend\.generated\.xml$)') {
        Stop-Ngcrkv 'NGCRK-FORBIDDEN-SECRET-FILE'
    }
    if ($item.Length -le 16777216) {
        try {
            if ([IO.File]::ReadAllText($item.FullName) -match '-----BEGIN [A-Z ]*PRIVATE KEY-----') {
                Stop-Ngcrkv 'NGCRK-FORBIDDEN-PRIVATE-KEY-CONTENT'
            }
        } catch [InvalidOperationException] { throw } catch { }
    }
    $expectedInventory += $relative
}
$reparsePoints = @(Get-ChildItem -LiteralPath $root -Recurse -Force | Where-Object {
    $_.Attributes -band [IO.FileAttributes]::ReparsePoint
})
if ($reparsePoints.Count) { Stop-Ngcrkv 'NGCRK-REPARSE-POINT-FORBIDDEN' }
$actualInventory = @(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
    $_.FullName.Substring($root.Length).TrimStart('\').Replace('\','/')
} | Sort-Object)
if (($actualInventory -join '|') -cne (@($expectedInventory | Sort-Object) -join '|')) {
    Stop-Ngcrkv 'NGCRK-INVENTORY-MISMATCH'
}
$checksumText = [IO.File]::ReadAllText((Join-Path $root 'clean-room-kit.sha256'))
if ($checksumText -cne ($ExpectedKitManifestSha256 + '  clean-room-kit.json' + [Environment]::NewLine)) {
    Stop-Ngcrkv 'NGCRK-CHECKSUM-FILE-MISMATCH'
}

$authorizationPath = Resolve-NgcrkvRelativePath $root `
    ([string]$manifest.installInputs.signedHostDeploymentAuthorizationPath) 'NGCRK-AUTHORIZATION-PATH-INVALID'
$authorization = Read-NgcrkvJson $authorizationPath 1048576
if ($authorization.initialPolicy.applyEnabled -ne $false -or
    @($authorization.initialPolicy.executableActions).Count -ne 0 -or
    $authorization.initialPolicy.canaryStage -cne 'disabled' -or
    $authorization.repository.commit -cne $manifest.repository.commit -or
    $authorization.repository.tree -cne $manifest.repository.tree -or
    $authorization.releaseManifestSha256 -cne $manifest.installInputs.releaseManifestSha256 -or
    $authorization.host.computerName -cne $manifest.targetHost.computerName -or
    $authorization.host.hostId -cne $manifest.targetHost.hostId -or
    $authorization.host.hyperVHostId -cne $manifest.targetHost.hyperVHostId -or
    $authorization.host.osBuild -cne $manifest.targetHost.osBuild -or
    $authorization.authorizationId -cne $manifest.targetHost.authorizationId -or
    $authorization.expiresAtUtc -cne $manifest.targetHost.authorizationExpiresAtUtc -or
    $authorization.identity.releaseSignerCertificateSha256 -cne $manifest.trustPins.releaseSignerCertificateSha256 -or
    $authorization.identity.deploymentAuthorizationSignerCertificateSha256 -cne $manifest.trustPins.deploymentAuthorizationSignerCertificateSha256 -or
    $authorization.identity.approvalSignerCertificateSha256 -cne $manifest.trustPins.approvalSignerCertificateSha256 -or
    $authorization.identity.receiptSignerCertificateSha256 -cne $manifest.trustPins.receiptSignerCertificateSha256) {
    Stop-Ngcrkv 'NGCRK-AUTHORIZATION-BINDING-INVALID'
}
if ($RequireCurrentlyInstallable) {
    try { $expires = [DateTimeOffset]::Parse([string]$authorization.expiresAtUtc) }
    catch { Stop-Ngcrkv 'NGCRK-AUTHORIZATION-EXPIRY-INVALID' }
    if ($expires -le [DateTimeOffset]::UtcNow) { Stop-Ngcrkv 'NGCRK-AUTHORIZATION-EXPIRED' }
}

$releaseManifestPath = Join-Path (Resolve-NgcrkvRelativePath $root `
    ([string]$manifest.installInputs.packageRoot) 'NGCRK-PACKAGE-PATH-INVALID') 'release-manifest.json'
$bundlePath = Join-Path (Resolve-NgcrkvRelativePath $root `
    ([string]$manifest.installInputs.dataBundleRoot) 'NGCRK-BUNDLE-PATH-INVALID') 'bundle.json'
$policyPath = Resolve-NgcrkvRelativePath $root ([string]$manifest.installInputs.backendPolicyPath) `
    'NGCRK-POLICY-PATH-INVALID'
if ((Get-NgcrkvSha256 $releaseManifestPath) -cne [string]$manifest.installInputs.releaseManifestSha256 -or
    (Get-NgcrkvSha256 $authorizationPath) -cne [string]$manifest.installInputs.deploymentAuthorizationSha256 -or
    (Get-NgcrkvSha256 $policyPath) -cne [string]$manifest.installInputs.backendPolicySha256 -or
    (Get-NgcrkvSha256 $bundlePath) -cne [string]$manifest.installInputs.dataBundleSha256) {
    Stop-Ngcrkv 'NGCRK-INSTALL-TUPLE-HASH-MISMATCH'
}
$releaseManifest = Read-NgcrkvJson $releaseManifestPath 4194304
$backendPolicy = Read-NgcrkvJson $policyPath 1048576
$dataBundle = Read-NgcrkvJson $bundlePath 10485760
if ($releaseManifest.schema -cne 'northgate/create-only-release-manifest/v2' -or
    $releaseManifest.releaseId -cne $manifest.release.releaseId -or
    $releaseManifest.repository.identity -cne $manifest.repository.identity -or
    $releaseManifest.repository.commit -cne $manifest.repository.commit -or
    $releaseManifest.repository.tree -cne $manifest.repository.tree -or
    $releaseManifest.repository.hostAllowlistId -cne $manifest.repository.hostAllowlistId -or
    $releaseManifest.repository.governanceExceptionId -cne $manifest.repository.governanceExceptionId) {
    Stop-Ngcrkv 'NGCRK-RELEASE-CONTENT-BINDING-INVALID'
}
if ($backendPolicy.schema -cne 'northgate/create-only-backend-policy/v1' -or
    $backendPolicy.authorizationSha256 -cne $manifest.installInputs.deploymentAuthorizationSha256 -or
    $backendPolicy.releaseManifestSha256 -cne $manifest.installInputs.releaseManifestSha256 -or
    $backendPolicy.applyEnabled -ne $true -or (@($backendPolicy.executableActions) -join '|') -cne 'Create') {
    Stop-Ngcrkv 'NGCRK-BACKEND-POLICY-CONTENT-BINDING-INVALID'
}
if ($dataBundle.schema -cne 'northgate/create-only-data-bundle/v1' -or
    $dataBundle.repository.identity -cne $manifest.repository.identity -or
    $dataBundle.repository.commit -cne $manifest.repository.commit -or
    $dataBundle.repository.tree -cne $manifest.repository.tree) {
    Stop-Ngcrkv 'NGCRK-DATA-BUNDLE-CONTENT-BINDING-INVALID'
}

[pscustomobject][ordered]@{
    status = 'verified-disabled-installation-kit'
    kitId = [string]$manifest.kitId
    kitManifestSha256 = $ExpectedKitManifestSha256
    releaseId = [string]$manifest.release.releaseId
    repositoryCommit = [string]$manifest.repository.commit
    repositoryTree = [string]$manifest.repository.tree
    targetComputerName = [string]$manifest.targetHost.computerName
    authorizationExpiresAtUtc = [string]$authorization.expiresAtUtc
    fileCount = @($manifest.files).Count
    applyEnabled = $false
    serviceStartMode = 'Disabled'
    activationIncluded = $false
}
