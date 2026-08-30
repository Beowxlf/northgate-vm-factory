[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$SourceRoot,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$ReleasePackageRoot,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$ReleaseManifestSignaturePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$SignedHostDeploymentAuthorizationPath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$DeploymentAuthorizationSignaturePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$BackendPolicyPath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$BackendPolicySignaturePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$DataBundleRoot,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$ReleaseSignerPublicCertificatePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$DeploymentAuthorizationSignerPublicCertificatePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$ApprovalSignerPublicCertificatePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$ReceiptSignerPublicCertificatePath,
    [Parameter(Mandatory)][switch]$ConfirmKitBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Ngcrk { param([string]$Code) throw [InvalidOperationException]::new($Code) }
function Get-NgcrkSha256 {
    param([string]$Path)
    $stream = New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Get-NgcrkBytesSha256 {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose() }
}
function Read-NgcrkJson {
    param([string]$Path,[int64]$MaximumBytes)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -le 0 -or $item.Length -gt $MaximumBytes -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Stop-Ngcrk 'NGCRK-INPUT-FILE-INVALID' }
    try { ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($item.FullName,[Text.Encoding]::UTF8)) }
    catch { Stop-Ngcrk 'NGCRK-INPUT-JSON-INVALID' }
}
function Test-NgcrkGitAncestor {
    param([string]$Path)
    $directory = New-Object IO.DirectoryInfo([IO.Path]::GetFullPath($Path))
    while ($null -ne $directory) {
        if (Test-Path -LiteralPath (Join-Path $directory.FullName '.git')) { return $true }
        $directory = $directory.Parent
    }
    $false
}
function Test-NgcrkPathWithin {
    param([string]$Candidate,[string]$Root)
    $candidatePath = [IO.Path]::GetFullPath($Candidate).TrimEnd('\')
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    [string]::Equals($candidatePath,$rootPath,[StringComparison]::OrdinalIgnoreCase) -or
        $candidatePath.StartsWith(($rootPath + '\'),[StringComparison]::OrdinalIgnoreCase)
}
function Assert-NgcrkTreeSafe {
    param([string]$Root)
    $unsafe = @(Get-ChildItem -LiteralPath $Root -Recurse -Force | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    })
    if ($unsafe.Count) { Stop-Ngcrk 'NGCRK-REPARSE-POINT-FORBIDDEN' }
    $secretFiles = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Where-Object {
        $_.Name -match '(?i)(^id_rsa$|^id_ed25519$|\.pfx$|\.p12$|\.p8$|\.key$|\.pem$|unattend\.generated\.xml$)'
    })
    if ($secretFiles.Count) { Stop-Ngcrk 'NGCRK-FORBIDDEN-SECRET-FILE' }
}
function Copy-NgcrkFile {
    param([string]$Source,[string]$Destination)
    $sourceItem = Get-Item -LiteralPath $Source -Force
    if ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-Ngcrk 'NGCRK-REPARSE-POINT-FORBIDDEN' }
    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { $null = [IO.Directory]::CreateDirectory($parent) }
    if (Test-Path -LiteralPath $Destination) { Stop-Ngcrk 'NGCRK-DESTINATION-COLLISION' }
    [IO.File]::Copy($sourceItem.FullName,$Destination,$false)
    if ((Get-NgcrkSha256 $sourceItem.FullName) -cne (Get-NgcrkSha256 $Destination)) {
        Stop-Ngcrk 'NGCRK-COPY-READBACK-FAILED'
    }
}
function Copy-NgcrkTree {
    param([string]$Source,[string]$Destination)
    $sourceRoot = [IO.Path]::GetFullPath($Source).TrimEnd('\')
    Assert-NgcrkTreeSafe $sourceRoot
    if (Test-Path -LiteralPath $Destination) { Stop-Ngcrk 'NGCRK-DESTINATION-COLLISION' }
    $null = [IO.Directory]::CreateDirectory($Destination)
    foreach ($directory in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -Directory -Force)) {
        $relative = $directory.FullName.Substring($sourceRoot.Length).TrimStart('\')
        $null = [IO.Directory]::CreateDirectory((Join-Path $Destination $relative))
    }
    foreach ($file in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Force)) {
        $relative = $file.FullName.Substring($sourceRoot.Length).TrimStart('\')
        Copy-NgcrkFile $file.FullName (Join-Path $Destination $relative)
    }
}
function Get-NgcrkPublicCertificate {
    param([string]$Path)
    if ([IO.Path]::GetExtension($Path) -cne '.cer') { Stop-Ngcrk 'NGCRK-PUBLIC-CERTIFICATE-EXTENSION-INVALID' }
    try { $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($Path) }
    catch { Stop-Ngcrk 'NGCRK-PUBLIC-CERTIFICATE-INVALID' }
    if ($certificate.HasPrivateKey) { Stop-Ngcrk 'NGCRK-PRIVATE-KEY-MATERIAL-FORBIDDEN' }
    [pscustomobject][ordered]@{
        Path = [IO.Path]::GetFullPath($Path)
        Certificate = $certificate
        Sha256 = Get-NgcrkBytesSha256 $certificate.RawData
    }
}
function Assert-NgcrkDetachedCms {
    param([string]$ContentPath,[string]$SignaturePath,[string]$ExpectedSignerSha256)
    try {
        $content = [IO.File]::ReadAllBytes($ContentPath)
        $signature = [IO.File]::ReadAllBytes($SignaturePath)
        $contentInfo = New-Object Security.Cryptography.Pkcs.ContentInfo -ArgumentList (, $content)
        $cms = New-Object Security.Cryptography.Pkcs.SignedCms($contentInfo,$true)
        $cms.Decode($signature)
        $cms.CheckSignature($true)
    }
    catch { Stop-Ngcrk 'NGCRK-DETACHED-CMS-INVALID' }
    if ($cms.SignerInfos.Count -ne 1 -or
        (Get-NgcrkBytesSha256 $cms.SignerInfos[0].Certificate.RawData) -cne $ExpectedSignerSha256) {
        Stop-Ngcrk 'NGCRK-DETACHED-CMS-SIGNER-MISMATCH'
    }
}
function Write-NgcrkUtf8 {
    param([string]$Path,[string]$Text)
    [IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false)))
}

if (-not $ConfirmKitBuild) { Stop-Ngcrk 'NGCRK-CONFIRMATION-REQUIRED' }
$source = [IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
$outputParent = Split-Path -Parent $output
if ([string]::IsNullOrWhiteSpace($outputParent) -or -not (Test-Path -LiteralPath $outputParent -PathType Container) -or
    (Test-NgcrkGitAncestor $outputParent) -or (Test-Path -LiteralPath $output)) {
    Stop-Ngcrk 'NGCRK-OUTPUT-LOCATION-INVALID'
}
if (-not (Test-Path -LiteralPath (Join-Path $source '.git')) -or
    (Test-Path -LiteralPath (Join-Path $source '.gitmodules'))) { Stop-Ngcrk 'NGCRK-SOURCE-REPOSITORY-INVALID' }

$manifestPath = Join-Path ([IO.Path]::GetFullPath($ReleasePackageRoot).TrimEnd('\')) 'release-manifest.json'
$bundlePath = Join-Path ([IO.Path]::GetFullPath($DataBundleRoot).TrimEnd('\')) 'bundle.json'
$bundleSignaturePath = Join-Path ([IO.Path]::GetFullPath($DataBundleRoot).TrimEnd('\')) 'bundle.p7s'
if ((Test-NgcrkPathWithin $output $ReleasePackageRoot) -or
    (Test-NgcrkPathWithin $output $DataBundleRoot)) { Stop-Ngcrk 'NGCRK-OUTPUT-OVERLAPS-INPUT' }
foreach ($required in @($manifestPath,$bundlePath,$bundleSignaturePath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { Stop-Ngcrk 'NGCRK-REQUIRED-INPUT-MISSING' }
}
$releaseManifest = Read-NgcrkJson $manifestPath 4194304
$authorization = Read-NgcrkJson $SignedHostDeploymentAuthorizationPath 1048576
$backendPolicy = Read-NgcrkJson $BackendPolicyPath 1048576
$dataBundle = Read-NgcrkJson $bundlePath 10485760

if ($releaseManifest.schema -cne 'northgate/create-only-release-manifest/v2' -or
    $releaseManifest.repository.identity -cne 'Beowxlf/northgate-vm-factory' -or
    $releaseManifest.repository.commit -cnotmatch '^[a-f0-9]{40}$' -or
    $releaseManifest.repository.tree -cnotmatch '^[a-f0-9]{40}$') { Stop-Ngcrk 'NGCRK-RELEASE-MANIFEST-INVALID' }
$head = (@(& git -C $source rev-parse HEAD 2>&1) -join '').Trim()
$tree = (@(& git -C $source rev-parse 'HEAD^{tree}' 2>&1) -join '').Trim()
$origin = (@(& git -C $source remote get-url origin 2>&1) -join '').Trim()
$worktree = (@(& git -C $source status --porcelain=v1 2>&1) -join "`n").Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne [string]$releaseManifest.repository.commit -or
    $tree -cne [string]$releaseManifest.repository.tree -or
    $origin -cne [string]$releaseManifest.repository.origin -or
    -not [string]::IsNullOrEmpty($worktree)) {
    Stop-Ngcrk 'NGCRK-SOURCE-COMMIT-TREE-OR-CLEANLINESS-MISMATCH'
}

$releaseManifestSha256 = Get-NgcrkSha256 $manifestPath
$authorizationSha256 = Get-NgcrkSha256 $SignedHostDeploymentAuthorizationPath
$backendPolicySha256 = Get-NgcrkSha256 $BackendPolicyPath
$dataBundleSha256 = Get-NgcrkSha256 $bundlePath
if ($authorization.schema -cne 'northgate/create-only-host-deployment-authorization/v2' -or
    $authorization.repository.identity -cne 'Beowxlf/northgate-vm-factory' -or
    $authorization.repository.commit -cne $head -or $authorization.repository.tree -cne $tree -or
    $authorization.releaseManifestSha256 -cne $releaseManifestSha256 -or
    $authorization.initialPolicy.applyEnabled -ne $false -or
    @($authorization.initialPolicy.executableActions).Count -ne 0 -or
    $authorization.initialPolicy.canaryStage -cne 'disabled') { Stop-Ngcrk 'NGCRK-AUTHORIZATION-NOT-DISABLED-OR-MISMATCHED' }
try { $authorizationExpiry = [DateTimeOffset]::Parse([string]$authorization.expiresAtUtc) }
catch { Stop-Ngcrk 'NGCRK-AUTHORIZATION-EXPIRY-INVALID' }
if ($authorizationExpiry -le [DateTimeOffset]::UtcNow) { Stop-Ngcrk 'NGCRK-AUTHORIZATION-EXPIRED' }
if ($backendPolicy.schema -cne 'northgate/create-only-backend-policy/v1' -or
    $backendPolicy.authorizationSha256 -cne $authorizationSha256 -or
    $backendPolicy.releaseManifestSha256 -cne $releaseManifestSha256 -or
    $backendPolicy.applyEnabled -ne $true -or (@($backendPolicy.executableActions) -join '|') -cne 'Create') {
    Stop-Ngcrk 'NGCRK-BACKEND-POLICY-BINDING-INVALID'
}
if ($dataBundle.schema -cne 'northgate/create-only-data-bundle/v1' -or
    $dataBundle.repository.identity -cne 'Beowxlf/northgate-vm-factory' -or
    $dataBundle.repository.commit -cne $head -or $dataBundle.repository.tree -cne $tree) {
    Stop-Ngcrk 'NGCRK-DATA-BUNDLE-BINDING-INVALID'
}

$certificates = [ordered]@{
    release = Get-NgcrkPublicCertificate $ReleaseSignerPublicCertificatePath
    deploymentAuthorization = Get-NgcrkPublicCertificate $DeploymentAuthorizationSignerPublicCertificatePath
    approval = Get-NgcrkPublicCertificate $ApprovalSignerPublicCertificatePath
    receipt = Get-NgcrkPublicCertificate $ReceiptSignerPublicCertificatePath
}
if (@($certificates.Values.Sha256 | Select-Object -Unique).Count -ne 4 -or
    $certificates.release.Sha256 -cne [string]$authorization.identity.releaseSignerCertificateSha256 -or
    $certificates.deploymentAuthorization.Sha256 -cne [string]$authorization.identity.deploymentAuthorizationSignerCertificateSha256 -or
    $certificates.approval.Sha256 -cne [string]$authorization.identity.approvalSignerCertificateSha256 -or
    $certificates.receipt.Sha256 -cne [string]$authorization.identity.receiptSignerCertificateSha256) {
    Stop-Ngcrk 'NGCRK-PUBLIC-CERTIFICATE-PIN-MISMATCH'
}
Assert-NgcrkDetachedCms $manifestPath $ReleaseManifestSignaturePath $certificates.release.Sha256
Assert-NgcrkDetachedCms $SignedHostDeploymentAuthorizationPath $DeploymentAuthorizationSignaturePath `
    $certificates.deploymentAuthorization.Sha256
Assert-NgcrkDetachedCms $BackendPolicyPath $BackendPolicySignaturePath $certificates.release.Sha256
Assert-NgcrkDetachedCms $bundlePath $bundleSignaturePath $certificates.release.Sha256

$authorizationValidator = Join-Path ([IO.Path]::GetFullPath($ReleasePackageRoot).TrimEnd('\')) `
    'Test-NorthGateCreateOnlyHostAuthorization.ps1'
if (-not (Test-Path -LiteralPath $authorizationValidator -PathType Leaf)) {
    Stop-Ngcrk 'NGCRK-AUTHORIZATION-VALIDATOR-MISSING'
}
$authorizationResult = & $authorizationValidator `
    -AuthorizationPath $SignedHostDeploymentAuthorizationPath `
    -ExpectedReleaseId ([string]$releaseManifest.releaseId) `
    -ExpectedReleaseManifestSha256 $releaseManifestSha256 `
    -ExpectedCommit $head -ExpectedTree $tree `
    -ExpectedHostAllowlistId ([string]$releaseManifest.repository.hostAllowlistId) `
    -ExpectedGovernanceExceptionId ([string]$releaseManifest.repository.governanceExceptionId)
if ($authorizationResult.status -cne 'semantic-validation-passed-signature-not-verified') {
    Stop-Ngcrk 'NGCRK-AUTHORIZATION-SEMANTIC-VALIDATION-FAILED'
}

$null = [IO.Directory]::CreateDirectory($output)
try {
    Copy-NgcrkTree $ReleasePackageRoot (Join-Path $output 'release')
    Copy-NgcrkFile $ReleaseManifestSignaturePath (Join-Path $output 'signatures\release-manifest.p7s')
    Copy-NgcrkFile $SignedHostDeploymentAuthorizationPath (Join-Path $output 'authorization\host-deployment-authorization.json')
    Copy-NgcrkFile $DeploymentAuthorizationSignaturePath (Join-Path $output 'signatures\host-deployment-authorization.p7s')
    Copy-NgcrkFile $BackendPolicyPath (Join-Path $output 'policy\backend-policy.json')
    Copy-NgcrkFile $BackendPolicySignaturePath (Join-Path $output 'signatures\backend-policy.p7s')
    Copy-NgcrkTree $DataBundleRoot (Join-Path $output 'data-bundle')
    Copy-NgcrkFile $certificates.release.Path (Join-Path $output 'trust\release-signer.cer')
    Copy-NgcrkFile $certificates.deploymentAuthorization.Path (Join-Path $output 'trust\deployment-authorization-signer.cer')
    Copy-NgcrkFile $certificates.approval.Path (Join-Path $output 'trust\approval-signer.cer')
    Copy-NgcrkFile $certificates.receipt.Path (Join-Path $output 'trust\receipt-signer.cer')
    Copy-NgcrkFile (Join-Path $PSScriptRoot 'Test-NorthGateCleanRoomKit.ps1') `
        (Join-Path $output 'tools\Test-NorthGateCleanRoomKit.ps1')
    Copy-NgcrkFile (Join-Path $PSScriptRoot 'INSTALL.md') (Join-Path $output 'README.md')

    $bootstrapBuilder = Join-Path $source 'control-plane\create-only-release\New-NorthGateCreateOnlyBootstrap.ps1'
    if (-not (Test-Path -LiteralPath $bootstrapBuilder -PathType Leaf)) { Stop-Ngcrk 'NGCRK-BOOTSTRAP-BUILDER-MISSING' }
    $bootstrapResult = & $bootstrapBuilder `
        -ReleaseSignerCertificateSha256 $certificates.release.Sha256 `
        -DeploymentAuthorizationSignerCertificateSha256 $certificates.deploymentAuthorization.Sha256 `
        -OutputDirectory (Join-Path $output 'bootstrap') `
        -ConfirmBootstrapBuild
    if ($null -eq $bootstrapResult -or
        $bootstrapResult.status -cne 'review-required-bootstrap-built' -or
        @($bootstrapResult.files).Count -ne 2) {
        Stop-Ngcrk 'NGCRK-BOOTSTRAP-BUILD-INCOMPLETE'
    }

    Assert-NgcrkTreeSafe $output
    $fileRecords = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $output -Recurse -File -Force | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($output.Length).TrimStart('\').Replace('\','/')
        $fileRecords += [pscustomobject][ordered]@{
            path = $relative
            sha256 = Get-NgcrkSha256 $file.FullName
            sizeBytes = [int64]$file.Length
        }
    }
    $kitManifest = [pscustomobject][ordered]@{
        schema = 'northgate/vm-factory-clean-room-kit/v1'
        kitId = ('ngcrk-' + [string]$releaseManifest.releaseId + '-' + $authorizationSha256.Substring(0,12))
        createdAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        repository = [pscustomobject][ordered]@{
            identity = [string]$releaseManifest.repository.identity
            origin = [string]$releaseManifest.repository.origin
            commit = $head
            tree = $tree
            hostAllowlistId = [string]$releaseManifest.repository.hostAllowlistId
            governanceExceptionId = [string]$releaseManifest.repository.governanceExceptionId
        }
        release = [pscustomobject][ordered]@{
            releaseId = [string]$releaseManifest.releaseId
            manifestSha256 = $releaseManifestSha256
        }
        targetHost = [pscustomobject][ordered]@{
            computerName = [string]$authorization.host.computerName
            hostId = [string]$authorization.host.hostId
            hyperVHostId = [string]$authorization.host.hyperVHostId
            osBuild = [string]$authorization.host.osBuild
            authorizationId = [string]$authorization.authorizationId
            authorizationExpiresAtUtc = [string]$authorization.expiresAtUtc
        }
        disabledInstallation = [pscustomobject][ordered]@{
            applyEnabled = $false
            executableActions = [object[]]@()
            canaryStage = 'disabled'
            serviceStartMode = 'Disabled'
            serviceState = 'Stopped'
            activationIncluded = $false
        }
        trustPins = [pscustomobject][ordered]@{
            releaseSignerCertificateSha256 = $certificates.release.Sha256
            deploymentAuthorizationSignerCertificateSha256 = $certificates.deploymentAuthorization.Sha256
            approvalSignerCertificateSha256 = $certificates.approval.Sha256
            receiptSignerCertificateSha256 = $certificates.receipt.Sha256
        }
        installInputs = [pscustomobject][ordered]@{
            bootstrapInstallerPath = 'bootstrap/Install-NorthGateCreateOnlyRelease.ps1'
            bootstrapRollbackPath = 'bootstrap/Rollback-NorthGateCreateOnlyRelease.ps1'
            packageRoot = 'release'
            releaseManifestSignaturePath = 'signatures/release-manifest.p7s'
            releaseManifestSha256 = $releaseManifestSha256
            signedHostDeploymentAuthorizationPath = 'authorization/host-deployment-authorization.json'
            deploymentAuthorizationSignaturePath = 'signatures/host-deployment-authorization.p7s'
            deploymentAuthorizationSha256 = $authorizationSha256
            backendPolicyPath = 'policy/backend-policy.json'
            backendPolicySignaturePath = 'signatures/backend-policy.p7s'
            backendPolicySha256 = $backendPolicySha256
            dataBundleRoot = 'data-bundle'
            dataBundleSha256 = $dataBundleSha256
        }
        files = [object[]]$fileRecords
    }
    $kitManifestPath = Join-Path $output 'clean-room-kit.json'
    Write-NgcrkUtf8 $kitManifestPath (ConvertTo-Json -InputObject $kitManifest -Depth 20 -Compress)
    $kitManifestSha256 = Get-NgcrkSha256 $kitManifestPath
    Write-NgcrkUtf8 (Join-Path $output 'clean-room-kit.sha256') `
        ($kitManifestSha256 + '  clean-room-kit.json' + [Environment]::NewLine)
    $verifyResult = & (Join-Path $output 'tools\Test-NorthGateCleanRoomKit.ps1') `
        -KitRoot $output -ExpectedKitManifestSha256 $kitManifestSha256 -RequireCurrentlyInstallable
    if ($verifyResult.status -cne 'verified-disabled-installation-kit') { Stop-Ngcrk 'NGCRK-SELF-VERIFICATION-FAILED' }

    [pscustomobject][ordered]@{
        status = 'clean-room-installation-kit-created'
        kitRoot = $output
        kitId = [string]$kitManifest.kitId
        kitManifestSha256 = $kitManifestSha256
        releaseId = [string]$releaseManifest.releaseId
        repositoryCommit = $head
        repositoryTree = $tree
        targetComputerName = [string]$authorization.host.computerName
        authorizationExpiresAtUtc = [string]$authorization.expiresAtUtc
        installState = 'disabled'
        activationIncluded = $false
    }
}
catch {
    if (Test-Path -LiteralPath $output -PathType Container) { [IO.Directory]::Delete($output,$true) }
    throw
}
