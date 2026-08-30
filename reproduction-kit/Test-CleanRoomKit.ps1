[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:AssertionCount = 0

function Assert-Ngcrkt {
    param([bool]$Condition,[string]$Message)
    $script:AssertionCount++
    if (-not $Condition) { throw $Message }
}
function Assert-NgcrktRejected {
    param([scriptblock]$Action,[string]$ExpectedCode,[string]$Message)
    $script:AssertionCount++
    try { & $Action; throw 'NGCRK-TEST-NOT-REJECTED' }
    catch {
        if ($_.Exception.Message -cnotmatch ('^' + [regex]::Escape($ExpectedCode) + '$')) {
            throw ($Message + ': ' + $_.Exception.Message)
        }
    }
}
function Get-NgcrktSha256 {
    param([string]$Path)
    $stream = New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Write-NgcrktUtf8 {
    param([string]$Path,[string]$Text)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { $null = [IO.Directory]::CreateDirectory($parent) }
    [IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false)))
}

$builderPath = Join-Path $PSScriptRoot 'New-NorthGateCleanRoomKit.ps1'
$verifierPath = Join-Path $PSScriptRoot 'Test-NorthGateCleanRoomKit.ps1'
foreach ($path in @($builderPath,$verifierPath)) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-Ngcrkt ($errors.Count -eq 0) "PowerShell parse failed for $path"
    Assert-Ngcrkt ($null -ne $ast.ParamBlock) "Parameter block missing from $path"
}

$builderSource = [IO.File]::ReadAllText($builderPath)
$verifierSource = [IO.File]::ReadAllText($verifierPath)
foreach ($required in @(
    'ConfirmKitBuild','New-NorthGateCreateOnlyBootstrap.ps1','Assert-NgcrkDetachedCms',
    'NGCRK-AUTHORIZATION-NOT-DISABLED-OR-MISMATCHED','NGCRK-FORBIDDEN-SECRET-FILE',
    'Test-NorthGateCreateOnlyHostAuthorization.ps1','NGCRK-OUTPUT-OVERLAPS-INPUT',
    'remote get-url origin'
)) {
    Assert-Ngcrkt ($builderSource.Contains($required)) "Assembler control missing: $required"
}
foreach ($required in @(
    'ExpectedKitManifestSha256','NGCRK-MANIFEST-HASH-MISMATCH','NGCRK-INVENTORY-MISMATCH',
    'NGCRK-DISABLED-CONTRACT-INVALID','NGCRK-AUTHORIZATION-EXPIRED',
    'verified-disabled-installation-kit'
)) {
    Assert-Ngcrkt ($verifierSource.Contains($required)) "Verifier control missing: $required"
}
Assert-Ngcrkt ($verifierSource -notmatch '(?im)^\s*(Start|Stop|Set|New)-Service\b|\bNew-VM\b|\bInvoke-Expression\b') `
    'Read-only verifier contains a mutation or dynamic execution primitive.'

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcrk-test-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($fixtureRoot)
try {
    $commit = '1' * 40
    $tree = '2' * 40
    $releaseManifest = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-release-manifest/v2'
        releaseId = 'ngcor-fixture-01'
        repository = [pscustomobject][ordered]@{
            identity = 'Beowxlf/northgate-vm-factory'; origin = 'https://github.com/Beowxlf/northgate-vm-factory.git'
            commit = $commit; tree = $tree; hostAllowlistId = 'ngallow-fixture-01'
            governanceExceptionId = 'NG-GOV-FIXTURE'
        }
    }
    $releaseManifestPath = Join-Path $fixtureRoot 'release\release-manifest.json'
    Write-NgcrktUtf8 $releaseManifestPath (ConvertTo-Json $releaseManifest -Depth 8 -Compress)
    $releaseManifestHash = Get-NgcrktSha256 $releaseManifestPath

    $authorization = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-host-deployment-authorization/v2'
        authorizationId = 'ngdeploy-fixture-01'
        expiresAtUtc = '2099-01-01T00:00:00Z'
        repository = [pscustomobject][ordered]@{ identity='Beowxlf/northgate-vm-factory';commit=$commit;tree=$tree }
        releaseManifestSha256 = $releaseManifestHash
        host = [pscustomobject][ordered]@{
            computerName='HC-FIXTURE';hostId='nghost-fixture'
            hyperVHostId='00000000-0000-0000-0000-000000000001';osBuild='20348.1'
        }
        identity = [pscustomobject][ordered]@{
            releaseSignerCertificateSha256='3'*64;deploymentAuthorizationSignerCertificateSha256='4'*64
            approvalSignerCertificateSha256='5'*64;receiptSignerCertificateSha256='6'*64
        }
        initialPolicy = [pscustomobject][ordered]@{ applyEnabled=$false;executableActions=[object[]]@();canaryStage='disabled' }
    }
    $authorizationPath = Join-Path $fixtureRoot 'authorization\host-deployment-authorization.json'
    Write-NgcrktUtf8 $authorizationPath (ConvertTo-Json $authorization -Depth 8 -Compress)
    $authorizationHash = Get-NgcrktSha256 $authorizationPath

    $backendPolicyPath = Join-Path $fixtureRoot 'policy\backend-policy.json'
    Write-NgcrktUtf8 $backendPolicyPath ('{"schema":"northgate/create-only-backend-policy/v1",' +
        '"authorizationSha256":"' + $authorizationHash + '","releaseManifestSha256":"' +
        $releaseManifestHash + '","applyEnabled":true,"executableActions":["Create"]}')
    $backendPolicyHash = Get-NgcrktSha256 $backendPolicyPath
    $bundlePath = Join-Path $fixtureRoot 'data-bundle\bundle.json'
    Write-NgcrktUtf8 $bundlePath ('{"schema":"northgate/create-only-data-bundle/v1","repository":{"identity":' +
        '"Beowxlf/northgate-vm-factory","commit":"' + $commit + '","tree":"' + $tree + '"}}')
    $bundleHash = Get-NgcrktSha256 $bundlePath

    $fixtureFiles = [ordered]@{
        'bootstrap/Install-NorthGateCreateOnlyRelease.ps1' = '# fixture installer'
        'bootstrap/Rollback-NorthGateCreateOnlyRelease.ps1' = '# fixture rollback'
        'signatures/release-manifest.p7s' = 'fixture signature'
        'signatures/host-deployment-authorization.p7s' = 'fixture signature'
        'signatures/backend-policy.p7s' = 'fixture signature'
        'data-bundle/bundle.p7s' = 'fixture signature'
        'trust/release-signer.cer' = 'fixture public certificate'
        'trust/deployment-authorization-signer.cer' = 'fixture public certificate'
        'trust/approval-signer.cer' = 'fixture public certificate'
        'trust/receipt-signer.cer' = 'fixture public certificate'
        'README.md' = 'fixture instructions'
    }
    foreach ($entry in $fixtureFiles.GetEnumerator()) {
        Write-NgcrktUtf8 (Join-Path $fixtureRoot $entry.Key.Replace('/','\')) ([string]$entry.Value)
    }

    $fileRecords = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $fixtureRoot -Recurse -File | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($fixtureRoot.Length).TrimStart('\').Replace('\','/')
        $fileRecords += [pscustomobject][ordered]@{
            path=$relative;sha256=(Get-NgcrktSha256 $file.FullName);sizeBytes=[int64]$file.Length
        }
    }
    $kitManifest = [pscustomobject][ordered]@{
        schema = 'northgate/vm-factory-clean-room-kit/v1'
        kitId = 'ngcrk-fixture-01-12345678'
        createdAtUtc = '2026-08-30T00:00:00Z'
        repository = [pscustomobject][ordered]@{
            identity='Beowxlf/northgate-vm-factory';origin='https://github.com/Beowxlf/northgate-vm-factory.git'
            commit=$commit;tree=$tree;hostAllowlistId='ngallow-fixture-01';governanceExceptionId='NG-GOV-FIXTURE'
        }
        release = [pscustomobject][ordered]@{ releaseId='ngcor-fixture-01';manifestSha256=$releaseManifestHash }
        targetHost = [pscustomobject][ordered]@{
            computerName='HC-FIXTURE';hostId='nghost-fixture';hyperVHostId='00000000-0000-0000-0000-000000000001'
            osBuild='20348.1';authorizationId='ngdeploy-fixture-01';authorizationExpiresAtUtc='2099-01-01T00:00:00Z'
        }
        disabledInstallation = [pscustomobject][ordered]@{
            applyEnabled=$false;executableActions=[object[]]@();canaryStage='disabled'
            serviceStartMode='Disabled';serviceState='Stopped';activationIncluded=$false
        }
        trustPins = [pscustomobject][ordered]@{
            releaseSignerCertificateSha256='3'*64;deploymentAuthorizationSignerCertificateSha256='4'*64
            approvalSignerCertificateSha256='5'*64;receiptSignerCertificateSha256='6'*64
        }
        installInputs = [pscustomobject][ordered]@{
            bootstrapInstallerPath='bootstrap/Install-NorthGateCreateOnlyRelease.ps1'
            bootstrapRollbackPath='bootstrap/Rollback-NorthGateCreateOnlyRelease.ps1'
            packageRoot='release';releaseManifestSignaturePath='signatures/release-manifest.p7s'
            releaseManifestSha256=$releaseManifestHash
            signedHostDeploymentAuthorizationPath='authorization/host-deployment-authorization.json'
            deploymentAuthorizationSignaturePath='signatures/host-deployment-authorization.p7s'
            deploymentAuthorizationSha256=$authorizationHash
            backendPolicyPath='policy/backend-policy.json';backendPolicySignaturePath='signatures/backend-policy.p7s'
            backendPolicySha256=$backendPolicyHash;dataBundleRoot='data-bundle';dataBundleSha256=$bundleHash
        }
        files = [object[]]$fileRecords
    }
    $kitManifestPath = Join-Path $fixtureRoot 'clean-room-kit.json'
    Write-NgcrktUtf8 $kitManifestPath (ConvertTo-Json $kitManifest -Depth 20 -Compress)
    $kitManifestHash = Get-NgcrktSha256 $kitManifestPath
    Write-NgcrktUtf8 (Join-Path $fixtureRoot 'clean-room-kit.sha256') `
        ($kitManifestHash + '  clean-room-kit.json' + [Environment]::NewLine)

    $result = & $verifierPath -KitRoot $fixtureRoot `
        -ExpectedKitManifestSha256 $kitManifestHash -RequireCurrentlyInstallable
    Assert-Ngcrkt ($result.status -ceq 'verified-disabled-installation-kit') 'Valid fixture was not verified.'
    Assert-Ngcrkt ($result.applyEnabled -eq $false -and $result.activationIncluded -eq $false) `
        'Verifier did not report the disabled contract.'

    [IO.File]::AppendAllText((Join-Path $fixtureRoot 'README.md'),'tamper')
    Assert-NgcrktRejected {
        & $verifierPath -KitRoot $fixtureRoot -ExpectedKitManifestSha256 $kitManifestHash
    } 'NGCRK-FILE-HASH-MISMATCH' 'Tampered kit file was not rejected'
}
finally {
    $resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolvedFixture.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedFixture) -like 'ngcrk-test-*' -and
        (Test-Path -LiteralPath $resolvedFixture -PathType Container)) {
        [IO.Directory]::Delete($resolvedFixture,$true)
    }
}

Write-Host "Clean-room kit tests passed: $script:AssertionCount assertions."
