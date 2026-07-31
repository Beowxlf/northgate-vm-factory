[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$schemaValidationCount = 0

function Test-IsUnderRepository {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $prefix = $repositoryRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    return $fullPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Read-JsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int64]$MaximumBytes = 1048576
    )

    $item = Get-Item -LiteralPath $Path
    if ($item.Length -gt $MaximumBytes) {
        throw "JSON document exceeds the $MaximumBytes byte limit: $Path"
    }

    $raw = [System.IO.File]::ReadAllText($item.FullName)
    if ($raw -match '[\x00-\x08\x0B\x0C\x0E-\x1F]') {
        throw "Unescaped control character detected in JSON: $Path"
    }

    $testJson = Get-Command Test-Json -ErrorAction SilentlyContinue
    if ($testJson) {
        if (-not (Test-Json -Json $raw -ErrorAction SilentlyContinue)) {
            throw "JSON is not strictly conformant: $Path"
        }
    }

    try {
        $object = $raw | ConvertFrom-Json
    }
    catch {
        throw "Invalid JSON: $Path`n$($_.Exception.Message)"
    }

    $schemaProperty = $object.PSObject.Properties['$schema']
    if ($testJson -and $schemaProperty -and $schemaProperty.Value -is [string] -and $schemaProperty.Value.StartsWith('.')) {
        $schemaPath = [System.IO.Path]::GetFullPath((Join-Path $item.DirectoryName $schemaProperty.Value))
        if (-not (Test-IsUnderRepository -Path $schemaPath) -or -not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) {
            throw "Local schema reference escapes the repository or does not exist: $Path"
        }
        if (-not (Test-Json -Json $raw -SchemaFile $schemaPath -ErrorAction SilentlyContinue)) {
            throw "JSON Schema validation failed: $Path"
        }
        $script:schemaValidationCount++
    }

    return $object
}

function Get-DuplicateValues {
    param([object[]]$Values)

    return @(
        $Values |
            Where-Object { $null -ne $_ } |
            Group-Object -Property { ([string]$_).ToUpperInvariant() } |
            Where-Object Count -gt 1 |
            Select-Object -ExpandProperty Name
    )
}

function Get-CatalogProfile {
    param(
        [Parameter(Mandatory)][object]$Catalog,
        [Parameter(Mandatory)][string]$Id,
        [string]$RequiredStatus = 'approved'
    )

    return @($Catalog.profiles | Where-Object { $_.id -ieq $Id -and $_.approvalStatus -eq $RequiredStatus })
}

function Test-CatalogIdentities {
    param(
        [Parameter(Mandatory)][object]$Catalog,
        [Parameter(Mandatory)][string]$Name
    )

    $duplicateIds = Get-DuplicateValues -Values @($Catalog.profiles.id)
    $duplicateServerIds = Get-DuplicateValues -Values @($Catalog.profiles.serverPolicyId)
    if ($duplicateIds.Count -or $duplicateServerIds.Count) {
        throw "$Name catalog identifiers must be case-insensitively unique. Ids=[$($duplicateIds -join ',')], ServerPolicyIds=[$($duplicateServerIds -join ',')]"
    }
}

function Test-ForbiddenManifestData {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [string]$Location = '$',
        [string]$PropertyName = ''
    )

    if ($null -eq $InputObject) {
        throw "Null is not permitted in a manifest at $Location"
    }

    if ($InputObject -is [string]) {
        if ($PropertyName -ne '$schema') {
            if ($InputObject -match '(?i)(^[a-z]:[\\/]|^\\\\|^//|^\\\\[?.]\\|(^|[\\/])\.\.([\\/]|$)|^(file|https?|smb|ssh)://|%[a-z_][a-z0-9_]*%|\$\{?[a-z_][a-z0-9_]*\}?|\*)') {
                throw "Path-, URI-, environment-, or wildcard-shaped data is forbidden at $Location"
            }
            if ($InputObject -match '(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b|\b[A-Za-z0-9+/]{80,}={0,2}\b)') {
                throw "Secret-like content is forbidden at $Location"
            }
        }
        return
    }

    if ($InputObject -is [ValueType]) {
        return
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [System.Management.Automation.PSCustomObject]) {
        $index = 0
        foreach ($item in $InputObject) {
            Test-ForbiddenManifestData -InputObject $item -Location "$Location[$index]"
            $index++
        }
        return
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.Name -match '(?i)(password|secret|token|credential|private.?key|api.?key|connection.?string|sas|unattend|domain.?join|command|script|raw.?path|switch.?name|vlan|mac.?address|ip.?address|uri|url|hyper.?v.?vm.?id)') {
            throw "Forbidden manifest property '$($property.Name)' at $Location"
        }
        Test-ForbiddenManifestData -InputObject $property.Value -Location "$Location.$($property.Name)" -PropertyName $property.Name
    }
}

$jsonFiles = @(Get-ChildItem -LiteralPath $repositoryRoot -Recurse -File -Filter '*.json' | Where-Object FullName -NotMatch '[\\/]\.git[\\/]')
foreach ($jsonFile in $jsonFiles) {
    $maximumBytes = if ($jsonFile.FullName -match '[\\/]manifests[\\/]') { 262144 } else { 1048576 }
    $null = Read-JsonFile -Path $jsonFile.FullName -MaximumBytes $maximumBytes
}

$networkCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\networks.json')
$storageCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\storage-profiles.json')
$imageCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\images.json')
$ownerCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\owners.json')
$bootstrapCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\bootstrap-profiles.json')
$recoveryCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\recovery-profiles.json')
$firmwareCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\firmware-profiles.json')
$resourcePolicy = Read-JsonFile -Path (Join-Path $repositoryRoot 'policy\resource-limits.json')

Test-CatalogIdentities -Catalog $networkCatalog -Name 'Network'
Test-CatalogIdentities -Catalog $storageCatalog -Name 'Storage'
Test-CatalogIdentities -Catalog $ownerCatalog -Name 'Owner'
Test-CatalogIdentities -Catalog $bootstrapCatalog -Name 'Bootstrap'
Test-CatalogIdentities -Catalog $recoveryCatalog -Name 'Recovery'
Test-CatalogIdentities -Catalog $firmwareCatalog -Name 'Firmware'

$duplicateImages = Get-DuplicateValues -Values @($imageCatalog.images.id)
if ($duplicateImages.Count) {
    throw "Image catalog identifiers must be case-insensitively unique: $($duplicateImages -join ', ')"
}

foreach ($network in $networkCatalog.profiles) {
    if ($network.allowCreate -ne $false -or $network.allowRebind -ne $false) {
        throw "Network profile '$($network.id)' may not authorize switch creation or rebinding."
    }
}

if ($resourcePolicy.applyEnabled -ne $false -or $resourcePolicy.status -ne 'proposed' -or @($resourcePolicy.executableActions).Count -ne 0) {
    throw 'Initial repository must remain plan-only with proposed policy, applyEnabled=false, and no executable actions.'
}

$expectedPlannerActions = @('NoOp', 'Create', 'UpdateOnline', 'UpdateOffline', 'ReplaceRequired', 'DecommissionRequired')
if ((@($resourcePolicy.plannerActions) -join '|') -ne ($expectedPlannerActions -join '|')) {
    throw 'Planner action enum was changed from the reviewed plan-only contract.'
}

$manifestDirectory = Join-Path $repositoryRoot 'manifests\vms'
$unexpectedManifestFiles = @(Get-ChildItem -LiteralPath $manifestDirectory -File | Where-Object { $_.Name -ne '.gitkeep' -and $_.Extension -ne '.json' })
if ($unexpectedManifestFiles.Count) {
    throw "Only JSON VM manifests are permitted: $($unexpectedManifestFiles.Name -join ', ')"
}

$manifestFiles = @(Get-ChildItem -LiteralPath $manifestDirectory -File -Filter '*.json')
$assetIds = @()
$vmNames = @()
foreach ($manifestFile in $manifestFiles) {
    $manifest = Read-JsonFile -Path $manifestFile.FullName -MaximumBytes 262144
    Test-ForbiddenManifestData -InputObject $manifest

    if ($manifest.'$schema' -ne '../../schemas/vm-manifest.schema.json' -or $manifest.apiVersion -ne 'northgate/v1alpha1' -or $manifest.kind -ne 'VirtualMachine') {
        throw "Unsupported manifest contract: $($manifestFile.FullName)"
    }
    if ($manifest.metadata.assetId -notmatch '^NG-VM-[0-9]{3,}$') {
        throw "Invalid immutable assetId in $($manifestFile.FullName)"
    }
    if ($manifest.metadata.name -cnotmatch '^[A-Z](?:[A-Z0-9-]{0,13}[A-Z0-9])?$') {
        throw "VM name must be 1-15 uppercase ASCII guest-safe characters in $($manifestFile.FullName)"
    }
    $expectedFileName = $manifest.metadata.assetId.ToLowerInvariant() + '.json'
    if ($manifestFile.Name -cne $expectedFileName) {
        throw "Manifest filename must be '$expectedFileName'."
    }
    if ($manifest.spec.intent -notin @('create', 'manage') -or $manifest.spec.generation -ne 2 -or $manifest.spec.destroyProtection -ne $true) {
        throw "Manifest intent, Generation 2, or destroy protection is invalid in $($manifestFile.FullName)"
    }
    if ($manifest.metadata.assetId -in @($manifest.metadata.dependencies)) {
        throw "A VM cannot depend on itself in $($manifestFile.FullName)"
    }

    $memory = $manifest.spec.compute.memory
    if ($memory.mode -eq 'dynamic' -and -not ($memory.minimumMiB -le $memory.startupMiB -and $memory.startupMiB -le $memory.maximumMiB)) {
        throw "Dynamic memory must satisfy minimumMiB <= startupMiB <= maximumMiB in $($manifestFile.FullName)"
    }

    $owner = Get-CatalogProfile -Catalog $ownerCatalog -Id $manifest.metadata.ownerRef
    $storage = Get-CatalogProfile -Catalog $storageCatalog -Id $manifest.spec.storage.profileRef
    $network = Get-CatalogProfile -Catalog $networkCatalog -Id $manifest.spec.network.profileRef
    $bootstrap = Get-CatalogProfile -Catalog $bootstrapCatalog -Id $manifest.spec.bootstrapProfileRef
    $recovery = Get-CatalogProfile -Catalog $recoveryCatalog -Id $manifest.spec.recoveryProfileRef
    $firmware = Get-CatalogProfile -Catalog $firmwareCatalog -Id $manifest.spec.firmwareProfileRef
    if ($owner.Count -ne 1 -or $storage.Count -ne 1 -or $network.Count -ne 1 -or $bootstrap.Count -ne 1 -or $recovery.Count -ne 1 -or $firmware.Count -ne 1) {
        throw "Every manifest reference must resolve exactly once to an approved profile in $($manifestFile.FullName)"
    }
    if ($network[0].allowAttach -ne $true -or $network[0].allowCreate -ne $false -or $network[0].allowRebind -ne $false) {
        throw "Network profile cannot be used safely in $($manifestFile.FullName)"
    }
    if ($storage[0].allowProvision -ne $true -or ($manifest.metadata.criticality -in @('high', 'critical') -and $storage[0].criticalWorkloadsAllowed -ne $true)) {
        throw "Storage profile is not approved for this workload in $($manifestFile.FullName)"
    }

    $image = @($imageCatalog.images | Where-Object { $_.id -ieq $manifest.spec.imageRef })
    if ($image.Count -ne 1 -or $image[0].approvalStatus -ne 'promoted' -or $image[0].retirementStatus -ne 'active' -or $image[0].sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw "Image reference is not an active immutable promoted image in $($manifestFile.FullName)"
    }
    if (2 -notin @($image[0].allowedGenerations) -or $manifest.spec.firmwareProfileRef -notin @($image[0].allowedFirmwareProfiles)) {
        throw "Image, generation, and firmware profile are incompatible in $($manifestFile.FullName)"
    }

    $assetIds += $manifest.metadata.assetId
    $vmNames += $manifest.metadata.name
}

$duplicateAssetIds = Get-DuplicateValues -Values $assetIds
$duplicateVmNames = Get-DuplicateValues -Values $vmNames
if ($duplicateAssetIds.Count -or $duplicateVmNames.Count) {
    throw "Manifest identities must be case-insensitively unique. AssetIds=[$($duplicateAssetIds -join ',')], Names=[$($duplicateVmNames -join ',')]"
}

$unsafeFiles = @(Get-ChildItem -LiteralPath $repositoryRoot -Recurse -File | Where-Object {
    $_.FullName -notmatch '[\\/]\.git[\\/]' -and
    $_.Name -match '(?i)(\.tfstate($|\.)|id_rsa|id_ed25519|\.pfx$|\.p12$|\.key$|\.pem$|unattend\.generated\.xml$)'
})
if ($unsafeFiles.Count) {
    throw "Unsafe files detected: $($unsafeFiles.FullName -join ', ')"
}

$reparsePoints = @(Get-ChildItem -LiteralPath $repositoryRoot -Recurse -Force | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint })
if ($reparsePoints.Count) {
    throw "Symlinks or reparse points are not permitted: $($reparsePoints.FullName -join ', ')"
}

$privateKeySignatures = @(Get-ChildItem -LiteralPath $repositoryRoot -Recurse -File | Where-Object FullName -NotMatch '[\\/]\.git[\\/]' | Where-Object {
    try { [System.IO.File]::ReadAllText($_.FullName) -match '-----BEGIN [A-Z ]*PRIVATE KEY-----' } catch { $false }
})
if ($privateKeySignatures.Count) {
    throw "Private-key signature detected: $($privateKeySignatures.FullName -join ', ')"
}

if (Test-Path -LiteralPath (Join-Path $repositoryRoot '.gitmodules')) {
    throw 'Git submodules are not permitted.'
}

$readme = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'README.md')
$architecture = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'docs\architecture.md')
if ($readme -notmatch '```mermaid' -or $readme -notmatch 'No GitHub Actions runner' -or $architecture -notmatch 'never infer deletion' -or $architecture -notmatch 'application.authenticat' -or $architecture -notmatch 'plan ID') {
    throw 'Architecture safety statements are missing or were weakened.'
}

Write-Host "Repository validation passed: $($jsonFiles.Count) JSON files; $($manifestFiles.Count) managed VM manifests; $schemaValidationCount schema validations; plan-only apply disabled."
