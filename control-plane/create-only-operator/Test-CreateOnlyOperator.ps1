[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyOperator.psd1'
$moduleSourcePath = Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyOperator.psm1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ngco-' + [guid]::NewGuid().ToString('N'))
$assertionCount = 0
$convertFromJsonSupportsDateKind = (
    (Get-Command -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -CommandType Cmdlet -ErrorAction Stop).Parameters.ContainsKey('DateKind')
)

function Assert-NgcoTest {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    $script:assertionCount++
    if (-not $Condition) { throw "NGCO-TEST-FAIL: $Message" }
}

function Assert-NgcoThrows {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    $script:assertionCount++
    try {
        & $Action
        throw "NGCO-TEST-FAIL: expected $Code"
    }
    catch {
        if ($_.Exception.Message -cne $Code) {
            throw "NGCO-TEST-FAIL: expected $Code, got $($_.Exception.Message)"
        }
    }
}

function ConvertFrom-NgcoTestJson {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)

    if ($script:convertFromJsonSupportsDateKind) {
        return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json -DateKind String)
    }
    return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json)
}

function Copy-NgcoObject {
    param([Parameter(Mandatory)][object]$Value)

    $json = $Value | ConvertTo-Json -Depth 30 -Compress
    return (ConvertFrom-NgcoTestJson -Json $json)
}

try {
    Import-Module $modulePath -Force
    $module = Get-Module NorthGate.VMFactory.CreateOnlyOperator
    Assert-NgcoTest ($null -ne $module) 'Module did not import.'

    $expectedExports = @(
        'Get-NorthGateCreateOnlyOperatorReceipt',
        'Get-NorthGateCreateOnlyOperatorStatus',
        'Invoke-NorthGateCreateOnlyOperatorApply',
        'Register-NorthGateCreateOnlyOperatorPlan'
    )
    $actualExports = @(Get-Command -Module $module.Name | Select-Object -ExpandProperty Name | Sort-Object)
    Assert-NgcoTest (($actualExports -join '|') -ceq ($expectedExports -join '|')) 'Exported command surface changed.'

    $status = Get-NorthGateCreateOnlyOperatorStatus
    Assert-NgcoTest ($status.releaseStatus -ceq 'local-only-hard-disabled') 'Status must remain local-only hard-disabled.'
    Assert-NgcoTest ($status.deployed -eq $false -and $status.applyEnabled -eq $false) 'Deployment or apply was enabled.'
    Assert-NgcoTest (@($status.executableActions).Count -eq 0) 'Effective action list must remain empty.'
    Assert-NgcoTest ($status.modeledAction -ceq 'Create' -and $status.maximumOperationsPerPlan -eq 1) 'Modeled action widened.'
    Assert-NgcoTest ($status.fixedFleetAssetCount -eq 12) 'Fixed fleet count changed.'
    Assert-NgcoTest ($status.repositoryTrustMode -ceq 'signed-exact-commit-tree-exception-v1' -and
        $status.repositoryTrustExceptionInstalled -eq $false) 'Repository trust exception was widened or claimed installed.'
    Assert-NgcoTest (-not $status.liveRevalidationImplemented -and -not $status.liveHyperVBackendImplemented -and
        -not $status.atomicCreateImplemented -and -not $status.quarantineImplemented -and
        -not $status.receiptSigningImplemented) 'An unimplemented production gate was claimed.'
    Assert-NgcoTest ($status.directMutationMethodsExposed -eq $false) 'Direct mutation exposure changed.'

    $policy = & $module { Get-NgcoFixedFleetPolicy }
    $expectedOrder = @(
        'NG-VM-018', 'NG-VM-010', 'NG-VM-014', 'NG-VM-013', 'NG-VM-011', 'NG-VM-012',
        'NG-VM-019', 'NG-VM-020', 'NG-VM-021', 'NG-VM-016', 'NG-VM-017', 'NG-VM-015'
    )
    $expectedNames = @(
        'NG-DEB-CAN01', 'NG-CANARY-01', 'NG-MAIL-EXT01', 'NG-MAIL-INT01', 'NG-WRK-01',
        'NG-WRK-02', 'NG-MGR-01', 'NG-IT-01', 'NG-CYBER-01', 'NG-HR-APP01',
        'NG-PLAT-APP01', 'NG-KALI-EXT01'
    )
    Assert-NgcoTest ((@($policy.fleet.assetId) -join '|') -ceq ($expectedOrder -join '|')) 'Fleet asset order drifted.'
    Assert-NgcoTest ((@($policy.fleet.name) -join '|') -ceq ($expectedNames -join '|')) 'Fleet names drifted.'
    Assert-NgcoTest ((@($policy.executableActions) -join '|') -ceq 'Create') 'Fixed policy is not Create-only.'
    foreach ($denied in @('UpdateOnline', 'UpdateOffline', 'ReplaceRequired', 'DecommissionRequired', 'Delete',
        'Purge', 'Adopt', 'SwitchCreate', 'SwitchDelete', 'SwitchRebind', 'FirewallChange',
        'HostFeatureChange', 'GuestCommand', 'ArbitraryCommand')) {
        Assert-NgcoTest ($denied -cin @($policy.deniedOperations)) "Missing denied operation $denied."
    }
    foreach ($entry in @($policy.fleet)) {
        Assert-NgcoTest ($entry.desired.generation -eq 2 -and $entry.desired.destroyProtection -eq $true -and
            $entry.desired.desiredPowerState -ceq 'off') "Unsafe base state for $($entry.assetId)."
        Assert-NgcoTest ($entry.desired.secureBootRequired -eq $true) "Secure Boot not required for $($entry.assetId)."
        $expectedVtpm = $entry.desired.firmwareProfileRef -ceq 'windows-gen2'
        Assert-NgcoTest ($entry.desired.vtpmRequired -eq $expectedVtpm) "vTPM policy mismatch for $($entry.assetId)."
        Assert-NgcoTest ($entry.desired.imageSha256 -cmatch '^[a-f0-9]{64}$' -and
            [long]$entry.desired.imageSizeBytes -gt 0) "Immutable image binding missing for $($entry.assetId)."
        Assert-NgcoTest ($entry.desired.memory.minimumMiB -le $entry.desired.memory.startupMiB -and
            $entry.desired.memory.startupMiB -le $entry.desired.memory.maximumMiB) "Memory range invalid for $($entry.assetId)."
    }
    $persistent = @($policy.fleet | Where-Object deploymentClass -ceq 'persistent')
    Assert-NgcoTest ($persistent.Count -eq 10) 'Persistent fleet count changed.'
    Assert-NgcoTest ((($persistent | ForEach-Object { $_.desired.processors } | Measure-Object -Sum).Sum) -eq 28) 'Persistent CPU total changed.'
    Assert-NgcoTest ((($persistent | ForEach-Object { $_.desired.memory.startupMiB } | Measure-Object -Sum).Sum) -eq 51200) 'Persistent startup memory total changed.'
    Assert-NgcoTest ((($persistent | ForEach-Object { $_.desired.memory.maximumMiB } | Measure-Object -Sum).Sum) -eq 92160) 'Persistent maximum memory total changed.'
    Assert-NgcoTest ((($persistent | ForEach-Object { $_.desired.osDiskGiB } | Measure-Object -Sum).Sum) -eq 900) 'Persistent disk total changed.'
    Assert-NgcoTest ($policy.policyHash -ceq $status.fixedFleetPolicyHash -and
        $policy.catalogHash -ceq $status.fixedCatalogBindingHash) 'Status hashes do not bind the fixed policy.'

    function New-NgcoTestPlan {
        param([Parameter(Mandatory)][object]$Entry)

        $desired = Copy-NgcoObject -Value $Entry.desired
        $desiredCanonical = & $module { param($Value) ConvertTo-NgcoCanonicalJson -InputObject $Value } $desired
        $desiredHash = & $module { param($Value) Get-NgcoSha256Hex -Value $Value } $desiredCanonical
        return [pscustomobject][ordered]@{
            apiVersion = 'northgate/v1alpha1'
            kind = 'CreateOnlyFleetPlan'
            repository = [pscustomobject][ordered]@{
                identity = 'Beowxlf/northgate-vm-factory'
                commit = ('a' * 40)
                tree = ('b' * 40)
                trustMode = 'signed-exact-commit-tree-exception-v1'
                signedReleaseSha256 = ('c' * 64)
                hostAllowlistId = 'ngallow-local-fixture-v1'
            }
            changeId = 'NG-CHG-20260802-900'
            plannedAtUtc = [System.DateTimeOffset]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
            policyHash = $policy.policyHash
            catalogHash = $policy.catalogHash
            observedStateHash = ('d' * 64)
            plannerVersion = '0.1.0'
            operatorVersion = '0.1.0'
            operations = [object[]]@(
                [pscustomobject][ordered]@{
                    sequence = 1
                    action = 'Create'
                    assetId = $Entry.assetId
                    name = $Entry.name
                    reservationId = 'ngrsv-local-fixture-900'
                    quarantineMode = 'isolate-new-artifacts'
                    desiredStateHash = $desiredHash
                    desired = $desired
                }
            )
        }
    }

    function ConvertTo-NgcoTestCanonical {
        param([Parameter(Mandatory)][object]$Value)
        return (& $module { param($Object) ConvertTo-NgcoCanonicalJson -InputObject $Object } $Value)
    }

    $plan = New-NgcoTestPlan -Entry $policy.fleet[0]
    $canonicalPlan = ConvertTo-NgcoTestCanonical -Value $plan
    $parsed = & $module { param($Json) ConvertFrom-NgcoCanonicalPlan -CanonicalPlanJson $Json } $canonicalPlan
    Assert-NgcoTest ($parsed.Plan.operations[0].assetId -ceq 'NG-VM-018') 'Valid fixed plan did not parse.'
    Assert-NgcoTest ($parsed.Plan.plannedAtUtc -is [string]) 'Plan timestamp was not preserved as a string.'
    Assert-NgcoTest ($parsed.CanonicalJson -ceq $canonicalPlan) 'Canonical plan changed during parsing.'

    $actionDrift = Copy-NgcoObject $plan
    $actionDrift.operations[0].action = 'UpdateOnline'
    $actionDriftJson = ConvertTo-NgcoTestCanonical $actionDrift
    Assert-NgcoThrows 'NGCO-CREATE-ONLY-VIOLATION' {
        & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $actionDriftJson
    }

    $extraOperation = Copy-NgcoObject $plan
    $extraOperation.operations = [object[]]@($extraOperation.operations[0], (Copy-NgcoObject $extraOperation.operations[0]))
    $extraOperation.operations[1].sequence = 2
    $extraOperation.operations[1].assetId = 'NG-VM-010'
    $extraOperation.operations[1].name = 'NG-CANARY-01'
    $extraOperationJson = ConvertTo-NgcoTestCanonical $extraOperation
    Assert-NgcoThrows 'NGCO-PLAN-CONTRACT-INVALID' {
        & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $extraOperationJson
    }

    $unknownAsset = Copy-NgcoObject $plan
    $unknownAsset.operations[0].assetId = 'NG-VM-999'
    $unknownAsset.operations[0].name = 'NG-UNKNOWN-01'
    $unknownAssetJson = ConvertTo-NgcoTestCanonical $unknownAsset
    Assert-NgcoThrows 'NGCO-ASSET-NOT-IN-FIXED-FLEET' {
        & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $unknownAssetJson
    }

    $resourceDrift = Copy-NgcoObject $plan
    $resourceDrift.operations[0].desired.processors = 3
    $resourceDriftJson = ConvertTo-NgcoTestCanonical $resourceDrift
    Assert-NgcoThrows 'NGCO-DESIRED-STATE-BINDING-MISMATCH' {
        & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $resourceDriftJson
    }

    $desiredHashDrift = Copy-NgcoObject $plan
    $desiredHashDrift.operations[0].desiredStateHash = ('e' * 64)
    $desiredHashDriftJson = ConvertTo-NgcoTestCanonical $desiredHashDrift
    Assert-NgcoThrows 'NGCO-DESIRED-STATE-BINDING-MISMATCH' {
        & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $desiredHashDriftJson
    }

    foreach ($property in @('policyHash', 'catalogHash')) {
        $bindingDrift = Copy-NgcoObject $plan
        $bindingDrift.$property = ('f' * 64)
        $bindingDriftJson = ConvertTo-NgcoTestCanonical $bindingDrift
        Assert-NgcoThrows 'NGCO-PLAN-POLICY-BINDING-MISMATCH' {
            & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $bindingDriftJson
        }
    }

    foreach ($mutation in @(
        @{ Property = 'identity'; Value = 'someone/fork' },
        @{ Property = 'trustMode'; Value = 'unprotected-branch' },
        @{ Property = 'signedReleaseSha256'; Value = ('A' * 64) },
        @{ Property = 'hostAllowlistId'; Value = 'moving-main' }
    )) {
        $repositoryDrift = Copy-NgcoObject $plan
        $repositoryDrift.repository.($mutation.Property) = $mutation.Value
        $repositoryDriftJson = ConvertTo-NgcoTestCanonical $repositoryDrift
        Assert-NgcoThrows 'NGCO-PLAN-CONTRACT-INVALID' {
            & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $repositoryDriftJson
        }
    }

    $extraField = Copy-NgcoObject $plan
    $extraField.operations[0].desired | Add-Member -NotePropertyName vlan -NotePropertyValue 150
    $extraFieldJson = ConvertTo-NgcoTestCanonical $extraField
    Assert-NgcoThrows 'NGCO-PLAN-DESIRED-PROPERTIES-INVALID' {
        & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $extraFieldJson
    }

    $duplicateJson = $canonicalPlan -replace '^\{"apiVersion":"northgate/v1alpha1",', '{"apiVersion":"northgate/v1alpha1","apiVersion":"northgate/v1alpha1",'
    Assert-NgcoThrows 'NGCO-PLAN-DUPLICATE-PROPERTY' {
        & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $duplicateJson
    }
    $nullJson = $canonicalPlan.Replace('"operatorVersion":"0.1.0"', '"operatorVersion":null')
    Assert-NgcoThrows 'NGCO-PLAN-NULL-FORBIDDEN' {
        & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $nullJson
    }
    $floatJson = $canonicalPlan.Replace('"processors":2', '"processors":2.5')
    Assert-NgcoThrows 'NGCO-PLAN-NONINTEGER-FORBIDDEN' {
        & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $floatJson
    }
    $prettyJson = $plan | ConvertTo-Json -Depth 30
    Assert-NgcoThrows 'NGCO-PLAN-NONCANONICAL' {
        & $module { param($Json) ConvertFrom-NgcoCanonicalPlan $Json } $prettyJson
    }

    $key = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    $context = & $module { param($Root, [byte[]]$Key) New-NgcoLocalTestContext -StateRoot $Root -MacKey $Key } $testRoot $key
    $auth = [pscustomobject][ordered]@{
        authenticated = $true
        principalId = 'ngco-local-test'
        roles = [object[]]@('planner')
    }
    $registration = & $module {
        param($Context, $AuthenticationContext, $CanonicalPlanJson)
        Register-NgcoLocalTestPlan -Context $Context -AuthenticationContext $AuthenticationContext `
            -CanonicalPlanJson $CanonicalPlanJson
    } $context $auth $canonicalPlan
    Assert-NgcoTest ($registration.accepted -eq $true -and $registration.productionApplicable -eq $false -and
        $registration.applyEnabled -eq $false) 'Local registry result claimed production applicability.'
    Assert-NgcoTest ($registration.planId -cmatch '^ngp-[a-f0-9]{64}$' -and
        $registration.planHash -cmatch '^[a-f0-9]{64}$') 'Host-style local plan capability is malformed.'
    $record = & $module { param($Context, $PlanId) Read-NgcoPlanRecord -Context $Context -PlanId $PlanId } $context $registration.planId
    Assert-NgcoTest ($record.planHash -ceq $registration.planHash -and
        $record.productionApplicable -eq $false) 'Authenticated local registry readback failed.'

    $planPath = Join-Path $context.PlansRoot ($registration.planId + '.json')
    $originalRegistryBytes = [System.IO.File]::ReadAllBytes($planPath)
    $registryObject = ConvertFrom-NgcoTestJson -Json ([System.Text.Encoding]::UTF8.GetString($originalRegistryBytes))
    Assert-NgcoTest ($registryObject.record.registeredAtUtc -is [string] -and
        $registryObject.record.expiresAtUtc -is [string]) 'Registry timestamps were not preserved as strings.'
    $registryObject.record.planHash = ('0' * 64)
    $tamperedRegistry = ConvertTo-NgcoTestCanonical $registryObject
    [System.IO.File]::WriteAllText($planPath, $tamperedRegistry, (New-Object System.Text.UTF8Encoding($false)))
    Assert-NgcoThrows 'NGCO-REGISTRY-AUTHENTICATION-FAILED' {
        & $module { param($Context, $PlanId) Read-NgcoPlanRecord $Context $PlanId } $context $registration.planId
    }
    [System.IO.File]::WriteAllBytes($planPath, $originalRegistryBytes)

    $lock = & $module { Enter-NgcoWriterLock }
    try {
        Assert-NgcoThrows 'NGCO-WRITER-LOCK-BUSY' {
            & $module {
                param($Context, $AuthenticationContext, $CanonicalPlanJson)
                Register-NgcoLocalTestPlan -Context $Context -AuthenticationContext $AuthenticationContext `
                    -CanonicalPlanJson $CanonicalPlanJson
            } $context $auth $canonicalPlan
        }
    }
    finally {
        & $module { param($Lock) Exit-NgcoWriterLock -Lock $Lock } $lock
    }

    $badAuth = [pscustomobject][ordered]@{
        authenticated = $true
        principalId = 'ngco-local-test'
        roles = [object[]]@('reader')
    }
    Assert-NgcoThrows 'NGCO-AUTHENTICATION-FAILED' {
        & $module {
            param($Context, $AuthenticationContext, $CanonicalPlanJson)
            Register-NgcoLocalTestPlan -Context $Context -AuthenticationContext $AuthenticationContext `
                -CanonicalPlanJson $CanonicalPlanJson
        } $context $badAuth $canonicalPlan
    }

    $publicPlan = Register-NorthGateCreateOnlyOperatorPlan -CanonicalPlanJson 'hostile plan input that must not echo'
    Assert-NgcoTest ($publicPlan.accepted -eq $false -and $publicPlan.status -ceq 'disabled' -and
        $publicPlan.productionApplicable -eq $false -and $publicPlan.applyEnabled -eq $false -and
        $publicPlan.reasonCode -ceq 'NGCO-NOT-INDEPENDENTLY-PROMOTED') 'Public plan registration did not fail closed.'
    Assert-NgcoTest (($publicPlan | ConvertTo-Json -Compress) -notmatch 'hostile plan') 'Plan rejection reflected caller input.'

    $apply = Invoke-NorthGateCreateOnlyOperatorApply -PlanId 'hostile caller input that must not echo'
    Assert-NgcoTest ($apply.accepted -eq $false -and $apply.status -ceq 'disabled' -and
        $apply.reasonCode -ceq 'NGCO-NOT-INDEPENDENTLY-PROMOTED' -and $apply.applyEnabled -eq $false) `
        'Apply did not fail closed.'
    Assert-NgcoTest (($apply | ConvertTo-Json -Compress) -notmatch 'hostile caller') 'Apply reflected caller input.'
    $receipt = Get-NorthGateCreateOnlyOperatorReceipt -PlanId 'hostile receipt input that must not echo'
    Assert-NgcoTest ($receipt.found -eq $false -and $receipt.status -ceq 'disabled' -and
        $receipt.reasonCode -ceq 'NGCO-NOT-INDEPENDENTLY-PROMOTED') 'Receipt did not fail closed.'
    Assert-NgcoTest (($receipt | ConvertTo-Json -Compress) -notmatch 'hostile receipt') 'Receipt reflected caller input.'

    $source = [System.IO.File]::ReadAllText($moduleSourcePath)
    foreach ($forbiddenPattern in @(
        '(?i)\bNew-VM\b', '(?i)\bSet-VM\b', '(?i)\bRemove-VM\b', '(?i)\bStart-VM\b',
        '(?i)\bStop-VM\b', '(?i)\bNew-VHD\b', '(?i)\bConnect-VMNetworkAdapter\b',
        '(?i)\bSet-VMNetworkAdapterVlan\b', '(?i)\bInvoke-Expression\b', '(?i)\bStart-Process\b',
        '(?i)\bssh(?:\.exe)?\b', '(?i)\bguest_run_command\b'
    )) {
        Assert-NgcoTest ($source -notmatch $forbiddenPattern) "Forbidden primitive found: $forbiddenPattern"
    }
    Assert-NgcoTest ($source -notmatch '(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----') 'Private key material found.'
    Assert-NgcoTest ($source -notmatch '(?i)(password|token|secret)\s*=\s*["''][^"'']+["'']') 'Credential-like literal found.'

    Write-Host "Create-only operator candidate tests passed: $assertionCount assertions."
}
finally {
    Remove-Module NorthGate.VMFactory.CreateOnlyOperator -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
