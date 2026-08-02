[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$candidateRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $candidateRoot 'NorthGate.VMFactory.HostAdapter.psd1'
$moduleSourcePath = Join-Path $candidateRoot 'NorthGate.VMFactory.HostAdapter.psm1'
$assertionCount = 0

function Assert-HostAdapter {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) { throw $Message }
    $script:assertionCount++
}

function Assert-HostAdapterThrows {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    try {
        $null = & $Action
        throw "Expected '$Code' but the action succeeded."
    }
    catch {
        if ($_.Exception.Message -cne $Code) {
            throw "Expected '$Code' but received '$($_.Exception.Message)'."
        }
        $script:assertionCount++
    }
}

function New-Fixture {
    return (& $script:adapterModule { New-NgvfInertTestFixture })
}

function Update-FixtureHash {
    param([Parameter(Mandatory)][object]$Fixture)

    $Fixture.Preflight.NormalizedStateHash = & $script:adapterModule {
        param($Preflight)
        Get-NgvfNormalizedPreflightHash -Preflight $Preflight
    } $Fixture.Preflight
    $Fixture.Operation.ExpectedPreflightHash = $Fixture.Preflight.NormalizedStateHash
}

function Invoke-Inert {
    param(
        [Parameter(Mandatory)][object]$Fixture,
        [Parameter(Mandatory)][ValidateSet('Success', 'ReportedFailure', 'Throw', 'Malformed')][string]$Scenario
    )

    return (& $script:adapterModule {
        param($Operation, $Preflight, $Scenario)
        Invoke-NgvfInertTestCreate -Operation $Operation -Preflight $Preflight -Scenario $Scenario
    } $Fixture.Operation $Fixture.Preflight $Scenario)
}

Import-Module -Name $modulePath -Force
$adapterModule = Get-Module -Name 'NorthGate.VMFactory.HostAdapter'

try {
    $exported = @(Get-Command -Module 'NorthGate.VMFactory.HostAdapter' | Select-Object -ExpandProperty Name)
    Assert-HostAdapter -Condition (($exported -join '|') -ceq 'Get-NorthGateVmFactoryHostAdapterState') `
        -Message 'The candidate exports an invocation or unexpected command.'

    $state = Get-NorthGateVmFactoryHostAdapterState
    Assert-HostAdapter -Condition ($state.releaseStatus -ceq 'proposed' -and $state.deployed -eq $false) `
        -Message 'Candidate must remain proposed and undeployed.'
    Assert-HostAdapter -Condition ($state.independentlySignedInstalledRelease -eq $false -and
        $state.productionInvocationEnabled -eq $false -and $state.routineInvocationExported -eq $false) `
        -Message 'Candidate falsely enables a production or routine invocation path.'
    Assert-HostAdapter -Condition (@($state.effectiveActions).Count -eq 0 -and
        $state.implementedTestAction -ceq 'Create') `
        -Message 'Only an inert Create test action may be implemented; effective actions must be empty.'
    Assert-HostAdapter -Condition ($state.generation -eq 2 -and $state.destroyProtectionRequired -eq $true) `
        -Message 'Generation 2 and destroy protection must remain fixed.'
    Assert-HostAdapter -Condition ($state.outcomeUnknownRequiresQuarantine -eq $true -and
        $state.identityReuseBlockedOnUnknown -eq $true) `
        -Message 'OutcomeUnknown must require quarantine and block identity reuse.'
    Assert-HostAdapter -Condition ($state.writerLockContractHash -cmatch '^[0-9a-f]{64}$') `
        -Message 'Writer-lock contract must be represented by a hash, not a caller-selected name.'
    Assert-HostAdapter -Condition ($state.reasonCode -ceq 'NGVF-ADAPTER-NOT-INDEPENDENTLY-PROMOTED') `
        -Message 'Candidate returned an unexpected hard-disable reason.'

    $fixture = New-Fixture
    $countBeforeProduction = & $adapterModule { $script:InertInvocationCount }
    Assert-HostAdapterThrows -Code 'NGVF-ADAPTER-NOT-INDEPENDENTLY-PROMOTED' -Action {
        & $adapterModule {
            param($Operation, $Preflight)
            Invoke-NgvfProductionCreate -Operation $Operation -Preflight $Preflight
        } $fixture.Operation $fixture.Preflight
    }
    $countAfterProduction = & $adapterModule { $script:InertInvocationCount }
    Assert-HostAdapter -Condition ($countAfterProduction -eq $countBeforeProduction) `
        -Message 'Hard-disabled production invocation reached the inert backend.'

    $success = Invoke-Inert -Fixture (New-Fixture) -Scenario Success
    Assert-HostAdapter -Condition ($success.GetType().FullName -ceq 'NorthGateHostAdapterOutcome') `
        -Message 'Success did not return the strict outcome type.'
    Assert-HostAdapter -Condition ($success.Status -ceq 'Succeeded' -and $success.Outcome -ceq 'Created' -and
        $success.ReasonCode -ceq 'NGVF-ADAPTER-CREATE-VERIFIED') `
        -Message 'Inert verified create returned an unexpected outcome.'
    Assert-HostAdapter -Condition ($success.AfterStateVerified -eq $true -and
        $success.DestroyProtectionObserved -eq $true -and $success.QuarantineState -ceq 'not-required') `
        -Message 'Successful outcome omitted after-state or destroy-protection evidence.'
    Assert-HostAdapter -Condition ($success.IdentityReuseBlocked -eq $false -and
        $success.ReconciliationRequired -eq $false -and ([guid]$success.VmId) -ne [guid]::Empty) `
        -Message 'Successful outcome carries an invalid identity/reconciliation state.'
    Assert-HostAdapter -Condition ($success.AfterStateHash -cmatch '^[0-9a-f]{64}$') `
        -Message 'Successful outcome lacks a normalized after-state hash.'

    $reportedFailure = Invoke-Inert -Fixture (New-Fixture) -Scenario ReportedFailure
    Assert-HostAdapter -Condition ($reportedFailure.GetType().FullName -ceq 'NorthGateHostAdapterOutcome' -and
        $reportedFailure.Status -ceq 'Failed' -and $reportedFailure.Outcome -ceq 'NotCreated') `
        -Message 'Reported backend failure did not return the strict failed outcome.'
    Assert-HostAdapter -Condition ($reportedFailure.QuarantineState -ceq 'required' -and
        $reportedFailure.IdentityReuseBlocked -eq $true -and $reportedFailure.ReconciliationRequired -eq $true) `
        -Message 'Reported failure did not require quarantine and identity blocking.'

    foreach ($scenario in @('Throw', 'Malformed')) {
        $unknown = Invoke-Inert -Fixture (New-Fixture) -Scenario $scenario
        Assert-HostAdapter -Condition ($unknown.GetType().FullName -ceq 'NorthGateHostAdapterOutcome' -and
            $unknown.Status -ceq 'OutcomeUnknown' -and $unknown.Outcome -ceq 'Unknown' -and
            $unknown.ReasonCode -ceq 'NGVF-ADAPTER-OUTCOME-UNKNOWN') `
            -Message "Scenario '$scenario' did not produce a strict OutcomeUnknown."
        Assert-HostAdapter -Condition ($unknown.AfterStateVerified -eq $false -and
            $unknown.QuarantineState -ceq 'required' -and $unknown.IdentityReuseBlocked -eq $true -and
            $unknown.ReconciliationRequired -eq $true) `
            -Message "Scenario '$scenario' did not preserve the quarantine/reconciliation contract."
    }

    $invalidCases = @(
        @{ Code = 'NGVF-ADAPTER-CREATE-ONLY'; Mutate = { param($f) $f.Operation.Action = 'Update' } },
        @{ Code = 'NGVF-ADAPTER-GENERATION-INVALID'; Mutate = { param($f) $f.Operation.Generation = 1 } },
        @{ Code = 'NGVF-ADAPTER-DESTROY-PROTECTION-REQUIRED'; Mutate = { param($f) $f.Operation.DestroyProtection = $false } },
        @{ Code = 'NGVF-ADAPTER-OPAQUE-REFERENCE-INVALID'; Mutate = { param($f) $f.Operation.NetworkProfileRef = 'C:\fabric\switch' } },
        @{ Code = 'NGVF-ADAPTER-OPAQUE-REFERENCE-INVALID'; Mutate = { param($f) $f.Operation.ImageRef = 'https://example.invalid/image' } },
        @{ Code = 'NGVF-ADAPTER-IMAGE-HASH-MISMATCH'; Mutate = {
            param($f) $f.Preflight.ImageArtifactSha256 = ('9' * 64); Update-FixtureHash -Fixture $f
        } },
        @{ Code = 'NGVF-ADAPTER-SWITCH-FINGERPRINT-MISMATCH'; Mutate = {
            param($f) $f.Preflight.NetworkFingerprint = ('9' * 64); Update-FixtureHash -Fixture $f
        } },
        @{ Code = 'NGVF-ADAPTER-IDENTITY-COLLISION'; Mutate = {
            param($f) $f.Preflight.NameCollisionCount = 1; Update-FixtureHash -Fixture $f
        } },
        @{ Code = 'NGVF-ADAPTER-MAINTENANCE-BLOCKED'; Mutate = {
            param($f) $f.Preflight.MaintenanceState = 'Blocked'; Update-FixtureHash -Fixture $f
        } },
        @{ Code = 'NGVF-ADAPTER-MEMORY-CAPACITY-INSUFFICIENT'; Mutate = {
            param($f) $f.Preflight.PendingMemoryReservationMiB = 50000; Update-FixtureHash -Fixture $f
        } },
        @{ Code = 'NGVF-ADAPTER-PROCESSOR-CAPACITY-INSUFFICIENT'; Mutate = {
            param($f) $f.Preflight.PendingProcessorReservationCount = 20; Update-FixtureHash -Fixture $f
        } },
        @{ Code = 'NGVF-ADAPTER-STORAGE-CAPACITY-INSUFFICIENT'; Mutate = {
            param($f) $f.Preflight.StorageFreeBytes = [long](80GB); Update-FixtureHash -Fixture $f
        } },
        @{ Code = 'NGVF-ADAPTER-MEMORY-NORMALIZATION-MISMATCH'; Mutate = {
            param($f) $f.Preflight.VmMemoryEvidence[0].NormalizedReservationMiB = 1048576; Update-FixtureHash -Fixture $f
        } },
        @{ Code = 'NGVF-ADAPTER-DISK-CHAIN-AMBIGUOUS'; Mutate = {
            param($f) $f.Preflight.VmStorageEvidence[1].ChainState = 'Unknown'; Update-FixtureHash -Fixture $f
        } },
        @{ Code = 'NGVF-ADAPTER-DISK-CHAIN-AMBIGUOUS'; Mutate = {
            param($f) $f.Preflight.VmStorageEvidence[1].DifferencingDiskCount = 0; Update-FixtureHash -Fixture $f
        } },
        @{ Code = 'NGVF-ADAPTER-PREFLIGHT-HASH-MISMATCH'; Mutate = {
            param($f) $f.Preflight.StateEpoch = 2
        } },
        @{ Code = 'NGVF-ADAPTER-PREFLIGHT-STALE'; Mutate = {
            param($f)
            $f.Preflight.ObservedAtUtc = [System.DateTimeOffset]::UtcNow.AddMinutes(-10).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
            Update-FixtureHash -Fixture $f
        } }
    )
    foreach ($case in $invalidCases) {
        $invalid = New-Fixture
        & $case.Mutate $invalid
        Assert-HostAdapterThrows -Code $case.Code -Action {
            $null = Invoke-Inert -Fixture $invalid -Scenario Success
        }
    }

    $extraProperty = New-Fixture
    $extraProperty.Operation | Add-Member -NotePropertyName vlan -NotePropertyValue 150
    Assert-HostAdapterThrows -Code 'NGVF-ADAPTER-OPERATION-TYPE-INVALID' -Action {
        $null = Invoke-Inert -Fixture $extraProperty -Scenario Success
    }

    $lockFixture = New-Fixture
    $heldLock = & $adapterModule { Enter-NgvfWriterLock }
    try {
        Assert-HostAdapterThrows -Code 'NGVF-ADAPTER-WRITER-LOCK-BUSY' -Action {
            $null = Invoke-Inert -Fixture $lockFixture -Scenario Success
        }
    }
    finally {
        & $adapterModule { param($Lock) Exit-NgvfWriterLock -Lock $Lock } $heldLock
    }

    $moduleSource = [System.IO.File]::ReadAllText($moduleSourcePath)
    $forbiddenSourcePatterns = @(
        '(?i)\[\s*scriptblock\s*\]',
        '(?i)\$(?:Command|Script|ScriptBlock|Path|Url|Uri|SwitchName|Vlan|Delegate|Provider)\b(?!:)',
        '(?i)\b(?:New|Set|Remove|Start|Stop|Checkpoint|Restore|Rename)-VM\b',
        '(?i)\b(?:Connect|Disconnect|Set|Add|Remove)-VMNetworkAdapter\b',
        '(?i)\bImport-Module\s+Hyper-V\b',
        '(?i)\bInvoke-Expression\b',
        '(?i)\bStart-Process\b',
        '(?i)\bInvoke-(?:WebRequest|RestMethod)\b',
        '(?i)\b(?:ssh|scp|sftp)(?:\.exe)?\b'
    )
    foreach ($pattern in $forbiddenSourcePatterns) {
        Assert-HostAdapter -Condition ($moduleSource -notmatch $pattern) `
            -Message "Host-adapter candidate contains forbidden source matching '$pattern'."
    }
}
finally {
    Remove-Module -Name 'NorthGate.VMFactory.HostAdapter' -Force -ErrorAction SilentlyContinue
}

Write-Host "Phase 3 host-adapter validation passed: $assertionCount assertions; production hard-disabled and fixed inert Create contract verified."
