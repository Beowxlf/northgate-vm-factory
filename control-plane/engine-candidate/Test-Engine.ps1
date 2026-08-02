[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$engineRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $engineRoot '..\..'))
$modulePath = Join-Path $engineRoot 'NorthGate.VMFactory.Engine.psd1'
$moduleSourcePath = Join-Path $engineRoot 'NorthGate.VMFactory.Engine.psm1'
$engineModule = Import-Module -Name $modulePath -Force -PassThru
$assertionCount = 0
$testSessionRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('northgate-vm-factory-engine-' + [guid]::NewGuid().ToString('N'))
$null = [System.IO.Directory]::CreateDirectory($testSessionRoot)

function Assert-Engine {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
    $script:assertionCount++
}

function Assert-EngineThrows {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Code
    )

    $caught = ''
    try {
        $null = & $Action
    }
    catch {
        $caught = $_.Exception.Message
    }
    Assert-Engine -Condition ($caught -ceq $Code) -Message "Expected '$Code', received '$caught'."
}

function New-TestMacKey {
    $bytes = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return $bytes
}

function New-TestLedgerEntry {
    param(
        [Parameter(Mandatory)][string]$AssetId,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ReservationId
    )

    [pscustomobject][ordered]@{
        assetId = $AssetId
        canonicalName = $Name
        reservationId = $ReservationId
        vmId = ''
        state = 'Reserved'
    }
}

function ConvertTo-TestCanonicalJson {
    param([Parameter(Mandatory)][object]$Value)

    return (& $script:engineModule { param($InputValue) ConvertTo-NgvfCanonicalJson -InputObject $InputValue } $Value)
}

function New-TestPlanObject {
    param(
        [Parameter(Mandatory)][string]$AssetId,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ReservationId,
        [Parameter(Mandatory)][System.DateTimeOffset]$PlannedAt,
        [string]$ChangeSuffix = 'ENGINE-TEST'
    )

    [pscustomobject][ordered]@{
        apiVersion = 'northgate/v1alpha1'
        kind = 'VmFactoryPlan'
        repository = [pscustomobject][ordered]@{
            identity = 'Beowxlf/northgate-vm-factory'
            commit = ('a' * 40)
            tree = ('b' * 40)
            protectedBranchVerified = $true
        }
        changeId = 'NG-CHG-20260802-' + $ChangeSuffix
        plannedAtUtc = $PlannedAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        policyHash = ('c' * 64)
        catalogHash = ('d' * 64)
        observedStateHash = ('e' * 64)
        plannerVersion = '0.2.0'
        provisionerVersion = '0.2.0'
        operations = @(
            [pscustomobject][ordered]@{
                sequence = 1
                action = 'Create'
                assetId = $AssetId
                name = $Name
                desiredStateHash = ('f' * 64)
                imageHash = ('1' * 64)
                reservationId = $ReservationId
                quarantineMode = 'isolate-artifacts'
            }
        )
    }
}

function New-TestHarness {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object[]]$LedgerEntries,
        [bool]$RepositoryProtectionVerified = $true,
        [bool]$RepositoryTupleMatches = $true,
        [bool]$StateProtectionVerified = $true,
        [ValidateSet('Strict', 'Coercive')][string]$AuthenticationMode = 'Strict',
        [ValidateSet('Exact', 'WrongHash', 'Reject', 'Expire')][string]$ApprovalMode = 'Exact',
        [ValidateSet('Succeed', 'Fail', 'Throw', 'Invalid')][string]$SimulationScenario = 'Succeed'
    )

    $stateRoot = Join-Path $script:testSessionRoot $Name
    $clockState = @{ Now = [System.DateTimeOffset]::Parse('2026-08-02T15:00:00Z') }
    $approvalState = @{ Mode = $ApprovalMode; Calls = 0; Consumed = @{} }
    $authenticator = {
        param($Operation, $AuthenticationContext)
        $null = $Operation
        if ($AuthenticationMode -eq 'Coercive') {
            return [pscustomobject]@{
                authenticated = 'true'
                principalId = 'northgate-engine-coercive'
                roles = 'reader'
            }
        }
        if ($AuthenticationContext -ceq 'authorized') {
            return [pscustomobject]@{
                authenticated = $true
                principalId = 'northgate-engine-test'
                roles = @('reader', 'planner', 'executor')
            }
        }
        if ($AuthenticationContext -ceq 'reader-only') {
            return [pscustomobject]@{
                authenticated = $true
                principalId = 'northgate-engine-reader'
                roles = @('reader')
            }
        }
        return [pscustomobject]@{
            authenticated = $false
            principalId = 'rejected'
            roles = @()
        }
    }.GetNewClosure()
    $repositoryVerifier = {
        param($Identity, $Commit, $Tree)
        $returnedCommit = if ($RepositoryTupleMatches) { $Commit } else { ('9' * 40) }
        return [pscustomobject][ordered]@{
            verified = $RepositoryProtectionVerified
            identity = $Identity
            commit = $returnedCommit
            tree = $Tree
            protectedBranchReachable = $RepositoryProtectionVerified
            verificationId = 'ngrv-engine-test-verification'
        }
    }.GetNewClosure()
    $approvalProvider = {
        param($PlanId, $PlanHash)
        $approvalState.Calls++
        if ($approvalState.Mode -eq 'Reject' -or $approvalState.Consumed.ContainsKey($PlanId)) {
            return $null
        }
        $approvalState.Consumed[$PlanId] = $true
        if ($approvalState.Mode -eq 'Expire') {
            $clockState.Now = $clockState.Now.AddMinutes(11)
        }
        $returnedHash = if ($approvalState.Mode -eq 'WrongHash') { ('0' * 64) } else { $PlanHash }
        return [pscustomobject][ordered]@{
            approved = $true
            planId = $PlanId
            planHash = $returnedHash
            approvalId = 'nga-engine-test-approval'
            oneTime = $true
        }
    }.GetNewClosure()
    $clock = { return $clockState.Now }.GetNewClosure()
    $macKey = New-TestMacKey
    $context = & $script:engineModule {
        param($Root, $Key, $Auth, $RepositoryTrust, $Approval, $ClockProvider, $Ledger, $StateProtection, $Scenario)
        New-NgvfEngineContext -StateRoot $Root -MacKey $Key -Authenticator $Auth `
            -RepositoryVerifier $RepositoryTrust -ApprovalProvider $Approval -Clock $ClockProvider `
            -InitialLedgerEntries $Ledger -StateProtectionVerified $StateProtection `
            -SimulationEnabled $true -SimulationScenario $Scenario
    } $stateRoot $macKey $authenticator $repositoryVerifier $approvalProvider $clock $LedgerEntries $StateProtectionVerified $SimulationScenario

    [pscustomobject][ordered]@{
        Context = $context
        ClockState = $clockState
        ApprovalState = $approvalState
        MacKey = $macKey
    }
}

try {
    $expectedCommands = @(
        'Get-NorthGateVmFactoryEnginePlan',
        'Get-NorthGateVmFactoryEngineState',
        'Invoke-NorthGateVmFactoryEngineApply',
        'Register-NorthGateVmFactoryEnginePlan'
    )
    $actualCommands = @(
        Get-Command -Module 'NorthGate.VMFactory.Engine' |
            Select-Object -ExpandProperty Name |
            Sort-Object
    )
    Assert-Engine -Condition (($actualCommands -join '|') -ceq ($expectedCommands -join '|')) `
        -Message 'Engine exports an unexpected operation or direct mutator.'

    $applyCommand = Get-Command Invoke-NorthGateVmFactoryEngineApply
    Assert-Engine -Condition ($applyCommand.Parameters.ContainsKey('PlanId')) `
        -Message 'Apply must accept a plan ID.'
    foreach ($forbiddenParameter in @('Command', 'Script', 'ScriptBlock', 'Path', 'Payload', 'Operation', 'Plan')) {
        Assert-Engine -Condition (-not $applyCommand.Parameters.ContainsKey($forbiddenParameter)) `
            -Message "Apply exposes forbidden payload parameter '$forbiddenParameter'."
    }
    $contextFactory = & $engineModule { Get-Command New-NgvfEngineContext }
    Assert-Engine -Condition (-not $contextFactory.Parameters.ContainsKey('Provisioner')) `
        -Message 'Engine context permits injection of an executable provisioner.'

    $moduleSource = [System.IO.File]::ReadAllText($moduleSourcePath)
    foreach ($pattern in @(
        '(?i)\b(?:New|Set|Remove|Start|Stop|Checkpoint|Restore|Rename)-VM\b',
        '(?i)\bImport-Module\s+Hyper-V\b',
        '(?i)\bInvoke-Expression\b',
        '(?i)\bStart-Process\b',
        '(?i)\bInvoke-(?:WebRequest|RestMethod)\b',
        '(?i)\b(?:ssh|scp|sftp)(?:\.exe)?\b'
    )) {
        Assert-Engine -Condition ($moduleSource -notmatch $pattern) `
            -Message "Engine contains a prohibited live-mutation primitive matching '$pattern'."
    }

    $resourcePolicy = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'policy\resource-limits.json') | ConvertFrom-Json
    Assert-Engine -Condition ($resourcePolicy.applyEnabled -eq $false -and @($resourcePolicy.executableActions).Count -eq 0) `
        -Message 'Repository apply policy was enabled by the engine scaffold.'

    $shortKeyRoot = Join-Path $testSessionRoot 'short-key'
    Assert-EngineThrows -Code 'NGVF-MAC-KEY-INVALID' -Action {
        $null = & $engineModule {
            param($Root)
            New-NgvfEngineContext -StateRoot $Root -MacKey (New-Object byte[] 8) `
                -Authenticator { } -RepositoryVerifier { } -ApprovalProvider { } `
                -Clock { [System.DateTimeOffset]::UtcNow } -InitialLedgerEntries @() `
                -SimulationEnabled $true
        } $shortKeyRoot
    }
    Assert-EngineThrows -Code 'NGVF-STATE-ROOT-REPOSITORY-FORBIDDEN' -Action {
        $null = & $engineModule {
            param($Root, $Key)
            New-NgvfEngineContext -StateRoot $Root -MacKey $Key `
                -Authenticator { } -RepositoryVerifier { } -ApprovalProvider { } `
                -Clock { [System.DateTimeOffset]::UtcNow } -InitialLedgerEntries @() `
                -SimulationEnabled $true
        } (Join-Path $repositoryRoot '.engine-state-must-not-exist') (New-TestMacKey)
    }
    $duplicateVmId = '00000000-0000-0000-0000-000000000999'
    $duplicateBoundEntries = @(
        [pscustomobject][ordered]@{ assetId = 'NG-VM-998'; canonicalName = 'NG-DUPVM-01'; reservationId = 'ngrsv-engine-dupvm-998'; vmId = $duplicateVmId; state = 'Bound' }
        [pscustomobject][ordered]@{ assetId = 'NG-VM-999'; canonicalName = 'NG-DUPVM-02'; reservationId = 'ngrsv-engine-dupvm-999'; vmId = $duplicateVmId; state = 'Bound' }
    )
    Assert-EngineThrows -Code 'NGVF-LEDGER-DUPLICATE' -Action {
        $null = & $engineModule {
            param($Root, $Key, $Entries)
            New-NgvfEngineContext -StateRoot $Root -MacKey $Key `
                -Authenticator { } -RepositoryVerifier { } -ApprovalProvider { } `
                -Clock { [System.DateTimeOffset]::UtcNow } -InitialLedgerEntries $Entries `
                -SimulationEnabled $true
        } (Join-Path $testSessionRoot 'duplicate-ledger') (New-TestMacKey) $duplicateBoundEntries
    }

    $mainEntries = @(
        New-TestLedgerEntry -AssetId 'NG-VM-900' -Name 'NG-TEST-01' -ReservationId 'ngrsv-engine-test-900'
        New-TestLedgerEntry -AssetId 'NG-VM-901' -Name 'NG-TEST-02' -ReservationId 'ngrsv-engine-test-901'
        New-TestLedgerEntry -AssetId 'NG-VM-902' -Name 'NG-TEST-03' -ReservationId 'ngrsv-engine-test-902'
    )
    $main = New-TestHarness -Name 'main' -LedgerEntries $mainEntries
    $state = Get-NorthGateVmFactoryEngineState -Context $main.Context -AuthenticationContext 'authorized'
    Assert-Engine -Condition ($state.deployed -eq $false -and $state.liveApplyEnabled -eq $false -and $state.simulationEnabled -eq $true) `
        -Message 'Engine scaffold must remain undeployed and simulation-only.'
    Assert-Engine -Condition ($state.repositoryVerification -ceq 'exact-identity-commit-tree-and-protected-branch' -and $state.directMutationMethodsExposed -eq $false) `
        -Message 'Engine state did not preserve the trust and surface boundary.'
    Assert-Engine -Condition ($state.stateProtectionVerified -eq $true) `
        -Message 'Engine state did not report protected-state verification.'

    $authMarker = 'raw-auth-context-must-never-be-audited'
    Assert-EngineThrows -Code 'NGVF-AUTHENTICATION-FAILED' -Action {
        Get-NorthGateVmFactoryEngineState -Context $main.Context -AuthenticationContext $authMarker
    }
    $auditText = [System.IO.File]::ReadAllText($main.Context.AuditPath)
    Assert-Engine -Condition ($auditText -notmatch [regex]::Escape($authMarker)) `
        -Message 'Sanitized audit reflected authentication input.'
    Assert-Engine -Condition ($auditText -match '"eventAuthenticationHash":"[a-f0-9]{64}"') `
        -Message 'Audit event lacks its authentication hash.'
    $coerciveAuthentication = New-TestHarness -Name 'coercive-auth' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-909' -Name 'NG-COERCE-01' -ReservationId 'ngrsv-engine-test-909'
    ) -AuthenticationMode 'Coercive'
    Assert-EngineThrows -Code 'NGVF-AUTHENTICATION-FAILED' -Action {
        Get-NorthGateVmFactoryEngineState -Context $coerciveAuthentication.Context -AuthenticationContext 'authorized'
    }
    $coerciveAudit = New-TestHarness -Name 'coercive-audit' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-908' -Name 'NG-AUDTYPE-01' -ReservationId 'ngrsv-engine-test-908'
    )
    $coerciveAudit.Context.AuditWriter = { param($Line) $null = $Line; return 'true' }
    Assert-EngineThrows -Code 'NGVF-AUDIT-UNAVAILABLE' -Action {
        Get-NorthGateVmFactoryEngineState -Context $coerciveAudit.Context -AuthenticationContext 'authorized'
    }

    $planObject = New-TestPlanObject -AssetId 'NG-VM-900' -Name 'NG-TEST-01' `
        -ReservationId 'ngrsv-engine-test-900' -PlannedAt $main.ClockState.Now
    $canonicalPlan = ConvertTo-TestCanonicalJson -Value $planObject
    Assert-Engine -Condition ($canonicalPlan -match '"operations":\[') `
        -Message 'Canonicalizer collapsed a one-operation array.'
    Assert-EngineThrows -Code 'NGVF-PLAN-NONCANONICAL' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $main.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson (' ' + $canonicalPlan)
    }
    $duplicatePlan = $canonicalPlan -replace '^\{', '{"apiVersion":"northgate/v1alpha1",'
    Assert-EngineThrows -Code 'NGVF-PLAN-DUPLICATE-PROPERTY' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $main.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson $duplicatePlan
    }
    $nullPlan = $canonicalPlan -replace '"changeId":"[^"]+"', '"changeId":null'
    Assert-EngineThrows -Code 'NGVF-PLAN-NULL-FORBIDDEN' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $main.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson $nullPlan
    }
    $floatPlan = $canonicalPlan -replace '"sequence":1', '"sequence":1.5'
    Assert-EngineThrows -Code 'NGVF-PLAN-NONINTEGER-FORBIDDEN' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $main.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson $floatPlan
    }
    $planWithExtra = $canonicalPlan | ConvertFrom-Json
    $planWithExtra | Add-Member -NotePropertyName unexpected -NotePropertyValue 'value'
    Assert-EngineThrows -Code 'NGVF-PLAN-PROPERTIES-INVALID' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $main.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $planWithExtra)
    }
    $planWithObjectOperation = $canonicalPlan | ConvertFrom-Json
    $planWithObjectOperation.operations = $planWithObjectOperation.operations[0]
    Assert-EngineThrows -Code 'NGVF-PLAN-OPERATIONS-ARRAY-REQUIRED' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $main.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $planWithObjectOperation)
    }
    $planWithStringTrust = $canonicalPlan | ConvertFrom-Json
    $planWithStringTrust.repository.protectedBranchVerified = 'true'
    Assert-EngineThrows -Code 'NGVF-REPOSITORY-TRUST-UNVERIFIED' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $main.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $planWithStringTrust)
    }
    $oversizedPlan = '{"value":"' + ('x' * 262144) + '"}'
    Assert-EngineThrows -Code 'NGVF-PLAN-SIZE-EXCEEDED' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $main.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson $oversizedPlan
    }
    $staleObject = New-TestPlanObject -AssetId 'NG-VM-900' -Name 'NG-TEST-01' `
        -ReservationId 'ngrsv-engine-test-900' -PlannedAt $main.ClockState.Now.AddMinutes(-20)
    Assert-EngineThrows -Code 'NGVF-PLAN-STALE' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $main.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $staleObject)
    }
    $badLedgerObject = New-TestPlanObject -AssetId 'NG-VM-900' -Name 'NG-TEST-01' `
        -ReservationId 'ngrsv-engine-wrong-900' -PlannedAt $main.ClockState.Now
    Assert-EngineThrows -Code 'NGVF-LEDGER-BINDING-MISMATCH' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $main.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $badLedgerObject)
    }

    $unprotected = New-TestHarness -Name 'unprotected' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-910' -Name 'NG-UNPROT-01' -ReservationId 'ngrsv-engine-test-910'
    ) -RepositoryProtectionVerified $false
    $unprotectedPlan = New-TestPlanObject -AssetId 'NG-VM-910' -Name 'NG-UNPROT-01' `
        -ReservationId 'ngrsv-engine-test-910' -PlannedAt $unprotected.ClockState.Now -ChangeSuffix 'UNPROTECTED'
    Assert-EngineThrows -Code 'NGVF-REPOSITORY-TRUST-UNVERIFIED' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $unprotected.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $unprotectedPlan)
    }
    $mismatchedRepository = New-TestHarness -Name 'mismatched-repository' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-912' -Name 'NG-REPO-01' -ReservationId 'ngrsv-engine-test-912'
    ) -RepositoryTupleMatches $false
    $mismatchedRepositoryPlan = New-TestPlanObject -AssetId 'NG-VM-912' -Name 'NG-REPO-01' `
        -ReservationId 'ngrsv-engine-test-912' -PlannedAt $mismatchedRepository.ClockState.Now -ChangeSuffix 'REPOSITORY-TUPLE'
    Assert-EngineThrows -Code 'NGVF-REPOSITORY-TRUST-UNVERIFIED' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $mismatchedRepository.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $mismatchedRepositoryPlan)
    }

    $unprotectedState = New-TestHarness -Name 'unprotected-state' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-911' -Name 'NG-STATE-01' -ReservationId 'ngrsv-engine-test-911'
    ) -StateProtectionVerified $false
    $unprotectedStatePlan = New-TestPlanObject -AssetId 'NG-VM-911' -Name 'NG-STATE-01' `
        -ReservationId 'ngrsv-engine-test-911' -PlannedAt $unprotectedState.ClockState.Now -ChangeSuffix 'STATE-PROTECTION'
    Assert-EngineThrows -Code 'NGVF-STATE-PROTECTION-UNVERIFIED' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $unprotectedState.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $unprotectedStatePlan)
    }
    $coerciveBoundary = New-TestHarness -Name 'coercive-boundary' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-914' -Name 'NG-BOUND-01' -ReservationId 'ngrsv-engine-test-914'
    )
    $coerciveBoundary.Context.SimulationEnabled = 'true'
    $coerciveBoundaryPlan = New-TestPlanObject -AssetId 'NG-VM-914' -Name 'NG-BOUND-01' `
        -ReservationId 'ngrsv-engine-test-914' -PlannedAt $coerciveBoundary.ClockState.Now -ChangeSuffix 'BOUNDARY-TYPE'
    Assert-EngineThrows -Code 'NGVF-SCAFFOLD-NOT-SIMULATION-ONLY' -Action {
        Register-NorthGateVmFactoryEnginePlan -Context $coerciveBoundary.Context -AuthenticationContext 'authorized' `
            -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $coerciveBoundaryPlan)
    }

    $registration = Register-NorthGateVmFactoryEnginePlan -Context $main.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson $canonicalPlan
    $secondRegistration = Register-NorthGateVmFactoryEnginePlan -Context $main.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson $canonicalPlan
    $secondAssetPlan = New-TestPlanObject -AssetId 'NG-VM-901' -Name 'NG-TEST-02' `
        -ReservationId 'ngrsv-engine-test-901' -PlannedAt $main.ClockState.Now -ChangeSuffix 'SECOND-ASSET'
    $secondAssetRegistration = Register-NorthGateVmFactoryEnginePlan -Context $main.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $secondAssetPlan)
    Assert-Engine -Condition ($registration.accepted -eq $true -and $registration.planId -cmatch '^ngp-[a-f0-9]{64}$') `
        -Message 'Host-issued plan ID was not random-format and accepted.'
    Assert-Engine -Condition ($registration.planHash -cmatch '^[a-f0-9]{64}$' -and $registration.planHash -cne $secondRegistration.planHash) `
        -Message 'Authenticated plan hashes were not bound to unique host-issued plan IDs.'
    Assert-Engine -Condition ($registration.planId -cne $secondRegistration.planId) `
        -Message 'Plan registration reused a host-issued random plan ID.'
    $registeredPlan = Get-NorthGateVmFactoryEnginePlan -Context $main.Context `
        -AuthenticationContext 'authorized' -PlanId $registration.planId
    Assert-Engine -Condition ($registeredPlan.planHash -ceq $registration.planHash -and $registeredPlan.state -ceq 'Registered') `
        -Message 'Authenticated registry readback did not match registration.'
    $keyHex = (($main.MacKey | ForEach-Object { $_.ToString('x2') }) -join '')
    $registryText = [System.IO.File]::ReadAllText((Join-Path $main.Context.PlansRoot ($registration.planId + '.json')))
    Assert-Engine -Condition ($registryText -notmatch [regex]::Escape($keyHex)) `
        -Message 'Runtime HMAC key was written into the registry.'

    $crossRootLock = New-TestHarness -Name 'cross-root-lock' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-915' -Name 'NG-XLOCK-01' -ReservationId 'ngrsv-engine-test-915'
    )
    $crossRootPlan = New-TestPlanObject -AssetId 'NG-VM-915' -Name 'NG-XLOCK-01' `
        -ReservationId 'ngrsv-engine-test-915' -PlannedAt $crossRootLock.ClockState.Now -ChangeSuffix 'CROSS-ROOT-LOCK'
    $crossRootRegistration = Register-NorthGateVmFactoryEnginePlan -Context $crossRootLock.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $crossRootPlan)
    $heldLock = & $engineModule { param($Context) Enter-NgvfWriterLock -Context $Context } $main.Context
    try {
        Assert-EngineThrows -Code 'NGVF-WRITER-LOCK-BUSY' -Action {
            Invoke-NorthGateVmFactoryEngineApply -Context $main.Context -AuthenticationContext 'authorized' `
                -PlanId $registration.planId
        }
        Assert-Engine -Condition ($main.Context.SimulationInvocationCount -eq 0) `
            -Message 'Provisioner ran while the host-wide writer lock was held.'
        Assert-EngineThrows -Code 'NGVF-WRITER-LOCK-BUSY' -Action {
            Invoke-NorthGateVmFactoryEngineApply -Context $crossRootLock.Context -AuthenticationContext 'authorized' `
                -PlanId $crossRootRegistration.planId
        }
        Assert-Engine -Condition ($crossRootLock.Context.SimulationInvocationCount -eq 0) `
            -Message 'Different state roots bypassed the system-wide writer lock.'
    }
    finally {
        & $engineModule { param($Lock) Exit-NgvfWriterLock -Lock $Lock } $heldLock
    }

    Assert-EngineThrows -Code 'NGVF-AUTHENTICATION-FAILED' -Action {
        Invoke-NorthGateVmFactoryEngineApply -Context $main.Context -AuthenticationContext 'reader-only' `
            -PlanId $registration.planId
    }
    Assert-Engine -Condition ($main.Context.SimulationInvocationCount -eq 0) `
        -Message 'Reader-only identity reached provisioner.'

    $receipt = Invoke-NorthGateVmFactoryEngineApply -Context $main.Context `
        -AuthenticationContext 'authorized' -PlanId $registration.planId
    Assert-Engine -Condition ($receipt.outcome -ceq 'Succeeded' -and $receipt.simulated -eq $true -and $receipt.quarantineState -ceq 'not-required') `
        -Message 'Valid simulation did not produce a successful signed receipt.'
    Assert-Engine -Condition ($receipt.receiptAuthenticationHash -cmatch '^[a-f0-9]{64}$') `
        -Message 'Receipt lacks an authenticated hash.'
    Assert-Engine -Condition ($receipt.executorPrincipalHash -cmatch '^[a-f0-9]{64}$' -and
        $receipt.approvalEvidenceHash -cmatch '^[a-f0-9]{64}$' -and
        $receipt.repositoryCommit -ceq ('a' * 40) -and
        $receipt.repositoryTree -ceq ('b' * 40) -and
        $receipt.receiptSignerId -ceq 'host-hmac-scaffold-v1') `
        -Message 'Receipt omitted executor, approval, repository, or signer evidence.'
    $receiptAgain = Invoke-NorthGateVmFactoryEngineApply -Context $main.Context `
        -AuthenticationContext 'authorized' -PlanId $registration.planId
    Assert-Engine -Condition (($receipt | ConvertTo-Json -Depth 20 -Compress) -ceq ($receiptAgain | ConvertTo-Json -Depth 20 -Compress)) `
        -Message 'Duplicate apply did not return the same idempotent receipt.'
    Assert-Engine -Condition ($main.Context.SimulationInvocationCount -eq 1 -and $main.ApprovalState.Calls -eq 1) `
        -Message 'Duplicate apply reran the provisioner or consumed a second approval.'
    Assert-EngineThrows -Code 'NGVF-APPROVAL-ALREADY-CONSUMED' -Action {
        Invoke-NorthGateVmFactoryEngineApply -Context $main.Context -AuthenticationContext 'authorized' `
            -PlanId $secondAssetRegistration.planId
    }
    Assert-Engine -Condition ($main.Context.SimulationInvocationCount -eq 1) `
        -Message 'Reused approval identity reached provisioner for a different plan.'
    $mainLedger = & $engineModule { param($Context) Read-NgvfLedger -Context $Context } $main.Context
    $boundEntry = @($mainLedger.entries | Where-Object { $_.assetId -eq 'NG-VM-900' })[0]
    Assert-Engine -Condition ($boundEntry.state -ceq 'Bound' -and $boundEntry.vmId -cne '') `
        -Message 'Successful simulation did not bind the protected identity ledger.'
    $receiptPath = Join-Path $main.Context.ReceiptsRoot ($registration.planId + '.json')
    $tamperedReceiptText = [System.IO.File]::ReadAllText($receiptPath).Replace('Succeeded', 'Failed')
    [System.IO.File]::WriteAllText($receiptPath, $tamperedReceiptText, (New-Object System.Text.UTF8Encoding($false)))
    Assert-EngineThrows -Code 'NGVF-RECORD-AUTHENTICATION-FAILED' -Action {
        Invoke-NorthGateVmFactoryEngineApply -Context $main.Context -AuthenticationContext 'authorized' `
            -PlanId $registration.planId
    }
    Assert-Engine -Condition ($main.Context.SimulationInvocationCount -eq 1) `
        -Message 'Tampered receipt caused provisioner replay.'

    $tamperEntries = @(
        New-TestLedgerEntry -AssetId 'NG-VM-920' -Name 'NG-TAMPER-01' -ReservationId 'ngrsv-engine-test-920'
    )
    $tamper = New-TestHarness -Name 'tamper' -LedgerEntries $tamperEntries
    $tamperPlan = New-TestPlanObject -AssetId 'NG-VM-920' -Name 'NG-TAMPER-01' `
        -ReservationId 'ngrsv-engine-test-920' -PlannedAt $tamper.ClockState.Now -ChangeSuffix 'TAMPER'
    $tamperRegistration = Register-NorthGateVmFactoryEnginePlan -Context $tamper.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $tamperPlan)
    $tamperPath = Join-Path $tamper.Context.PlansRoot ($tamperRegistration.planId + '.json')
    $tamperedText = [System.IO.File]::ReadAllText($tamperPath).Replace('Registered', 'Applying')
    [System.IO.File]::WriteAllText($tamperPath, $tamperedText, (New-Object System.Text.UTF8Encoding($false)))
    Assert-EngineThrows -Code 'NGVF-RECORD-AUTHENTICATION-FAILED' -Action {
        Get-NorthGateVmFactoryEnginePlan -Context $tamper.Context -AuthenticationContext 'authorized' `
            -PlanId $tamperRegistration.planId
    }

    $expiry = New-TestHarness -Name 'expiry' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-930' -Name 'NG-EXPIRY-01' -ReservationId 'ngrsv-engine-test-930'
    )
    $expiryPlan = New-TestPlanObject -AssetId 'NG-VM-930' -Name 'NG-EXPIRY-01' `
        -ReservationId 'ngrsv-engine-test-930' -PlannedAt $expiry.ClockState.Now -ChangeSuffix 'EXPIRY'
    $expiryRegistration = Register-NorthGateVmFactoryEnginePlan -Context $expiry.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $expiryPlan)
    $expiry.ClockState.Now = $expiry.ClockState.Now.AddMinutes(11)
    Assert-EngineThrows -Code 'NGVF-PLAN-EXPIRED' -Action {
        Invoke-NorthGateVmFactoryEngineApply -Context $expiry.Context -AuthenticationContext 'authorized' `
            -PlanId $expiryRegistration.planId
    }
    Assert-Engine -Condition ($expiry.Context.SimulationInvocationCount -eq 0 -and $expiry.ApprovalState.Calls -eq 0) `
        -Message 'Expired plan reached approval or provisioner.'

    $wrongApproval = New-TestHarness -Name 'wrong-approval' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-940' -Name 'NG-APPROVE-01' -ReservationId 'ngrsv-engine-test-940'
    ) -ApprovalMode 'WrongHash'
    $wrongApprovalPlan = New-TestPlanObject -AssetId 'NG-VM-940' -Name 'NG-APPROVE-01' `
        -ReservationId 'ngrsv-engine-test-940' -PlannedAt $wrongApproval.ClockState.Now -ChangeSuffix 'APPROVAL'
    $wrongApprovalRegistration = Register-NorthGateVmFactoryEnginePlan -Context $wrongApproval.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $wrongApprovalPlan)
    Assert-EngineThrows -Code 'NGVF-EXACT-APPROVAL-REQUIRED' -Action {
        Invoke-NorthGateVmFactoryEngineApply -Context $wrongApproval.Context -AuthenticationContext 'authorized' `
            -PlanId $wrongApprovalRegistration.planId
    }
    Assert-Engine -Condition ($wrongApproval.Context.SimulationInvocationCount -eq 0) `
        -Message 'Mismatched exact approval reached provisioner.'

    $approvalExpiry = New-TestHarness -Name 'approval-expiry' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-941' -Name 'NG-APPEXP-01' -ReservationId 'ngrsv-engine-test-941'
    ) -ApprovalMode 'Expire'
    $approvalExpiryPlan = New-TestPlanObject -AssetId 'NG-VM-941' -Name 'NG-APPEXP-01' `
        -ReservationId 'ngrsv-engine-test-941' -PlannedAt $approvalExpiry.ClockState.Now -ChangeSuffix 'APPROVAL-EXPIRY'
    $approvalExpiryRegistration = Register-NorthGateVmFactoryEnginePlan -Context $approvalExpiry.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $approvalExpiryPlan)
    Assert-EngineThrows -Code 'NGVF-PLAN-EXPIRED' -Action {
        Invoke-NorthGateVmFactoryEngineApply -Context $approvalExpiry.Context -AuthenticationContext 'authorized' `
            -PlanId $approvalExpiryRegistration.planId
    }
    Assert-Engine -Condition ($approvalExpiry.ApprovalState.Calls -eq 1 -and $approvalExpiry.Context.SimulationInvocationCount -eq 0) `
        -Message 'Plan expiring during approval reached the fixed adapter.'

    $auditFailure = New-TestHarness -Name 'audit-failure' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-950' -Name 'NG-AUDIT-01' -ReservationId 'ngrsv-engine-test-950'
    )
    $auditFailurePlan = New-TestPlanObject -AssetId 'NG-VM-950' -Name 'NG-AUDIT-01' `
        -ReservationId 'ngrsv-engine-test-950' -PlannedAt $auditFailure.ClockState.Now -ChangeSuffix 'AUDIT'
    $auditFailureRegistration = Register-NorthGateVmFactoryEnginePlan -Context $auditFailure.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $auditFailurePlan)
    $auditFailure.Context.AuditWriter = { param($Line) $null = $Line; return $false }
    Assert-EngineThrows -Code 'NGVF-AUDIT-UNAVAILABLE' -Action {
        Invoke-NorthGateVmFactoryEngineApply -Context $auditFailure.Context -AuthenticationContext 'authorized' `
            -PlanId $auditFailureRegistration.planId
    }
    Assert-Engine -Condition ($auditFailure.Context.SimulationInvocationCount -eq 0 -and $auditFailure.ApprovalState.Calls -eq 0) `
        -Message 'Audit failure did not stop before approval and provisioner.'

    $failed = New-TestHarness -Name 'failed' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-960' -Name 'NG-FAIL-01' -ReservationId 'ngrsv-engine-test-960'
    ) -SimulationScenario 'Fail'
    $failedPlan = New-TestPlanObject -AssetId 'NG-VM-960' -Name 'NG-FAIL-01' `
        -ReservationId 'ngrsv-engine-test-960' -PlannedAt $failed.ClockState.Now -ChangeSuffix 'FAILURE'
    $failedRegistration = Register-NorthGateVmFactoryEnginePlan -Context $failed.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $failedPlan)
    $failedReceipt = Invoke-NorthGateVmFactoryEngineApply -Context $failed.Context `
        -AuthenticationContext 'authorized' -PlanId $failedRegistration.planId
    Assert-Engine -Condition ($failedReceipt.outcome -ceq 'Failed' -and $failedReceipt.quarantineState -ceq 'required' -and $failedReceipt.rollbackState -ceq 'not-applicable') `
        -Message 'Partial create failure did not produce quarantine-required state.'
    $failedLedger = & $engineModule { param($Context) Read-NgvfLedger -Context $Context } $failed.Context
    Assert-Engine -Condition (@($failedLedger.entries | Where-Object { $_.state -eq 'Quarantined' }).Count -eq 1) `
        -Message 'Failed create artifacts were not represented as quarantined in the identity ledger.'
    $failedReceiptAgain = Invoke-NorthGateVmFactoryEngineApply -Context $failed.Context `
        -AuthenticationContext 'authorized' -PlanId $failedRegistration.planId
    Assert-Engine -Condition (($failedReceipt | ConvertTo-Json -Depth 20 -Compress) -ceq ($failedReceiptAgain | ConvertTo-Json -Depth 20 -Compress)) `
        -Message 'Failed outcome receipt was not idempotent.'
    Assert-Engine -Condition ($failed.Context.SimulationInvocationCount -eq 1 -and $failed.ApprovalState.Calls -eq 1) `
        -Message 'Failed idempotent retry reran work or consumed another approval.'

    $ledgerCollision = New-TestHarness -Name 'ledger-collision' -LedgerEntries @(
        New-TestLedgerEntry -AssetId 'NG-VM-970' -Name 'NG-LEDCOL-01' -ReservationId 'ngrsv-engine-test-970'
        [pscustomobject][ordered]@{
            assetId = 'NG-VM-971'
            canonicalName = 'NG-LEDCOL-02'
            reservationId = 'ngrsv-engine-test-971'
            vmId = '00000000-0000-0000-0000-000000000970'
            state = 'Bound'
        }
    )
    $ledgerCollisionPlan = New-TestPlanObject -AssetId 'NG-VM-970' -Name 'NG-LEDCOL-01' `
        -ReservationId 'ngrsv-engine-test-970' -PlannedAt $ledgerCollision.ClockState.Now -ChangeSuffix 'LEDGER-COLLISION'
    $ledgerCollisionRegistration = Register-NorthGateVmFactoryEnginePlan -Context $ledgerCollision.Context `
        -AuthenticationContext 'authorized' -CanonicalPlanJson (ConvertTo-TestCanonicalJson -Value $ledgerCollisionPlan)
    $ledgerCollisionReceipt = Invoke-NorthGateVmFactoryEngineApply -Context $ledgerCollision.Context `
        -AuthenticationContext 'authorized' -PlanId $ledgerCollisionRegistration.planId
    Assert-Engine -Condition ($ledgerCollisionReceipt.outcome -ceq 'Failed' -and
        $ledgerCollisionReceipt.reasonCode -ceq 'NGVF-LEDGER-UPDATE-FAILED' -and
        $ledgerCollisionReceipt.quarantineState -ceq 'required') `
        -Message 'A duplicate returned VM identity did not fail into quarantine state.'
    Assert-Engine -Condition ($ledgerCollision.Context.SimulationInvocationCount -eq 1) `
        -Message 'Ledger collision test did not exercise exactly one adapter call.'

    foreach ($unknownScenario in @('Throw', 'Invalid')) {
        $unknownAssetId = if ($unknownScenario -eq 'Throw') { 'NG-VM-980' } else { 'NG-VM-981' }
        $unknownName = if ($unknownScenario -eq 'Throw') { 'NG-UNKNOWN-01' } else { 'NG-UNKNOWN-02' }
        $unknownReservation = if ($unknownScenario -eq 'Throw') { 'ngrsv-engine-test-980' } else { 'ngrsv-engine-test-981' }
        $unknown = New-TestHarness -Name ('unknown-' + $unknownScenario.ToLowerInvariant()) -LedgerEntries @(
            New-TestLedgerEntry -AssetId $unknownAssetId -Name $unknownName -ReservationId $unknownReservation
        ) -SimulationScenario $unknownScenario
        $unknownPlan = New-TestPlanObject -AssetId $unknownAssetId -Name $unknownName `
            -ReservationId $unknownReservation -PlannedAt $unknown.ClockState.Now -ChangeSuffix ('UNKNOWN-' + $unknownScenario.ToUpperInvariant())
        $unknownCanonicalPlan = ConvertTo-TestCanonicalJson -Value $unknownPlan
        $unknownRegistration = Register-NorthGateVmFactoryEnginePlan -Context $unknown.Context `
            -AuthenticationContext 'authorized' -CanonicalPlanJson $unknownCanonicalPlan
        $unknownReceipt = Invoke-NorthGateVmFactoryEngineApply -Context $unknown.Context `
            -AuthenticationContext 'authorized' -PlanId $unknownRegistration.planId
        Assert-Engine -Condition ($unknownReceipt.outcome -ceq 'OutcomeUnknown' -and
            $unknownReceipt.reasonCode -ceq 'NGVF-OUTCOME-UNKNOWN' -and
            $unknownReceipt.afterStateVerified -eq $false -and
            $unknownReceipt.quarantineState -ceq 'required') `
            -Message "Scenario '$unknownScenario' did not enter outcome-unknown reconciliation state."
        $unknownLedger = & $engineModule { param($Context) Read-NgvfLedger -Context $Context } $unknown.Context
        Assert-Engine -Condition (@($unknownLedger.entries | Where-Object { $_.state -eq 'OutcomeUnknown' }).Count -eq 1) `
            -Message "Scenario '$unknownScenario' left its identity reservation reusable."
        Assert-EngineThrows -Code 'NGVF-LEDGER-RESERVATION-INVALID' -Action {
            Register-NorthGateVmFactoryEnginePlan -Context $unknown.Context -AuthenticationContext 'authorized' `
                -CanonicalPlanJson $unknownCanonicalPlan
        }
        $unknownReceiptAgain = Invoke-NorthGateVmFactoryEngineApply -Context $unknown.Context `
            -AuthenticationContext 'authorized' -PlanId $unknownRegistration.planId
        Assert-Engine -Condition (($unknownReceipt | ConvertTo-Json -Depth 20 -Compress) -ceq
            ($unknownReceiptAgain | ConvertTo-Json -Depth 20 -Compress)) `
            -Message "Scenario '$unknownScenario' did not return an idempotent unknown-outcome receipt."
        Assert-Engine -Condition ($unknown.Context.SimulationInvocationCount -eq 1) `
            -Message "Scenario '$unknownScenario' replayed the fixed adapter."
    }

    $noOpPlan = New-TestPlanObject -AssetId 'NG-VM-990' -Name 'NG-NOOP-01' `
        -ReservationId 'ngrsv-engine-test-990' -PlannedAt $main.ClockState.Now -ChangeSuffix 'NOOP'
    $noOpPlan.operations[0].action = 'NoOp'
    $invalidNoOpResult = [pscustomobject][ordered]@{
        status = 'Succeeded'
        afterStateHash = ('3' * 64)
        outcomes = @(
            [pscustomobject][ordered]@{
                assetId = 'NG-VM-990'
                name = 'NG-NOOP-01'
                vmId = '00000000-0000-0000-0000-000000000990'
                outcome = 'NoOp'
            }
        )
    }
    Assert-EngineThrows -Code 'NGVF-PROVISIONER-RESULT-INVALID' -Action {
        $null = & $engineModule {
            param($Result, $Plan)
            Assert-NgvfProvisionerResult -Result $Result -Plan $Plan
        } $invalidNoOpResult $noOpPlan
    }

    $auditText = [System.IO.File]::ReadAllText($main.Context.AuditPath)
    Assert-Engine -Condition ($auditText -notmatch [regex]::Escape($canonicalPlan) -and $auditText -notmatch 'northgate-engine-test') `
        -Message 'Audit log contained canonical plan content or a raw principal identity.'
}
finally {
    Remove-Module -Name 'NorthGate.VMFactory.Engine' -Force -ErrorAction SilentlyContinue
    $fullTestRoot = [System.IO.Path]::GetFullPath($testSessionRoot)
    $temporaryPrefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $env:NGVF_KEEP_TEST_STATE -and
        $fullTestRoot.StartsWith($temporaryPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $fullTestRoot) -like 'northgate-vm-factory-engine-*') {
        Remove-Item -LiteralPath $fullTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "VM Factory engine validation passed: $assertionCount assertions; simulation-only apply, authenticated registry, and idempotent receipts verified."
