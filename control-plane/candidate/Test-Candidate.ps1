[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$candidateRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $candidateRoot 'NorthGate.VMFactory.Candidate.psd1'
$moduleSourcePath = Join-Path $candidateRoot 'NorthGate.VMFactory.Candidate.psm1'
$assertionCount = 0

function Assert-Candidate {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
    $script:assertionCount++
}

Import-Module -Name $modulePath -Force

$expectedCommands = @(
    'Get-NorthGateVmFactoryPlan',
    'Get-NorthGateVmFactoryState',
    'Invoke-NorthGateVmFactoryApply',
    'Register-NorthGateVmFactoryPlan'
)
$actualCommands = @(
    Get-Command -Module 'NorthGate.VMFactory.Candidate' |
        Select-Object -ExpandProperty Name |
        Sort-Object
)
Assert-Candidate -Condition (($actualCommands -join '|') -ceq ($expectedCommands -join '|')) `
    -Message 'The candidate exports an unexpected operation.'

$state = Get-NorthGateVmFactoryState
Assert-Candidate -Condition ($state.releaseStatus -ceq 'proposed') `
    -Message 'Candidate release status must remain proposed.'
Assert-Candidate -Condition ($state.deployed -eq $false -and $state.applyEnabled -eq $false -and $state.planRegistrationEnabled -eq $false) `
    -Message 'Candidate deployment, apply, and plan registration must remain disabled.'
Assert-Candidate -Condition (@($state.executableActions).Count -eq 0) `
    -Message 'Candidate must expose no executable actions.'
Assert-Candidate -Condition ($state.applicationAuthenticationConfigured -eq $false -and $state.writerLockConfigured -eq $false -and $state.receiptSigningConfigured -eq $false) `
    -Message 'Unimplemented security dependencies must not be claimed as configured.'
Assert-Candidate -Condition ($state.directMutationMethodsExposed -eq $false) `
    -Message 'Candidate must not expose direct mutation methods.'

$opaqueMarker = 'opaque-input-must-not-be-reflected'
$responses = @(
    Register-NorthGateVmFactoryPlan -CanonicalPlan ([pscustomobject]@{ opaque = $opaqueMarker })
    Get-NorthGateVmFactoryPlan -PlanId $opaqueMarker
    Invoke-NorthGateVmFactoryApply -PlanId $opaqueMarker
)
foreach ($response in $responses) {
    $serialized = $response | ConvertTo-Json -Compress
    Assert-Candidate -Condition ($response.accepted -eq $false -and $response.status -ceq 'disabled') `
        -Message 'Candidate operation did not reject while disabled.'
    Assert-Candidate -Condition ($response.reasonCode -ceq 'NGVF-CANDIDATE-NOT-PROMOTED') `
        -Message 'Candidate operation returned an unexpected reason code.'
    Assert-Candidate -Condition ($serialized -notmatch [regex]::Escape($opaqueMarker)) `
        -Message 'Candidate reflected untrusted input in its response.'
}

$applyCommand = Get-Command Invoke-NorthGateVmFactoryApply
$declaredRiskyParameters = @('Command', 'Script', 'ScriptBlock', 'Path', 'Payload', 'Operation')
Assert-Candidate -Condition ($applyCommand.Parameters.ContainsKey('PlanId')) `
    -Message 'Apply candidate must accept a plan ID.'
foreach ($parameterName in $declaredRiskyParameters) {
    Assert-Candidate -Condition (-not $applyCommand.Parameters.ContainsKey($parameterName)) `
        -Message "Apply candidate exposes forbidden parameter '$parameterName'."
}

$moduleSource = [System.IO.File]::ReadAllText($moduleSourcePath)
$forbiddenSourcePatterns = @(
    '(?i)\b(?:New|Set|Remove|Start|Stop|Checkpoint|Restore|Rename)-VM\b',
    '(?i)\bImport-Module\s+Hyper-V\b',
    '(?i)\bInvoke-Expression\b',
    '(?i)\bStart-Process\b',
    '(?i)\b(?:Set|Add|Out)-Content\b',
    '(?i)\bRemove-Item\b',
    '(?i)\bInvoke-(?:WebRequest|RestMethod)\b',
    '(?i)\b(?:ssh|scp|sftp)(?:\.exe)?\b'
)
foreach ($pattern in $forbiddenSourcePatterns) {
    Assert-Candidate -Condition ($moduleSource -notmatch $pattern) `
        -Message "Candidate module contains a prohibited live-mutation primitive matching '$pattern'."
}

Remove-Module -Name 'NorthGate.VMFactory.Candidate' -Force
Write-Host "Control-plane candidate validation passed: $assertionCount assertions; registration and apply disabled."
