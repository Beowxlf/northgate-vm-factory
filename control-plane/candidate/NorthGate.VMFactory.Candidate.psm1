Set-StrictMode -Version Latest

$script:CandidateVersion = '0.1.0'
$script:NotPromotedCode = 'NGVF-CANDIDATE-NOT-PROMOTED'

function New-NorthGateVmFactoryRejection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Operation
    )

    [pscustomobject][ordered]@{
        operation = $Operation
        accepted = $false
        status = 'disabled'
        reasonCode = $script:NotPromotedCode
        candidateVersion = $script:CandidateVersion
    }
}

function Get-NorthGateVmFactoryState {
    [CmdletBinding()]
    param()

    [pscustomobject][ordered]@{
        operation = 'vm_factory_get_state'
        candidateVersion = $script:CandidateVersion
        releaseStatus = 'proposed'
        deployed = $false
        applicationAuthenticationConfigured = $false
        planRegistrationEnabled = $false
        applyEnabled = $false
        executableActions = @()
        writerLockConfigured = $false
        receiptSigningConfigured = $false
        directMutationMethodsExposed = $false
        reasonCode = $script:NotPromotedCode
    }
}

function Register-NorthGateVmFactoryPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$CanonicalPlan
    )

    $null = $CanonicalPlan
    New-NorthGateVmFactoryRejection -Operation 'vm_factory_register_plan'
}

function Get-NorthGateVmFactoryPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$PlanId
    )

    $null = $PlanId
    New-NorthGateVmFactoryRejection -Operation 'vm_factory_get_plan'
}

function Invoke-NorthGateVmFactoryApply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$PlanId
    )

    $null = $PlanId
    New-NorthGateVmFactoryRejection -Operation 'vm_factory_apply_plan'
}

Export-ModuleMember -Function @(
    'Get-NorthGateVmFactoryState',
    'Register-NorthGateVmFactoryPlan',
    'Get-NorthGateVmFactoryPlan',
    'Invoke-NorthGateVmFactoryApply'
)
