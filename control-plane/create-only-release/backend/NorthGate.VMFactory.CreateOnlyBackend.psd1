@{
    RootModule = 'NorthGate.VMFactory.CreateOnlyBackend.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'cd43ffac-8e98-41df-a5e5-bd667d93d50c'
    Author = 'NorthGate VM Factory'
    Description = 'Transaction-owned, fail-closed Generation 2 Hyper-V create-only planner and apply backend.'
    PowerShellVersion = '5.1'
    RequiredModules = @()
    FunctionsToExport = @(
        'New-NorthGateCreateOnlyBackendContext',
        'Get-NorthGateCreateOnlyBackendState',
        'New-NorthGateCreateOnlyHostPlan',
        'Get-NorthGateCreateOnlyHostPlan',
        'Get-NorthGateCreateOnlyRolloutPromotionContext',
        'Register-NorthGateCreateOnlyRolloutPromotion',
        'Register-NorthGateCreateOnlyApproval',
        'Invoke-NorthGateCreateOnlyApply',
        'Get-NorthGateCreateOnlyReceipt',
        'Invoke-NorthGateCreateOnlyCrashRecovery'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ Tags = @('NorthGate','HyperV','CreateOnly','Planner','Transaction') } }
}
