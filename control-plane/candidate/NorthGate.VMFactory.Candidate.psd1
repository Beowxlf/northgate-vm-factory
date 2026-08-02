@{
    RootModule = 'NorthGate.VMFactory.Candidate.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'd76ccdf9-9eb2-4a8e-b2ee-8df6462f90e7'
    Author = 'NorthGate'
    CompanyName = 'NorthGate'
    Copyright = '(c) NorthGate. All rights reserved.'
    Description = 'Non-operative VM Factory control-plane interface candidate for local validation only.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-NorthGateVmFactoryState',
        'Register-NorthGateVmFactoryPlan',
        'Get-NorthGateVmFactoryPlan',
        'Invoke-NorthGateVmFactoryApply'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('NorthGate', 'Hyper-V', 'PlanOnly', 'Candidate')
            ProjectUri = 'https://github.com/Beowxlf/northgate-vm-factory'
        }
    }
}
