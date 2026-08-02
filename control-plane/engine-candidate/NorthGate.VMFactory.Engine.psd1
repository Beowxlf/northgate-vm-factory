@{
    RootModule = 'NorthGate.VMFactory.Engine.psm1'
    ModuleVersion = '0.2.0'
    GUID = '83ddf46a-5f42-4ee2-92c7-90881481c570'
    Author = 'NorthGate'
    CompanyName = 'NorthGate'
    Copyright = '(c) NorthGate. All rights reserved.'
    Description = 'Undeployed simulation-only VM Factory authorization and state-engine scaffold.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-NorthGateVmFactoryEngineState',
        'Register-NorthGateVmFactoryEnginePlan',
        'Get-NorthGateVmFactoryEnginePlan',
        'Invoke-NorthGateVmFactoryEngineApply'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('NorthGate', 'PlanOnly', 'Simulation', 'ControlPlane')
            ProjectUri = 'https://github.com/Beowxlf/northgate-vm-factory'
        }
    }
}
