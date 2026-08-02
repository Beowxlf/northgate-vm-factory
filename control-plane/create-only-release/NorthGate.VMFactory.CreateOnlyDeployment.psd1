@{
    RootModule = 'NorthGate.VMFactory.CreateOnlyDeployment.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'df690c23-fd51-4d52-96c3-0b0f1527c93a'
    Author = 'NorthGate Lab'
    CompanyName = 'NorthGate'
    Copyright = '(c) NorthGate Lab. All rights reserved.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-NorthGateCreateOnlyInstallTransaction',
        'Invoke-NorthGateCreateOnlyRollbackTransaction',
        'Test-NorthGateCreateOnlyInstalledRelease'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
