[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree,
    [Parameter(Mandatory)][string[]]$SourcePaths,
    [Parameter(Mandatory)][string]$OutputRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SignerCertificateSha256,
    [ValidateSet('LocalMachine','CurrentUser')][string]$CertificateStoreLocation='LocalMachine',
    [ValidateRange(300,86400)][int]$LifetimeSeconds=3600,
    [Parameter(Mandatory)][switch]$ConfirmAuthoring
)
$ErrorActionPreference='Stop'
$releaseRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $releaseRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -Force -ErrorAction Stop
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NorthGate.VMFactory.CreateOnlyBackend.psd1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyAuthoring.psd1') -Force -ErrorAction Stop
New-NorthGateCreateOnlyDataBundle @PSBoundParameters
