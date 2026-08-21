[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PlanEvidencePath,
    [Parameter(Mandatory)][string]$HostAuthorizationPath,
    [Parameter(Mandatory)][string]$HostAuthorizationSignaturePath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedHostAuthorizationSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedHostAuthorizationSignerCertificateSha256,
    [Parameter(Mandatory)][string]$BackendPolicyPath,
    [Parameter(Mandatory)][string]$BackendPolicySignaturePath,
    [Parameter(Mandatory)][string]$DataBundlePath,
    [Parameter(Mandatory)][string]$DataBundleSignaturePath,
    [Parameter(Mandatory)][string]$ApprovalStateRoot,
    [Parameter(Mandatory)][string]$OutputRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SignerCertificateSha256,
    [ValidateSet('LocalMachine','CurrentUser')][string]$CertificateStoreLocation='LocalMachine',
    [ValidateRange(30,600)][int]$LifetimeSeconds=300,
    [Parameter(Mandatory)][switch]$ConfirmApproval
)
$ErrorActionPreference='Stop'
$releaseRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $releaseRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -Force -ErrorAction Stop
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NorthGate.VMFactory.CreateOnlyBackend.psd1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyAuthoring.psd1') -Force -ErrorAction Stop
New-NorthGateCreateOnlyPlanApprovalArtifact @PSBoundParameters
