[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][string]$HostAuthorizationPath,
    [Parameter(Mandatory)][string]$HostAuthorizationSignaturePath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedHostAuthorizationSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedHostAuthorizationSignerCertificateSha256,
    [Parameter(Mandatory)][string]$MappingPath,
    [Parameter(Mandatory)][string]$OutputRoot,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SignerCertificateSha256,
    [ValidateSet('LocalMachine','CurrentUser')][string]$CertificateStoreLocation='LocalMachine',
    [ValidateRange(300,86400)][int]$LifetimeSeconds=3600,
    [string]$PromotionRecordPath='',
    [string]$ExpectedPromotionRecordSha256='',
    [Parameter(Mandatory)][switch]$ConfirmAuthoring
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyAuthoring.psd1') -Force -ErrorAction Stop
New-NorthGateCreateOnlyBackendPolicyArtifact @PSBoundParameters
