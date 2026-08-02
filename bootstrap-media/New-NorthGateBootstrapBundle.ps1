[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RequestPath,
    [Parameter(Mandatory)][string]$AuthorizedPublicKeyPath,
    [Parameter(Mandatory)][string]$OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'NorthGate.BootstrapMedia.psd1') -Force
New-NorthGateBootstrapBundle -RequestPath $RequestPath -AuthorizedPublicKeyPath $AuthorizedPublicKeyPath -OutputDirectory $OutputDirectory
