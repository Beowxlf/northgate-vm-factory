[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ReleaseSignerCertificateSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$DeploymentAuthorizationSignerCertificateSha256,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][switch]$ConfirmBootstrapBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Stop-Ngcbt { param([string]$Code) throw [InvalidOperationException]::new($Code) }
function Get-NgcbtSha256 { param([byte[]]$Bytes) $a=[Security.Cryptography.SHA256]::Create();try{$h=$a.ComputeHash($Bytes)}finally{$a.Dispose()};(($h|ForEach-Object{$_.ToString('x2')})-join '') }
function Test-NgcbtGitAncestor { param([string]$Path) $d=New-Object IO.DirectoryInfo([IO.Path]::GetFullPath($Path));while($null-ne$d){if(Test-Path -LiteralPath (Join-Path $d.FullName '.git')){return $true};$d=$d.Parent};$false }

if(-not$ConfirmBootstrapBuild){Stop-Ngcbt 'NGCOR-BOOTSTRAP-CONFIRMATION-REQUIRED'}
if($ReleaseSignerCertificateSha256 -ceq ('0'*64) -or
    $DeploymentAuthorizationSignerCertificateSha256 -ceq ('0'*64) -or
    $ReleaseSignerCertificateSha256 -ceq $DeploymentAuthorizationSignerCertificateSha256){
    Stop-Ngcbt 'NGCOR-BOOTSTRAP-TRUST-PINS-INVALID'
}
$output=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
$parent=Split-Path -Parent $output
if([string]::IsNullOrEmpty($parent)-or-not(Test-Path -LiteralPath $parent -PathType Container)){
    Stop-Ngcbt 'NGCOR-BOOTSTRAP-OUTPUT-PARENT-MISSING'
}
if((Test-NgcbtGitAncestor $parent)-or(Test-Path -LiteralPath $output)){
    Stop-Ngcbt 'NGCOR-BOOTSTRAP-OUTPUT-INVALID'
}
$sources=[ordered]@{
    'Install-NorthGateCreateOnlyRelease.ps1'=Join-Path $PSScriptRoot 'Install-NorthGateCreateOnlyRelease.ps1'
    'Rollback-NorthGateCreateOnlyRelease.ps1'=Join-Path $PSScriptRoot 'Rollback-NorthGateCreateOnlyRelease.ps1'
}
$null=[IO.Directory]::CreateDirectory($output)
try{
    $results=@()
    foreach($name in $sources.Keys){
        $source=[IO.File]::ReadAllText($sources[$name])
        if($name -ceq 'Install-NorthGateCreateOnlyRelease.ps1'){
            $releaseNeedle="`$bakedReleaseSignerCertificateSha256 = ''"
            $authorizationNeedle="`$bakedDeploymentAuthorizationSignerCertificateSha256 = ''"
            if(([regex]::Matches($source,[regex]::Escape($releaseNeedle))).Count-ne1-or
               ([regex]::Matches($source,[regex]::Escape($authorizationNeedle))).Count-ne1){
                Stop-Ngcbt 'NGCOR-BOOTSTRAP-SOURCE-ANCHOR-INVALID'
            }
            $rendered=$source.Replace($releaseNeedle,
                "`$bakedReleaseSignerCertificateSha256 = '$ReleaseSignerCertificateSha256'").Replace(
                $authorizationNeedle,
                "`$bakedDeploymentAuthorizationSignerCertificateSha256 = '$DeploymentAuthorizationSignerCertificateSha256'")
        }else{
            $authorizationNeedle="`$bakedDeploymentAuthorizationSignerCertificateSha256 = ''"
            if(([regex]::Matches($source,[regex]::Escape($authorizationNeedle))).Count-ne1){
                Stop-Ngcbt 'NGCOR-BOOTSTRAP-SOURCE-ANCHOR-INVALID'
            }
            $rendered=$source.Replace($authorizationNeedle,
                "`$bakedDeploymentAuthorizationSignerCertificateSha256 = '$DeploymentAuthorizationSignerCertificateSha256'")
        }
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes($rendered)
        $destination=Join-Path $output $name
        $stream=New-Object IO.FileStream($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        $readback=[IO.File]::ReadAllBytes($destination)
        if((Get-NgcbtSha256 $readback)-cne(Get-NgcbtSha256 $bytes)){Stop-Ngcbt 'NGCOR-BOOTSTRAP-READBACK-FAILED'}
        $results+=[pscustomobject][ordered]@{path=$destination;sha256=(Get-NgcbtSha256 $bytes);sizeBytes=[int64]$bytes.Length}
    }
    [pscustomobject][ordered]@{
        status='review-required-bootstrap-built';outputDirectory=$output
        releaseSignerCertificateSha256=$ReleaseSignerCertificateSha256
        deploymentAuthorizationSignerCertificateSha256=$DeploymentAuthorizationSignerCertificateSha256
        files=[object[]]$results;installable=$false
        nextGate='native-review-hash-approval-and-pinned-ssh-transfer-readback'
    }
}catch{throw}
