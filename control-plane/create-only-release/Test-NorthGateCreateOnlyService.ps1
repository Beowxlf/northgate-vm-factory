[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:Assertions=0
$script:RegisteredApprovalBytes=$null
$script:RegisteredPromotionBytes=$null

function Assert-NgcsTest { param([bool]$Condition,[string]$Message) $script:Assertions++; if(-not $Condition){throw "SERVICE ASSERTION FAILED: $Message"} }
function Assert-NgcsThrows { param([scriptblock]$Action,[string]$Pattern,[string]$Message) $script:Assertions++; try{&$Action;throw "SERVICE ASSERTION FAILED: $Message (no exception)"}catch{if($_.Exception.Message -like 'SERVICE ASSERTION FAILED:*'){throw};if($_.Exception.Message -cnotmatch $Pattern){throw "SERVICE ASSERTION FAILED: $Message (got $($_.Exception.Message))"}} }

function global:Get-NorthGateCreateOnlyBackendState { param($Context) [pscustomobject]@{marker='status'} }
function global:New-NorthGateCreateOnlyHostPlan { param($Context,[byte[]]$PlanRequestBytes) [pscustomobject]@{marker='plan';length=$PlanRequestBytes.Length} }
function global:Get-NorthGateCreateOnlyHostPlan { param($Context,[string]$PlanId) [pscustomobject]@{marker='approval-context';planId=$PlanId} }
function global:Register-NorthGateCreateOnlyApproval { param($Context,[byte[]]$ApprovalBytes,[byte[]]$DetachedCmsSignatureBytes) $script:RegisteredApprovalBytes=$ApprovalBytes;[pscustomobject]@{marker='approved';signatureLength=$DetachedCmsSignatureBytes.Length} }
function global:Get-NorthGateCreateOnlyRolloutPromotionContext { param($Context) [pscustomobject]@{marker='rollout-context'} }
function global:Register-NorthGateCreateOnlyRolloutPromotion { param($Context,[byte[]]$PromotionBytes,[byte[]]$DetachedCmsSignatureBytes) $script:RegisteredPromotionBytes=$PromotionBytes;[pscustomobject]@{marker='rollout-promoted';signatureLength=$DetachedCmsSignatureBytes.Length} }
function global:Invoke-NorthGateCreateOnlyApply { param($Context,[string]$PlanId) [pscustomobject]@{marker='apply';planId=$PlanId} }
function global:Get-NorthGateCreateOnlyReceipt { param($Context,[string]$PlanId) [pscustomobject]@{marker='receipt';planId=$PlanId} }

$root=$PSScriptRoot
$protocol=Import-Module (Join-Path $root 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -Force -PassThru
$service=Import-Module (Join-Path $root 'NorthGate.VMFactory.CreateOnlyService.psd1') -Force -PassThru
$sshSid='S-1-5-21-1-2-3-1001';$serviceSid='S-1-5-80-1-2-3-4-5';$adminSid='S-1-5-21-1-2-3-500'
$planId='ngp-'+('a'*64);$empty=New-Object byte[] 0
try {
    $status=Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) -Operation status `
        -BodyBytes $empty -ActorSid $sshSid -ActorIsAdministrator $false -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid
    Assert-NgcsTest ($status.marker -ceq 'status') 'SSH identity reaches backend status.'
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) -Operation status `
        -BodyBytes $empty -ActorSid $adminSid -ActorIsAdministrator $true -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid } `
        '^NGCOR-SERVICE-ACTOR-NOT-AUTHORIZED$' 'Administrator cannot impersonate the routine SSH actor.'
    $approvalContext=Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation approval-context -PlanId $planId -BodyBytes $empty -ActorSid $adminSid `
        -ActorIsAdministrator $true -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid
    Assert-NgcsTest ($approvalContext.marker -ceq 'approval-context') 'Native administrator obtains exact plan evidence.'

    $approval=[pscustomobject][ordered]@{approverSid=$adminSid;planId=$planId}
    $approvalJson=ConvertTo-NorthGateCreateOnlyCanonicalJson $approval
    $wrapper=[pscustomobject][ordered]@{approvalCanonicalJson=$approvalJson;detachedCmsSignatureBase64=[Convert]::ToBase64String([byte[]](1,2,3))}
    $wrapperBytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $wrapper))
    $registered=Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) -Operation approve `
        -PlanId $planId -BodyBytes $wrapperBytes -ActorSid $adminSid -ActorIsAdministrator $true `
        -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid
    Assert-NgcsTest ($registered.marker -ceq 'approved' -and
        [Text.Encoding]::UTF8.GetString($script:RegisteredApprovalBytes) -ceq $approvalJson) `
        'Approval registration preserves exact canonical approval bytes.'
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) -Operation approve `
        -PlanId $planId -BodyBytes $wrapperBytes -ActorSid $sshSid -ActorIsAdministrator $false `
        -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid } '^NGCOR-APPROVAL-NATIVE-ADMIN-REQUIRED$' `
        'Routine SSH identity cannot register approvals.'
    $wrongApproval=[pscustomobject][ordered]@{approverSid='S-1-5-21-1-2-3-501';planId=$planId}
    $wrongWrapper=[pscustomobject][ordered]@{approvalCanonicalJson=(ConvertTo-NorthGateCreateOnlyCanonicalJson $wrongApproval);detachedCmsSignatureBase64='AQID'}
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) -Operation approve `
        -PlanId $planId -BodyBytes ([Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $wrongWrapper))) `
        -ActorSid $adminSid -ActorIsAdministrator $true -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid } `
        '^NGCOR-APPROVAL-ACTOR-BINDING-MISMATCH$' 'Approval must bind the actual native approving SID.'

    $rolloutContext=Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation rollout-context -BodyBytes $empty -ActorSid $adminSid -ActorIsAdministrator $true `
        -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid
    Assert-NgcsTest ($rolloutContext.marker -ceq 'rollout-context') `
        'Native administrator obtains signed-promotion source evidence.'
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation rollout-context -BodyBytes $empty -ActorSid $sshSid -ActorIsAdministrator $false `
        -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid } `
        '^NGCOR-ROLLOUT-NATIVE-ADMIN-REQUIRED$' 'Routine SSH identity cannot obtain rollout-promotion context.'
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation rollout-context -BodyBytes $empty -ActorSid 'S-1-5-18' -ActorIsAdministrator $true `
        -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid } `
        '^NGCOR-ROLLOUT-NATIVE-ADMIN-REQUIRED$' 'SYSTEM cannot perform rollout-promotion operations.'
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation rollout-context -BodyBytes $empty -ActorSid $serviceSid -ActorIsAdministrator $true `
        -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid } `
        '^NGCOR-ROLLOUT-NATIVE-ADMIN-REQUIRED$' 'Service identity cannot perform rollout-promotion operations.'

    $promotion=[pscustomobject][ordered]@{approverSid=$adminSid;promotionId=('ngrollout-'+('c'*64))}
    $promotionJson=ConvertTo-NorthGateCreateOnlyCanonicalJson $promotion
    $promotionWrapper=[pscustomobject][ordered]@{
        promotionCanonicalJson=$promotionJson
        detachedCmsSignatureBase64=[Convert]::ToBase64String([byte[]](4,5,6))
    }
    $promotionWrapperBytes=[Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-NorthGateCreateOnlyCanonicalJson $promotionWrapper)
    )
    $promoted=Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation promote-rollout -BodyBytes $promotionWrapperBytes -ActorSid $adminSid `
        -ActorIsAdministrator $true -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid
    Assert-NgcsTest ($promoted.marker -ceq 'rollout-promoted' -and
        [Text.Encoding]::UTF8.GetString($script:RegisteredPromotionBytes) -ceq $promotionJson) `
        'Rollout registration preserves exact canonical promotion bytes.'
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation promote-rollout -BodyBytes $promotionWrapperBytes -ActorSid $sshSid `
        -ActorIsAdministrator $false -SshIdentitySid $sshSid -ServiceIdentitySid $serviceSid } `
        '^NGCOR-ROLLOUT-NATIVE-ADMIN-REQUIRED$' 'Routine SSH identity cannot register rollout promotions.'
    $wrongPromotion=[pscustomobject][ordered]@{
        approverSid='S-1-5-21-1-2-3-501';promotionId=('ngrollout-'+('d'*64))
    }
    $wrongPromotionWrapper=[pscustomobject][ordered]@{
        promotionCanonicalJson=(ConvertTo-NorthGateCreateOnlyCanonicalJson $wrongPromotion)
        detachedCmsSignatureBase64='BAUG'
    }
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation promote-rollout `
        -BodyBytes ([Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $wrongPromotionWrapper))) `
        -ActorSid $adminSid -ActorIsAdministrator $true -SshIdentitySid $sshSid `
        -ServiceIdentitySid $serviceSid } '^NGCOR-ROLLOUT-ACTOR-BINDING-MISMATCH$' `
        'Rollout promotion must bind the actual native approving SID.'
    $badPromotionWrapper=[pscustomobject][ordered]@{
        promotionCanonicalJson=$promotionJson;detachedCmsSignatureBase64='not-base64'
    }
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation promote-rollout `
        -BodyBytes ([Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $badPromotionWrapper))) `
        -ActorSid $adminSid -ActorIsAdministrator $true -SshIdentitySid $sshSid `
        -ServiceIdentitySid $serviceSid } '^NGCOR-ROLLOUT-CMS-BASE64-INVALID$' `
        'Malformed rollout detached-signature encoding is rejected.'
    $extraPromotionWrapper=[pscustomobject][ordered]@{
        promotionCanonicalJson=$promotionJson;detachedCmsSignatureBase64='BAUG';extra='forbidden'
    }
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation promote-rollout `
        -BodyBytes ([Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $extraPromotionWrapper))) `
        -ActorSid $adminSid -ActorIsAdministrator $true -SshIdentitySid $sshSid `
        -ServiceIdentitySid $serviceSid } '^NGCOR-ROLLOUT-ENVELOPE-CONTRACT-INVALID$' `
        'Unexpected rollout wrapper properties are rejected.'
    Assert-NgcsThrows { Invoke-NorthGateCreateOnlyBackendServiceRequest -Context ([pscustomobject]@{}) `
        -Operation promote-rollout -BodyBytes ([Text.Encoding]::UTF8.GetBytes(' ' +
            (ConvertTo-NorthGateCreateOnlyCanonicalJson $promotionWrapper))) `
        -ActorSid $adminSid -ActorIsAdministrator $true -SshIdentitySid $sshSid `
        -ServiceIdentitySid $serviceSid } '^NGCOR-ROLLOUT-ENVELOPE-NONCANONICAL$' `
        'Whitespace-normalized rollout wrappers are rejected.'
    Assert-NgcsTest (([IO.File]::ReadAllText((Join-Path $root 'Start-NorthGateCreateOnlyPipeService.ps1')) -notmatch
        'CreateOnlyRelease\.psd1|Invoke-NorthGateCreateOnlyServiceRequest') -and
        ([IO.File]::ReadAllText((Join-Path $root 'Start-NorthGateCreateOnlyPipeService.ps1')) -match
        'New-NorthGateCreateOnlyBackendContext') -and
        ([IO.File]::ReadAllText((Join-Path $root 'Start-NorthGateCreateOnlyPipeService.ps1')) -match
        'Invoke-NorthGateCreateOnlyCrashRecovery -Context \$backendContext')) `
        'Production service initializes, recovers, and dispatches only the new backend.'
    Write-Output "PASS: $script:Assertions service-dispatch assertions"
}
finally {
    Remove-Module $service.Name -Force -ErrorAction SilentlyContinue
    foreach($name in @('Get-NorthGateCreateOnlyBackendState','New-NorthGateCreateOnlyHostPlan','Get-NorthGateCreateOnlyHostPlan','Register-NorthGateCreateOnlyApproval','Get-NorthGateCreateOnlyRolloutPromotionContext','Register-NorthGateCreateOnlyRolloutPromotion','Invoke-NorthGateCreateOnlyApply','Get-NorthGateCreateOnlyReceipt','Invoke-NorthGateCreateOnlyCrashRecovery')){Remove-Item ('Function:\global\'+$name) -Force -ErrorAction SilentlyContinue}
}
