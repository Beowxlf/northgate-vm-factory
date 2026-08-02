Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Ngcs {
    param([Parameter(Mandatory)][string]$Code)
    throw [InvalidOperationException]::new($Code)
}

function Assert-NgcsEmptyBody {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$BodyBytes)
    if ($BodyBytes.Length -ne 0) { Stop-Ngcs 'NGCOR-STDIN-NOT-EMPTY' }
}

function Assert-NgcsSshActor {
    param([string]$ActorSid,[string]$SshIdentitySid)
    if ($ActorSid -cne $SshIdentitySid) { Stop-Ngcs 'NGCOR-SERVICE-ACTOR-NOT-AUTHORIZED' }
}

function Assert-NgcsAdministratorActor {
    param(
        [string]$ActorSid,[bool]$ActorIsAdministrator,[string]$SshIdentitySid,
        [string]$ServiceIdentitySid,[string]$Code='NGCOR-APPROVAL-NATIVE-ADMIN-REQUIRED'
    )
    if (-not $ActorIsAdministrator -or $ActorSid -cnotmatch '^S-1-[0-9-]+$' -or
        $ActorSid -in @('S-1-5-18','S-1-5-19','S-1-5-20',$SshIdentitySid,$ServiceIdentitySid)) {
        Stop-Ngcs $Code
    }
}

function ConvertFrom-NgcsRolloutPromotionWrapper {
    param([byte[]]$BodyBytes,[string]$ActorSid)
    if ($BodyBytes.Length -eq 0 -or $BodyBytes.Length -gt 65536) {
        Stop-Ngcs 'NGCOR-ROLLOUT-ENVELOPE-SIZE-INVALID'
    }
    try {
        $parsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $BodyBytes -MaximumBytes 65536
    }
    catch { Stop-Ngcs 'NGCOR-ROLLOUT-ENVELOPE-NONCANONICAL' }
    $wrapper = $parsed.Value
    $names = @($wrapper.PSObject.Properties.Name | Sort-Object)
    if (($names -join '|') -cne 'detachedCmsSignatureBase64|promotionCanonicalJson' -or
        $wrapper.promotionCanonicalJson -isnot [string] -or
        $wrapper.detachedCmsSignatureBase64 -isnot [string] -or
        ([string]$wrapper.promotionCanonicalJson).Length -gt 32768 -or
        ([string]$wrapper.detachedCmsSignatureBase64).Length -gt 16384) {
        Stop-Ngcs 'NGCOR-ROLLOUT-ENVELOPE-CONTRACT-INVALID'
    }
    $promotionBytes = [Text.Encoding]::UTF8.GetBytes([string]$wrapper.promotionCanonicalJson)
    try {
        $promotion = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
            -Bytes $promotionBytes -MaximumBytes 32768).Value
    }
    catch { Stop-Ngcs 'NGCOR-ROLLOUT-CANONICAL-JSON-INVALID' }
    if ($promotion.approverSid -cne $ActorSid) {
        Stop-Ngcs 'NGCOR-ROLLOUT-ACTOR-BINDING-MISMATCH'
    }
    try { $signatureBytes = [Convert]::FromBase64String([string]$wrapper.detachedCmsSignatureBase64) }
    catch { Stop-Ngcs 'NGCOR-ROLLOUT-CMS-BASE64-INVALID' }
    if ($signatureBytes.Length -eq 0 -or $signatureBytes.Length -gt 12288 -or
        [Convert]::ToBase64String($signatureBytes) -cne [string]$wrapper.detachedCmsSignatureBase64) {
        Stop-Ngcs 'NGCOR-ROLLOUT-CMS-BASE64-INVALID'
    }
    [pscustomobject]@{ PromotionBytes=$promotionBytes; SignatureBytes=$signatureBytes }
}

function ConvertFrom-NgcsApprovalWrapper {
    param([byte[]]$BodyBytes,[string]$PlanId,[string]$ActorSid)
    if ($BodyBytes.Length -eq 0 -or $BodyBytes.Length -gt 65536) {
        Stop-Ngcs 'NGCOR-APPROVAL-ENVELOPE-SIZE-INVALID'
    }
    try {
        $parsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $BodyBytes -MaximumBytes 65536
    }
    catch { Stop-Ngcs 'NGCOR-APPROVAL-ENVELOPE-NONCANONICAL' }
    $wrapper = $parsed.Value
    $names = @($wrapper.PSObject.Properties.Name | Sort-Object)
    if (($names -join '|') -cne 'approvalCanonicalJson|detachedCmsSignatureBase64' -or
        $wrapper.approvalCanonicalJson -isnot [string] -or
        $wrapper.detachedCmsSignatureBase64 -isnot [string] -or
        ([string]$wrapper.approvalCanonicalJson).Length -gt 32768 -or
        ([string]$wrapper.detachedCmsSignatureBase64).Length -gt 16384) {
        Stop-Ngcs 'NGCOR-APPROVAL-ENVELOPE-CONTRACT-INVALID'
    }
    $approvalBytes = [Text.Encoding]::UTF8.GetBytes([string]$wrapper.approvalCanonicalJson)
    try {
        $approval = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $approvalBytes -MaximumBytes 32768).Value
    }
    catch { Stop-Ngcs 'NGCOR-APPROVAL-CANONICAL-JSON-INVALID' }
    if ($approval.planId -cne $PlanId -or $approval.approverSid -cne $ActorSid) {
        Stop-Ngcs 'NGCOR-APPROVAL-ACTOR-BINDING-MISMATCH'
    }
    try { $signatureBytes = [Convert]::FromBase64String([string]$wrapper.detachedCmsSignatureBase64) }
    catch { Stop-Ngcs 'NGCOR-APPROVAL-CMS-BASE64-INVALID' }
    if ($signatureBytes.Length -eq 0 -or $signatureBytes.Length -gt 12288 -or
        [Convert]::ToBase64String($signatureBytes) -cne [string]$wrapper.detachedCmsSignatureBase64) {
        Stop-Ngcs 'NGCOR-APPROVAL-CMS-BASE64-INVALID'
    }
    [pscustomobject]@{ ApprovalBytes=$approvalBytes; SignatureBytes=$signatureBytes }
}

function Invoke-NorthGateCreateOnlyBackendServiceRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][ValidateSet(
            'status','plan','approval-context','approve','rollout-context','promote-rollout','apply','receipt'
        )][string]$Operation,
        [AllowEmptyString()][string]$PlanId = '',
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$BodyBytes,
        [Parameter(Mandatory)][string]$ActorSid,
        [Parameter(Mandatory)][bool]$ActorIsAdministrator,
        [Parameter(Mandatory)][string]$SshIdentitySid,
        [Parameter(Mandatory)][string]$ServiceIdentitySid
    )
    try {
        switch ($Operation) {
            'status' {
                Assert-NgcsSshActor $ActorSid $SshIdentitySid
                Assert-NgcsEmptyBody $BodyBytes
                return Get-NorthGateCreateOnlyBackendState -Context $Context
            }
            'plan' {
                Assert-NgcsSshActor $ActorSid $SshIdentitySid
                return New-NorthGateCreateOnlyHostPlan -Context $Context -PlanRequestBytes $BodyBytes
            }
            'approval-context' {
                Assert-NgcsAdministratorActor $ActorSid $ActorIsAdministrator $SshIdentitySid $ServiceIdentitySid
                Assert-NgcsEmptyBody $BodyBytes
                return Get-NorthGateCreateOnlyHostPlan -Context $Context -PlanId $PlanId
            }
            'approve' {
                Assert-NgcsAdministratorActor $ActorSid $ActorIsAdministrator $SshIdentitySid $ServiceIdentitySid
                $approval = ConvertFrom-NgcsApprovalWrapper $BodyBytes $PlanId $ActorSid
                return Register-NorthGateCreateOnlyApproval -Context $Context `
                    -ApprovalBytes $approval.ApprovalBytes `
                    -DetachedCmsSignatureBytes $approval.SignatureBytes
            }
            'rollout-context' {
                Assert-NgcsAdministratorActor $ActorSid $ActorIsAdministrator `
                    $SshIdentitySid $ServiceIdentitySid 'NGCOR-ROLLOUT-NATIVE-ADMIN-REQUIRED'
                Assert-NgcsEmptyBody $BodyBytes
                return Get-NorthGateCreateOnlyRolloutPromotionContext -Context $Context
            }
            'promote-rollout' {
                Assert-NgcsAdministratorActor $ActorSid $ActorIsAdministrator `
                    $SshIdentitySid $ServiceIdentitySid 'NGCOR-ROLLOUT-NATIVE-ADMIN-REQUIRED'
                $promotion = ConvertFrom-NgcsRolloutPromotionWrapper $BodyBytes $ActorSid
                return Register-NorthGateCreateOnlyRolloutPromotion -Context $Context `
                    -PromotionBytes $promotion.PromotionBytes `
                    -DetachedCmsSignatureBytes $promotion.SignatureBytes
            }
            'apply' {
                Assert-NgcsSshActor $ActorSid $SshIdentitySid
                Assert-NgcsEmptyBody $BodyBytes
                return Invoke-NorthGateCreateOnlyApply -Context $Context -PlanId $PlanId
            }
            'receipt' {
                Assert-NgcsSshActor $ActorSid $SshIdentitySid
                Assert-NgcsEmptyBody $BodyBytes
                return Get-NorthGateCreateOnlyReceipt -Context $Context -PlanId $PlanId
            }
        }
    }
    catch {
        $code = [string]$_.Exception.Message
        if ($code -cmatch '^NGCOR-[A-Z0-9-]{1,96}$') { throw }
        if ($code -cmatch '^NGCB-(?<Suffix>[A-Z0-9-]{1,80})$') {
            Stop-Ngcs ('NGCOR-BACKEND-' + $Matches.Suffix)
        }
        Stop-Ngcs 'NGCOR-SERVICE-BACKEND-FAILURE'
    }
}

Export-ModuleMember -Function 'Invoke-NorthGateCreateOnlyBackendServiceRequest'
