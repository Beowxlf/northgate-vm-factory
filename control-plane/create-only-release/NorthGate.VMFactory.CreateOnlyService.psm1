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
            'status','plan','approval-context','approve','rollout-context','promote-rollout','apply','receipt',
            'reconcile-receipt'
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
            'reconcile-receipt' {
                Assert-NgcsSshActor $ActorSid $SshIdentitySid
                Assert-NgcsEmptyBody $BodyBytes
                return Invoke-NorthGateCreateOnlyReceiptReconciliation -Context $Context -PlanId $PlanId
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

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBsuvXQGSBxG+66
# Gwh1WU8WIyIJymwEsqdrvmMzr0bEHqCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
# sEhN7njmUsaSMA0GCSqGSIb3DQEBCwUAMDwxOjA4BgNVBAMMMU5vcnRoR2F0ZSBW
# TSBGYWN0b3J5IFJlbGVhc2UgU2lnbmVyIDIwMjYtMDgtMjEgdjIwHhcNMjYwODIx
# MDI0ODM5WhcNMjgwODIxMDc1ODM5WjA8MTowOAYDVQQDDDFOb3J0aEdhdGUgVk0g
# RmFjdG9yeSBSZWxlYXNlIFNpZ25lciAyMDI2LTA4LTIxIHYyMIIBojANBgkqhkiG
# 9w0BAQEFAAOCAY8AMIIBigKCAYEAuK2RPh+kwyLvYhpQmiHvsROwEKzmIdyEc6WV
# b1N80dzFqV4o16F7MTsoC1Xbo3VdbDurlCWifItnM+UTZ7B6xP8TLmPGRys7sGa/
# QQOm77wKKQ7OdjJlqSSXz4+efiUwoMEkhyP3YkL8G7VvS7EcKCVaspPX8ghvtCYe
# rOQQYWVFOV9EuvajfvnFPna0Y4Y4qMJAxZZEtfMVKtLejdftGHra9pZm/Vi3OiIx
# At/lfqeqK1vYu96Uyh4LhSoxSaev2EOpsznHtTIwY3KNC9dpwlogX2FYa0l1zH1k
# Kk0n/AjTYgR0mxQXMP89640xScVCb+rmY8SNG5w/YZB9uQnkTY5Zkh8z5dfHH8HM
# Fvibww5+B8nEBiMe/1RrUzpf1qOyuwyCphrAMRl2NbWR/yzdjCvUBaLbbmkVW20f
# U3X2CTd144vt2iLfCco+WEIuXaRy6g1vQxu1bYtOHuO5GwobWUCN4CVvhILf+VVt
# hPvyDnvdRZEyaJ2wmI3xWE0+QJY9AgMBAAGjVzBVMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRb
# WaTBPZZW7QhHiKCc/W2Z3DB9oTANBgkqhkiG9w0BAQsFAAOCAYEAaNP8lBhUC94L
# AUcORggLbH+yuwZ92dK4vhUVrqukaQKL0CpTouv88GOJtrocGo09vyZ1Y7T+ieZ2
# SKKMwmM+efwt+cDQ0b4HDIWYfswSQdfd/HATQX5PNSmC6uEYi6cf/yd31aHkySrN
# W2gfy82zjixp/SP/k9KmpbE+I5f8wppCZ4+ePk5/g+f7gb7a9+g66Ywua2apF76N
# gQB0LPaz0SXwWZ4QS4w/X4TUSDnluz9uHzX2NZ4oNAzT1tR7tBF7Ntu+8mEw2mot
# BcI7pQEu6CDLNGl1rSwPswnZDUWOcnImdqW3IDab4XUmN5my5pB3iLmojG2UOVXr
# SWVYZkiHWI5RGHNDBmdnbDXxK2Xy4uJMLiVEqws8QosKSTUTSAL5B3KM1/HWwQzv
# X2fiwRK2cIfTIJ34Dtlp0lewhzvauoSuVZkYxQ/43QfYxed20zWo44UnRTrScDdC
# 9UmREbQDcZjjpb04T4zAXLHmS9e0k1IwA7vXMRcs4x7Uiq5diaQdMYICgjCCAn4C
# AQEwUDA8MTowOAYDVQQDDDFOb3J0aEdhdGUgVk0gRmFjdG9yeSBSZWxlYXNlIFNp
# Z25lciAyMDI2LTA4LTIxIHYyAhAvazDvs9z4sEhN7njmUsaSMA0GCWCGSAFlAwQC
# AQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwG
# CisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZI
# hvcNAQkEMSIEICLwn/t9ZXqY7TqJUYSSeWAIp7fazrJRooSqMzsiDkSRMA0GCSqG
# SIb3DQEBAQUABIIBgJCx0kvaQmxckUrqZPefoo1y4VASwlSGC8aJ0fPve/1P15cW
# cXAGk522SmG3LRNcMV+2S25ckC3LivgOa4qsl7ctsr8y4GB937CrkUXceZxF780m
# ETWaCG6aAyyv/RJIOCOU5P6DKTe9aJbnkL+fDsQyCiy15UXa+PbqkSxk3vnm64kZ
# 0sCKwVF8xR4AttyV9ytoFMd+cRI+KxJDtQVlYijM3m7lZkZkoXi+KajO5t92b0I/
# z5OHkJUc+a1a3ADh7fqCNE2A82bLFBZDZG9hNwVIiGqYwryjTOeZ8qA645rWc9r3
# BRZjay0qbZuB1HgwPhfyVrY79zYEJI+EwNtPsu8dkOoChL/DyAKAy8HOAatWz7V/
# aOwq201SMOzwUBOKjmxb/ev9wVaF04tiwEhyEa8qGrQuVLnq1WJrF3ZMBAQUPIVm
# KWI58ZX+5IA6GkIEzZxby12QUJUODeQGEsQ9ml6yZNOfkusswK7L3VrXm1GH59fV
# K4HCH/HKASBvwgGUOg==
# SIG # End signature block
