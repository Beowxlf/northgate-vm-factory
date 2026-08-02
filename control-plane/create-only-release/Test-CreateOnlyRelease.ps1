[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Assertions = 0

function Assert-NgcorTest {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Assert-NgcorThrows {
    param([scriptblock]$Action, [string]$Pattern, [string]$Message)
    $script:Assertions++
    try { & $Action; throw "ASSERTION FAILED: $Message (no exception)" }
    catch {
        if ($_.Exception.Message -like 'ASSERTION FAILED:*') { throw }
        if ($_.Exception.Message -cnotmatch $Pattern) {
            throw "ASSERTION FAILED: $Message (got $($_.Exception.Message))"
        }
    }
}

$root = $PSScriptRoot
$parseErrors = New-Object 'System.Collections.Generic.List[string]'
foreach ($file in Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1') }) {
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    foreach ($error in @($errors)) { $parseErrors.Add("$($file.Name): $($error.Message)") }
}
Assert-NgcorTest ($parseErrors.Count -eq 0) ('All PowerShell files parse: ' + ($parseErrors -join '; '))

$release = Import-Module (Join-Path $root 'NorthGate.VMFactory.CreateOnlyRelease.psd1') -Force -PassThru
$protocol = Import-Module (Join-Path $root 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -Force -PassThru

foreach ($command in @('status','plan',('apply ngp-' + ('a' * 64)),('receipt ngp-' + ('0' * 64)))) {
    $parsed = ConvertFrom-NorthGateCreateOnlyCommand $command
    Assert-NgcorTest ($parsed.operation -in @('status','plan','apply','receipt')) "Accepted exact command $command"
}

$badCommands = @(
    '', 'Status', 'PLAN', ' status', 'status ', "status`t", "status`n", "status`0",
    'status;whoami', 'plan extra', 'apply', 'apply  ngp-' + ('a' * 64),
    'apply ngp-' + ('A' * 64), 'apply ngp-' + ('a' * 63),
    'receipt ngp-' + ('a' * 64) + ' x', 'powershell -EncodedCommand AAAA',
    'apply ngp' + [char]0x2010 + ('a' * 64), ('x' * 81)
)
foreach ($command in $badCommands) {
    Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyCommand $command } '^NGCOR-COMMAND-' "Rejected command variant"
}

$request = [pscustomobject][ordered]@{
    apiVersion = 'northgate/v1alpha1'
    kind = 'CreateOnlyPlanRequest'
    assetId = 'NG-VM-018'
    changeId = 'NG-CHG-20260802-CANARY-1'
    repository = [pscustomobject][ordered]@{
        identity = 'Beowxlf/northgate-vm-factory'
        commit = ('a' * 40)
        tree = ('b' * 40)
        signedReleaseSha256 = ('c' * 64)
        hostAllowlistId = 'ngallow-northgate-prod-01'
    }
}
$canonicalRequest = ConvertTo-NorthGateCreateOnlyCanonicalJson $request
$requestBytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalRequest)
$parsedRequest = ConvertFrom-NorthGateCreateOnlyPlanRequestBytes $requestBytes
Assert-NgcorTest ($parsedRequest.Request.assetId -ceq 'NG-VM-018') 'Parsed the fixed asset ID.'
Assert-NgcorTest ($parsedRequest.CanonicalJson -ceq $canonicalRequest) 'Preserved canonical request bytes.'

$bom = [byte[]](0xef,0xbb,0xbf) + $requestBytes
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyPlanRequestBytes $bom } '^NGCOR-PLAN-BOM-FORBIDDEN$' 'Rejected UTF-8 BOM.'
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyPlanRequestBytes ([byte[]](0xc3,0x28)) } '^NGCOR-PLAN-UTF8-INVALID$' 'Rejected invalid UTF-8.'
$duplicate = $canonicalRequest -replace '^\{', '{"apiVersion":"northgate/v1alpha1",'
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyPlanRequestBytes ([Text.Encoding]::UTF8.GetBytes($duplicate)) } '^NGCOR-JSON-DUPLICATE-PROPERTY$' 'Rejected duplicate property.'
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyPlanRequestBytes ([Text.Encoding]::UTF8.GetBytes(" $canonicalRequest")) } '^NGCOR-PLAN-NONCANONICAL$' 'Rejected whitespace-normalized JSON.'
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyPlanRequestBytes ([Text.Encoding]::UTF8.GetBytes($canonicalRequest + '{}')) } '^NGCOR-JSON-TRAILING-CONTENT$' 'Rejected trailing JSON.'
$nullJson = $canonicalRequest.Replace('"assetId":"NG-VM-018"','"assetId":null')
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyPlanRequestBytes ([Text.Encoding]::UTF8.GetBytes($nullJson)) } '^NGCOR-JSON-NULL-FORBIDDEN$' 'Rejected null.'
$floatJson = $canonicalRequest.Replace('"assetId":"NG-VM-018"','"assetId":2.5')
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyPlanRequestBytes ([Text.Encoding]::UTF8.GetBytes($floatJson)) } '^NGCOR-JSON-NONINTEGER-FORBIDDEN$' 'Rejected float.'
$pathJson = $canonicalRequest.Replace('NG-VM-018','C:\\HyperV\\bad')
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyPlanRequestBytes ([Text.Encoding]::UTF8.GetBytes($pathJson)) } '^NGCOR-PLAN-CONTRACT-INVALID$' 'Rejected caller path as asset.'
$requestWithCommand = [pscustomobject][ordered]@{
    apiVersion = $request.apiVersion; kind = $request.kind; assetId = $request.assetId
    changeId = $request.changeId; repository = $request.repository; command = 'New-VM'
}
$extraJson = ConvertTo-NorthGateCreateOnlyCanonicalJson $requestWithCommand
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyPlanRequestBytes ([Text.Encoding]::UTF8.GetBytes($extraJson)) } '^NGCOR-PLAN-PROPERTIES-INVALID$' 'Rejected caller command field.'
$upperCommit = $canonicalRequest.Replace(('a' * 40), ('A' * 40))
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyPlanRequestBytes ([Text.Encoding]::UTF8.GetBytes($upperCommit)) } '^NGCOR-PLAN-CONTRACT-INVALID$' 'Rejected uppercase commit pin.'

$planEnvelope = ConvertTo-NorthGateCreateOnlyCanonicalJson ([pscustomobject][ordered]@{
    version = 1; command = 'plan'; body = $canonicalRequest
})
$parsedEnvelope = ConvertFrom-NorthGateCreateOnlyServiceEnvelopeBytes ([Text.Encoding]::UTF8.GetBytes($planEnvelope))
Assert-NgcorTest ($parsedEnvelope.Operation -ceq 'plan' -and $parsedEnvelope.BodyBytes.Length -eq $requestBytes.Length) 'Revalidated canonical service envelope.'
$badStatusEnvelope = ConvertTo-NorthGateCreateOnlyCanonicalJson ([pscustomobject][ordered]@{
    version = 1; command = 'status'; body = 'x'
})
Assert-NgcorThrows { ConvertFrom-NorthGateCreateOnlyServiceEnvelopeBytes ([Text.Encoding]::UTF8.GetBytes($badStatusEnvelope)) } '^NGCOR-STDIN-NOT-EMPTY$' 'Rejected nonempty status body.'

$catalog = Get-NorthGateCreateOnlyFixedCatalog
Assert-NgcorTest (@($catalog.fleet).Count -eq 12) 'Catalog contains exactly 12 assets.'
Assert-NgcorTest ((@($catalog.fleet.assetId | Sort-Object -Unique).Count) -eq 12) 'All asset IDs are unique.'
Assert-NgcorTest ((@($catalog.fleet.name | Sort-Object -Unique).Count) -eq 12) 'All VM names are unique.'
Assert-NgcorTest (@($catalog.fleet | Where-Object { $_.desired.generation -ne 2 }).Count -eq 0) 'All VMs are Generation 2.'
Assert-NgcorTest (@($catalog.fleet | Where-Object { $_.desired.desiredPowerState -cne 'off' }).Count -eq 0) 'All VMs remain off.'
Assert-NgcorTest (@($catalog.fleet | Where-Object { -not $_.desired.secureBootRequired }).Count -eq 0) 'All VMs require Secure Boot.'
Assert-NgcorTest (@($catalog.fleet | Where-Object { $_.desired.firmwareProfile -ceq 'windows-gen2' -and -not $_.desired.vtpmRequired }).Count -eq 0) 'All Windows VMs require vTPM.'
$catalogJson = ConvertTo-NorthGateCreateOnlyCanonicalJson $catalog
Assert-NgcorTest ($catalogJson -cnotmatch '(?i)[A-Z]:\\|New-VM|Invoke-Expression|"switchName"') 'Catalog has no live path, switch name, or command primitive.'
Assert-NgcorTest ('Start' -in @($catalog.deniedOperations) -and 'Delete' -in @($catalog.deniedOperations)) 'Start and Delete are explicitly denied.'

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-test-' + [guid]::NewGuid().ToString('N'))
$key = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
try {
    $context = & $release { param($Path,$Key) New-NgcorTestContext $Path $Key 'debian-canary' @() $true } $tempRoot $key
    $result = & $release { param($Context,$Request) Register-NgcorSimulationPlan $Context $Request 'S-1-5-21-100-200-300-400' } $context $parsedRequest
    Assert-NgcorTest ($result.accepted -and $result.assetId -ceq 'NG-VM-018' -and $result.action -ceq 'Create') 'Registered one Debian canary plan.'
    Assert-NgcorTest ($result.planId -cmatch '^ngp-[a-f0-9]{64}$' -and $result.planHash -cmatch '^[a-f0-9]{64}$') 'Issued exact plan capability and hash.'
    $ledger = & $release { param($Context) Read-NgcorLedger $Context } $context
    Assert-NgcorTest (@($ledger.reservations).Count -eq 1 -and $ledger.sequence -eq 1) 'Ledger atomically contains one reservation.'
    $hostPlan = $ledger.reservations[0].canonicalPlan | ConvertFrom-Json
    Assert-NgcorTest ($hostPlan.operation.action -ceq 'Create' -and $hostPlan.operation.sequence -eq 1) 'Host plan has exactly one Create operation.'
    Assert-NgcorTest ($hostPlan.observedStateHash -cmatch '^[a-f0-9]{64}$') 'Plan binds normalized observed state.'
    Assert-NgcorThrows {
        & $release { param($Context,$Request) Register-NgcorSimulationPlan $Context $Request 'S-1-5-21-100-200-300-400' } $context $parsedRequest
    } '^NGCOR-CANARY-GATE-BLOCKED$' 'Blocked overlapping canary plan.'

    $held = & $release { param($Name) Enter-NgcorWriterLock $Name } $context.LockName
    try {
        Assert-NgcorThrows {
            & $release { param($Context,$Request) Register-NgcorSimulationPlan $Context $Request 'S-1-5-21-100-200-300-400' } $context $parsedRequest
        } '^NGCOR-WRITER-LOCK-BUSY$' 'Cross-process writer primitive is non-reentrant.'
    }
    finally { & $release { param($Lock) Exit-NgcorWriterLock $Lock } $held }

    $rawLedger = [IO.File]::ReadAllText($context.LedgerPath)
    [IO.File]::WriteAllText($context.LedgerPath, $rawLedger.Replace('NG-VM-018','NG-VM-019'), (New-Object Text.UTF8Encoding($false)))
    Assert-NgcorThrows { & $release { param($Context) Read-NgcorLedger $Context } $context } '^NGCOR-LEDGER-AUTHENTICATION-FAILED$' 'Detected ledger tamper.'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}

$disabledRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-disabled-' + [guid]::NewGuid().ToString('N'))
try {
    $disabled = & $release { param($Path,$Key) New-NgcorTestContext $Path $Key 'disabled' @() $false } $disabledRoot $key
    Assert-NgcorThrows {
        & $release { param($Context,$Request) Register-NgcorSimulationPlan $Context $Request 'S-1-5-21-1-2-3-4' } $disabled $parsedRequest
    } '^NGCOR-POLICY-DISABLED$' 'Initial policy blocks plan registration.'
}
finally { if (Test-Path -LiteralPath $disabledRoot) { Remove-Item -LiteralPath $disabledRoot -Recurse -Force } }

$status = Invoke-NorthGateCreateOnlyServiceRequest -Command status -RequestBytes (New-Object byte[] 0) -ActorSid 'S-1-5-21-1-2-3-4'
Assert-NgcorTest (-not $status.applyEnabled -and @($status.executableActions).Count -eq 0 -and -not $status.productionApplicable) 'Public status is explicitly disabled.'
Assert-NgcorThrows {
    Invoke-NorthGateCreateOnlyServiceRequest -Command plan -RequestBytes $requestBytes -ActorSid 'S-1-5-21-1-2-3-4'
} '^NGCOR-PRODUCTION-PLAN-REGISTRY-DISABLED$' 'Production plan registry fails closed.'
Assert-NgcorThrows {
    Invoke-NorthGateCreateOnlyServiceRequest -Command ('apply ngp-' + ('a' * 64)) -RequestBytes (New-Object byte[] 0) -ActorSid 'S-1-5-21-1-2-3-4'
} '^NGCOR-LIVE-APPLY-NOT-IMPLEMENTED$' 'Production apply fails closed.'
Assert-NgcorThrows {
    Invoke-NorthGateCreateOnlyServiceRequest -Command ('receipt ngp-' + ('a' * 64)) -RequestBytes (New-Object byte[] 0) -ActorSid 'S-1-5-21-1-2-3-4'
} '^NGCOR-RECEIPT-SIGNING-NOT-IMPLEMENTED$' 'Production receipt fails closed.'

$forcedSource = [IO.File]::ReadAllText((Join-Path $root 'Invoke-NorthGateCreateOnlyForcedCommand.ps1'))
$serviceSource = [IO.File]::ReadAllText((Join-Path $root 'Start-NorthGateCreateOnlyPipeService.ps1'))
Assert-NgcorTest ($forcedSource -cnotmatch '(?i)Invoke-Expression|ScriptBlock::Create|EncodedCommand|New-VM|Hyper-V|CreateOnlyRelease\.psd1') 'Forced handler has no privileged module or evaluation primitive.'
Assert-NgcorTest ($forcedSource.IndexOf('ConvertFrom-NorthGateCreateOnlyCommand') -lt $forcedSource.IndexOf('NamedPipeClientStream')) 'Command is parsed before pipe construction.'
Assert-NgcorTest ($forcedSource -match 'Read-NgcorStandardInput 1 2000' -and $forcedSource -match 'NGCOR-STDIN-NOT-EMPTY') 'Non-plan stdin is bounded and required empty.'
Assert-NgcorTest ($forcedSource -match '\$maximumPlanBytes \+ 1' -and $forcedSource -match 'ConvertFrom-NorthGateCreateOnlyPlanRequestBytes') 'Plan stdin is bounded and strictly parsed before forwarding.'
Assert-NgcorTest ($serviceSource -cnotmatch 'S-1-5-2|CreateNewInstance') 'Pipe ACL does not deny NETWORK or grant instance creation.'
Assert-NgcorTest ($serviceSource -match 'ReadAsync' -and $serviceSource -match 'PIPE-READ-TIMEOUT') 'Service frame reads are bounded and asynchronous.'

$runtimeFiles = Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Extension -in @('.ps1','.psm1') }
foreach ($file in $runtimeFiles) {
    $source = [IO.File]::ReadAllText($file.FullName)
    if ($file.Name -notlike 'Test-*') {
        Assert-NgcorTest ($source -cnotmatch '(?m)\b(New-VM|New-VHD|Set-VM|Start-VM|Stop-VM|Remove-VM|Invoke-Command)\b') "$($file.Name) contains no live backend cmdlet."
    }
}

$installer = Join-Path $root 'Install-NorthGateCreateOnlyRelease.ps1'
$dummyRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-install-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($dummyRoot)
$auth = Join-Path $dummyRoot 'authorization.json'
[IO.File]::WriteAllText($auth, '{}', (New-Object Text.UTF8Encoding($false)))
try {
    Assert-NgcorThrows {
        & $installer -PackageRoot $dummyRoot -ExpectedReleaseManifestSha256 ('a' * 64) `
            -ExpectedCommit ('b' * 40) -ExpectedTree ('c' * 40) `
            -ExpectedHostAllowlistId 'ngallow-northgate-prod-01' `
            -SignedHostDeploymentAuthorizationPath $auth `
            -ExpectedDeploymentAuthorizationSha256 ('d' * 64) -ConfirmInstall
    } '^NGCOR-INSTALL-BLOCKED-TRUST-ANCHOR-NOT-BAKED$' 'Installer is non-operative without baked trust anchor.'
    Assert-NgcorTest (@(Get-ChildItem -LiteralPath $dummyRoot -Force).Count -eq 1) 'Blocked installer wrote nothing.'
}
finally { Remove-Item -LiteralPath $dummyRoot -Recurse -Force }

$packageOut = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-package-' + [guid]::NewGuid().ToString('N'))
try {
    $packageResult = & (Join-Path $root 'New-NorthGateCreateOnlyReleasePackage.ps1') `
        -SourceRoot $root -OutputDirectory $packageOut -ReleaseId 'ngcor-0.1.0-test' `
        -Commit ('a' * 40) -Tree ('b' * 40) -HostAllowlistId 'ngallow-northgate-prod-01' `
        -GovernanceExceptionId 'NG-GOV-20260802-TEST'
    Assert-NgcorTest ($packageResult.status -ceq 'package-generated-unsigned' -and -not $packageResult.installable) 'Package declares unsigned, non-installable state.'
    $manifestPath = Join-Path $packageOut 'release-manifest.json'
    $actualManifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-NgcorTest ($actualManifestHash -ceq $packageResult.releaseManifestSha256) 'Package reports the exact manifest hash.'
    $shaLine = [IO.File]::ReadAllText((Join-Path $packageOut 'release-manifest.sha256')).Trim()
    Assert-NgcorTest ($shaLine -ceq ($actualManifestHash + '  release-manifest.json')) 'Sidecar manifest hash is exact.'
    $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    Assert-NgcorTest (-not $manifest.packageSemantics.sourceExecutableOnHost -and
        -not $manifest.packageSemantics.installInitiallyEnabled -and
        -not $manifest.packageSemantics.liveApplyImplemented) 'Manifest preserves disabled package semantics.'
    Assert-NgcorTest (@($manifest.files).Count -eq 12) 'Package includes only the fixed release allowlist.'
    foreach ($entry in @($manifest.files)) {
        $packagedPath = Join-Path $packageOut ([string]$entry.path).Replace('/', '\')
        $actual = (Get-FileHash -LiteralPath $packagedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-NgcorTest ($actual -ceq $entry.sha256 -and (Get-Item -LiteralPath $packagedPath).Length -eq $entry.sizeBytes) "Verified packaged file $($entry.path)."
    }
    $unexpectedSignature = @(Get-ChildItem -LiteralPath $packageOut -File | Where-Object { $_.Extension -in @('.sig','.pfx','.p12','.key','.pem') })
    Assert-NgcorTest ($unexpectedSignature.Count -eq 0) 'Unsigned package contains no key or signature artifact.'
}
finally { if (Test-Path -LiteralPath $packageOut) { Remove-Item -LiteralPath $packageOut -Recurse -Force } }

$denialRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-denial-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($denialRoot)
try {
    Push-Location $denialRoot
    try {
        Assert-NgcorThrows {
            & (Join-Path $root 'New-NorthGateCreateOnlyApproval.ps1') `
                -PlanId ('ngp-' + ('a' * 64)) -PlanHash ('b' * 64) `
                -ApprovalCertificateThumbprint ('C' * 40) -LifetimeSeconds 60 -ConfirmApproval
        } '^NGCOR-APPROVAL-(?:ADMIN-IDENTITY-REQUIRED|BLOCKED-DURABLE-STATE-ANCHOR-NOT-IMPLEMENTED)$' 'Approval writer is non-operative.'
        Assert-NgcorTest (@(Get-ChildItem -LiteralPath $denialRoot -Force).Count -eq 0) 'Denied approval wrote nothing.'
        Assert-NgcorThrows {
            & (Join-Path $root 'Rollback-NorthGateCreateOnlyRelease.ps1') `
                -InstalledReleaseId 'ngcor-0.1.0-test' `
                -InstalledReleaseManifestSha256 ('d' * 64) -BackupReceiptSha256 ('e' * 64) -ConfirmRollback
        } '^NGCOR-ROLLBACK-BLOCKED-NO-PROMOTED-INSTALLER$' 'Rollback is non-operative.'
        Assert-NgcorTest (@(Get-ChildItem -LiteralPath $denialRoot -Force).Count -eq 0) 'Denied rollback wrote nothing.'
    }
    finally { Pop-Location }
}
finally { Remove-Item -LiteralPath $denialRoot -Recurse -Force }

Write-Output "PASS: $script:Assertions assertions"
