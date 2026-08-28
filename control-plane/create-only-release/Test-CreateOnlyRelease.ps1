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

function ConvertFrom-NgcorTestJsonText {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)
    $converter = Microsoft.PowerShell.Core\Get-Command `
        -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json -DateKind String
    }
    return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json
}

function Invoke-NgcorTestGit {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    $output = @(& git.exe -C $RepositoryRoot @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = (@($output | ForEach-Object { [string]$_ }) -join "`n").TrimEnd("`r", "`n")
    if ($exitCode -ne 0) {
        throw "TEST-GIT-COMMAND-FAILED: git $($Arguments -join ' '): $text"
    }
    $text
}

function Write-NgcorTestCanonicalJsonFile {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )
    $json = ConvertTo-NorthGateCreateOnlyCanonicalJson $Value
    [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
}

function Copy-NgcorTestObject {
    param([Parameter(Mandatory)][object]$Value)
    ConvertFrom-NgcorTestJsonText (ConvertTo-NorthGateCreateOnlyCanonicalJson $Value)
}

function New-NgcorTestCodeSigningCertificate {
    $rsa = [Security.Cryptography.RSA]::Create(3072)
    $request = New-Object Security.Cryptography.X509Certificates.CertificateRequest(
        'CN=NorthGate Create-Only Test Signer', $rsa,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $request.CertificateExtensions.Add((New-Object `
        Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($false,$false,0,$true)))
    $request.CertificateExtensions.Add((New-Object `
        Security.Cryptography.X509Certificates.X509KeyUsageExtension(
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,$true
        )))
    $oids = New-Object Security.Cryptography.OidCollection
    $null = $oids.Add((New-Object Security.Cryptography.Oid('1.3.6.1.5.5.7.3.3','Code Signing')))
    $request.CertificateExtensions.Add((New-Object `
        Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oids,$true)))
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(2)
    )
    [pscustomobject]@{ Certificate = $certificate; Key = $rsa }
}

function New-NgcorTestDetachedCmsBytes {
    param([byte[]]$ContentBytes, [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    $content = New-Object Security.Cryptography.Pkcs.ContentInfo(,$ContentBytes)
    $cms = New-Object Security.Cryptography.Pkcs.SignedCms($content,$true)
    $signer = New-Object Security.Cryptography.Pkcs.CmsSigner($Certificate)
    $signer.DigestAlgorithm = New-Object Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1','SHA256')
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cms.ComputeSignature($signer,$true)
    $cms.Encode()
}

function Get-NgcorTestCertificateSha256 {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Certificate.RawData) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
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
$deployment = Import-Module (Join-Path $root 'NorthGate.VMFactory.CreateOnlyDeployment.psd1') -Force -PassThru
$canonicalProbe = [Text.Encoding]::UTF8.GetBytes('{"probe":"module-scope"}')
$canonicalParsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $canonicalProbe -MaximumBytes 1024
Assert-NgcorTest ($canonicalParsed.Value.probe -ceq 'module-scope') `
    'Nested dependency imports preserve the caller-visible protocol commands under Windows PowerShell.'
$bundleLimitParsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
    -Bytes $canonicalProbe -MaximumBytes 10485760
Assert-NgcorTest ($bundleLimitParsed.Value.probe -ceq 'module-scope') `
    'Canonical parser accepts the explicit ten-MiB artifact ceiling used for signed data bundles.'

foreach ($command in @('status','plan','rollout-context','promote-rollout',
        ('approval-context ngp-' + ('a' * 64)),('approve ngp-' + ('b' * 64)),
        ('apply ngp-' + ('a' * 64)),('receipt ngp-' + ('0' * 64)))) {
    $parsed = ConvertFrom-NorthGateCreateOnlyCommand $command
    Assert-NgcorTest ($parsed.operation -in @(
            'status','plan','rollout-context','promote-rollout',
            'approval-context','approve','apply','receipt'
        )) `
        "Accepted exact command $command"
}

$badCommands = @(
    '', 'Status', 'PLAN', ' status', 'status ', "status`t", "status`n", "status`0",
    'status;whoami', 'plan extra', 'rollout-context extra', 'Promote-rollout',
    'promote-rollout extra', 'apply', 'apply  ngp-' + ('a' * 64),
    'apply ngp-' + ('A' * 64), 'apply ngp-' + ('a' * 63),
    'receipt ngp-' + ('a' * 64) + ' x', 'powershell -EncodedCommand AAAA',
    'apply ngp' + [char]0x2010 + ('a' * 64), ('x' * 97)
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
$emptyArrayCanonical = ConvertTo-NorthGateCreateOnlyCanonicalJson ([pscustomobject][ordered]@{
    executableActions = [object[]]@()
})
Assert-NgcorTest ($emptyArrayCanonical -ceq '{"executableActions":[]}') `
    'Canonical serializer preserves an explicit empty array on Windows PowerShell 5.1.'

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
$promotionEnvelopeBody = ConvertTo-NorthGateCreateOnlyCanonicalJson ([pscustomobject][ordered]@{
    detachedCmsSignatureBase64='AQID';promotionCanonicalJson='{}'
})
$promotionEnvelope = ConvertTo-NorthGateCreateOnlyCanonicalJson ([pscustomobject][ordered]@{
    version=1;command='promote-rollout';body=$promotionEnvelopeBody
})
$parsedPromotionEnvelope = ConvertFrom-NorthGateCreateOnlyServiceEnvelopeBytes `
    ([Text.Encoding]::UTF8.GetBytes($promotionEnvelope))
Assert-NgcorTest ($parsedPromotionEnvelope.Operation -ceq 'promote-rollout' -and
    [Text.Encoding]::UTF8.GetString($parsedPromotionEnvelope.BodyBytes) -ceq $promotionEnvelopeBody) `
    'Preserved the canonical native-admin rollout-promotion wrapper.'
$rolloutContextEnvelope = ConvertTo-NorthGateCreateOnlyCanonicalJson ([pscustomobject][ordered]@{
    version=1;command='rollout-context';body=''
})
$parsedRolloutContextEnvelope = ConvertFrom-NorthGateCreateOnlyServiceEnvelopeBytes `
    ([Text.Encoding]::UTF8.GetBytes($rolloutContextEnvelope))
Assert-NgcorTest ($parsedRolloutContextEnvelope.Operation -ceq 'rollout-context' -and
    $parsedRolloutContextEnvelope.BodyBytes.Length -eq 0) `
    'Accepted an empty rollout-context request for service-side administrator authorization.'
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
    $hostPlan = ConvertFrom-NgcorTestJsonText ([string]$ledger.reservations[0].canonicalPlan)
    Assert-NgcorTest ($hostPlan.issuedAtUtc -is [string] -and $hostPlan.expiresAtUtc -is [string]) `
        'ISO-8601 plan timestamps remain strings across supported PowerShell versions.'
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
    [IO.File]::WriteAllText($context.LedgerPath, $rawLedger.Replace('NG-VM-018','NG-VM-014'), (New-Object Text.UTF8Encoding($false)))
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
$serviceHostSource = [IO.File]::ReadAllText((Join-Path $root 'NorthGate.CreateOnly.ServiceHost.cs'))
Assert-NgcorTest ($forcedSource -cnotmatch '(?i)Invoke-Expression|ScriptBlock::Create|EncodedCommand|New-VM|Hyper-V|CreateOnlyRelease\.psd1') 'Forced handler has no privileged module or evaluation primitive.'
Assert-NgcorTest ($forcedSource.IndexOf('ConvertFrom-NorthGateCreateOnlyCommand $originalCommand') -lt
    $forcedSource.IndexOf('New-Object System.IO.Pipes.NamedPipeClientStream')) `
    'Command is parsed before pipe construction.'
Assert-NgcorTest ($serviceHostSource -match 'GetNamedPipeServerProcessId' -and
    $serviceHostSource -match 'OpenSCManager' -and $serviceHostSource -match 'OpenService' -and
    $serviceHostSource -match 'QueryServiceStatusEx' -and
    $forcedSource -match 'NGCOR-PIPE-SERVER-PROCESS-MISMATCH' -and
    $serviceHostSource -notmatch 'OpenProcess|QueryFullProcessImageName' -and
    $forcedSource -notmatch 'Add-Type\s+-TypeDefinition') `
    'Signed least-privilege server authentication binds the pipe PID to the running registered service PID.'
Assert-NgcorTest ($forcedSource -match "installed\.serviceName -cne 'NorthGateCreateOnly'" -and
    $serviceSource -match "installed\.serviceName -cne 'NorthGateCreateOnly'" -and
    $forcedSource -match "serviceArguments\[0\] = \[string\]\`$Installed\.serviceName") `
    'Forced command refuses missing or altered installed service-name evidence before SCM verification.'
Assert-NgcorTest ($forcedSource -match 'Read-NgcorStandardInput 1 2000' -and $forcedSource -match 'NGCOR-STDIN-NOT-EMPTY') 'Non-plan stdin is bounded and required empty.'
Assert-NgcorTest ($forcedSource -match 'function Read-NgcorStandardInput[\s\S]{0,1800}\$bytes = \$memory\.ToArray\(\)[\s\S]{0,80}return ,\$bytes') `
    'Empty standard input is preserved as a scalar byte array across the PowerShell function boundary.'
Assert-NgcorTest ($forcedSource -match '\$maximumPlanBytes \+ 1' -and $forcedSource -match 'ConvertFrom-NorthGateCreateOnlyPlanRequestBytes') 'Plan stdin is bounded and strictly parsed before forwarding.'
Assert-NgcorTest ($forcedSource -match 'function Get-NgcorForcedSafeErrorCode' -and
    $forcedSource -match '\\bNGCOR-\[A-Z0-9-\]\{1,96\}\\b' -and
    $forcedSource -match 'RegexOptions\]::CultureInvariant' -and
    $forcedSource -match 'Get-NgcorForcedSafeErrorCode \$_\.Exception') `
    'Wrapped failures preserve only a bounded NorthGate code and otherwise fail closed generically.'
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
$installerSource = [IO.File]::ReadAllText($installer)
Assert-NgcorTest ($installerSource -match 'Win32_ComputerSystemProduct' -and $installerSource -match '\$hostSystem\[0\]\.UUID' -and $installerSource -notmatch 'Msvm_ComputerSystem') 'Installer binds the supported host to the same SMBIOS UUID used by the backend.'
Assert-NgcorTest ($installerSource -match 'function Read-NgciExclusiveBytes[\s\S]{0,1800}return ,\$bytes') `
    'Installer preserves exclusive file reads as byte arrays across the PowerShell function boundary.'
$dummyRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-install-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($dummyRoot)
$auth = Join-Path $dummyRoot 'authorization.json'
[IO.File]::WriteAllText($auth, '{}', (New-Object Text.UTF8Encoding($false)))
try {
    Assert-NgcorThrows {
        & $installer -PackageRoot $dummyRoot -ExpectedReleaseManifestSha256 ('a' * 64) `
            -ExpectedCommit ('b' * 40) -ExpectedTree ('c' * 40) `
            -ExpectedHostAllowlistId 'ngallow-northgate-prod-01' `
            -ReleaseManifestSignaturePath $auth `
            -SignedHostDeploymentAuthorizationPath $auth `
            -DeploymentAuthorizationSignaturePath $auth `
            -ExpectedDeploymentAuthorizationSha256 ('d' * 64) `
            -BackendPolicyPath $auth -BackendPolicySignaturePath $auth `
            -ExpectedBackendPolicySha256 ('e' * 64) -DataBundleRoot $dummyRoot `
            -ExpectedDataBundleSha256 ('f' * 64) -ConfirmInstall
    } '^NGCOR-INSTALL-BLOCKED-TRUST-ANCHOR-NOT-BAKED$' 'Installer is non-operative without baked trust anchor.'
    Assert-NgcorTest (@(Get-ChildItem -LiteralPath $dummyRoot -Force).Count -eq 1) 'Blocked installer wrote nothing.'
}
finally { Remove-Item -LiteralPath $dummyRoot -Recurse -Force }

$bootstrapRoot=Join-Path ([IO.Path]::GetTempPath()) ('ngcor-bootstrap-test-'+[guid]::NewGuid().ToString('N'))
try {
    $bootstrap=& (Join-Path $root 'New-NorthGateCreateOnlyBootstrap.ps1') `
        -ReleaseSignerCertificateSha256 ('1'*64) `
        -DeploymentAuthorizationSignerCertificateSha256 ('2'*64) `
        -OutputDirectory $bootstrapRoot -ConfirmBootstrapBuild
    Assert-NgcorTest ($bootstrap.status -ceq 'review-required-bootstrap-built' -and
        -not $bootstrap.installable -and @($bootstrap.files).Count -eq 2) `
        'Bootstrap builder emits only review-required installer and rollback artifacts.'
    foreach($file in @($bootstrap.files)){
        Assert-NgcorTest ((Get-FileHash -LiteralPath $file.path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
            $file.sha256) 'Bootstrap builder reports exact readback hash.'
        $tokens=$null;$errors=$null
        $null=[Management.Automation.Language.Parser]::ParseFile($file.path,[ref]$tokens,[ref]$errors)
        Assert-NgcorTest (@($errors).Count -eq 0) 'Generated bootstrap artifact parses under Windows PowerShell.'
    }
    Assert-NgcorTest (([IO.File]::ReadAllText((Join-Path $bootstrapRoot 'Install-NorthGateCreateOnlyRelease.ps1')) -match
        ("bakedReleaseSignerCertificateSha256 = '"+('1'*64)+"'")) -and
        ([IO.File]::ReadAllText((Join-Path $bootstrapRoot 'Rollback-NorthGateCreateOnlyRelease.ps1')) -match
        ("bakedDeploymentAuthorizationSignerCertificateSha256 = '"+('2'*64)+"'"))) `
        'Bootstrap artifacts bake only the two approved public certificate pins.'
}
finally { if(Test-Path -LiteralPath $bootstrapRoot){Remove-Item -LiteralPath $bootstrapRoot -Recurse -Force} }

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-git-fixture-' + [guid]::NewGuid().ToString('N'))
$authorizationRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-authorization-' + [guid]::NewGuid().ToString('N'))
$packageArtifactRoots = New-Object 'System.Collections.Generic.List[string]'
$testSigner = $null
$gitEnvironmentSnapshot = [ordered]@{}
$gitEnvironmentNames = @(
    [Environment]::GetEnvironmentVariables().Keys |
        ForEach-Object { [string]$_ } |
        Where-Object { $_ -like 'GIT_*' }
)
foreach ($name in $gitEnvironmentNames) {
    $gitEnvironmentSnapshot[$name] = [Environment]::GetEnvironmentVariable($name)
    [Environment]::SetEnvironmentVariable($name, $null, [EnvironmentVariableTarget]::Process)
}
try {
    $fixtureSourceRoot = Join-Path $fixtureRoot 'control-plane\create-only-release'
    $null = [IO.Directory]::CreateDirectory($fixtureSourceRoot)
    $null = [IO.Directory]::CreateDirectory($authorizationRoot)
    foreach ($sourceFile in Get-ChildItem -LiteralPath $root -File) {
        [IO.File]::WriteAllBytes(
            (Join-Path $fixtureSourceRoot $sourceFile.Name),
            [IO.File]::ReadAllBytes($sourceFile.FullName)
        )
    }
    foreach ($sourceFile in Get-ChildItem -LiteralPath (Join-Path $root 'backend') -Recurse -File) {
        $relativePath = $sourceFile.FullName.Substring($root.Length).TrimStart('\')
        $destinationPath = Join-Path $fixtureSourceRoot $relativePath
        $destinationParent = Split-Path -Parent $destinationPath
        if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
            $null = [IO.Directory]::CreateDirectory($destinationParent)
        }
        [IO.File]::WriteAllBytes($destinationPath,[IO.File]::ReadAllBytes($sourceFile.FullName))
    }

    $testSigner = New-NgcorTestCodeSigningCertificate
    $authenticodePaths = @(
        'NorthGate.VMFactory.CreateOnlyProtocol.psd1','NorthGate.VMFactory.CreateOnlyProtocol.psm1',
        'NorthGate.VMFactory.CreateOnlyDeployment.psd1','NorthGate.VMFactory.CreateOnlyDeployment.psm1',
        'Build-NorthGateCreateOnlyServiceHost.ps1','NorthGate.VMFactory.CreateOnlyService.psd1',
        'NorthGate.VMFactory.CreateOnlyService.psm1','backend\NorthGate.VMFactory.CreateOnlyBackend.psd1',
        'backend\NorthGate.VMFactory.CreateOnlyBackend.psm1','Invoke-NorthGateCreateOnlyForcedCommand.ps1',
        'Start-NorthGateCreateOnlyPipeService.ps1','Install-NorthGateCreateOnlyRelease.ps1',
        'New-NorthGateCreateOnlyApproval.ps1','New-NorthGateCreateOnlyRolloutPromotion.ps1',
        'Rollback-NorthGateCreateOnlyRelease.ps1','Test-NorthGateCreateOnlyHostAuthorization.ps1'
    )
    foreach ($relative in $authenticodePaths) {
        $signed = Set-AuthenticodeSignature -LiteralPath (Join-Path $fixtureSourceRoot $relative) `
            -Certificate $testSigner.Certificate -HashAlgorithm SHA256 -ErrorAction Stop
        Assert-NgcorTest ($signed.Status -notin @(
                [Management.Automation.SignatureStatus]::NotSigned,
                [Management.Automation.SignatureStatus]::HashMismatch,
                [Management.Automation.SignatureStatus]::NotSupportedFileFormat,
                [Management.Automation.SignatureStatus]::Incompatible
            )) `
            "Fixture Authenticode signing succeeds for $relative."
    }

    $null = Invoke-NgcorTestGit $fixtureRoot @('init')
    $null = Invoke-NgcorTestGit $fixtureRoot @('config','user.name','NorthGate fixture')
    $null = Invoke-NgcorTestGit $fixtureRoot @('config','user.email','northgate-fixture@example.invalid')
    $null = Invoke-NgcorTestGit $fixtureRoot @('config','commit.gpgSign','false')
    $null = Invoke-NgcorTestGit $fixtureRoot @('config','core.autocrlf','false')
    $null = Invoke-NgcorTestGit $fixtureRoot @(
        'remote','add','origin','https://github.com/Beowxlf/northgate-vm-factory.git'
    )
    $null = Invoke-NgcorTestGit $fixtureRoot @('add','--all')
    $null = Invoke-NgcorTestGit $fixtureRoot @('commit','--no-gpg-sign','-m','Create-only release fixture')

    $fixtureCommit = Invoke-NgcorTestGit $fixtureRoot @('rev-parse','--verify','HEAD')
    $fixtureTree = Invoke-NgcorTestGit $fixtureRoot @('rev-parse',($fixtureCommit + '^{tree}'))
    Assert-NgcorTest ($fixtureCommit -cmatch '^[a-f0-9]{40}$' -and $fixtureTree -cmatch '^[a-f0-9]{40}$') `
        'Disposable fixture has exact SHA-1 commit and tree pins.'
    Assert-NgcorTest ([string]::IsNullOrEmpty((Invoke-NgcorTestGit $fixtureRoot @('status','--porcelain=v1','--untracked-files=all')))) `
        'Disposable fixture starts with a clean worktree.'

    $fixtureBuilder = Join-Path $fixtureSourceRoot 'New-NorthGateCreateOnlyReleasePackage.ps1'
    $fixtureAuthorizationValidator = Join-Path $fixtureSourceRoot 'Test-NorthGateCreateOnlyHostAuthorization.ps1'
    $releaseId = 'ngcor-0.1.0-test'
    $serviceHostArtifactRoot = Join-Path ([IO.Path]::GetTempPath()) `
        ('ngcor-service-host-artifact-' + [guid]::NewGuid().ToString('N'))
    $packageArtifactRoots.Add($serviceHostArtifactRoot)
    $null = [IO.Directory]::CreateDirectory($serviceHostArtifactRoot)
    $unsignedServiceHost = Join-Path $serviceHostArtifactRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $buildProvenance = Join-Path $serviceHostArtifactRoot `
        'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
    $finalServiceHost = Join-Path $serviceHostArtifactRoot 'NorthGate.CreateOnly.ServiceHost.final.exe'
    $serviceHostCms = Join-Path $serviceHostArtifactRoot 'NorthGate.CreateOnly.ServiceHost.exe.p7s'
    $programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $compilerPath = @(
        (Join-Path $programFilesX86 'Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe'),
        (Join-Path $programFilesX86 'Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe'),
        (Join-Path $programFiles 'Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\Roslyn\csc.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($compilerPath)) { throw 'Approved fixture Roslyn compiler is unavailable.' }
    try { Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop }
    catch { throw 'System.ServiceProcess is unavailable.' }
    $sourceHash = (Get-FileHash -LiteralPath (Join-Path $fixtureSourceRoot 'NorthGate.CreateOnly.ServiceHost.cs') `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $compilerHash = (Get-FileHash -LiteralPath $compilerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $mscorlibHash = (Get-FileHash -LiteralPath ([object].Assembly.Location) -Algorithm SHA256).Hash.ToLowerInvariant()
    $systemHash = (Get-FileHash -LiteralPath ([ComponentModel.Component].Assembly.Location) `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $systemCoreHash = (Get-FileHash -LiteralPath ([Linq.Enumerable].Assembly.Location) `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $automationHash = (Get-FileHash -LiteralPath ([Management.Automation.PowerShell].Assembly.Location) `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $serviceProcessHash = (Get-FileHash -LiteralPath ([ServiceProcess.ServiceBase].Assembly.Location) `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = & (Join-Path $fixtureSourceRoot 'Build-NorthGateCreateOnlyServiceHost.ps1') `
        -OutputPath $unsignedServiceHost -ProvenancePath $buildProvenance -CompilerPath $compilerPath `
        -ExpectedSourceSha256 $sourceHash -ExpectedCompilerSha256 $compilerHash `
        -ExpectedMscorlibAssemblySha256 $mscorlibHash -ExpectedSystemAssemblySha256 $systemHash `
        -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
        -ExpectedAutomationAssemblySha256 $automationHash `
        -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    [IO.File]::Copy($unsignedServiceHost,$finalServiceHost,$false)
    $releaseSignerPin = Get-NgcorTestCertificateSha256 $testSigner.Certificate
    [IO.File]::WriteAllBytes(
        $serviceHostCms,
        (New-NgcorTestDetachedCmsBytes ([IO.File]::ReadAllBytes($finalServiceHost)) $testSigner.Certificate)
    )
    $packageParameters = @{
        SourceRoot = $fixtureSourceRoot
        OutputDirectory = ''
        ReleaseId = $releaseId
        Commit = $fixtureCommit
        Tree = $fixtureTree
        HostAllowlistId = 'ngallow-northgate-prod-01'
        GovernanceExceptionId = 'NG-GOV-20260802-TEST'
        UnsignedServiceHostPath = $unsignedServiceHost
        ServiceHostBuildProvenancePath = $buildProvenance
        SignedServiceHostPath = $finalServiceHost
        ServiceHostDetachedCmsPath = $serviceHostCms
        ExpectedReleaseSignerCertificateSha256 = $releaseSignerPin
    }

    $packageOut = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-package-' + [guid]::NewGuid().ToString('N'))
    $packageArtifactRoots.Add($packageOut)
    $successParameters = $packageParameters.Clone()
    $successParameters.OutputDirectory = $packageOut
    $packageResult = & $fixtureBuilder @successParameters
    Assert-NgcorTest ($packageResult.status -ceq
        'package-generated-with-verified-source-and-signed-derived-artifact-manifest-unsigned' -and
        -not $packageResult.installable) 'Raw-Git package declares unsigned, non-installable state.'
    Assert-NgcorTest ($packageResult.repositoryCommit -ceq $fixtureCommit -and
        $packageResult.repositoryTree -ceq $fixtureTree) 'Package result preserves the verified Git tuple.'

    $manifestPath = Join-Path $packageOut 'release-manifest.json'
    $actualManifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-NgcorTest ($actualManifestHash -ceq $packageResult.releaseManifestSha256) 'Package reports the exact manifest hash.'
    $shaLine = [IO.File]::ReadAllText((Join-Path $packageOut 'release-manifest.sha256')).Trim()
    Assert-NgcorTest ($shaLine -ceq ($actualManifestHash + '  release-manifest.json')) 'Sidecar manifest hash is exact.'
    $manifest = ConvertFrom-NgcorTestJsonText ([IO.File]::ReadAllText($manifestPath))
    Assert-NgcorTest ($manifest.repository.identity -ceq 'Beowxlf/northgate-vm-factory' -and
        $manifest.repository.origin -ceq 'https://github.com/Beowxlf/northgate-vm-factory.git' -and
        $manifest.repository.commit -ceq $fixtureCommit -and $manifest.repository.tree -ceq $fixtureTree -and
        $manifest.repository.packageAllowlistSha256 -cmatch '^[a-f0-9]{64}$') `
        'Manifest binds the exact repository identity, origin, tuple, and package allowlist.'
    Assert-NgcorTest ($manifest.sourceProof.sourceKind -ceq
        'raw-git-blobs-plus-derived-signed-artifact' -and
        $manifest.sourceProof.headEqualsCommit -and $manifest.sourceProof.cleanWorktree -and
        $manifest.sourceProof.replaceRefsAbsent -and $manifest.sourceProof.contentFiltersAbsent) `
        'Manifest records the raw-Git source proof.'
    Assert-NgcorTest ($manifest.packageSemantics.sourceExecutableOnHost -and
        -not $manifest.packageSemantics.installInitiallyEnabled -and
        $manifest.packageSemantics.liveApplyImplemented -and
        (@($manifest.packageSemantics.allowedProtocolCommands) -join '|') -ceq
            'status|plan|approval-context|approve|rollout-context|promote-rollout|apply|receipt') `
        'Manifest declares the production implementation while installation remains separately gated.'
    $expectedPackageFiles = @(
        'NorthGate.VMFactory.CreateOnlyProtocol.psd1',
        'NorthGate.VMFactory.CreateOnlyProtocol.psm1',
        'NorthGate.VMFactory.CreateOnlyDeployment.psd1',
        'NorthGate.VMFactory.CreateOnlyDeployment.psm1',
        'NorthGate.CreateOnly.ServiceHost.cs',
        'Build-NorthGateCreateOnlyServiceHost.ps1',
        'NorthGate.VMFactory.CreateOnlyService.psd1',
        'NorthGate.VMFactory.CreateOnlyService.psm1',
        'backend/NorthGate.VMFactory.CreateOnlyBackend.psd1',
        'backend/NorthGate.VMFactory.CreateOnlyBackend.psm1',
        'backend/schemas/create-only-backend-policy.schema.json',
        'backend/schemas/create-only-data-bundle.schema.json',
        'backend/schemas/create-only-host-plan.schema.json',
        'backend/schemas/create-only-journal-event.schema.json',
        'backend/schemas/create-only-plan-approval.schema.json',
        'backend/schemas/create-only-rollout-promotion.schema.json',
        'backend/schemas/create-only-signed-receipt.schema.json',
        'Invoke-NorthGateCreateOnlyForcedCommand.ps1',
        'Start-NorthGateCreateOnlyPipeService.ps1',
        'Install-NorthGateCreateOnlyRelease.ps1',
        'New-NorthGateCreateOnlyApproval.ps1',
        'New-NorthGateCreateOnlyRolloutPromotion.ps1',
        'Rollback-NorthGateCreateOnlyRelease.ps1',
        'Test-NorthGateCreateOnlyHostAuthorization.ps1',
        'host-deployment-authorization.schema.json',
        'release-manifest.schema.json',
        'sshd_config.create-only.example',
        'README.md',
        'NorthGate.CreateOnly.ServiceHost.exe'
    )
    Assert-NgcorTest (@($manifest.files).Count -eq $expectedPackageFiles.Count) `
        'Package contains exactly the fixed release allowlist.'
    Assert-NgcorTest ((@($manifest.files.path | Sort-Object) -join '|') -ceq
        (@($expectedPackageFiles | Sort-Object) -join '|')) 'Package file names equal the fixed release allowlist.'
    foreach ($entry in @($manifest.files)) {
        $packagedPath = Join-Path $packageOut ([string]$entry.path).Replace('/', '\')
        $actual = (Get-FileHash -LiteralPath $packagedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($entry.artifactKind -ceq 'raw-git-blob') {
            $packagedBlob = Invoke-NgcorTestGit $fixtureRoot @('hash-object','--no-filters',$packagedPath)
            Assert-NgcorTest ($actual -ceq $entry.sha256 -and
                (Get-Item -LiteralPath $packagedPath).Length -eq $entry.sizeBytes -and
                $packagedBlob -ceq $entry.gitBlobOid) "Verified raw Git blob $($entry.path)."
        }
        else {
            $cmsPath = Join-Path $packageOut ([string]$entry.detachedCms.path)
            Assert-NgcorTest ($entry.artifactKind -ceq 'derived-signed-artifact' -and
                $actual -ceq $entry.sha256 -and $entry.buildProvenance.deterministic -eq $true -and
                $entry.buildProvenance.unsignedSha256 -ceq $entry.sha256 -and
                (Get-FileHash -LiteralPath $cmsPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
                    $entry.detachedCms.sha256 -and
                $entry.detachedCms.signerCertificateSha256 -ceq $releaseSignerPin) `
                'Verified deterministic service-host provenance and detached CMS inventory.'
        }
    }
    $privateMaterial = @(Get-ChildItem -LiteralPath $packageOut -File | Where-Object {
        $_.Extension -in @('.pfx','.p12','.key','.pem')
    })
    Assert-NgcorTest ($privateMaterial.Count -eq 0 -and
        (Test-Path -LiteralPath (Join-Path $packageOut 'NorthGate.CreateOnly.ServiceHost.exe.p7s') -PathType Leaf)) `
        'Package contains the bounded detached service-host signature and no private key material.'

    $fakeTupleOut = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-package-fake-' + [guid]::NewGuid().ToString('N'))
    $packageArtifactRoots.Add($fakeTupleOut)
    $fakeTupleParameters = $packageParameters.Clone()
    $fakeTupleParameters.OutputDirectory = $fakeTupleOut
    $fakeTupleParameters.Commit = 'a' * 40
    Assert-NgcorThrows { & $fixtureBuilder @fakeTupleParameters } '^NGCOR-PACKAGE-HEAD-COMMIT-MISMATCH$' `
        'Package builder rejects a caller-invented commit tuple.'

    $fakeTreeOut = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-package-tree-' + [guid]::NewGuid().ToString('N'))
    $packageArtifactRoots.Add($fakeTreeOut)
    $fakeTreeParameters = $packageParameters.Clone()
    $fakeTreeParameters.OutputDirectory = $fakeTreeOut
    $fakeTreeParameters.Tree = 'b' * 40
    Assert-NgcorThrows { & $fixtureBuilder @fakeTreeParameters } '^NGCOR-PACKAGE-COMMIT-TREE-MISMATCH$' `
        'Package builder rejects a caller-invented tree paired with the real HEAD commit.'

    $dirtyOut = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-package-dirty-' + [guid]::NewGuid().ToString('N'))
    $packageArtifactRoots.Add($dirtyOut)
    $dirtyParameters = $packageParameters.Clone()
    $dirtyParameters.OutputDirectory = $dirtyOut
    $dirtyPath = Join-Path $fixtureSourceRoot 'README.md'
    $cleanBytes = [IO.File]::ReadAllBytes($dirtyPath)
    try {
        [IO.File]::AppendAllText($dirtyPath, "`nfixture dirt", (New-Object Text.UTF8Encoding($false)))
        Assert-NgcorThrows { & $fixtureBuilder @dirtyParameters } '^NGCOR-PACKAGE-WORKTREE-NOT-CLEAN$' `
            'Package builder rejects a dirty tracked worktree.'
    }
    finally { [IO.File]::WriteAllBytes($dirtyPath, $cleanBytes) }
    Assert-NgcorTest ([string]::IsNullOrEmpty((Invoke-NgcorTestGit $fixtureRoot @('status','--porcelain=v1','--untracked-files=all')))) `
        'Dirty-worktree test restores the clean fixture.'

    $wrongOriginOut = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-package-origin-' + [guid]::NewGuid().ToString('N'))
    $packageArtifactRoots.Add($wrongOriginOut)
    $wrongOriginParameters = $packageParameters.Clone()
    $wrongOriginParameters.OutputDirectory = $wrongOriginOut
    $null = Invoke-NgcorTestGit $fixtureRoot @('remote','set-url','origin','https://github.com/example/not-northgate.git')
    try {
        Assert-NgcorThrows { & $fixtureBuilder @wrongOriginParameters } '^NGCOR-PACKAGE-REPOSITORY-IDENTITY-MISMATCH$' `
            'Package builder rejects the wrong origin identity.'
    }
    finally {
        $null = Invoke-NgcorTestGit $fixtureRoot @(
            'remote','set-url','origin','https://github.com/Beowxlf/northgate-vm-factory.git'
        )
    }

    $replaceOut = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-package-replace-' + [guid]::NewGuid().ToString('N'))
    $packageArtifactRoots.Add($replaceOut)
    $replaceParameters = $packageParameters.Clone()
    $replaceParameters.OutputDirectory = $replaceOut
    $replacementCommit = Invoke-NgcorTestGit $fixtureRoot @(
        'commit-tree',$fixtureTree,'-p',$fixtureCommit,'-m','replacement fixture commit'
    )
    $null = Invoke-NgcorTestGit $fixtureRoot @('replace',$fixtureCommit,$replacementCommit)
    try {
        Assert-NgcorThrows { & $fixtureBuilder @replaceParameters } '^NGCOR-PACKAGE-REPLACE-REF-FORBIDDEN$' `
            'Package builder rejects replace refs even when raw objects are requested.'
    }
    finally { $null = Invoke-NgcorTestGit $fixtureRoot @('replace','-d',$fixtureCommit) }

    $issuedAt = [DateTimeOffset]::UtcNow.AddMinutes(-1).ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture
    )
    $expiresAt = [DateTimeOffset]::UtcNow.AddMinutes(30).ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture
    )
    $bootstrapFleet = @(
        'NG-VM-018','NG-VM-010','NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012',
        'NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015'
    )
    $windowsBootstrapAssets = @('NG-VM-010','NG-VM-011','NG-VM-012','NG-VM-019','NG-VM-020','NG-VM-021')
    $bootstrapMedia = [object[]]@(
        for ($index = 0; $index -lt $bootstrapFleet.Count; $index++) {
            $assetId = $bootstrapFleet[$index]
            $sourceImageId = if ($assetId -in $windowsBootstrapAssets) {
                'windows-11-25h2-english-x64'
            }
            elseif ($assetId -ceq 'NG-VM-015') {
                'kali-2026.2-installer-netinst-amd64'
            }
            else {
                'debian-12.12-amd64-netinst'
            }
            $sourceImageSha256 = switch ($sourceImageId) {
                'windows-11-25h2-english-x64' {
                    'd141f6030fed50f75e2b03e1eb2e53646c4b21e5386047cb860af5223f102a32'
                }
                'kali-2026.2-installer-netinst-amd64' {
                    'd32f929dacc48134a31461a09f2160d13ad1d26b820cee920446813ca979b39b'
                }
                default {
                    'dfc30e04fd095ac2c07e998f145e94bb8f7d3a8eca3a631d2eb012398deae531'
                }
            }
            [pscustomobject][ordered]@{
                assetId = $assetId
                mediaId = 'ngmedia-' + $assetId.ToLowerInvariant()
                mode = 'asset-bound-derivative-iso'
                path = "D:\HyperV\VM-ISO\NorthGate-Bootstrap\$assetId.iso"
                sha256 = ('{0:x64}' -f [uint64](4097 + $index))
                sizeBytes = [int64](1048576 + $index)
                sourceImageId = $sourceImageId
                sourceImageSha256 = $sourceImageSha256
                provenancePath = "D:\HyperV\VM-ISO\NorthGate-Bootstrap\$assetId.provenance.json"
                provenanceSha256 = ('{0:x64}' -f [uint64](6145 + $index))
                bundleManifestSha256 = ('{0:x64}' -f [uint64](7169 + $index))
                builderId = 'northgate-unattended-media-v1'
                builderReleaseSha256 = $actualManifestHash
                recipeSha256 = ('{0:x64}' -f [uint64](8193 + $index))
                unattendedPayloadSha256 = ('{0:x64}' -f [uint64](12289 + $index))
                sourceCommit = $fixtureCommit
                sourceTree = $fixtureTree
            }
        }
    )
    $authorization = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-host-deployment-authorization/v2'
        authorizationId = 'ngdeploy-northgate-test-01'
        sequence = 1
        issuedAtUtc = $issuedAt
        expiresAtUtc = $expiresAt
        repository = [pscustomobject][ordered]@{
            identity = 'Beowxlf/northgate-vm-factory'
            releaseId = $releaseId
            commit = $fixtureCommit
            tree = $fixtureTree
            hostAllowlistId = 'ngallow-northgate-prod-01'
            packageAllowlistSha256 = [string]$manifest.repository.packageAllowlistSha256
            governanceExceptionId = 'NG-GOV-20260802-TEST'
        }
        releaseManifestSha256 = $actualManifestHash
        host = [pscustomobject][ordered]@{
            hostId = 'nghost-northgate-hv01'
            computerName = 'HC-HV01'
            machineGuidSha256 = '1' * 64
            hyperVHostId = '11111111-1111-1111-1111-111111111111'
            osBuild = '20348.2762'
        }
        install = [pscustomobject][ordered]@{
            versionedReleaseRoot = "C:\Program Files\NorthGate\VMFactory\CreateOnly\releases\$releaseId"
            stateRoot = 'C:\ProgramData\NorthGate\VMFactory\CreateOnly\state'
            quarantineRoot = 'C:\ProgramData\NorthGate\VMFactory\CreateOnly\quarantine'
        }
        identity = [pscustomobject][ordered]@{
            sshIdentitySid = 'S-1-5-21-100-200-300-1001'
            serviceIdentitySid = 'S-1-5-21-100-200-300-1002'
            releaseSignerCertificateSha256 = '2' * 64
            deploymentAuthorizationSignerCertificateSha256 = '3' * 64
            approvalSignerCertificateSha256 = '4' * 64
            receiptSignerCertificateSha256 = '5' * 64
        }
        'switch' = [pscustomobject][ordered]@{
            switchPolicyId = 'northgate-app-trunk'
            name = 'NorthGate-App-Trunk'
            id = '22222222-2222-2222-2222-222222222222'
            fingerprint = '6' * 64
            trunkAdapterId = '33333333-3333-3333-3333-333333333333'
            trunkAdapterFingerprint = '7' * 64
            mode = 'existing-only'
            allowCreate = $false
            vlanProfiles = [pscustomobject][ordered]@{
                'business-apps' = 150
                'commercial-dmz' = 160
                'cyber-workstations' = 140
                'external-mail' = 240
                'it-admin-workstations' = 130
                'mail-internal' = 120
                'sim-wan' = 250
                'users-workstations' = 110
            }
        }
        volumes = [object[]]@(
            [pscustomobject][ordered]@{
                volumeId = 'volume-d'; uniqueId = 'volume-d-unique-001'; root = 'D:\HyperV\VMs'
                persistentCeilingGiB = 440; canaryCeilingGiB = 40
            },
            [pscustomobject][ordered]@{
                volumeId = 'volume-f'; uniqueId = 'volume-f-unique-001'; root = 'F:\HyperV\VMs'
                persistentCeilingGiB = 460; canaryCeilingGiB = 80
            }
        )
        images = [object[]]@(
            [pscustomobject][ordered]@{
                imageId = 'debian-12.12-amd64-netinst'
                path = 'D:\HyperV\VM-ISO\debian-12.12.0-amd64-netinst.iso'
                sha256 = 'dfc30e04fd095ac2c07e998f145e94bb8f7d3a8eca3a631d2eb012398deae531'
                sizeBytes = [int64]704643072
            },
            [pscustomobject][ordered]@{
                imageId = 'kali-2026.2-installer-netinst-amd64'
                path = 'D:\HyperV\VM-ISO\kali-linux-2026.2-installer-netinst-amd64.iso'
                sha256 = 'd32f929dacc48134a31461a09f2160d13ad1d26b820cee920446813ca979b39b'
                sizeBytes = [int64]779091968
            },
            [pscustomobject][ordered]@{
                imageId = 'windows-11-25h2-english-x64'
                path = 'D:\HyperV\VM-ISO\Win11_25H2_English_x64.iso'
                sha256 = 'd141f6030fed50f75e2b03e1eb2e53646c4b21e5386047cb860af5223f102a32'
                sizeBytes = [int64]7736125440
            }
        )
        bootstrapMedia = $bootstrapMedia
        protectedAssets = [object[]]@(
            [pscustomobject][ordered]@{ name = 'JS-BlueBench'; vmId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1'; diskUniqueIds = [object[]]@('disk-bluebench-001'); adapterIds = [object[]]@('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1') },
            [pscustomobject][ordered]@{ name = 'JS-Server-01'; vmId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2'; diskUniqueIds = [object[]]@('disk-server-001'); adapterIds = [object[]]@('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2') },
            [pscustomobject][ordered]@{ name = 'OPNsense-Tooling'; vmId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3'; diskUniqueIds = [object[]]@('disk-opnsense-001'); adapterIds = [object[]]@('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb3') },
            [pscustomobject][ordered]@{ name = 'TRMM-Tooling'; vmId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa4'; diskUniqueIds = [object[]]@('disk-trmm-001'); adapterIds = [object[]]@('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb4') },
            [pscustomobject][ordered]@{ name = 'Wazuh-Machine'; vmId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa5'; diskUniqueIds = [object[]]@('disk-wazuh-001'); adapterIds = [object[]]@('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb5') }
        )
        accessIsolation = [pscustomobject][ordered]@{
            routineSshIsLocalAdministrator = $false
            routineSshIsHyperVAdministrator = $false
            routineSshCanUsePowerShellRemoting = $false
            routineSshCanReachLegacyMcp = $false
        }
        initialPolicy = [pscustomobject][ordered]@{
            applyEnabled = $false
            executableActions = [object[]]@()
            canaryStage = 'disabled'
        }
    }

    $validAuthorizationPath = Join-Path $authorizationRoot 'valid.json'
    Write-NgcorTestCanonicalJsonFile $authorization $validAuthorizationPath
    $authorizationParameters = @{
        AuthorizationPath = $validAuthorizationPath
        ExpectedReleaseId = $releaseId
        ExpectedReleaseManifestSha256 = $actualManifestHash
        ExpectedCommit = $fixtureCommit
        ExpectedTree = $fixtureTree
        ExpectedHostAllowlistId = 'ngallow-northgate-prod-01'
        ExpectedGovernanceExceptionId = 'NG-GOV-20260802-TEST'
    }
    $authorizationResult = & $fixtureAuthorizationValidator @authorizationParameters
    $actualAuthorizationHash = (Get-FileHash -LiteralPath $validAuthorizationPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-NgcorTest ($authorizationResult.status -ceq 'semantic-validation-passed-signature-not-verified' -and
        $authorizationResult.authorizationSha256 -ceq $actualAuthorizationHash -and
        $authorizationResult.repositoryCommit -ceq $fixtureCommit -and
        $authorizationResult.repositoryTree -ceq $fixtureTree) 'Valid host authorization passes semantic validation with exact pins.'
    Assert-NgcorTest (-not $authorizationResult.applyEnabled -and
        @($authorizationResult.executableActions).Count -eq 0 -and -not $authorizationResult.installable) `
        'Semantic validation leaves apply and installation disabled.'

    $duplicateAuthorization = Copy-NgcorTestObject $authorization
    $duplicateAuthorization.volumes[1].volumeId = $duplicateAuthorization.volumes[0].volumeId
    $duplicateAuthorizationPath = Join-Path $authorizationRoot 'duplicate-volume.json'
    Write-NgcorTestCanonicalJsonFile $duplicateAuthorization $duplicateAuthorizationPath
    $duplicateAuthorizationParameters = $authorizationParameters.Clone()
    $duplicateAuthorizationParameters.AuthorizationPath = $duplicateAuthorizationPath
    Assert-NgcorThrows { & $fixtureAuthorizationValidator @duplicateAuthorizationParameters } `
        '^NGCOR-AUTHORIZATION-VOLUMES-INVALID$' 'Host authorization rejects duplicate volume mappings.'

    $duplicateMediaAuthorization = Copy-NgcorTestObject $authorization
    $duplicateMediaAuthorization.bootstrapMedia[1].sha256 =
        $duplicateMediaAuthorization.bootstrapMedia[0].sha256
    $duplicateMediaAuthorizationPath = Join-Path $authorizationRoot 'duplicate-bootstrap-media.json'
    Write-NgcorTestCanonicalJsonFile $duplicateMediaAuthorization $duplicateMediaAuthorizationPath
    $duplicateMediaParameters = $authorizationParameters.Clone()
    $duplicateMediaParameters.AuthorizationPath = $duplicateMediaAuthorizationPath
    Assert-NgcorThrows { & $fixtureAuthorizationValidator @duplicateMediaParameters } `
        '^NGCOR-AUTHORIZATION-BOOTSTRAP-MEDIA-COLLISION$' `
        'Host authorization rejects a derivative-media hash collision.'

    $wrongMediaBaseAuthorization = Copy-NgcorTestObject $authorization
    $wrongMediaBaseAuthorization.bootstrapMedia[0].sourceImageId = 'windows-11-25h2-english-x64'
    $wrongMediaBaseAuthorization.bootstrapMedia[0].sourceImageSha256 =
        'd141f6030fed50f75e2b03e1eb2e53646c4b21e5386047cb860af5223f102a32'
    $wrongMediaBaseAuthorizationPath = Join-Path $authorizationRoot 'wrong-bootstrap-base.json'
    Write-NgcorTestCanonicalJsonFile $wrongMediaBaseAuthorization $wrongMediaBaseAuthorizationPath
    $wrongMediaBaseParameters = $authorizationParameters.Clone()
    $wrongMediaBaseParameters.AuthorizationPath = $wrongMediaBaseAuthorizationPath
    Assert-NgcorThrows { & $fixtureAuthorizationValidator @wrongMediaBaseParameters } `
        '^NGCOR-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID$' `
        'Host authorization rejects a derivative medium bound to the wrong source image.'

    $wrongMappingAuthorization = Copy-NgcorTestObject $authorization
    $wrongMappingAuthorization.switch.vlanProfiles.'business-apps' = 151
    $wrongMappingAuthorizationPath = Join-Path $authorizationRoot 'wrong-vlan.json'
    Write-NgcorTestCanonicalJsonFile $wrongMappingAuthorization $wrongMappingAuthorizationPath
    $wrongMappingParameters = $authorizationParameters.Clone()
    $wrongMappingParameters.AuthorizationPath = $wrongMappingAuthorizationPath
    Assert-NgcorThrows { & $fixtureAuthorizationValidator @wrongMappingParameters } `
        '^NGCOR-AUTHORIZATION-VLAN-PROFILES-INVALID$' 'Host authorization rejects an incorrect VLAN mapping.'

    $identityAuthorization = Copy-NgcorTestObject $authorization
    $identityAuthorization.identity.serviceIdentitySid = $identityAuthorization.identity.sshIdentitySid
    $identityAuthorizationPath = Join-Path $authorizationRoot 'same-principal.json'
    Write-NgcorTestCanonicalJsonFile $identityAuthorization $identityAuthorizationPath
    $identityParameters = $authorizationParameters.Clone()
    $identityParameters.AuthorizationPath = $identityAuthorizationPath
    Assert-NgcorThrows { & $fixtureAuthorizationValidator @identityParameters } `
        '^NGCOR-AUTHORIZATION-IDENTITY-SEPARATION-INVALID$' 'Host authorization requires separate SSH and service identities.'

    $signerAuthorization = Copy-NgcorTestObject $authorization
    $signerAuthorization.identity.receiptSignerCertificateSha256 =
        $signerAuthorization.identity.approvalSignerCertificateSha256
    $signerAuthorizationPath = Join-Path $authorizationRoot 'same-signer.json'
    Write-NgcorTestCanonicalJsonFile $signerAuthorization $signerAuthorizationPath
    $signerParameters = $authorizationParameters.Clone()
    $signerParameters.AuthorizationPath = $signerAuthorizationPath
    Assert-NgcorThrows { & $fixtureAuthorizationValidator @signerParameters } `
        '^NGCOR-AUTHORIZATION-SIGNER-SEPARATION-INVALID$' 'Host authorization requires four separate signer pins.'

    $attributesPath = Join-Path $fixtureRoot '.gitattributes'
    [IO.File]::WriteAllText(
        $attributesPath,
        "control-plane/create-only-release/README.md filter=fixture-filter`n",
        (New-Object Text.UTF8Encoding($false))
    )
    $null = Invoke-NgcorTestGit $fixtureRoot @('add','.gitattributes')
    $null = Invoke-NgcorTestGit $fixtureRoot @('commit','--no-gpg-sign','-m','Add forbidden content filter')
    $filterCommit = Invoke-NgcorTestGit $fixtureRoot @('rev-parse','--verify','HEAD')
    $filterTree = Invoke-NgcorTestGit $fixtureRoot @('rev-parse',($filterCommit + '^{tree}'))
    $filterOut = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-package-filter-' + [guid]::NewGuid().ToString('N'))
    $packageArtifactRoots.Add($filterOut)
    $filterParameters = $packageParameters.Clone()
    $filterParameters.OutputDirectory = $filterOut
    $filterParameters.Commit = $filterCommit
    $filterParameters.Tree = $filterTree
    Assert-NgcorThrows { & $fixtureBuilder @filterParameters } '^NGCOR-PACKAGE-CONTENT-FILTER-FORBIDDEN$' `
        'Package builder rejects Git content filters on an allowlisted blob.'
}
finally {
    if ($null -ne $testSigner) {
        $testSigner.Certificate.Dispose()
        $testSigner.Key.Dispose()
    }
    foreach ($artifactRoot in $packageArtifactRoots) {
        if (Test-Path -LiteralPath $artifactRoot) { Remove-Item -LiteralPath $artifactRoot -Recurse -Force }
    }
    if (Test-Path -LiteralPath $authorizationRoot) { Remove-Item -LiteralPath $authorizationRoot -Recurse -Force }
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    foreach ($name in $gitEnvironmentSnapshot.Keys) {
        [Environment]::SetEnvironmentVariable(
            $name, [string]$gitEnvironmentSnapshot[$name], [EnvironmentVariableTarget]::Process
        )
    }
}

$denialRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-denial-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($denialRoot)
try {
    Push-Location $denialRoot
    try {
        Assert-NgcorThrows {
            & (Join-Path $root 'New-NorthGateCreateOnlyApproval.ps1') `
                -PlanId ('ngp-' + ('a' * 64)) -ApprovalCertificateSha256 ('b' * 64) `
                -LifetimeSeconds 60 -ConfirmApproval
        } '^NGCOR-APPROVAL-(?:ADMIN-IDENTITY-REQUIRED|CHECKOUT-EXECUTION-FORBIDDEN)$' `
            'Approval writer is restricted to a native administrator using the installed release.'
        Assert-NgcorTest (@(Get-ChildItem -LiteralPath $denialRoot -Force).Count -eq 0) 'Denied approval wrote nothing.'
        Assert-NgcorThrows {
            & (Join-Path $root 'New-NorthGateCreateOnlyRolloutPromotion.ps1') `
                -ToStage windows-canary -AcceptanceEvidenceSha256 ('a' * 64) `
                -RetirementEvidenceSha256 ('b' * 64) `
                -ApprovalCertificateSha256 ('c' * 64) -LifetimeSeconds 60 -ConfirmPromotion
        } '^NGCOR-ROLLOUT-(?:ADMIN-IDENTITY-REQUIRED|CHECKOUT-EXECUTION-FORBIDDEN)$' `
            'Rollout promotion writer is restricted to a native administrator using the installed release.'
        Assert-NgcorTest (@(Get-ChildItem -LiteralPath $denialRoot -Force).Count -eq 0) `
            'Denied rollout promotion wrote nothing.'
        Assert-NgcorThrows {
            & (Join-Path $root 'Rollback-NorthGateCreateOnlyRelease.ps1') `
                -TransactionId ('ngtxn-' + ('a' * 64)) `
                -InstalledReleaseId 'ngcor-0.1.0-test' `
                -InstalledReleaseManifestSha256 ('d' * 64) -BackupReceiptSha256 ('e' * 64) `
                -BackupReceiptPath (Join-Path $root 'README.md') `
                -BackupReceiptSignaturePath (Join-Path $root 'README.md') `
                -SignedHostDeploymentAuthorizationPath (Join-Path $root 'README.md') `
                -DeploymentAuthorizationSignaturePath (Join-Path $root 'README.md') `
                -ExpectedDeploymentAuthorizationSha256 ('f' * 64) -ConfirmRollback
        } '^NGCOR-ROLLBACK-BLOCKED-TRUST-ANCHOR-NOT-BAKED$' 'Rollback is non-operative without a baked trust anchor.'
        Assert-NgcorTest (@(Get-ChildItem -LiteralPath $denialRoot -Force).Count -eq 0) 'Denied rollback wrote nothing.'
    }
    finally { Pop-Location }
}
finally { Remove-Item -LiteralPath $denialRoot -Recurse -Force }

$null = & (Join-Path $root 'Test-NorthGateCreateOnlyServiceHost.ps1')
$null = & (Join-Path $root 'Test-NorthGateCreateOnlyService.ps1')
$null = & (Join-Path $root 'Test-NorthGateCreateOnlyDeployment.ps1')

Write-Output "PASS: $script:Assertions assertions"
