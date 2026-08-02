[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$candidateRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $candidateRoot 'NorthGate.VMFactory.PromotionCandidate.psd1'
$moduleSourcePath = Join-Path $candidateRoot 'NorthGate.VMFactory.PromotionCandidate.psm1'
$script:assertionCount = 0
$testCertificate = $null
$testRoot = $null

function Assert-Promotion {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) { throw $Message }
    $script:assertionCount++
}

function ConvertTo-TestCanonicalBytes {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object]$Value)
    $json = & $script:promotionModule { param($InputValue) ConvertTo-NgCanonicalJson -Value $InputValue } $Value
    return (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
}

function Get-TestSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function New-TestNonce {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) }
    finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Format-TestUtc {
    param([Parameter(Mandatory)][DateTimeOffset]$Value)
    return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Set-TestDirectoryAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AddEveryoneWriter
    )
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($script:currentSid)))
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sidText in $script:allowedWriterSids) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $security.AddAccessRule($rule)
    }
    if ($AddEveryoneWriter) {
        $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $everyone,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $security.AddAccessRule($rule)
    }
    [System.IO.Directory]::SetAccessControl($Path, $security)
}

function Set-TestFileAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AddEveryoneWriter
    )
    $security = New-Object System.Security.AccessControl.FileSecurity
    $security.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($script:currentSid)))
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sidText in $script:allowedWriterSids) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $security.AddAccessRule($rule)
    }
    if ($AddEveryoneWriter) {
        $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $everyone,
            [Security.AccessControl.FileSystemRights]::Write,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $security.AddAccessRule($rule)
    }
    [System.IO.File]::SetAccessControl($Path, $security)
}

function Sign-TestBytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($script:testCertificate)
    try {
        return $rsa.SignData(
            $Bytes,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    }
    finally { $rsa.Dispose() }
}

function New-TestEnvelope {
    param(
        [string]$Nonce = (New-TestNonce),
        [DateTimeOffset]$IssuedAt = ([DateTimeOffset]::UtcNow.AddSeconds(-5)),
        [DateTimeOffset]$ExpiresAt = ([DateTimeOffset]::UtcNow.AddMinutes(5))
    )
    $artifactCopies = New-Object System.Collections.Generic.List[object]
    foreach ($artifact in $script:expectedArtifacts) {
        $artifactCopies.Add([ordered]@{
            destinationRelativePath = $artifact.destinationRelativePath
            id = $artifact.id
            sha256 = $artifact.sha256
            sizeBytes = [long]$artifact.sizeBytes
            sourceRelativePath = $artifact.sourceRelativePath
        })
    }
    $artifacts = [object[]]$artifactCopies.ToArray()
    $artifactSetHash = Get-TestSha256Hex -Bytes (ConvertTo-TestCanonicalBytes -Value $artifacts)
    return [ordered]@{
        actions = [object[]]@()
        applyEnabled = $false
        artifactSetSha256 = $artifactSetHash
        artifacts = $artifacts
        envelopeId = [Guid]::NewGuid().ToString('D').ToLowerInvariant()
        expiresAtUtc = Format-TestUtc -Value $ExpiresAt
        installRoot = $script:installRoot
        issuedAtUtc = Format-TestUtc -Value $IssuedAt
        nonce = $Nonce
        operation = 'install-control-plane-candidate'
        repository = [ordered]@{
            commitSha = $script:commitSha
            id = $script:repositoryId
            treeSha = $script:treeSha
            uri = $script:repositoryUri
        }
        schemaVersion = 'northgate/promotion-envelope/v1'
        signatureAlgorithm = 'RSASSA-PKCS1-v1_5-SHA256'
        stagingRoot = $script:stagingRoot
    }
}

function Update-TestArtifactSetHash {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Envelope)
    $Envelope.artifactSetSha256 = Get-TestSha256Hex -Bytes (ConvertTo-TestCanonicalBytes -Value $Envelope.artifacts)
}

function Write-TestEnvelopeBytes {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [byte[]]$Signature
    )
    [IO.File]::WriteAllBytes($script:envelopePath, $Bytes)
    if ($null -eq $Signature) { $Signature = Sign-TestBytes -Bytes $Bytes }
    [IO.File]::WriteAllBytes($script:signaturePath, $Signature)
}

function Write-TestEnvelope {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Envelope)
    Write-TestEnvelopeBytes -Bytes (ConvertTo-TestCanonicalBytes -Value $Envelope)
}

function Get-TestLedgerDigest {
    if (-not [IO.File]::Exists($script:ledgerPath)) { return '<absent>' }
    return Get-TestSha256Hex -Bytes ([IO.File]::ReadAllBytes($script:ledgerPath))
}

function Invoke-TestVerifier {
    param([hashtable]$Overrides = @{})
    $arguments = @{
        EnvelopePath = $script:envelopePath
        SignaturePath = $script:signaturePath
        SignerCertificatePath = $script:certificatePath
        ExpectedSignerCertificateSha256 = $script:certificatePin
        ExpectedRepositoryId = $script:repositoryId
        ExpectedRepositoryUri = $script:repositoryUri
        ExpectedCommitSha = $script:commitSha
        ExpectedTreeSha = $script:treeSha
        ExpectedInstallRoot = $script:installRoot
        ExpectedStagingRoot = $script:stagingRoot
        ExpectedStateRoot = $script:stateRoot
        ExpectedArtifacts = $script:expectedArtifacts
        LedgerPath = $script:ledgerPath
        LedgerKeyPath = $script:ledgerKeyPath
        LedgerId = $script:ledgerId
        AllowedWriterSids = $script:allowedWriterSids
        MaximumEnvelopeLifetimeMinutes = 10
    }
    foreach ($key in $Overrides.Keys) { $arguments[$key] = $Overrides[$key] }
    return Test-NorthGatePromotionEnvelope @arguments
}

function Assert-TestRejection {
    param(
        [Parameter(Mandatory)][string]$ExpectedCode,
        [hashtable]$Overrides = @{},
        [switch]$SkipLedgerInvariant
    )
    $before = Get-TestLedgerDigest
    $caught = $null
    try {
        $null = Invoke-TestVerifier -Overrides $Overrides
    }
    catch { $caught = $_.Exception.Message }
    Assert-Promotion -Condition ($null -ne $caught -and $caught.StartsWith("$ExpectedCode`:", [StringComparison]::Ordinal)) `
        -Message "Expected rejection $ExpectedCode but received '$caught'."
    if (-not $SkipLedgerInvariant) {
        $after = Get-TestLedgerDigest
        Assert-Promotion -Condition ($before -ceq $after) -Message "$ExpectedCode changed the replay ledger on rejection."
    }
}

function Invoke-SignedMutationRejection {
    param(
        [Parameter(Mandatory)][scriptblock]$Mutation,
        [Parameter(Mandatory)][string]$ExpectedCode,
        [switch]$PreserveArtifactSetHash
    )
    $envelope = New-TestEnvelope
    & $Mutation $envelope
    if (-not $PreserveArtifactSetHash) { Update-TestArtifactSetHash -Envelope $envelope }
    Write-TestEnvelope -Envelope $envelope
    Assert-TestRejection -ExpectedCode $ExpectedCode
}

Import-Module -Name $modulePath -Force
$script:promotionModule = Get-Module 'NorthGate.VMFactory.PromotionCandidate'

try {
    $script:currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:allowedWriterSids = @('S-1-5-18', 'S-1-5-32-544', $script:currentSid) | Select-Object -Unique
    $script:repositoryId = 'Beowxlf/northgate-vm-factory'
    $script:repositoryUri = 'https://github.com/Beowxlf/northgate-vm-factory.git'
    $script:commitSha = '0123456789abcdef0123456789abcdef01234567'
    $script:treeSha = '89abcdef0123456789abcdef0123456789abcdef'
    $script:ledgerId = 'northgate-vm-factory-owner-promotion-v1'

    $script:testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngpc-' + [Guid]::NewGuid().ToString('N'))
    $script:installRoot = Join-Path $script:testRoot 'Install'
    $script:stagingRoot = Join-Path $script:testRoot 'Staging'
    $script:stateRoot = Join-Path $script:testRoot 'State'
    foreach ($path in @($script:testRoot, $script:installRoot, $script:stagingRoot, $script:stateRoot)) {
        $null = [IO.Directory]::CreateDirectory($path)
    }
    foreach ($path in @($script:installRoot, $script:stagingRoot, $script:stateRoot)) { Set-TestDirectoryAcl -Path $path }

    $script:ledgerPath = Join-Path $script:stateRoot 'promotion-replay-ledger.json'
    $script:ledgerKeyPath = Join-Path $script:stateRoot 'promotion-replay-ledger.key'
    $ledgerKey = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($ledgerKey) } finally { $rng.Dispose() }
    [IO.File]::WriteAllBytes($script:ledgerKeyPath, $ledgerKey)
    Set-TestFileAcl -Path $script:ledgerKeyPath

    $certificateFolder = Join-Path $script:installRoot 'certificates'
    $null = [IO.Directory]::CreateDirectory($certificateFolder)
    $subject = 'CN=NorthGate Promotion Candidate Ephemeral Test ' + [Guid]::NewGuid().ToString('N')
    $script:testCertificate = New-SelfSignedCertificate -Subject $subject -CertStoreLocation 'Cert:\CurrentUser\My' `
        -Type CodeSigningCert -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable -NotAfter ([DateTime]::UtcNow.AddDays(2))
    $script:certificatePath = Join-Path $certificateFolder 'owner-promotion-public.cer'
    $certificateBytes = $script:testCertificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [IO.File]::WriteAllBytes($script:certificatePath, $certificateBytes)
    Set-TestFileAcl -Path $script:certificatePath
    $script:certificatePin = Get-TestSha256Hex -Bytes $certificateBytes

    $artifactFolder = Join-Path $script:stagingRoot 'release'
    $null = [IO.Directory]::CreateDirectory($artifactFolder)
    $manifestSource = Join-Path $artifactFolder 'NorthGate.VMFactory.Candidate.psd1'
    $moduleSource = Join-Path $artifactFolder 'NorthGate.VMFactory.Candidate.psm1'
    [IO.File]::WriteAllBytes($manifestSource, (New-Object Text.UTF8Encoding($false)).GetBytes("@{ ModuleVersion = '0.0.0-test' }`n"))
    [IO.File]::WriteAllBytes($moduleSource, (New-Object Text.UTF8Encoding($false)).GetBytes("# inert promotion verifier test artifact`n"))
    $script:expectedArtifacts = [object[]]@(
        [ordered]@{
            destinationRelativePath = 'modules/NorthGate.VMFactory.Candidate.psd1'
            id = 'promotion-manifest'
            sha256 = Get-TestSha256Hex -Bytes ([IO.File]::ReadAllBytes($manifestSource))
            sizeBytes = [long](Get-Item -LiteralPath $manifestSource).Length
            sourceRelativePath = 'release/NorthGate.VMFactory.Candidate.psd1'
        },
        [ordered]@{
            destinationRelativePath = 'modules/NorthGate.VMFactory.Candidate.psm1'
            id = 'promotion-module'
            sha256 = Get-TestSha256Hex -Bytes ([IO.File]::ReadAllBytes($moduleSource))
            sizeBytes = [long](Get-Item -LiteralPath $moduleSource).Length
            sourceRelativePath = 'release/NorthGate.VMFactory.Candidate.psm1'
        }
    )
    $script:envelopePath = Join-Path $script:stagingRoot 'promotion-envelope.json'
    $script:signaturePath = Join-Path $script:stagingRoot 'promotion-envelope.sig'

    $commands = @(Get-Command -Module 'NorthGate.VMFactory.PromotionCandidate' | Select-Object -ExpandProperty Name)
    Assert-Promotion -Condition ($commands.Count -eq 1 -and $commands[0] -ceq 'Test-NorthGatePromotionEnvelope') `
        -Message 'The candidate exports an unexpected command surface.'
    $command = Get-Command Test-NorthGatePromotionEnvelope
    foreach ($forbiddenParameter in @('Command', 'Script', 'ScriptBlock', 'PlanId', 'Action', 'Apply', 'Install')) {
        Assert-Promotion -Condition (-not $command.Parameters.ContainsKey($forbiddenParameter)) `
            -Message "The verifier exposes forbidden parameter '$forbiddenParameter'."
    }
    $sourceText = [IO.File]::ReadAllText($moduleSourcePath)
    foreach ($pattern in @(
        '(?i)\b(?:New|Set|Remove|Start|Stop|Checkpoint|Restore|Rename)-VM\b',
        '(?i)\bImport-Module\s+Hyper-V\b',
        '(?i)\bInvoke-Expression\b',
        '(?i)\bInvoke-(?:WebRequest|RestMethod)\b',
        '(?i)\b(?:ssh|scp|sftp)(?:\.exe)?\b'
    )) {
        Assert-Promotion -Condition ($sourceText -notmatch $pattern) -Message "Candidate contains prohibited primitive '$pattern'."
    }

    $validEnvelope = New-TestEnvelope
    Write-TestEnvelope -Envelope $validEnvelope
    $validResult = Invoke-TestVerifier
    Assert-Promotion -Condition ($validResult.accepted -eq $true -and $validResult.status -ceq 'verified-and-nonce-consumed') `
        -Message 'A valid signed envelope was not accepted.'
    Assert-Promotion -Condition ($validResult.operation -ceq 'install-control-plane-candidate' -and $validResult.installed -eq $false) `
        -Message 'The verifier must report install-only verification without claiming installation.'
    Assert-Promotion -Condition ($validResult.applyEnabled -eq $false -and @($validResult.executableActions).Count -eq 0) `
        -Message 'The verifier must preserve apply disabled and zero executable actions.'
    Assert-Promotion -Condition ($validResult.ledgerSequence -eq 1 -and [IO.File]::Exists($script:ledgerPath)) `
        -Message 'The first accepted envelope did not create replay-ledger sequence 1.'
    Assert-TestRejection -ExpectedCode 'NGPC-REPLAY'

    $secondEnvelope = New-TestEnvelope
    Write-TestEnvelope -Envelope $secondEnvelope
    $secondResult = Invoke-TestVerifier
    Assert-Promotion -Condition ($secondResult.ledgerSequence -eq 2) -Message 'A distinct nonce did not advance the authenticated ledger.'

    # Byte-boundary and canonical JSON rejection.
    $baseEnvelope = New-TestEnvelope
    $baseBytes = ConvertTo-TestCanonicalBytes -Value $baseEnvelope
    $baseText = (New-Object Text.UTF8Encoding($false)).GetString($baseBytes)
    $duplicateBytes = (New-Object Text.UTF8Encoding($false)).GetBytes($baseText.Replace('{"actions":[]', '{"actions":[],"actions":[]'))
    Write-TestEnvelopeBytes -Bytes $duplicateBytes
    Assert-TestRejection -ExpectedCode 'NGPC-JSON-DUPLICATE-KEY'

    $caseCollisionBytes = (New-Object Text.UTF8Encoding($false)).GetBytes($baseText.Replace('{"actions":[]', '{"Actions":[],"actions":[]'))
    Write-TestEnvelopeBytes -Bytes $caseCollisionBytes
    Assert-TestRejection -ExpectedCode 'NGPC-JSON-CASE-COLLISION'

    $malformedBytes = New-Object byte[] $baseBytes.Length
    [Array]::Copy($baseBytes, $malformedBytes, $baseBytes.Length)
    $malformedBytes[20] = 0xC3
    Write-TestEnvelopeBytes -Bytes $malformedBytes
    Assert-TestRejection -ExpectedCode 'NGPC-UTF8-MALFORMED'

    $bomBytes = New-Object byte[] ($baseBytes.Length + 3)
    $bomBytes[0] = 0xEF; $bomBytes[1] = 0xBB; $bomBytes[2] = 0xBF
    [Array]::Copy($baseBytes, 0, $bomBytes, 3, $baseBytes.Length)
    Write-TestEnvelopeBytes -Bytes $bomBytes
    Assert-TestRejection -ExpectedCode 'NGPC-UTF8-BOM'

    $spaceBytes = (New-Object Text.UTF8Encoding($false)).GetBytes(' ' + $baseText)
    Write-TestEnvelopeBytes -Bytes $spaceBytes
    Assert-TestRejection -ExpectedCode 'NGPC-JSON-NONCANONICAL'

    $nullBytes = (New-Object Text.UTF8Encoding($false)).GetBytes($baseText.Replace('"actions":[]', '"actions":null'))
    Write-TestEnvelopeBytes -Bytes $nullBytes
    Assert-TestRejection -ExpectedCode 'NGPC-JSON-NULL'

    $floatText = [regex]::Replace($baseText, '"sizeBytes":\d+', '"sizeBytes":1.0', 1)
    Write-TestEnvelopeBytes -Bytes ((New-Object Text.UTF8Encoding($false)).GetBytes($floatText))
    Assert-TestRejection -ExpectedCode 'NGPC-JSON-INTEGER-ONLY'

    $oversized = New-Object byte[] 65537
    for ($i = 0; $i -lt $oversized.Length; $i++) { $oversized[$i] = 0x20 }
    Write-TestEnvelopeBytes -Bytes $oversized -Signature (New-Object byte[] 384)
    Assert-TestRejection -ExpectedCode 'NGPC-FILE-SIZE'

    Write-TestEnvelope -Envelope (New-TestEnvelope)
    [IO.File]::WriteAllBytes($script:signaturePath, (New-Object byte[] 1025))
    Assert-TestRejection -ExpectedCode 'NGPC-FILE-SIZE'

    # Signature and signer trust failures.
    $signedEnvelope = New-TestEnvelope
    Write-TestEnvelope -Envelope $signedEnvelope
    Assert-TestRejection -ExpectedCode 'NGPC-SCHEMA-PATTERN' -Overrides @{ ExpectedSignerCertificateSha256 = 'not-a-pin' }
    Assert-TestRejection -ExpectedCode 'NGPC-CERT-PIN' -Overrides @{ ExpectedSignerCertificateSha256 = ('0' * 64) }
    $badSignature = [IO.File]::ReadAllBytes($script:signaturePath)
    $badSignature[0] = $badSignature[0] -bxor 0x01
    [IO.File]::WriteAllBytes($script:signaturePath, $badSignature)
    Assert-TestRejection -ExpectedCode 'NGPC-SIGNATURE-INVALID'

    $outsideCertificate = Join-Path $script:testRoot 'outside.cer'
    [IO.File]::WriteAllBytes($outsideCertificate, $certificateBytes)
    Set-TestFileAcl -Path $outsideCertificate
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-CERT-BOUNDARY' -Overrides @{ SignerCertificatePath = $outsideCertificate }

    $outsideEnvelope = Join-Path $script:testRoot 'outside.json'
    [IO.File]::WriteAllBytes($outsideEnvelope, [IO.File]::ReadAllBytes($script:envelopePath))
    Set-TestFileAcl -Path $outsideEnvelope
    Assert-TestRejection -ExpectedCode 'NGPC-STAGING-BOUNDARY' -Overrides @{ EnvelopePath = $outsideEnvelope }

    # Install-only, expiry, repository, root, and exact artifact bindings.
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-APPLY-DISABLED' -Mutation { param($e) $e.applyEnabled = $true }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-ACTIONS-EMPTY' -Mutation { param($e) $e.actions = [object[]]@('Create') }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-INSTALL-ONLY' -Mutation { param($e) $e.operation = 'apply-vm' }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-INSTALL-ONLY' -Mutation { param($e) $e.signatureAlgorithm = 'none' }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-SCHEMA-KEYS' -Mutation { param($e) $e.Add('unexpected', 'value') }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-SCHEMA-PATTERN' -Mutation { param($e) $e.nonce = 'too-short' }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-EXPIRED' -Mutation {
        param($e)
        $e.issuedAtUtc = Format-TestUtc ([DateTimeOffset]::UtcNow.AddMinutes(-2))
        $e.expiresAtUtc = Format-TestUtc ([DateTimeOffset]::UtcNow.AddMinutes(-1))
    }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-ISSUED-FUTURE' -Mutation {
        param($e)
        $e.issuedAtUtc = Format-TestUtc ([DateTimeOffset]::UtcNow.AddMinutes(2))
        $e.expiresAtUtc = Format-TestUtc ([DateTimeOffset]::UtcNow.AddMinutes(3))
    }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-LIFETIME' -Mutation {
        param($e)
        $e.issuedAtUtc = Format-TestUtc ([DateTimeOffset]::UtcNow)
        $e.expiresAtUtc = Format-TestUtc ([DateTimeOffset]::UtcNow.AddMinutes(11))
    }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-REPOSITORY-BINDING' -Mutation { param($e) $e.repository.id = 'fork/northgate-vm-factory' }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-REPOSITORY-BINDING' -Mutation { param($e) $e.repository.uri = 'https://github.com/fork/northgate-vm-factory.git' }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-REPOSITORY-BINDING' -Mutation { param($e) $e.repository.commitSha = '1111111111111111111111111111111111111111' }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-REPOSITORY-BINDING' -Mutation { param($e) $e.repository.treeSha = '2222222222222222222222222222222222222222' }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-FIXED-ROOT' -Mutation { param($e) $e.installRoot = 'C:\Program Files\Unapproved' }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-FIXED-ROOT' -Mutation { param($e) $e.stagingRoot = 'C:\ProgramData\Unapproved' }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-ARTIFACT-BINDING' -Mutation { param($e) $e.artifacts[0].sha256 = ('a' * 64) }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-ARTIFACT-BINDING' -Mutation { param($e) $e.artifacts[0].sizeBytes = [long]($e.artifacts[0].sizeBytes + 1) }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-ARTIFACT-SET-HASH' -PreserveArtifactSetHash -Mutation { param($e) $e.artifactSetSha256 = ('b' * 64) }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-ARTIFACT-ORDER' -Mutation {
        param($e)
        $first = $e.artifacts[0]; $e.artifacts[0] = $e.artifacts[1]; $e.artifacts[1] = $first
    }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-ARTIFACT-DUPLICATE' -Mutation { param($e) $e.artifacts[1].sourceRelativePath = $e.artifacts[0].sourceRelativePath }
    Invoke-SignedMutationRejection -ExpectedCode 'NGPC-RELATIVE-PATH' -Mutation { param($e) $e.artifacts[0].sourceRelativePath = '../escape.psm1' }

    # Actual staged artifacts remain authoritative even when signed metadata is otherwise correct.
    $manifestOriginal = [IO.File]::ReadAllBytes($manifestSource)
    [IO.File]::WriteAllBytes($manifestSource, (New-Object Text.UTF8Encoding($false)).GetBytes('tampered'))
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-ARTIFACT-ACTUAL-SIZE'
    [IO.File]::WriteAllBytes($manifestSource, $manifestOriginal)

    $moduleOriginal = [IO.File]::ReadAllBytes($moduleSource)
    $sameLengthTamper = New-Object byte[] $moduleOriginal.Length
    [Array]::Copy($moduleOriginal, $sameLengthTamper, $moduleOriginal.Length)
    $sameLengthTamper[0] = $sameLengthTamper[0] -bxor 0x01
    [IO.File]::WriteAllBytes($moduleSource, $sameLengthTamper)
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-ARTIFACT-ACTUAL-HASH'
    [IO.File]::WriteAllBytes($moduleSource, $moduleOriginal)

    $missingPath = $manifestSource + '.held'
    [IO.File]::Move($manifestSource, $missingPath)
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-ARTIFACT-MISSING'
    [IO.File]::Move($missingPath, $manifestSource)

    # ACL fail-closed checks.
    Set-TestDirectoryAcl -Path $script:stagingRoot -AddEveryoneWriter
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-ACL-WRITER'
    Set-TestDirectoryAcl -Path $script:stagingRoot

    Set-TestFileAcl -Path $script:certificatePath -AddEveryoneWriter
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-ACL-WRITER'
    Set-TestFileAcl -Path $script:certificatePath

    Set-TestFileAcl -Path $script:ledgerKeyPath -AddEveryoneWriter
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-ACL-WRITER'
    Set-TestFileAcl -Path $script:ledgerKeyPath

    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-ACL-POLICY' -Overrides @{ AllowedWriterSids = @('S-1-5-18', $script:currentSid) }

    Set-TestDirectoryAcl -Path $script:stateRoot -AddEveryoneWriter
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-ACL-WRITER'
    Set-TestDirectoryAcl -Path $script:stateRoot

    # Authenticated ledger corruption, wrong key, malformed UTF-8, duplicate keys, and identity drift.
    $ledgerOriginal = [IO.File]::ReadAllBytes($script:ledgerPath)
    $ledgerText = (New-Object Text.UTF8Encoding($false)).GetString($ledgerOriginal)
    $ledgerTamperedText = [regex]::Replace($ledgerText, '"mac":"[0-9a-f]', '"mac":"f', 1)
    if ($ledgerTamperedText -ceq $ledgerText) {
        $ledgerTamperedText = [regex]::Replace($ledgerText, '"mac":"[0-9a-f]', '"mac":"e', 1)
    }
    [IO.File]::WriteAllBytes($script:ledgerPath, (New-Object Text.UTF8Encoding($false)).GetBytes($ledgerTamperedText))
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-LEDGER-MAC' -SkipLedgerInvariant
    [IO.File]::WriteAllBytes($script:ledgerPath, $ledgerOriginal)

    $ledgerMalformed = New-Object byte[] $ledgerOriginal.Length
    [Array]::Copy($ledgerOriginal, $ledgerMalformed, $ledgerOriginal.Length)
    $ledgerMalformed[15] = 0xC3
    [IO.File]::WriteAllBytes($script:ledgerPath, $ledgerMalformed)
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-UTF8-MALFORMED' -SkipLedgerInvariant
    [IO.File]::WriteAllBytes($script:ledgerPath, $ledgerOriginal)

    $duplicateLedgerText = $ledgerText.Replace('{"entries":', '{"entries":[],"entries":')
    [IO.File]::WriteAllBytes($script:ledgerPath, (New-Object Text.UTF8Encoding($false)).GetBytes($duplicateLedgerText))
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-JSON-DUPLICATE-KEY' -SkipLedgerInvariant
    [IO.File]::WriteAllBytes($script:ledgerPath, $ledgerOriginal)

    $keyOriginal = [IO.File]::ReadAllBytes($script:ledgerKeyPath)
    $wrongKey = New-Object byte[] 32
    [Array]::Copy($keyOriginal, $wrongKey, 32)
    $wrongKey[0] = $wrongKey[0] -bxor 0x01
    [IO.File]::WriteAllBytes($script:ledgerKeyPath, $wrongKey)
    Set-TestFileAcl -Path $script:ledgerKeyPath
    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-LEDGER-MAC'
    [IO.File]::WriteAllBytes($script:ledgerKeyPath, $keyOriginal)
    Set-TestFileAcl -Path $script:ledgerKeyPath

    Write-TestEnvelope -Envelope (New-TestEnvelope)
    Assert-TestRejection -ExpectedCode 'NGPC-LEDGER-IDENTITY' -Overrides @{ LedgerId = 'wrong-ledger-id' }

    # A final clean acceptance proves all negative tests preserved recoverability and sequence continuity.
    $finalEnvelope = New-TestEnvelope
    Write-TestEnvelope -Envelope $finalEnvelope
    $finalResult = Invoke-TestVerifier
    Assert-Promotion -Condition ($finalResult.ledgerSequence -eq 3) `
        -Message 'Negative tests changed ledger state or prevented a final valid acceptance.'

    Write-Host "Promotion control candidate validation passed: $script:assertionCount assertions; install not performed; apply disabled; three ephemeral nonces consumed."
}
finally {
    if ($null -ne $script:testCertificate) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $script:testCertificate.Thumbprint) -Force -ErrorAction SilentlyContinue
    }
    Remove-Module -Name 'NorthGate.VMFactory.PromotionCandidate' -Force -ErrorAction SilentlyContinue
    if ($null -ne $script:testRoot -and [IO.Directory]::Exists($script:testRoot)) {
        Remove-Item -LiteralPath $script:testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
