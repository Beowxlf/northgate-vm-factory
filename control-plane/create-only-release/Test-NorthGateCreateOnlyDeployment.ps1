[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:DeploymentAssertions = 0

function Assert-NgcdTest {
    param([bool]$Condition, [string]$Message)
    $script:DeploymentAssertions++
    if (-not $Condition) { throw "DEPLOYMENT ASSERTION FAILED: $Message" }
}

function Assert-NgcdTestThrows {
    param([scriptblock]$Action, [string]$Pattern, [string]$Message)
    $script:DeploymentAssertions++
    try { & $Action; throw "DEPLOYMENT ASSERTION FAILED: $Message (no exception)" }
    catch {
        if ($_.Exception.Message -like 'DEPLOYMENT ASSERTION FAILED:*') { throw }
        if ($_.Exception.Message -cnotmatch $Pattern) {
            throw "DEPLOYMENT ASSERTION FAILED: $Message (got $($_.Exception.Message))"
        }
    }
}

function Get-NgcdTestSha256 {
    param([byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

$root = $PSScriptRoot
$modulePath = Join-Path $root 'NorthGate.VMFactory.CreateOnlyDeployment.psd1'
$deployment = Import-Module $modulePath -Force -PassThru
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcor-deployment-test-' + [guid]::NewGuid().ToString('N'))

function ConvertTo-NgcdTestCanonical {
    param([object]$Value)
    & $deployment {
        param($InputValue)
        ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $InputValue
    } $Value
}

function New-NgcdTestFixture {
    param([string]$FixtureRoot, [string]$ReleaseId, [string]$AuthorizationId)
    $packageRoot = Join-Path $FixtureRoot 'package'
    $null = [IO.Directory]::CreateDirectory($packageRoot)
    $fileValues = [ordered]@{
        'alpha.ps1' = "Set-StrictMode -Version Latest`r`n"
        'beta.txt' = "northgate-create-only-fixture`r`n"
        'NorthGate.CreateOnly.ServiceHost.cs' = "namespace NorthGate.Fixture { internal class Host {} }`r`n"
        'Build-NorthGateCreateOnlyServiceHost.ps1' = "Set-StrictMode -Version Latest`r`n"
    }
    $records = @()
    $oidCharacter = 'a'
    foreach ($entry in $fileValues.GetEnumerator()) {
        $path = Join-Path $packageRoot $entry.Key
        [IO.File]::WriteAllText($path, $entry.Value, (New-Object Text.UTF8Encoding($false)))
        $bytes = [IO.File]::ReadAllBytes($path)
        $records += [pscustomobject][ordered]@{
            artifactKind = 'raw-git-blob'
            path = $entry.Key
            gitMode = '100644'
            gitBlobOid = ([string]$oidCharacter) * 40
            sizeBytes = [int64]$bytes.Length
            sha256 = Get-NgcdTestSha256 $bytes
        }
        $oidCharacter = [char]([int][char]$oidCharacter + 1)
    }
    $serviceHostPath = Join-Path $packageRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $serviceHostBytes = [Text.Encoding]::UTF8.GetBytes('fixture-service-host-bytes')
    [IO.File]::WriteAllBytes($serviceHostPath, $serviceHostBytes)
    $cmsPath = Join-Path $packageRoot 'NorthGate.CreateOnly.ServiceHost.exe.p7s'
    $cmsBytes = [Text.Encoding]::UTF8.GetBytes('fixture-detached-cms-bytes')
    [IO.File]::WriteAllBytes($cmsPath, $cmsBytes)
    $sourceRecord = @($records | Where-Object { $_.path -ceq 'NorthGate.CreateOnly.ServiceHost.cs' })[0]
    $buildRecord = @($records | Where-Object { $_.path -ceq 'Build-NorthGateCreateOnlyServiceHost.ps1' })[0]
    $records += [pscustomobject][ordered]@{
        artifactKind = 'derived-signed-artifact'
        path = 'NorthGate.CreateOnly.ServiceHost.exe'
        sizeBytes = [int64]$serviceHostBytes.Length
        sha256 = Get-NgcdTestSha256 $serviceHostBytes
        buildProvenance = [pscustomobject][ordered]@{
            sourcePath = 'NorthGate.CreateOnly.ServiceHost.cs'
            sourceGitBlobOid = $sourceRecord.gitBlobOid
            sourceSha256 = $sourceRecord.sha256
            buildScriptPath = 'Build-NorthGateCreateOnlyServiceHost.ps1'
            buildScriptGitBlobOid = $buildRecord.gitBlobOid
            buildScriptSha256 = $buildRecord.sha256
            compilerPath = 'C:\Approved\Roslyn\csc.exe'
            compilerSha256 = 'e' * 64
            compilerVersion = '4.0.0.0'
            deterministic = $true
            unsignedSha256 = Get-NgcdTestSha256 $serviceHostBytes
            references = [object[]]@(
                [pscustomobject]@{ path = 'C:\Approved\mscorlib.dll'; sha256 = '1' * 64; fileVersion = '4.0.0.0' },
                [pscustomobject]@{ path = 'C:\Approved\System.dll'; sha256 = '2' * 64; fileVersion = '4.0.0.0' },
                [pscustomobject]@{ path = 'C:\Approved\System.Core.dll'; sha256 = '3' * 64; fileVersion = '4.0.0.0' },
                [pscustomobject]@{ path = 'C:\Approved\System.Management.Automation.dll'; sha256 = '4' * 64; fileVersion = '3.0.0.0' },
                [pscustomobject]@{ path = 'C:\Approved\System.ServiceProcess.dll'; sha256 = '5' * 64; fileVersion = '4.0.0.0' }
            )
        }
        detachedCms = [pscustomobject][ordered]@{
            path = 'NorthGate.CreateOnly.ServiceHost.exe.p7s'
            sizeBytes = [int64]$cmsBytes.Length
            sha256 = Get-NgcdTestSha256 $cmsBytes
            signerCertificateSha256 = '8' * 64
        }
    }
    $manifest = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-release-manifest/v2'
        releaseId = $ReleaseId
        repository = [pscustomobject][ordered]@{
            identity = 'Beowxlf/northgate-vm-factory'
            commit = 'c' * 40
            tree = 'd' * 40
        }
        files = [object[]]$records
    }
    $manifestJson = ConvertTo-NgcdTestCanonical $manifest
    $manifestHash = Get-NgcdTestSha256 ([Text.Encoding]::UTF8.GetBytes($manifestJson))
    $authorization = [pscustomobject][ordered]@{
        authorizationId = $AuthorizationId
        releaseManifestSha256 = $manifestHash
        repository = [pscustomobject][ordered]@{ releaseId = $ReleaseId }
        host = [pscustomobject][ordered]@{ hostId = 'nghost-transaction-fixture' }
        identity = [pscustomobject][ordered]@{
            releaseSignerCertificateSha256 = '8' * 64
            receiptSignerCertificateSha256 = '9' * 64
            serviceIdentitySid = 'S-1-5-21-100-200-300-1002'
            sshIdentitySid = 'S-1-5-21-100-200-300-1001'
        }
    }
    $authorizationHash = Get-NgcdTestSha256 ([Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-NgcdTestCanonical $authorization)
    ))
    [pscustomobject]@{
        PackageRoot = $packageRoot
        Manifest = $manifest
        Authorization = $authorization
        AuthorizationSha256 = $authorizationHash
        PolicyBytes = [Text.Encoding]::UTF8.GetBytes('new-policy-fixture')
        SshBytes = [Text.Encoding]::UTF8.GetBytes('new-sshd-fixture')
    }
}

try {
    $exports = @(Get-Command -Module $deployment.Name | Select-Object -ExpandProperty Name | Sort-Object)
    $expectedExports = @(
        @('Invoke-NorthGateCreateOnlyInstallTransaction','Invoke-NorthGateCreateOnlyRollbackTransaction',
            'Test-NorthGateCreateOnlyInstalledRelease') | Sort-Object
    )
    Assert-NgcdTest (($exports -join '|') -ceq ($expectedExports -join '|')) `
        'Deployment module exports only its three bounded entrypoints.'

    $source = [IO.File]::ReadAllText((Join-Path $root 'NorthGate.VMFactory.CreateOnlyDeployment.psm1'))
    Assert-NgcdTest ($source -cnotmatch '(?m)\b(?:New-VM|Set-VM|Remove-VM|Start-VM|Stop-VM|New-VHD)\b') `
        'Deployment module contains no Hyper-V mutation primitive.'
    Assert-NgcdTest ($source -cnotmatch '(?m)\bRemove-Item\b|Invoke-Expression|ScriptBlock::Create') `
        'Deployment module contains no recursive deletion or dynamic evaluation primitive.'
    Assert-NgcdTest ($source -match "FixedSshSourceCidr = '10\.10\.100\.20/32'" -and
        $source -match 'addr=10\.10\.100\.20' -and
        $source -cnotmatch "FixedSshSourceCidr = '10\.10\.100\.11/32'") `
        'Forced-command SSH is source-restricted to the authorized management workstation.'
    Assert-NgcdTest ($source -cnotmatch "'    PermitUserEnvironment no'") `
        'Managed Match blocks omit the Windows OpenSSH-incompatible PermitUserEnvironment directive.'
    Assert-NgcdTest ($source -match 'user=\.\\\$SshUserName,host=') `
        'Windows OpenSSH effective-policy validation resolves the dedicated account as a local user.'
    Assert-NgcdTest ($source -match 'Set-NgcdProtectedDirectoryAcl \$stateRoot[^\r\n]*\$serviceRead' -and
        $source -match 'Set-NgcdProtectedDirectoryAcl \(Join-Path \$stateRoot ''deployment-transactions''\)[\s\S]{0,160}\$serviceRead') `
        'Runtime service has read-only deployment-state access.'
    Assert-NgcdTest ($source -match 'GetOwner\(\[System\.Security\.Principal\.SecurityIdentifier\]\)' -and
        $source -match 'GetAccessRules\([\s\S]{0,100}\$true, \$true, \[System\.Security\.Principal\.SecurityIdentifier\]' -and
        $source -match 'Get-NgcdAclRuleFingerprint' -and
        $source -cnotmatch 'GetSecurityDescriptor(?:BinaryForm|SddlForm)\(') `
        'ACL readback binds the protected owner and exact authorization rules without host-normalized representation metadata.'
    Assert-NgcdTest ($source -match 'Get-NgcdRawAclFingerprint' -and
        $source -match 'ControlFlags\]::DiscretionaryAclProtected' -and
        $source -match '\$wantedOwner -cne \$actualOwner[\s\S]{0,220}\$wantedDacl -cne \$actualDacl' -and
        $source -cnotmatch '\$wanted\.GetBinaryForm\(') `
        'Rollback ACL readback binds owner, group, protection, and every raw ACE without descriptor-order metadata.'

    $key = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    $normalRoot = Join-Path $testRoot 'normal'
    $context = & $deployment { param($Path,$Key) New-NgcdLocalTestContext $Path $Key } $normalRoot $key
    [IO.File]::WriteAllText($context.CurrentPointerPath, 'old-pointer', (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($context.PolicyPath, 'old-policy', (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($context.SshConfigPath, 'old-sshd', (New-Object Text.UTF8Encoding($false)))
    $ledgerPath = Join-Path $context.StateRoot 'ledger.keep'
    [IO.File]::WriteAllText($ledgerPath, 'durable-ledger-must-survive', (New-Object Text.UTF8Encoding($false)))
    $fixture = New-NgcdTestFixture (Join-Path $normalRoot 'input') 'ngcor-transaction-test-01' `
        'ngdeploy-transaction-test-01'
    $result = & $deployment {
        param($Context,$Fixture)
        Invoke-NgcdFileInstallTransaction $Context $Fixture.PackageRoot $Fixture.Manifest `
            $Fixture.Authorization $Fixture.AuthorizationSha256 $Fixture.PolicyBytes $Fixture.SshBytes 'None'
    } $context $fixture
    Assert-NgcdTest ($result.status -ceq 'verified' -and $result.phase -ceq 'Verified' -and
        $result.transactionId -cmatch '^ngtxn-[a-f0-9]{64}$') 'Normal transaction reaches Verified.'
    Assert-NgcdTest ((Test-Path -LiteralPath $result.releaseRoot -PathType Container) -and
        (Test-Path -LiteralPath (Join-Path $result.releaseRoot 'installed-release.json') -PathType Leaf)) `
        'Verified transaction atomically exposes one versioned release.'
    Assert-NgcdTest ([IO.File]::ReadAllText($context.PolicyPath) -ceq 'new-policy-fixture' -and
        [IO.File]::ReadAllText($context.SshConfigPath) -ceq 'new-sshd-fixture') `
        'Verified transaction writes and reads back managed configuration.'
    $idempotent = & $deployment {
        param($Context,$Fixture)
        Invoke-NgcdFileInstallTransaction $Context $Fixture.PackageRoot $Fixture.Manifest `
            $Fixture.Authorization $Fixture.AuthorizationSha256 $Fixture.PolicyBytes $Fixture.SshBytes 'None'
    } $context $fixture
    Assert-NgcdTest ($idempotent.status -ceq 'already-verified' -and
        $idempotent.transactionId -ceq $result.transactionId) 'Verified replay is idempotent and tuple-bound.'
    Assert-NgcdTestThrows {
        & $deployment {
            param($Context,$Fixture,$ChangedPolicy)
            Invoke-NgcdFileInstallTransaction $Context $Fixture.PackageRoot $Fixture.Manifest `
                $Fixture.Authorization $Fixture.AuthorizationSha256 $ChangedPolicy $Fixture.SshBytes 'None'
        } $context $fixture ([Text.Encoding]::UTF8.GetBytes('different-policy-fixture'))
    } '^NGCOR-DEPLOYMENT-VERIFIED-REPLAY-CONFIGURATION-MISMATCH$' `
        'Install replay cannot masquerade as a backend-policy promotion.'

    $tamperedFile = Join-Path $result.releaseRoot 'beta.txt'
    $originalBytes = [IO.File]::ReadAllBytes($tamperedFile)
    try {
        [IO.File]::WriteAllText($tamperedFile, 'tampered', (New-Object Text.UTF8Encoding($false)))
        Assert-NgcdTestThrows {
            Test-NorthGateCreateOnlyInstalledRelease -Context $context -Manifest $fixture.Manifest `
                -Authorization $fixture.Authorization -AuthorizationSha256 $fixture.AuthorizationSha256
        } '^NGCOR-DEPLOYMENT-INSTALLED-FILE-HASH-MISMATCH$' 'Installed-file tampering is rejected.'
    }
    finally { [IO.File]::WriteAllBytes($tamperedFile, $originalBytes) }

    Assert-NgcdTestThrows {
        & $deployment {
            param($Context,$TransactionId,$ReleaseId,$ManifestHash)
            Invoke-NgcdFileRollbackTransaction $Context $TransactionId $ReleaseId $ManifestHash ('f' * 64)
        } $context $result.transactionId $fixture.Manifest.releaseId $fixture.Authorization.releaseManifestSha256
    } '^NGCOR-ROLLBACK-BINDING-MISMATCH$' 'Rollback rejects the wrong receipt binding before mutation.'
    $stillVerified = & $deployment {
        param($Context,$Path) Read-NgcdJournal $Context $Path
    } $context (Join-Path $context.TransactionsRoot ($result.transactionId + '.json'))
    Assert-NgcdTest ($stillVerified.phase -ceq 'Verified') 'Pre-mutation rollback rejection does not poison state.'

    $rollback = & $deployment {
        param($Context,$TransactionId,$ReleaseId,$ManifestHash,$ReceiptHash)
        Invoke-NgcdFileRollbackTransaction $Context $TransactionId $ReleaseId $ManifestHash $ReceiptHash
    } $context $result.transactionId $fixture.Manifest.releaseId `
        $fixture.Authorization.releaseManifestSha256 $result.backupReceiptSha256
    Assert-NgcdTest ($rollback.phase -ceq 'RolledBack' -and $rollback.durableStatePreserved) `
        'Bound rollback reaches RolledBack and declares durable state preserved.'
    Assert-NgcdTest ([IO.File]::ReadAllText($context.CurrentPointerPath) -ceq 'old-pointer' -and
        [IO.File]::ReadAllText($context.PolicyPath) -ceq 'old-policy' -and
        [IO.File]::ReadAllText($context.SshConfigPath) -ceq 'old-sshd') `
        'Rollback restores exact prior pointer, policy, and SSH bytes.'
    Assert-NgcdTest ([IO.File]::ReadAllText($ledgerPath) -ceq 'durable-ledger-must-survive') `
        'Rollback leaves unrelated durable state byte-for-byte unchanged.'
    Assert-NgcdTest (-not (Test-Path -LiteralPath $result.releaseRoot) -and
        (Test-Path -LiteralPath $rollback.quarantinedReleaseRoot -PathType Container)) `
        'Rollback quarantines release code instead of deleting it.'

    foreach ($crashPhase in @('Prepared','Activated')) {
        $phaseRoot = Join-Path $testRoot $crashPhase.ToLowerInvariant()
        $phaseKey = New-Object byte[] 32
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($phaseKey)
        $phaseContext = & $deployment { param($Path,$Key) New-NgcdLocalTestContext $Path $Key } `
            $phaseRoot $phaseKey
        [IO.File]::WriteAllText($phaseContext.PolicyPath, "old-$crashPhase-policy", (New-Object Text.UTF8Encoding($false)))
        [IO.File]::WriteAllText($phaseContext.SshConfigPath, "old-$crashPhase-sshd", (New-Object Text.UTF8Encoding($false)))
        $phaseFixture = New-NgcdTestFixture (Join-Path $phaseRoot 'input') `
            ("ngcor-crash-$($crashPhase.ToLowerInvariant())-01") `
            ("ngdeploy-crash-$($crashPhase.ToLowerInvariant())-01")
        Assert-NgcdTestThrows {
            & $deployment {
                param($Context,$Fixture,$Phase)
                Invoke-NgcdFileInstallTransaction $Context $Fixture.PackageRoot $Fixture.Manifest `
                    $Fixture.Authorization $Fixture.AuthorizationSha256 $Fixture.PolicyBytes $Fixture.SshBytes $Phase
            } $phaseContext $phaseFixture $crashPhase
        } ("^NGCOR-DEPLOYMENT-TEST-CRASH-$($crashPhase.ToUpperInvariant())$") `
            "Injected $crashPhase crash leaves recoverable evidence."
        Assert-NgcdTestThrows {
            & $deployment {
                param($Context,$Fixture)
                Invoke-NgcdFileInstallTransaction $Context $Fixture.PackageRoot $Fixture.Manifest `
                    $Fixture.Authorization $Fixture.AuthorizationSha256 $Fixture.PolicyBytes $Fixture.SshBytes 'None'
            } $phaseContext $phaseFixture
        } '^NGCOR-DEPLOYMENT-RECOVERED-RERUN-REQUIRED$' `
            "$crashPhase journal triggers bounded recovery before any retry."
        $phaseBinding = & $deployment {
            param($Manifest,$Authorization,$Hash) New-NgcdBinding $Manifest $Authorization $Hash
        } $phaseFixture.Manifest $phaseFixture.Authorization $phaseFixture.AuthorizationSha256
        $phaseTransactionId = & $deployment {
            param($Binding,$Id) New-NgcdTransactionId $Binding $Id
        } $phaseBinding $phaseFixture.Authorization.authorizationId
        $phaseJournalPath = Join-Path $phaseContext.TransactionsRoot ($phaseTransactionId + '.json')
        $phaseJournal = & $deployment {
            param($Context,$Path) Read-NgcdJournal $Context $Path
        } $phaseContext $phaseJournalPath
        Assert-NgcdTest ($phaseJournal.phase -ceq 'Recovered') "$crashPhase recovery is durably recorded."
        Assert-NgcdTest ([IO.File]::ReadAllText($phaseContext.PolicyPath) -ceq "old-$crashPhase-policy" -and
            [IO.File]::ReadAllText($phaseContext.SshConfigPath) -ceq "old-$crashPhase-sshd") `
            "$crashPhase recovery restores the exact prior configuration."
        $rawJournal = [IO.File]::ReadAllText($phaseJournalPath)
        [IO.File]::WriteAllText(
            $phaseJournalPath, $rawJournal.Replace('"phase":"Recovered"','"phase":"Verified"'),
            (New-Object Text.UTF8Encoding($false))
        )
        Assert-NgcdTestThrows {
            & $deployment { param($Context,$Path) Read-NgcdJournal $Context $Path } `
                $phaseContext $phaseJournalPath
        } '^NGCOR-DEPLOYMENT-STATE-AUTHENTICATION-FAILED$' `
            "$crashPhase journal tampering is detected by its MAC."
    }

    $lockRoot = Join-Path $testRoot 'lock'
    $lockKey = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($lockKey)
    $lockContext = & $deployment { param($Path,$Key) New-NgcdLocalTestContext $Path $Key } $lockRoot $lockKey
    $lockFixture = New-NgcdTestFixture (Join-Path $lockRoot 'input') 'ngcor-lock-test-01' 'ngdeploy-lock-test-01'
    $held = & $deployment { param($Name) Enter-NgcdDeploymentLock $Name } $lockContext.LockName
    try {
        Assert-NgcdTestThrows {
            & $deployment {
                param($Context,$Fixture)
                Invoke-NgcdFileInstallTransaction $Context $Fixture.PackageRoot $Fixture.Manifest `
                    $Fixture.Authorization $Fixture.AuthorizationSha256 $Fixture.PolicyBytes $Fixture.SshBytes 'None'
            } $lockContext $lockFixture
        } '^NGCOR-DEPLOYMENT-LOCK-BUSY$' 'Host-wide deployment lock rejects concurrent writers.'
    }
    finally { & $deployment { param($Lock) Exit-NgcdDeploymentLock $Lock } $held }

    Write-Output "PASS: $script:DeploymentAssertions deployment assertions"
}
finally {
    Remove-Module NorthGate.VMFactory.CreateOnlyDeployment -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
