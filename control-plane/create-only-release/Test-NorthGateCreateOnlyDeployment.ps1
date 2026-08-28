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

$dpapiRoot = Join-Path $testRoot 'dpapi-state'
$null = [IO.Directory]::CreateDirectory($dpapiRoot)
$firstProductionKey = & $deployment {
    param($StateRoot) Get-NgcdProductionMacKey $StateRoot
} $dpapiRoot
$secondProductionKey = & $deployment {
    param($StateRoot) Get-NgcdProductionMacKey $StateRoot
} $dpapiRoot
Assert-NgcdTest ($firstProductionKey -is [byte[]] -and $firstProductionKey.Length -eq 32) `
    'A clean process can initialize the LocalMachine DPAPI deployment-state key.'
Assert-NgcdTest ($secondProductionKey -is [byte[]] -and $secondProductionKey.Length -eq 32 -and
    (Get-NgcdTestSha256 $firstProductionKey) -ceq (Get-NgcdTestSha256 $secondProductionKey)) `
    'A clean process can reopen the same LocalMachine DPAPI deployment-state key.'

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
        initialPolicy = [pscustomobject][ordered]@{
            applyEnabled = $false
            executableActions = [object[]]@()
            canaryStage = 'disabled'
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
        @('Invoke-NorthGateCreateOnlyInstallTransaction','Invoke-NorthGateCreateOnlyInitialActivationTransaction',
            'Invoke-NorthGateCreateOnlyRollbackTransaction',
            'Test-NorthGateCreateOnlyInstalledRelease') | Sort-Object
    )
    Assert-NgcdTest (($exports -join '|') -ceq ($expectedExports -join '|')) `
        'Deployment module exports only its four bounded entrypoints.'

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
    Assert-NgcdTest ($source.Contains("('Match User ' + `$SshUserName + ',.\' + `$SshUserName")) `
        'Managed SSH policy matches both wire and local-account forms of the dedicated Windows user.'
    Assert-NgcdTest (([regex]::Matches($source, 'return ,\$key')).Count -eq 2) `
        'Production DPAPI key reads preserve the byte-array type required by the deployment context.'
    Assert-NgcdTest ($source -match [regex]::Escape("`$signer.DigestAlgorithm = New-Object System.Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1')")) `
        'Production deployment receipts explicitly use SHA-256 CMS signatures.'
    Assert-NgcdTest ($source -match 'Invoke-CimMethod -ClassName Win32_Service -MethodName Create' -and
        $source -match 'Invoke-CimMethod -InputObject \$existing -MethodName Change' -and
        $source -cnotmatch "Invoke-NgcdSc @\('create'" -and $source -cnotmatch "Invoke-NgcdSc @\('config'") `
        'Service registration uses the native Windows API for quoted Program Files command lines.'
    Assert-NgcdTest ($source -match '\$startMode = if \(\$InstallEnabled\) \{ ''Automatic'' \} else \{ ''Disabled'' \}' -and
        $source -match '\$expectedState = if \(\$InstallEnabled\) \{ ''Running'' \} else \{ ''Stopped'' \}' -and
        $source -match '\[bool\]\$Authorization\.initialPolicy\.applyEnabled') `
        'Installation preserves the authorized disabled service posture instead of starting the backend.'
    $firstSsh = & $deployment {
        New-NgcdManagedSshConfiguration 'Port 22' 'northgate-vmfactory' 'C:\Factory\Release-One'
    }
    $upgradedSsh = & $deployment {
        param($Configuration)
        New-NgcdManagedSshConfiguration $Configuration 'northgate-vmfactory' 'C:\Factory\Release-Two'
    } $firstSsh
    Assert-NgcdTest (([regex]::Matches(
            $upgradedSsh, [regex]::Escape('# BEGIN NORTHGATE CREATE-ONLY MANAGED BLOCK')
        )).Count -eq 1 -and
        $upgradedSsh -match [regex]::Escape('C:\Factory\Release-Two') -and
        $upgradedSsh -notmatch [regex]::Escape('C:\Factory\Release-One')) `
        'An upgrade atomically replaces exactly one prior managed SSH block.'
    Assert-NgcdTestThrows {
        & $deployment {
            New-NgcdManagedSshConfiguration `
                "Port 22`r`n# BEGIN NORTHGATE CREATE-ONLY MANAGED BLOCK`r`n" `
                'northgate-vmfactory' 'C:\Factory\Release-Two'
        }
    } '^NGCOR-DEPLOYMENT-SSH-CONFIGURATION-INVALID$' `
        'A partial prior managed SSH block remains fail closed.'
    $disabledAuthorization = [pscustomobject]@{
        identity = [pscustomobject]@{
            sshIdentitySid = 'S-1-5-21-100-200-300-1001'
            serviceIdentitySid = 'S-1-5-21-100-200-300-1002'
            releaseSignerCertificateSha256 = '8' * 64
        }
        initialPolicy = [pscustomobject]@{
            applyEnabled = $false
            executableActions = [object[]]@()
            canaryStage = 'disabled'
        }
    }
    $disabledInstalledPolicy = & $deployment {
        param($Authorization)
        New-NgcdInstalledPolicy $Authorization 'ngcor-disabled-policy-test' ('a' * 64) ('b' * 64) ('c' * 64)
    } $disabledAuthorization
    Assert-NgcdTest (-not $disabledInstalledPolicy.applyEnabled -and
        @($disabledInstalledPolicy.executableActions).Count -eq 0 -and
        $disabledInstalledPolicy.canaryStage -ceq 'disabled' -and
        $disabledInstalledPolicy.initialActivationSha256 -ceq '' -and
        $disabledInstalledPolicy.backendPolicySha256 -ceq ('b' * 64)) `
        'An active signed backend bundle cannot override the host authorization initialPolicy=false gate.'
    Assert-NgcdTest ($source -match 'function Invoke-NorthGateCreateOnlyInitialActivationTransaction' -and
        $source -match 'New-NgcdCurrentUserApprovalSignature' -and
        $source -match 'Test-NgcdInitialActivationState' -and
        $source -match 'NGCOR-INITIAL-ACTIVATION-OUTCOME-UNKNOWN') `
        'Initial activation is an approval-signed, installed-release-bound transaction with fail-closed recovery.'
    $activationInstalled = [pscustomobject]@{
        releaseId = 'ngcor-activation-contract-test'
        releaseManifestSha256 = '1' * 64
        deploymentAuthorizationSha256 = '2' * 64
        backendPolicySha256 = '3' * 64
        dataBundleSha256 = '4' * 64
        repositoryCommit = '5' * 40
        repositoryTree = '6' * 40
    }
    $activationManifest = [pscustomobject]@{
        releaseId = $activationInstalled.releaseId
        repository = [pscustomobject]@{
            commit = $activationInstalled.repositoryCommit
            tree = $activationInstalled.repositoryTree
        }
    }
    $activationAuthorization = [pscustomobject]@{
        initialPolicy = [pscustomobject]@{
            applyEnabled = $false; executableActions = [object[]]@(); canaryStage = 'disabled'
        }
    }
    $activation = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-initial-activation/v1'
        activationId = 'ngactivate-' + ('7' * 64)
        changeId = 'NG-CHG-20260828-ACTIVATION'
        authorizationSha256 = $activationInstalled.deploymentAuthorizationSha256
        releaseManifestSha256 = $activationInstalled.releaseManifestSha256
        backendPolicySha256 = $activationInstalled.backendPolicySha256
        dataBundleSha256 = $activationInstalled.dataBundleSha256
        repository = [pscustomobject][ordered]@{
            identity = 'Beowxlf/northgate-vm-factory'
            commit = $activationInstalled.repositoryCommit
            tree = $activationInstalled.repositoryTree
        }
        fromStage = 'disabled'; toStage = 'debian-canary'; applyEnabled = $true
        executableActions = [object[]]@('Create'); readinessEvidenceSha256 = '8' * 64
        issuedAtUtc = '2026-08-28T12:00:00Z'; expiresAtUtc = '2026-08-28T12:01:00Z'
        approverSid = 'S-1-5-21-100-200-300-400'; nonce = '9' * 64
    }
    $activationValid = & $deployment {
        param($Activation,$Installed,$Manifest,$Authorization)
        Assert-NgcdInitialActivationContract $Activation $Installed $Manifest $Authorization `
            $Installed.deploymentAuthorizationSha256 '2026-08-28T12:00:30Z'
    } $activation $activationInstalled $activationManifest $activationAuthorization
    Assert-NgcdTest $activationValid `
        'Exact signed-activation content is valid only inside its short registration window.'
    $activation.backendPolicySha256 = 'a' * 64
    Assert-NgcdTestThrows {
        & $deployment {
            param($Activation,$Installed,$Manifest,$Authorization)
            Assert-NgcdInitialActivationContract $Activation $Installed $Manifest $Authorization `
                $Installed.deploymentAuthorizationSha256 '2026-08-28T12:00:30Z'
        } $activation $activationInstalled $activationManifest $activationAuthorization
    } '^NGCOR-INITIAL-ACTIVATION-CONTRACT-INVALID$' `
        'Initial activation rejects a backend-policy hash substitution.'
    $activation.backendPolicySha256 = $activationInstalled.backendPolicySha256
    Assert-NgcdTestThrows {
        & $deployment {
            param($Activation,$Installed,$Manifest,$Authorization)
            Assert-NgcdInitialActivationContract $Activation $Installed $Manifest $Authorization `
                $Installed.deploymentAuthorizationSha256 '2026-08-28T12:02:00Z'
        } $activation $activationInstalled $activationManifest $activationAuthorization
    } '^NGCOR-INITIAL-ACTIVATION-CONTRACT-INVALID$' `
        'Initial activation rejects registration outside the signed validity window.'
    Assert-NgcdTest ($source -match 'Set-NgcdProtectedDirectoryAcl \$stateRoot[^\r\n]*\$serviceRead' -and
        $source -match 'Set-NgcdProtectedDirectoryAcl \(Join-Path \$stateRoot ''deployment-transactions''\)[\s\S]{0,160}\$serviceRead') `
        'Runtime service has read-only deployment-state access.'
    Assert-NgcdTest ($source -match 'function Set-NgcdServiceQueryIdentity' -and
        $source -match '0x0004, \$sid' -and
        $source -match 'Set-NgcdServiceQueryIdentity \$ExpectedSshSid' -and
        $source -notmatch 'Set-NgcdServiceQueryIdentity[\s\S]{0,2500}0x0010|Set-NgcdServiceQueryIdentity[\s\S]{0,2500}0x0020') `
        'Dedicated SSH identity receives only SERVICE_QUERY_STATUS on the factory service.'
    Assert-NgcdTest ($source -match 'securityDescriptorSddl = Get-NgcdServiceSecurityDescriptor' -and
        $source -match 'Invoke-NgcdSc @\(''sdset'',\$script:ServiceName,\(\[string\]\$Configuration\.securityDescriptorSddl\)\)') `
        'Service security descriptor is captured and exactly restored by rollback.'
    Assert-NgcdTest ($source -match 'function Restore-NgcdServiceConfiguration' -and
        $source -match 'Invoke-CimMethod -InputObject \$current -MethodName Change' -and
        $source -match 'Invoke-CimMethod -ClassName Win32_Service -MethodName Create' -and
        $source -notmatch '''config'',\$script:ServiceName,''binPath=''' ) `
        'Rollback restores quoted service paths through the native Windows service API.'
    Assert-NgcdTest ($source -match "Verified = @\('RollbackPending','OutcomeUnknown'\)" -and
        $source -match "RollbackPending = @\('RolledBack','OutcomeUnknown'\)" -and
        $source -match 'NGCOR-DEPLOYMENT-ROLLBACK-RETRY-REQUIRED') `
        'An interrupted rollback remains bound and explicitly retryable instead of becoming ambiguous.'
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
    $installedRecord = Get-Content -LiteralPath (Join-Path $result.releaseRoot 'installed-release.json') `
        -Raw | ConvertFrom-Json
    Assert-NgcdTest ($installedRecord.serviceName -ceq 'NorthGateCreateOnly' -and
        $installedRecord.serviceHostFileName -ceq 'NorthGate.CreateOnly.ServiceHost.exe') `
        'Installed evidence binds both the registered service name and signed host filename.'
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

    $runtimeBackendRoot = Join-Path (Join-Path $context.StateRoot 'backend') `
        ([string]$fixture.Manifest.releaseId)
    $null = [IO.Directory]::CreateDirectory($runtimeBackendRoot)
    [IO.File]::WriteAllText((Join-Path $runtimeBackendRoot 'state-key.dpapi'),
        'runtime-state-must-be-recoverable', (New-Object Text.UTF8Encoding($false)))
    & $deployment {
        param($Context,$TransactionId,$BackendRoot)
        $path = Join-Path $Context.TransactionsRoot ($TransactionId + '.json')
        $journal = Read-NgcdJournal $Context $path
        $journal.paths.backendStateRoot = $BackendRoot
        Write-NgcdProtectedRecord $path $journal $Context.MacKey
    } $context $result.transactionId $runtimeBackendRoot

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
    Assert-NgcdTest (-not (Test-Path -LiteralPath $runtimeBackendRoot) -and
        (Test-Path -LiteralPath $rollback.quarantinedBackendStateRoot -PathType Container) -and
        [IO.File]::ReadAllText((Join-Path $rollback.quarantinedBackendStateRoot 'state-key.dpapi')) `
            -ceq 'runtime-state-must-be-recoverable') `
        'Rollback quarantines release-bound backend state so the same release can be reinstalled.'

    $retryRoot = Join-Path $testRoot 'rollback-retry'
    $retryKey = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($retryKey)
    $retryContext = & $deployment { param($Path,$Key) New-NgcdLocalTestContext $Path $Key } `
        $retryRoot $retryKey
    [IO.File]::WriteAllText($retryContext.CurrentPointerPath, 'retry-old-pointer',
        (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($retryContext.PolicyPath, 'retry-old-policy',
        (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($retryContext.SshConfigPath, 'retry-old-sshd',
        (New-Object Text.UTF8Encoding($false)))
    $retryFixture = New-NgcdTestFixture (Join-Path $retryRoot 'input') `
        'ngcor-rollback-retry-01' 'ngdeploy-rollback-retry-01'
    $retryInstall = & $deployment {
        param($Context,$Fixture)
        Invoke-NgcdFileInstallTransaction $Context $Fixture.PackageRoot $Fixture.Manifest `
            $Fixture.Authorization $Fixture.AuthorizationSha256 $Fixture.PolicyBytes $Fixture.SshBytes 'None'
    } $retryContext $retryFixture
    $quarantineConflict = Join-Path $retryContext.QuarantineRoot `
        ($retryInstall.transactionId + '-rollback')
    $null = [IO.Directory]::CreateDirectory($quarantineConflict)
    Assert-NgcdTestThrows {
        & $deployment {
            param($Context,$TransactionId,$ReleaseId,$ManifestHash,$ReceiptHash)
            Invoke-NgcdFileRollbackTransaction $Context $TransactionId $ReleaseId $ManifestHash $ReceiptHash
        } $retryContext $retryInstall.transactionId $retryFixture.Manifest.releaseId `
            $retryFixture.Authorization.releaseManifestSha256 $retryInstall.backupReceiptSha256
    } '^NGCOR-DEPLOYMENT-QUARANTINE-TARGET-EXISTS$' `
        'A post-restore quarantine conflict leaves a retryable rollback record.'
    $retryPending = & $deployment {
        param($Context,$Path) Read-NgcdJournal $Context $Path
    } $retryContext (Join-Path $retryContext.TransactionsRoot ($retryInstall.transactionId + '.json'))
    Assert-NgcdTest ($retryPending.phase -ceq 'RollbackPending') `
        'A partially completed rollback is recorded as RollbackPending.'
    Assert-NgcdTestThrows {
        & $deployment {
            param($Context,$Fixture)
            Invoke-NgcdFileInstallTransaction $Context $Fixture.PackageRoot $Fixture.Manifest `
                $Fixture.Authorization $Fixture.AuthorizationSha256 $Fixture.PolicyBytes $Fixture.SshBytes 'None'
        } $retryContext $retryFixture
    } '^NGCOR-DEPLOYMENT-ROLLBACK-RETRY-REQUIRED$' `
        'Install replay cannot bypass a pending rollback.'
    [IO.Directory]::Delete($quarantineConflict)
    $retryRollback = & $deployment {
        param($Context,$TransactionId,$ReleaseId,$ManifestHash,$ReceiptHash)
        Invoke-NgcdFileRollbackTransaction $Context $TransactionId $ReleaseId $ManifestHash $ReceiptHash
    } $retryContext $retryInstall.transactionId $retryFixture.Manifest.releaseId `
        $retryFixture.Authorization.releaseManifestSha256 $retryInstall.backupReceiptSha256
    Assert-NgcdTest ($retryRollback.phase -ceq 'RolledBack' -and
        [IO.File]::ReadAllText($retryContext.CurrentPointerPath) -ceq 'retry-old-pointer' -and
        [IO.File]::ReadAllText($retryContext.PolicyPath) -ceq 'retry-old-policy' -and
        [IO.File]::ReadAllText($retryContext.SshConfigPath) -ceq 'retry-old-sshd') `
        'The exact bound rollback retries idempotently and restores the prior configuration.'

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
# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDKMmwmFnaj3aNL
# UFAJI8O/RX7EhgY6Nj9w31Kde/O2Y6CCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIHt7qUlH8MznJkI6jtqTycvaDO569ZrPHPiUYCvE3Y5rMA0GCSqG
# SIb3DQEBAQUABIIBgJlQzPxQgnNPpu+LfLG5pGX0TIBlljeHxjrixfs3iHfFoZJw
# CaH0erCoPc/VdPx+EfWP4Cjdbcpk+X35+OchxsDWYSgKHOM+SgSxE8U4joNfo5wp
# pjeSrFKORaRZXO5AmNx83jJpTq3aKzqZecEcDw/u4WM8zAfuswxQkL7O9LvsXKff
# Cf6hw6GkcvMwHY3u3An/Q5OhHqKmgUS5quBMirqRL4HpkmT5GKIrkLzkZyI6hryd
# 3YxXTXj4QC3rOxjbqwXfDCIJYGfef0Pwc+gKEYYvFbkngqywMTZB1yopCayLuudT
# XxfWF6oVYiaA/eQElQUv6SZcgpG2Bw+oiJA9CD4Ypfl/0yA9fITUncpa9bs47xZr
# xoJtjDGtAmeKAjlguyk0CJLiOhyoPa+119IuKsASnqGpCRF0itvP/+SZp4xcCvUK
# dubF/vSrCvUfk+GVRFKjdLwdi/OFgQkM9Ee75A0JaAz55tBv+LiXn7bZZQ4vtSPW
# wKJG7f+dNZ9Vh6Zg/w==
# SIG # End signature block
