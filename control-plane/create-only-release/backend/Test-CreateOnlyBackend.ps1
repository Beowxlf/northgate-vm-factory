[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$modulePath = Join-Path $root 'NorthGate.VMFactory.CreateOnlyBackend.psd1'
$protocolPath = Join-Path (Split-Path -Parent $root) 'NorthGate.VMFactory.CreateOnlyProtocol.psd1'
Import-Module $protocolPath -Force -ErrorAction Stop
$module = Import-Module $modulePath -Force -PassThru -ErrorAction Stop
Import-Module $protocolPath -Force -Global -ErrorAction Stop
$script:Assertions = 0

function Assert-NgcbTest {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Assert-NgcbThrows {
    param([scriptblock]$Action, [string]$Pattern, [string]$Message)
    $script:Assertions++
    try { & $Action; throw "ASSERTION FAILED: $Message (no exception)" }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "ASSERTION FAILED: $Message (got '$($_.Exception.Message)')"
        }
    }
}

function New-NgcbTestCertificate {
    param([string]$Subject)
    $rsa = [Security.Cryptography.RSA]::Create(3072)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$Subject", $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
    $eku=New-Object Security.Cryptography.OidCollection
    $null=$eku.Add((New-Object Security.Cryptography.Oid '1.3.6.1.5.5.7.3.3'))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku,$true))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,$true))
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(4)
    )
    [pscustomobject]@{ Certificate = $certificate; Rsa = $rsa }
}

function Get-NgcbTestCertificateHash {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $bytes = $algorithm.ComputeHash($Certificate.RawData) }
    finally { $algorithm.Dispose() }
    (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function ConvertTo-NgcbTestBytes {
    param([object]$Value)
    [Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $Value))
}

function Get-NgcbTestSha {
    param([byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Format-NgcbTestUtc {
    param([DateTimeOffset]$Value)
    $Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function Copy-NgcbTestObject {
    param($Value)
    ConvertFrom-Json (ConvertTo-Json $Value -Depth 30)
}

function Write-NgcbTestArtifact {
    param([string]$Base, [string]$RelativePath, [object]$Value)
    $path = Join-Path $Base $RelativePath
    $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $path))
    $bytes = ConvertTo-NgcbTestBytes $Value
    [IO.File]::WriteAllBytes($path, $bytes)
    [pscustomobject]@{ Path=$path; Bytes=$bytes; Sha256=(Get-NgcbTestSha $bytes); Size=[int64]$bytes.Length }
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ngcb-tests-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($testRoot)
$approvalMaterial = New-NgcbTestCertificate 'NorthGate Backend Approval Test'
$receiptMaterial = New-NgcbTestCertificate 'NorthGate Backend Receipt Test'
try {
    foreach ($schema in @(Get-ChildItem -LiteralPath (Join-Path $root 'schemas') -Filter '*.json' -File)) {
        $raw = [IO.File]::ReadAllText($schema.FullName)
        Assert-NgcbTest ($null -ne (ConvertFrom-Json $raw)) "Schema $($schema.Name) parses as JSON."
        if (Get-Command Test-Json -ErrorAction SilentlyContinue) {
            Assert-NgcbTest (Test-Json -Json $raw -ErrorAction SilentlyContinue) "Schema $($schema.Name) is valid JSON."
        }
    }
    $source = [IO.File]::ReadAllText((Join-Path $root 'NorthGate.VMFactory.CreateOnlyBackend.psm1'))
    foreach ($forbidden in @(
        '(?i)\bRemove-VM\b','(?i)\bRemove-VHD\b','(?i)\bRemove-VMSwitch\b','(?i)\bRename-VM\b',
        '(?i)\bNew-VMSwitch\b','(?i)\bSet-VMSwitch\b','(?i)\bAdd-VMHardDiskDrive\b',
        '(?i)\bMount-VHD\b','(?i)\bInvoke-Expression\b','(?i)\bStart-Process\b'
    )) { Assert-NgcbTest ($source -notmatch $forbidden) "Privileged source excludes $forbidden." }
    Assert-NgcbTest ($source -match 'Win32_ComputerSystemProduct' -and $source -match '\$hostProducts\[0\]\.UUID' -and $source -notmatch '\$vmHost\.Id') 'Production snapshot binds the supported host to its SMBIOS UUID without assuming a Get-VMHost Id property.'
    Assert-NgcbTest ($source -match '\$Adapter\.AdapterId' -and $source -match '\$adapter\.AdapterId' -and $source -match '\$adapters\[0\]\.AdapterId' -and $source -notmatch '\$(?:Adapter|adapter)\.Id' -and $source -notmatch '\$adapters\[0\]\.Id') 'Production snapshots, trunk fingerprints, journals, and readback use the bare Hyper-V AdapterId GUID rather than the composite resource Id.'

    $approvalPin = Get-NgcbTestCertificateHash $approvalMaterial.Certificate
    $receiptPin = Get-NgcbTestCertificateHash $receiptMaterial.Certificate
    Assert-NgcbTest ($approvalPin -cne $receiptPin) 'Approval and receipt signers are distinct.'
    $commit = 'a' * 40
    $tree = 'b' * 40
    $artifactIssued = [DateTimeOffset]::UtcNow.AddMinutes(-1)
    $artifactExpires = [DateTimeOffset]::UtcNow.AddHours(20)
    $release = [pscustomobject][ordered]@{
        schema='northgate/create-only-release-manifest/v2'; releaseId='ngcor-backend-test-01'
        repository=[pscustomobject][ordered]@{
            identity='Beowxlf/northgate-vm-factory'; origin='https://github.com/Beowxlf/northgate-vm-factory.git'
            commit=$commit; tree=$tree; objectFormat='sha1'; commitSignatureStatus='G'
            hostAllowlistId='ngallow-backend-test-01'; packageAllowlistSha256=('c'*64)
            governanceExceptionId='NG-GOV-20260802-TEST'
        }
        sourceProof=[pscustomobject][ordered]@{sourceKind='raw-git-blobs';headEqualsCommit=$true;cleanWorktree=$true;replaceRefsAbsent=$true;submodulesAbsent=$true;contentFiltersAbsent=$true}
        packageSemantics=[pscustomobject][ordered]@{sourceExecutableOnHost=$false;installInitiallyEnabled=$false;liveApplyImplemented=$true;allowedProtocolCommands=[object[]]@('status','plan','apply','receipt')}
        files=[object[]]@([pscustomobject][ordered]@{path='backend/NorthGate.VMFactory.CreateOnlyBackend.psm1';gitMode='100644';gitBlobOid=('d'*40);sizeBytes=1;sha256=('e'*64)})
    }
    $releaseHash = Get-NgcbTestSha (ConvertTo-NgcbTestBytes $release)
    $protected = [object[]]@(
        [pscustomobject][ordered]@{name='JS-BlueBench';vmId='11111111-1111-1111-1111-111111111111';diskUniqueIds=[object[]]@('disk-bluebench-001');adapterIds=[object[]]@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1')},
        [pscustomobject][ordered]@{name='JS-Server-01';vmId='22222222-2222-2222-2222-222222222222';diskUniqueIds=[object[]]@('disk-server-001');adapterIds=[object[]]@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2')},
        [pscustomobject][ordered]@{name='OPNsense-Tooling';vmId='33333333-3333-3333-3333-333333333333';diskUniqueIds=[object[]]@('disk-opnsense-001');adapterIds=[object[]]@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3')},
        [pscustomobject][ordered]@{name='TRMM-Tooling';vmId='44444444-4444-4444-4444-444444444444';diskUniqueIds=[object[]]@('disk-trmm-001');adapterIds=[object[]]@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa4')},
        [pscustomobject][ordered]@{name='Wazuh-Machine';vmId='55555555-5555-5555-5555-555555555555';diskUniqueIds=[object[]]@('disk-wazuh-001');adapterIds=[object[]]@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa5')}
    )
    $storageRoot = Join-Path $testRoot 'storage'
    $null = [IO.Directory]::CreateDirectory($storageRoot)
    $imagePath = Join-Path $testRoot 'debian-12.12.0-amd64-netinst.iso'
    [IO.File]::WriteAllBytes($imagePath, [byte[]](1,2,3,4))
    $authorizedImages=[object[]]@(
        [pscustomobject][ordered]@{imageId='debian-12.12-amd64-netinst';path=$imagePath;sha256=('6'*64);sizeBytes=[int64]4},
        [pscustomobject][ordered]@{imageId='kali-2026.2-installer-netinst-amd64';path=(Join-Path $testRoot 'kali.iso');sha256=('7'*64);sizeBytes=[int64]4},
        [pscustomobject][ordered]@{imageId='windows-11-25h2-english-x64';path=(Join-Path $testRoot 'win.iso');sha256=('8'*64);sizeBytes=[int64]4}
    )
    $fleetAssetIds=@('NG-VM-018','NG-VM-010','NG-VM-019','NG-VM-020','NG-VM-011','NG-VM-012','NG-VM-013','NG-VM-014','NG-VM-015','NG-VM-016','NG-VM-017','NG-VM-021')
    $windowsAssetIds=@('NG-VM-010','NG-VM-011','NG-VM-012','NG-VM-013','NG-VM-014','NG-VM-015')
    $bootstrapMedia=@()
    for($mediaIndex=0;$mediaIndex-lt $fleetAssetIds.Count;$mediaIndex++){
        $mediaAssetId=$fleetAssetIds[$mediaIndex]
        $sourceImageId=if($mediaAssetId-in$windowsAssetIds){'windows-11-25h2-english-x64'}elseif($mediaAssetId-ceq'NG-VM-021'){'kali-2026.2-installer-netinst-amd64'}else{'debian-12.12-amd64-netinst'}
        $sourceImage=@($authorizedImages|Where-Object imageId -ceq $sourceImageId)[0]
        $bootstrapMedia += [pscustomobject][ordered]@{
            assetId=$mediaAssetId;mediaId=('ngmedia-'+$mediaAssetId.ToLowerInvariant())
            mode='asset-bound-derivative-iso'
            path=(Join-Path $testRoot ($mediaAssetId.ToLowerInvariant()+'-unattended.iso'))
            sha256=('{0:x64}'-f(100+$mediaIndex));sizeBytes=[int64](16+$mediaIndex);sourceImageId=$sourceImageId
            sourceImageSha256=$sourceImage.sha256;provenancePath=(Join-Path $testRoot ($mediaAssetId.ToLowerInvariant()+'-provenance.json'))
            provenanceSha256=('{0:x64}'-f(400+$mediaIndex));bundleManifestSha256=('{0:x64}'-f(500+$mediaIndex))
            builderId='northgate-unattended-media-v1';builderReleaseSha256=$releaseHash
            recipeSha256=('{0:x64}'-f(200+$mediaIndex));unattendedPayloadSha256=('{0:x64}'-f(300+$mediaIndex))
            sourceCommit=$commit;sourceTree=$tree
        }
    }
    $authorization = [pscustomobject][ordered]@{
        schema='northgate/create-only-host-deployment-authorization/v2';authorizationId='ngdeploy-backend-test-01';sequence=1
        issuedAtUtc=(Format-NgcbTestUtc $artifactIssued);expiresAtUtc=(Format-NgcbTestUtc $artifactExpires)
        repository=[pscustomobject][ordered]@{identity='Beowxlf/northgate-vm-factory';releaseId=$release.releaseId;commit=$commit;tree=$tree;hostAllowlistId=$release.repository.hostAllowlistId;packageAllowlistSha256=$release.repository.packageAllowlistSha256;governanceExceptionId=$release.repository.governanceExceptionId}
        releaseManifestSha256=$releaseHash
        host=[pscustomobject][ordered]@{hostId='nghost-backend-test-01';computerName='HC-HV01';machineGuidSha256=('1'*64);hyperVHostId='99999999-9999-9999-9999-999999999999';osBuild='20348.2762'}
        install=[pscustomobject][ordered]@{versionedReleaseRoot='C:\Program Files\NorthGate\VMFactory\CreateOnly\releases\test';stateRoot='C:\ProgramData\NorthGate\VMFactory\CreateOnly\state';quarantineRoot='C:\ProgramData\NorthGate\VMFactory\CreateOnly\quarantine'}
        identity=[pscustomobject][ordered]@{sshIdentitySid='S-1-5-21-1-2-3-1001';serviceIdentitySid='S-1-5-21-1-2-3-1002';releaseSignerCertificateSha256=('2'*64);deploymentAuthorizationSignerCertificateSha256=('3'*64);approvalSignerCertificateSha256=$approvalPin;receiptSignerCertificateSha256=$receiptPin}
        'switch'=[pscustomobject][ordered]@{switchPolicyId='northgate-app-trunk';name='NorthGate-App-Trunk';id='88888888-8888-8888-8888-888888888888';fingerprint=('4'*64);trunkAdapterId='77777777-7777-7777-7777-777777777777';trunkAdapterFingerprint=('5'*64);mode='existing-only';allowCreate=$false;vlanProfiles=[pscustomobject][ordered]@{'business-apps'=150;'commercial-dmz'=160;'cyber-workstations'=140;'external-mail'=240;'it-admin-workstations'=130;'mail-internal'=120;'sim-wan'=250;'users-workstations'=110}}
        volumes=[object[]]@(
            [pscustomobject][ordered]@{volumeId='volume-d';uniqueId='volume-d-test-001';root=$storageRoot;persistentCeilingGiB=800;canaryCeilingGiB=80},
            [pscustomobject][ordered]@{volumeId='volume-f';uniqueId='volume-f-test-001';root=(Join-Path $testRoot 'other-storage');persistentCeilingGiB=800;canaryCeilingGiB=80}
        )
        images=$authorizedImages
        bootstrapMedia=[object[]]$bootstrapMedia
        protectedAssets=$protected
        accessIsolation=[pscustomobject][ordered]@{routineSshIsLocalAdministrator=$false;routineSshIsHyperVAdministrator=$false;routineSshCanUsePowerShellRemoting=$false;routineSshCanReachLegacyMcp=$false}
        initialPolicy=[pscustomobject][ordered]@{applyEnabled=$false;executableActions=[object[]]@();canaryStage='disabled'}
    }
    $authorizationHash = Get-NgcbTestSha (ConvertTo-NgcbTestBytes $authorization)
    & $module { param($a,$r,$h) Assert-NgcbHostAuthorization $a $r $h } $authorization $release $authorizationHash
    Assert-NgcbTest $true 'A current host authorization with a lifetime below 24 hours is accepted.'
    Assert-NgcbTest (@($authorization.bootstrapMedia|Where-Object mode -ceq 'asset-bound-derivative-iso').Count-eq12 -and
        @($authorization.bootstrapMedia|Where-Object sourceImageId -ceq 'debian-12.12-amd64-netinst').Count-eq5 -and
        @($authorization.bootstrapMedia|Where-Object sourceImageId -ceq 'windows-11-25h2-english-x64').Count-eq6 -and
        @($authorization.bootstrapMedia|Where-Object sourceImageId -ceq 'kali-2026.2-installer-netinst-amd64').Count-eq1) 'Authorization binds one complete asset-specific derivative ISO for each of the twelve systems.'
    $baseOnlyAuthorization=Copy-NgcbTestObject $authorization
    $baseOnlyAuthorization.bootstrapMedia[0].path=$baseOnlyAuthorization.images[0].path
    Assert-NgcbThrows { & $module { param($a,$r,$h) Assert-NgcbHostAuthorization $a $r $h } $baseOnlyAuthorization $release $authorizationHash } '^NGCB-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID$' 'Interactive base media cannot masquerade as asset-specific unattended media.'
    $mediaBaseMismatchAuthorization=Copy-NgcbTestObject $authorization
    $mediaBaseMismatchAuthorization.bootstrapMedia[0].sourceImageSha256='f'*64
    Assert-NgcbThrows { & $module { param($a,$r,$h) Assert-NgcbHostAuthorization $a $r $h } $mediaBaseMismatchAuthorization $release $authorizationHash } '^NGCB-AUTHORIZATION-BOOTSTRAP-MEDIA-INVALID$' 'Derivative media must bind the exact authorized base-image hash.'
    $expiredAuthorization = Copy-NgcbTestObject $authorization
    $expiredAuthorization.issuedAtUtc = Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddHours(-2))
    $expiredAuthorization.expiresAtUtc = Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddHours(-1))
    Assert-NgcbThrows { & $module { param($a,$r,$h) Assert-NgcbHostAuthorization $a $r $h } $expiredAuthorization $release $authorizationHash } '^NGCB-AUTHORIZATION-EXPIRED$' 'An already expired host authorization is rejected.'
    $longAuthorization = Copy-NgcbTestObject $authorization
    $longAuthorization.issuedAtUtc = Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddMinutes(-1))
    $longAuthorization.expiresAtUtc = Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddHours(25))
    Assert-NgcbThrows { & $module { param($a,$r,$h) Assert-NgcbHostAuthorization $a $r $h } $longAuthorization $release $authorizationHash } '^NGCB-AUTHORIZATION-LIFETIME-INVALID$' 'A host authorization lifetime above 24 hours is rejected.'
    $futureAuthorization = Copy-NgcbTestObject $authorization
    $futureAuthorization.issuedAtUtc = Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddMinutes(10))
    $futureAuthorization.expiresAtUtc = Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddHours(2))
    Assert-NgcbThrows { & $module { param($a,$r,$h) Assert-NgcbHostAuthorization $a $r $h } $futureAuthorization $release $authorizationHash } '^NGCB-AUTHORIZATION-CLOCK-INVALID$' 'A materially future-issued host authorization is rejected as clock rollback evidence.'
    Assert-NgcbTest ($authorization.images[0].imageId -ceq 'debian-12.12-amd64-netinst' -and [IO.Path]::GetFileName($authorization.images[0].path) -ceq 'debian-12.12.0-amd64-netinst.iso') 'Debian public catalog ID is separate from the exact source artifact filename.'
    $policy = [pscustomobject][ordered]@{
        schema='northgate/create-only-backend-policy/v1';policyId='northgate-backend-test';policyVersion='2026.08.02.1'
        authorizationSha256=$authorizationHash;releaseManifestSha256=$releaseHash;hostId=$authorization.host.hostId
        issuedAtUtc=(Format-NgcbTestUtc $artifactIssued);expiresAtUtc=(Format-NgcbTestUtc $artifactExpires);applyEnabled=$true
        executableActions=[object[]]@('Create');planTtlSeconds=900;approvalTtlSeconds=600;stateKeyId='ngkey-backend-test-01'
        limits=[pscustomobject][ordered]@{hostReserveMemoryMiB=49152;hostProcessorReserveCount=2;maximumVcpuToLogicalRatio=2;minimumVolumeFreeBytes=[int64](100GB);minimumVolumeFreePercent=15;maximumProcessorCount=8;maximumStartupMemoryMiB=32768;maximumDynamicMemoryMiB=65536;maximumOsDiskGiB=256}
        rollout=[pscustomobject][ordered]@{stage='debian-canary';exactAssetOrder=[object[]]@('NG-VM-018','NG-VM-010','NG-VM-019','NG-VM-020','NG-VM-011','NG-VM-012','NG-VM-013','NG-VM-014','NG-VM-015','NG-VM-016','NG-VM-017','NG-VM-021');maximumConcurrentTransactions=1;debianCanary=[pscustomobject][ordered]@{assetId='NG-VM-018';status='pending';receiptSha256='';acceptanceEvidenceSha256='';retirementEvidenceSha256=''};windowsCanary=[pscustomobject][ordered]@{assetId='NG-VM-010';status='pending';receiptSha256='';acceptanceEvidenceSha256='';retirementEvidenceSha256=''}}
       storageProfiles=[object[]]@([pscustomobject][ordered]@{profileRef='lab-ephemeral';catalogServerPolicyId='ng-storage-lab-ephemeral-v1';volumeId='volume-d';root=$storageRoot;reserveBytes=[int64](100GB);maximumOsDiskGiB=80;workloadClass='canary'})
        networkProfiles=[object[]]@([pscustomobject][ordered]@{profileRef='business-apps';catalogServerPolicyId='ng-network-business-apps-v1';switchPolicyId='northgate-app-trunk';vlanId=150})
        images=[object[]]@(
            [pscustomobject][ordered]@{imageRef='debian-12.12-amd64-netinst';authorizationImageId='debian-12.12-amd64-netinst';path=$imagePath;sha256=('6'*64);sizeBytes=[int64]4;guestFamily='linux';firmwareProfileRef='linux-gen2';secureBootEnabled=$true;secureBootTemplate='MicrosoftUEFICertificateAuthority';secureBootExceptionId='none';vtpmRequired=$false},
            [pscustomobject][ordered]@{imageRef='windows-11-25h2-english-x64';authorizationImageId='windows-11-25h2-english-x64';path=$authorizedImages[2].path;sha256=('8'*64);sizeBytes=[int64]4;guestFamily='windows';firmwareProfileRef='windows-gen2';secureBootEnabled=$true;secureBootTemplate='MicrosoftWindows';secureBootExceptionId='none';vtpmRequired=$true}
        )
        bootstrapMedia=[object[]]$bootstrapMedia
        firmwareProfiles=[object[]]@(
            [pscustomobject][ordered]@{profileRef='linux-gen2';catalogServerPolicyId='ng-firmware-linux-gen2-v1'},
            [pscustomobject][ordered]@{profileRef='windows-gen2';catalogServerPolicyId='ng-firmware-windows-gen2-v1'}
        )
        bootstrapProfiles=[object[]]@(
            [pscustomobject][ordered]@{profileRef='debian12-disposable-canary';catalogServerPolicyId='ng-bootstrap-debian12-disposable-canary-v1'},
            [pscustomobject][ordered]@{profileRef='windows11-disposable-canary';catalogServerPolicyId='ng-bootstrap-windows11-disposable-canary-v1'}
        )
        recoveryProfiles=[object[]]@([pscustomobject][ordered]@{profileRef='none-canary';catalogServerPolicyId='ng-recovery-none-canary-v1'})
        allowedAssets=[object[]]@(
            [pscustomobject][ordered]@{assetId='NG-VM-018';name='NG-DEB-CAN01';allowedImageRefs=[object[]]@('debian-12.12-amd64-netinst');allowedStorageProfileRefs=[object[]]@('lab-ephemeral');allowedNetworkProfileRefs=[object[]]@('business-apps');allowedFirmwareProfileRefs=[object[]]@('linux-gen2');allowedBootstrapProfileRefs=[object[]]@('debian12-disposable-canary');allowedRecoveryProfileRefs=[object[]]@('none-canary');maximumProcessors=2;maximumMemoryMiB=4096;maximumOsDiskGiB=40;adapterPolicyId='ngnic-ng-deb-can01';staticMacAddress='02AABBCCDDEE';bootstrapMediaId='ngmedia-ng-vm-018'},
            [pscustomobject][ordered]@{assetId='NG-VM-010';name='NG-CANARY-01';allowedImageRefs=[object[]]@('windows-11-25h2-english-x64');allowedStorageProfileRefs=[object[]]@('lab-ephemeral');allowedNetworkProfileRefs=[object[]]@('business-apps');allowedFirmwareProfileRefs=[object[]]@('windows-gen2');allowedBootstrapProfileRefs=[object[]]@('windows11-disposable-canary');allowedRecoveryProfileRefs=[object[]]@('none-canary');maximumProcessors=2;maximumMemoryMiB=4096;maximumOsDiskGiB=64;adapterPolicyId='ngnic-ng-canary-01';staticMacAddress='02AABBCCDDEF';bootstrapMediaId='ngmedia-ng-vm-010'}
        )
    }
    $policyHash = Get-NgcbTestSha (ConvertTo-NgcbTestBytes $policy)
    $manifest = [pscustomobject][ordered]@{
        '$schema'='../../schemas/vm-manifest.schema.json';apiVersion='northgate/v1alpha1';kind='VirtualMachine'
        metadata=[pscustomobject][ordered]@{assetId='NG-VM-018';name='NG-DEB-CAN01';ownerRef='infrastructure';purpose='Disposable Debian canary';environment='lab';criticality='low';dataClassification='internal';lifecycle='approved';reviewOrRetirementDate='2026-08-31';changeRef='NG-CHG-20260802-001';dependencies=[object[]]@()}
        spec=[pscustomobject][ordered]@{intent='create';generation=2;imageRef='debian-12.12-amd64-netinst';firmwareProfileRef='linux-gen2';compute=[pscustomobject][ordered]@{processors=2;memory=[pscustomobject][ordered]@{mode='dynamic';minimumMiB=1024;startupMiB=2048;maximumMiB=4096}};storage=[pscustomobject][ordered]@{profileRef='lab-ephemeral';osDiskGiB=40};network=[pscustomobject][ordered]@{profileRef='business-apps'};bootstrapProfileRef='debian12-disposable-canary';recoveryProfileRef='none-canary';desiredPowerState='running';destroyProtection=$true}
    }
    $windowsManifest = [pscustomobject][ordered]@{
        '$schema'='../../schemas/vm-manifest.schema.json';apiVersion='northgate/v1alpha1';kind='VirtualMachine'
        metadata=[pscustomobject][ordered]@{assetId='NG-VM-010';name='NG-CANARY-01';ownerRef='infrastructure';purpose='Disposable Windows canary';environment='lab';criticality='low';dataClassification='internal';lifecycle='approved';reviewOrRetirementDate='2026-08-31';changeRef='NG-CHG-20260802-002';dependencies=[object[]]@()}
        spec=[pscustomobject][ordered]@{intent='create';generation=2;imageRef='windows-11-25h2-english-x64';firmwareProfileRef='windows-gen2';compute=[pscustomobject][ordered]@{processors=2;memory=[pscustomobject][ordered]@{mode='dynamic';minimumMiB=2048;startupMiB=4096;maximumMiB=4096}};storage=[pscustomobject][ordered]@{profileRef='lab-ephemeral';osDiskGiB=64};network=[pscustomobject][ordered]@{profileRef='business-apps'};bootstrapProfileRef='windows11-disposable-canary';recoveryProfileRef='none-canary';desiredPowerState='running';destroyProtection=$true}
    }
    $catalogs = [ordered]@{
        imageCatalog=[pscustomobject][ordered]@{'$schema'='../schemas/image-catalog.schema.json';apiVersion='northgate/v1alpha1';kind='ImageCatalog';catalogVersion='2026.08.02.1';promotedOnly=$true;images=[object[]]@(
            [pscustomobject][ordered]@{id='debian-12.12-amd64-netinst';sha256=('6'*64);sizeBytes=[int64]4;guestFamily='linux';architecture='x86_64';allowedGenerations=[object[]]@(2);allowedFirmwareProfiles=[object[]]@('linux-gen2');sourceArtifactId='debian-12.12.0-amd64-netinst-iso';approvalStatus='promoted';retirementStatus='active'},
            [pscustomobject][ordered]@{id='windows-11-25h2-english-x64';sha256=('8'*64);sizeBytes=[int64]4;guestFamily='windows';architecture='x86_64';allowedGenerations=[object[]]@(2);allowedFirmwareProfiles=[object[]]@('windows-gen2');sourceArtifactId='windows-11-25h2-english-x64-iso';approvalStatus='promoted';retirementStatus='active'}
        );status='active'}
        networkCatalog=[pscustomobject][ordered]@{'$schema'='../schemas/network-catalog.schema.json';apiVersion='northgate/v1alpha1';kind='NetworkCatalog';catalogVersion='2026.08.02.1';profiles=[object[]]@([pscustomobject][ordered]@{id='business-apps';serverPolicyId='ng-network-business-apps-v1';approvalStatus='approved';allowAttach=$true;allowCreate=$false;allowRebind=$false})}
        storageCatalog=[pscustomobject][ordered]@{'$schema'='../schemas/storage-catalog.schema.json';apiVersion='northgate/v1alpha1';kind='StorageCatalog';catalogVersion='2026.08.02.1';profiles=[object[]]@([pscustomobject][ordered]@{id='lab-ephemeral';serverPolicyId='ng-storage-lab-ephemeral-v1';approvalStatus='approved';allowProvision=$true;criticalWorkloadsAllowed=$false})}
        firmwareCatalog=[pscustomobject][ordered]@{'$schema'='../schemas/profile-catalog.schema.json';apiVersion='northgate/v1alpha1';kind='FirmwareCatalog';catalogVersion='2026.08.02.1';profiles=[object[]]@([pscustomobject][ordered]@{id='linux-gen2';serverPolicyId='ng-firmware-linux-gen2-v1';approvalStatus='approved'},[pscustomobject][ordered]@{id='windows-gen2';serverPolicyId='ng-firmware-windows-gen2-v1';approvalStatus='approved'})}
        bootstrapCatalog=[pscustomobject][ordered]@{'$schema'='../schemas/profile-catalog.schema.json';apiVersion='northgate/v1alpha1';kind='BootstrapCatalog';catalogVersion='2026.08.02.1';profiles=[object[]]@([pscustomobject][ordered]@{id='debian12-disposable-canary';serverPolicyId='ng-bootstrap-debian12-disposable-canary-v1';approvalStatus='approved'},[pscustomobject][ordered]@{id='windows11-disposable-canary';serverPolicyId='ng-bootstrap-windows11-disposable-canary-v1';approvalStatus='approved'})}
        recoveryCatalog=[pscustomobject][ordered]@{'$schema'='../schemas/profile-catalog.schema.json';apiVersion='northgate/v1alpha1';kind='RecoveryCatalog';catalogVersion='2026.08.02.1';profiles=[object[]]@([pscustomobject][ordered]@{id='none-canary';serverPolicyId='ng-recovery-none-canary-v1';approvalStatus='approved'})}
    }
    $dataRoot = Join-Path $testRoot 'data'
    $files = @()
    $manifestArtifact = Write-NgcbTestArtifact $dataRoot 'files/manifests/NG-VM-018.json' $manifest
    $files += [pscustomobject][ordered]@{role='manifest';assetId='NG-VM-018';sourcePath='manifests/NG-VM-018.json';gitBlobOid=('1'*40);gitMode='100644';sourceSha256=$manifestArtifact.Sha256;canonicalRelativePath='files/manifests/NG-VM-018.json';canonicalSha256=$manifestArtifact.Sha256;sizeBytes=[int64]$manifestArtifact.Size}
    $windowsManifestArtifact = Write-NgcbTestArtifact $dataRoot 'files/manifests/NG-VM-010.json' $windowsManifest
    $files += [pscustomobject][ordered]@{role='manifest';assetId='NG-VM-010';sourcePath='manifests/NG-VM-010.json';gitBlobOid=('9'*40);gitMode='100644';sourceSha256=$windowsManifestArtifact.Sha256;canonicalRelativePath='files/manifests/NG-VM-010.json';canonicalSha256=$windowsManifestArtifact.Sha256;sizeBytes=[int64]$windowsManifestArtifact.Size}
    $index=2
    foreach($role in $catalogs.Keys){
        $artifact=Write-NgcbTestArtifact $dataRoot ("files/catalog/$role.json") $catalogs[$role]
        $files += [pscustomobject][ordered]@{role=$role;sourcePath=("catalog/$role.json");gitBlobOid=([string]$index*40);gitMode='100644';sourceSha256=$artifact.Sha256;canonicalRelativePath=("files/catalog/$role.json");canonicalSha256=$artifact.Sha256;sizeBytes=[int64]$artifact.Size}
        $index++
    }
    $bundle=[pscustomobject][ordered]@{schema='northgate/create-only-data-bundle/v1';bundleId=('ngdata-'+('9'*64));repository=[pscustomobject][ordered]@{identity='Beowxlf/northgate-vm-factory';commit=$commit;tree=$tree};createdAtUtc=(Format-NgcbTestUtc $artifactIssued);expiresAtUtc=(Format-NgcbTestUtc $artifactExpires);files=[object[]]$files}
    $bundleHash=Get-NgcbTestSha (ConvertTo-NgcbTestBytes $bundle)
    $baseVms=@();$baseDisks=@();$baseAdapters=@()
    foreach($p in $protected){
        $baseVms += [pscustomobject][ordered]@{vmId=$p.vmId;name=$p.name;generation=2;state='Running';path=(Join-Path $testRoot $p.name);notes=''}
        $baseDisks += [pscustomobject][ordered]@{vmId=$p.vmId;controllerType='SCSI';controllerNumber=0;controllerLocation=0;path=(Join-Path $testRoot ($p.name+'.vhdx'));diskIdentifier=$p.diskUniqueIds[0]}
        $baseAdapters += [pscustomobject][ordered]@{vmId=$p.vmId;adapterId=$p.adapterIds[0];macAddress=('00155D{0:X6}' -f $baseAdapters.Count);dynamicMacAddressEnabled=$true;switchId=$authorization.switch.id}
    }
    $baseState=[pscustomobject][ordered]@{
        host=[pscustomobject][ordered]@{computerName='HC-HV01';machineGuidSha256=('1'*64);hyperVHostId=$authorization.host.hyperVHostId;osBuild='20348.2762';logicalProcessorCount=32;memoryCapacityMiB=211000}
        protectedAssets=$protected;switch=[pscustomobject][ordered]@{id=$authorization.switch.id;fingerprint=$authorization.switch.fingerprint;trunkAdapterId=$authorization.switch.trunkAdapterId;trunkAdapterFingerprint=$authorization.switch.trunkAdapterFingerprint}
        volumes=[object[]]@([pscustomobject][ordered]@{volumeId='volume-d';uniqueId='volume-d-test-001';root=$storageRoot;sizeBytes=[int64](1TB);freeBytes=[int64](800GB)},[pscustomobject][ordered]@{volumeId='volume-f';uniqueId='volume-f-test-001';root=(Join-Path $testRoot 'other-storage');sizeBytes=[int64](1TB);freeBytes=[int64](800GB)})
        selectedImage=[pscustomobject][ordered]@{path=$imagePath;sizeBytes=[int64]4;sha256=('6'*64)}
        selectedBootstrapMedia=[pscustomobject][ordered]@{mediaId=$bootstrapMedia[0].mediaId;path=$bootstrapMedia[0].path;sizeBytes=[int64]$bootstrapMedia[0].sizeBytes;sha256=$bootstrapMedia[0].sha256}
        selectedBootstrapProvenance=[pscustomobject][ordered]@{path=$bootstrapMedia[0].provenancePath;sha256=$bootstrapMedia[0].provenanceSha256;bundleManifestSha256=$bootstrapMedia[0].bundleManifestSha256}
        vms=[object[]]$baseVms;disks=[object[]]$baseDisks;adapters=[object[]]$baseAdapters;existingProcessorCount=12;existingMemoryMiB=32768
    }
    $badDebianPolicy=Copy-NgcbTestObject $policy
    $badDebianPolicy.images[0].secureBootEnabled=$false
    $badDebianPolicy.images[0].secureBootTemplate='None'
    $badDebianPolicy.images[0].secureBootExceptionId='NG-FW-20260802-KALI-UNSIGNED'
    Assert-NgcbThrows { & $module { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } $badDebianPolicy $authorization $authorizationHash ('a'*64) } '^NGCB-POLICY-IMAGE-INVALID$' 'Secure Boot cannot be disabled for Debian.'
    $badWindowsPolicy=Copy-NgcbTestObject $policy
    $badWindowsPolicy.images[0].guestFamily='windows'
    $badWindowsPolicy.images[0].firmwareProfileRef='windows-gen2'
    $badWindowsPolicy.images[0].secureBootTemplate='MicrosoftWindows'
    $badWindowsPolicy.images[0].vtpmRequired=$false
    Assert-NgcbThrows { & $module { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } $badWindowsPolicy $authorization $authorizationHash ('b'*64) } '^NGCB-POLICY-IMAGE-INVALID$' 'Windows policy cannot omit vTPM.'
    $kaliPolicy=Copy-NgcbTestObject $policy
    $kaliPolicy.images[0].imageRef='kali-2026.2-installer-netinst-amd64'
    $kaliPolicy.images[0].authorizationImageId='kali-2026.2-installer-netinst-amd64'
    $kaliPolicy.images[0].firmwareProfileRef='kali-gen2-unsigned'
    $kaliPolicy.images[0].secureBootEnabled=$false
    $kaliPolicy.images[0].secureBootTemplate='None'
    $kaliPolicy.images[0].secureBootExceptionId='NG-FW-20260802-KALI-UNSIGNED'
    $kaliPolicy.images[0].vtpmRequired=$false
    & $module { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } $kaliPolicy $authorization $authorizationHash ('c'*64)
    Assert-NgcbTest $true 'Exact Kali unsigned-installer exception is accepted without vTPM.'
    $mediaDriftPolicy=Copy-NgcbTestObject $policy
    $mediaDriftPolicy.bootstrapMedia[0].sha256='e'*64
    Assert-NgcbThrows { & $module { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } $mediaDriftPolicy $authorization $authorizationHash ('e'*64) } '^NGCB-POLICY-BOOTSTRAP-MEDIA-AUTHORIZATION-MISMATCH$' 'Signed backend policy cannot substitute derivative media bytes.'
    $provenanceDriftPolicy=Copy-NgcbTestObject $policy
    $provenanceDriftPolicy.bootstrapMedia[0].provenanceSha256='e'*64
    Assert-NgcbThrows { & $module { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } $provenanceDriftPolicy $authorization $authorizationHash ('e'*64) } '^NGCB-POLICY-BOOTSTRAP-MEDIA-AUTHORIZATION-MISMATCH$' 'Signed backend policy cannot substitute derivative-media provenance.'
    $bundleManifestDriftPolicy=Copy-NgcbTestObject $policy
    $bundleManifestDriftPolicy.bootstrapMedia[0].bundleManifestSha256='e'*64
    Assert-NgcbThrows { & $module { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } $bundleManifestDriftPolicy $authorization $authorizationHash ('e'*64) } '^NGCB-POLICY-BOOTSTRAP-MEDIA-AUTHORIZATION-MISMATCH$' 'Signed backend policy cannot substitute the derivative bundle-manifest binding.'
    $assetMediaDriftPolicy=Copy-NgcbTestObject $policy
    $assetMediaDriftPolicy.allowedAssets[0].bootstrapMediaId='ngmedia-ng-vm-019'
    Assert-NgcbThrows { & $module { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } $assetMediaDriftPolicy $authorization $authorizationHash ('f'*64) } '^NGCB-POLICY-ASSET-MAC-INVALID$' 'Asset policy cannot bind another VM''s unattended media.'
    $unsignedStageAdvancePolicy=Copy-NgcbTestObject $policy
    $unsignedStageAdvancePolicy.rollout.stage='windows-canary'
    Assert-NgcbThrows { & $module { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } $unsignedStageAdvancePolicy $authorization $authorizationHash ('f'*64) } '^NGCB-POLICY-ROLLOUT-INVALID$' 'Rollout stage cannot advance without receipt, acceptance, and retirement hashes in the signed policy.'
    $advancedBasePolicy=Copy-NgcbTestObject $policy
    $advancedBasePolicy.rollout.stage='windows-canary'
    $advancedBasePolicy.rollout.debianCanary.status='accepted-retired'
    $advancedBasePolicy.rollout.debianCanary.receiptSha256='a'*64
    $advancedBasePolicy.rollout.debianCanary.acceptanceEvidenceSha256='b'*64
    $advancedBasePolicy.rollout.debianCanary.retirementEvidenceSha256='c'*64
    Assert-NgcbThrows { & $module { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } $advancedBasePolicy $authorization $authorizationHash ('f'*64) } '^NGCB-POLICY-ROLLOUT-INITIAL-STAGE-INVALID$' 'Immutable base policy must begin at the Debian canary; later stages require same-release promotions.'
    function New-NgcbHarness {
        $stateRoot=Join-Path $testRoot ('state-'+[guid]::NewGuid().ToString('N'))
        $state=Copy-NgcbTestObject $baseState
        $parameters=@{StateRoot=$stateRoot;Authorization=(Copy-NgcbTestObject $authorization);AuthorizationSha256=$authorizationHash;ReleaseManifest=$release;ReleaseManifestSha256=$releaseHash;Policy=(Copy-NgcbTestObject $policy);PolicySha256=$policyHash;DataBundle=(Copy-NgcbTestObject $bundle);DataBundleSha256=$bundleHash;DataRoot=$dataRoot;TestState=$state;ReceiptCertificate=$receiptMaterial.Certificate}
        $context=& $module { param($p) New-NgcbInertTestContext @p } $parameters
        [pscustomobject]@{Context=$context;State=$state}
    }
    function New-NgcbPlanRequest {
        param([string]$AssetId='NG-VM-018')
        $changeId=if($AssetId-ceq'NG-VM-010'){'NG-CHG-20260802-002'}else{'NG-CHG-20260802-001'}
        $request=[pscustomobject][ordered]@{apiVersion='northgate/v1alpha1';kind='CreateOnlyPlanRequest';assetId=$AssetId;changeId=$changeId;repository=[pscustomobject][ordered]@{identity='Beowxlf/northgate-vm-factory';commit=$commit;tree=$tree;signedReleaseSha256=$releaseHash;hostAllowlistId=$release.repository.hostAllowlistId}}
        ConvertTo-NgcbTestBytes $request
    }
    function New-NgcbApprovalForPlan {
        param($Plan)
        $issued=[DateTimeOffset]::UtcNow
        $canonicalPlanObject=ConvertFrom-Json $Plan.canonicalPlan
        $planExpiry=[DateTimeOffset]::Parse($Plan.expiresAtUtc)
        $expires=$issued.AddMinutes(5);if($expires -gt $planExpiry){$expires=$planExpiry.AddSeconds(-1)}
        [pscustomobject][ordered]@{schema='northgate/create-only-plan-approval/v1';approvalId=('nga-'+(([guid]::NewGuid().ToString('N'))*2));decision='approve';planId=$Plan.planId;planHash=$Plan.planHash;planAuthenticationHash=$Plan.planAuthenticationHash;changeId=[string]$canonicalPlanObject.operation.changeId;repository=[pscustomobject][ordered]@{identity='Beowxlf/northgate-vm-factory';commit=$commit;tree=$tree};releaseManifestSha256=$releaseHash;authorizationSha256=$authorizationHash;policySha256=$policyHash;dataBundleSha256=$bundleHash;issuedAtUtc=$issued.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");expiresAtUtc=$expires.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");approverSid='S-1-5-21-1-2-3-500';nonce=(([guid]::NewGuid().ToString('N'))*2);useLimit=1}
    }
    function Register-NgcbTestApproval {
        param($Context,$Plan,$Mutate)
        $approval=New-NgcbApprovalForPlan $Plan
        if($Mutate){& $Mutate $approval}
        $bytes=ConvertTo-NgcbTestBytes $approval
        $signature=& $module { param($b,$c) New-NgcbDetachedCmsSignature $b $c } $bytes $approvalMaterial.Certificate
        Register-NorthGateCreateOnlyApproval -Context $Context -ApprovalBytes $bytes -DetachedCmsSignatureBytes $signature
    }

    $harness=New-NgcbHarness
    $state=Get-NorthGateCreateOnlyBackendState -Context $harness.Context
    Assert-NgcbTest ($state.applyEnabled -and $state.createOnly -and -not $state.destructiveOperationsExposed) 'Backend state is enabled only for Create.'
    $plan=New-NorthGateCreateOnlyHostPlan -Context $harness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    Assert-NgcbTest ($plan.planId -match '^ngp-[a-f0-9]{64}$' -and $plan.planAuthenticationHash -match '^[a-f0-9]{64}$') 'Host issues random authenticated plan capability.'
    if (Get-Command Test-Json -ErrorAction SilentlyContinue) {
        Assert-NgcbTest (Test-Json -Json $plan.canonicalPlan -SchemaFile (Join-Path $root 'schemas\create-only-host-plan.schema.json') -ErrorAction SilentlyContinue) 'Issued plan validates against its schema.'
    }
    $planObject=ConvertFrom-Json $plan.canonicalPlan
    Assert-NgcbTest ($planObject.operation.staticMacAddress -ceq '02AABBCCDDEE' -and $planObject.operation.adapterReservationId -match '^ngnicr-[a-f0-9]{64}$' -and $planObject.operation.adapterIdBindingMode -ceq 'hyperv-issued-journal-before-first-boot') 'Plan binds factory-owned static MAC and adapter-ID reservation/journal mode.'
    Assert-NgcbTest ($planObject.operation.secureBootEnabled -and $planObject.operation.secureBootTemplate -ceq 'MicrosoftUEFICertificateAuthority' -and -not $planObject.operation.vtpmRequired) 'Debian plan requires Secure Boot and does not claim vTPM.'
    Assert-NgcbTest ($planObject.operation.bootstrapMediaId -ceq 'ngmedia-ng-vm-018' -and
        $planObject.operation.bootstrapMediaMode -ceq 'asset-bound-derivative-iso' -and
        $planObject.operation.installationMediaBindingMode -ceq 'asset-bound-immutable-unattended' -and
        $planObject.operation.expectedDvdCount -eq 1 -and
        $planObject.operation.bootstrapMediaPath -cne $planObject.operation.imagePath) 'Debian plan binds the asset-specific remastered unattended ISO and cannot boot the interactive base ISO.'
    Assert-NgcbThrows { New-NorthGateCreateOnlyHostPlan -Context $harness.Context -PlanRequestBytes (New-NgcbPlanRequest) } '^NGCB-CREATE-COLLISION$' 'Reserved asset cannot receive a second plan.'
    Assert-NgcbThrows { Register-NgcbTestApproval $harness.Context $plan {param($a)$a.planHash='f'*64} } '^NGCB-APPROVAL-BINDING-INVALID$' 'Approval cannot change the plan hash.'
    Assert-NgcbThrows { Register-NgcbTestApproval $harness.Context $plan {param($a)$a.approverSid=$authorization.identity.sshIdentitySid} } '^NGCB-APPROVAL-BINDING-INVALID$' 'Routine SSH identity cannot approve a deployment plan.'
    Assert-NgcbThrows { Register-NgcbTestApproval $harness.Context $plan {param($a)$a.approverSid=$authorization.identity.serviceIdentitySid} } '^NGCB-APPROVAL-BINDING-INVALID$' 'Backend service identity cannot approve its own deployment plan.'
    Assert-NgcbThrows { Register-NgcbTestApproval $harness.Context $plan {param($a)$a.issuedAtUtc=(Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddMinutes(-2)));$a.expiresAtUtc=(Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddSeconds(-1)))} } '^NGCB-APPROVAL-TIME-INVALID$' 'Expired approval is rejected before durable registration.'
    $wrongSignerApproval=New-NgcbApprovalForPlan $plan
    $wrongSignerBytes=ConvertTo-NgcbTestBytes $wrongSignerApproval
    $wrongSignerSignature=& $module { param($b,$c) New-NgcbDetachedCmsSignature $b $c } $wrongSignerBytes $receiptMaterial.Certificate
    Assert-NgcbThrows { Register-NorthGateCreateOnlyApproval -Context $harness.Context -ApprovalBytes $wrongSignerBytes -DetachedCmsSignatureBytes $wrongSignerSignature } '^NGCB-APPROVAL-SIGNATURE-INVALID$' 'Approval signed by the receipt identity is rejected.'
    $registeredApproval=New-NgcbApprovalForPlan $plan
    $registeredApprovalBytes=ConvertTo-NgcbTestBytes $registeredApproval
    $registeredApprovalSignature=& $module { param($b,$c) New-NgcbDetachedCmsSignature $b $c } $registeredApprovalBytes $approvalMaterial.Certificate
    $approvalResult=Register-NorthGateCreateOnlyApproval -Context $harness.Context -ApprovalBytes $registeredApprovalBytes -DetachedCmsSignatureBytes $registeredApprovalSignature
    Assert-NgcbTest ($approvalResult.state -ceq 'Registered') 'Exact signed approval registers.'
    Assert-NgcbThrows { Register-NorthGateCreateOnlyApproval -Context $harness.Context -ApprovalBytes $registeredApprovalBytes -DetachedCmsSignatureBytes $registeredApprovalSignature } '^NGCB-APPROVAL-REPLAY$' 'A byte-identical second approval registration is rejected as replay.'
    $reusedIdApproval=New-NgcbApprovalForPlan $plan;$reusedIdApproval.approvalId=$registeredApproval.approvalId
    $reusedIdBytes=ConvertTo-NgcbTestBytes $reusedIdApproval
    $reusedIdSignature=& $module { param($b,$c) New-NgcbDetachedCmsSignature $b $c } $reusedIdBytes $approvalMaterial.Certificate
    Assert-NgcbThrows { Register-NorthGateCreateOnlyApproval -Context $harness.Context -ApprovalBytes $reusedIdBytes -DetachedCmsSignatureBytes $reusedIdSignature } '^NGCB-APPROVAL-REPLAY$' 'Approval ID reuse is rejected even with a fresh nonce.'
    $reusedNonceApproval=New-NgcbApprovalForPlan $plan;$reusedNonceApproval.nonce=$registeredApproval.nonce
    $reusedNonceBytes=ConvertTo-NgcbTestBytes $reusedNonceApproval
    $reusedNonceSignature=& $module { param($b,$c) New-NgcbDetachedCmsSignature $b $c } $reusedNonceBytes $approvalMaterial.Certificate
    Assert-NgcbThrows { Register-NorthGateCreateOnlyApproval -Context $harness.Context -ApprovalBytes $reusedNonceBytes -DetachedCmsSignatureBytes $reusedNonceSignature } '^NGCB-APPROVAL-REPLAY$' 'Approval nonce reuse is rejected even with a fresh approval ID.'
    $receipt=Invoke-NorthGateCreateOnlyApply -Context $harness.Context -PlanId $plan.planId
    Assert-NgcbTest ($receipt.receipt.outcome -ceq 'Succeeded' -and $receipt.receipt.afterStateVerified) 'Successful inert creation produces verified receipt.'
    if (Get-Command Test-Json -ErrorAction SilentlyContinue) {
        Assert-NgcbTest (Test-Json -Json (ConvertTo-NorthGateCreateOnlyCanonicalJson $receipt.receipt) -SchemaFile (Join-Path $root 'schemas\create-only-signed-receipt.schema.json') -ErrorAction SilentlyContinue) 'Signed receipt validates against its schema.'
    }
    Assert-NgcbTest ($receipt.receipt.operation.staticMacAddress -ceq '02AABBCCDDEE' -and $receipt.receipt.operation.adapterId -match '^[a-f0-9-]{36}$' -and -not $receipt.receipt.operation.dynamicMacAddressEnabled) 'Receipt binds static MAC and Hyper-V-issued adapter ID.'
    Assert-NgcbTest ($receipt.receipt.operation.secureBootEnabled -and -not $receipt.receipt.operation.vtpmRequired -and -not $receipt.receipt.operation.vtpmEnabled) 'Receipt binds Debian firmware security readback.'
    Assert-NgcbTest ($receipt.receipt.operation.bootstrapMediaId -ceq 'ngmedia-ng-vm-018' -and
        $receipt.receipt.operation.bootstrapMediaMode -ceq 'asset-bound-derivative-iso' -and
        @($receipt.receipt.operation.installationMediaPaths).Count -eq 1 -and
        $receipt.receipt.operation.installationMediaPaths[0] -ceq $bootstrapMedia[0].path) 'Receipt proves the asset-bound unattended media was attached instead of the interactive base ISO.'
    $rolloutIdentity=[pscustomobject][ordered]@{vms=$harness.State.vms;adapters=$harness.State.adapters}
    Assert-NgcbThrows { & $module {param($c,$a,$i)Assert-NgcbRolloutState $c $a $i} $harness.Context 'NG-VM-010' $rolloutIdentity } '^NGCB-ROLLOUT-STAGE-ADVANCE-REQUIRED$' 'Windows canary remains blocked until a newly signed rollout-stage policy carries Debian acceptance and retirement evidence.'
    Assert-NgcbThrows { Get-NorthGateCreateOnlyRolloutPromotionContext -Context $harness.Context } '^NGCB-ROLLOUT-CANARY-NOT-RETIRED$' 'The promotion context is withheld while the Debian canary is still running and connected.'
    $harness.State.vms[-1].state='Off';$harness.State.adapters[-1].switchId=''
    $rolloutIdentity=[pscustomobject][ordered]@{vms=$harness.State.vms;adapters=$harness.State.adapters}
    $promotionContext=Get-NorthGateCreateOnlyRolloutPromotionContext -Context $harness.Context
    Assert-NgcbTest ($promotionContext.nextSequence -eq 1 -and
        $promotionContext.previousAuthorizationSha256 -ceq $policyHash -and
        $promotionContext.fromStage -ceq 'debian-canary' -and
        $promotionContext.permittedToStage -ceq 'windows-canary' -and
        $promotionContext.requiredCanaryAssetId -ceq 'NG-VM-018' -and
        $promotionContext.requiredCanaryReceiptSha256 -ceq $receipt.receiptSha256) 'Authenticated promotion context exposes the exact monotonic transition and verified canary receipt.'
    function New-NgcbRolloutPromotion {
        param($PromotionContext)
        $issued=[DateTimeOffset]::UtcNow
        $nextRollout=Copy-NgcbTestObject $PromotionContext.currentRollout
        $nextRollout.stage=[string]$PromotionContext.permittedToStage
        $canaryGate=if([int]$PromotionContext.nextSequence-eq1){$nextRollout.debianCanary}else{$nextRollout.windowsCanary}
        $canaryGate.status='accepted-retired'
        $canaryGate.receiptSha256=$PromotionContext.requiredCanaryReceiptSha256
        $canaryGate.acceptanceEvidenceSha256=if([int]$PromotionContext.nextSequence-eq1){'a'*64}else{'c'*64}
        $canaryGate.retirementEvidenceSha256=if([int]$PromotionContext.nextSequence-eq1){'b'*64}else{'d'*64}
        [pscustomobject][ordered]@{
            schema='northgate/create-only-rollout-promotion/v1'
            promotionId=('ngrollout-'+(([guid]::NewGuid().ToString('N'))*2))
            sequence=[int]$PromotionContext.nextSequence
            previousAuthorizationSha256=[string]$PromotionContext.previousAuthorizationSha256
            basePolicySha256=[string]$PromotionContext.basePolicySha256
            authorizationSha256=[string]$PromotionContext.authorizationSha256
            releaseManifestSha256=[string]$PromotionContext.releaseManifestSha256
            dataBundleSha256=[string]$PromotionContext.dataBundleSha256
            repository=$PromotionContext.repository
            fromStage=[string]$PromotionContext.fromStage
            toStage=[string]$PromotionContext.permittedToStage
            rollout=$nextRollout
            issuedAtUtc=Format-NgcbTestUtc $issued
            expiresAtUtc=Format-NgcbTestUtc $issued.AddMinutes(5)
            approverSid='S-1-5-21-1-2-3-500'
            nonce=(([guid]::NewGuid().ToString('N'))*2)
        }
    }
    function Register-NgcbRolloutPromotion {
        param($Context,$Promotion,$Certificate=$approvalMaterial.Certificate)
        $bytes=ConvertTo-NgcbTestBytes $Promotion
        $signature=& $module {param($b,$c)New-NgcbDetachedCmsSignature $b $c} $bytes $Certificate
        Register-NorthGateCreateOnlyRolloutPromotion -Context $Context -PromotionBytes $bytes `
            -DetachedCmsSignatureBytes $signature
    }
    $promotion=New-NgcbRolloutPromotion $promotionContext
    if (Get-Command Test-Json -ErrorAction SilentlyContinue) {
        Assert-NgcbTest (Test-Json -Json (ConvertTo-NorthGateCreateOnlyCanonicalJson $promotion) `
            -SchemaFile (Join-Path $root 'schemas\create-only-rollout-promotion.schema.json') `
            -ErrorAction SilentlyContinue) 'Rollout promotion validates against its strict schema.'
    }
    $wrongPromotionSigner=New-NgcbRolloutPromotion $promotionContext
    Assert-NgcbThrows { Register-NgcbRolloutPromotion $harness.Context $wrongPromotionSigner $receiptMaterial.Certificate } '^NGCB-ROLLOUT-PROMOTION-SIGNATURE-INVALID$' 'Receipt signer cannot authorize a rollout-stage promotion.'
    $servicePromotion=New-NgcbRolloutPromotion $promotionContext
    $servicePromotion.approverSid=$authorization.identity.serviceIdentitySid
    Assert-NgcbThrows { Register-NgcbRolloutPromotion $harness.Context $servicePromotion } '^NGCB-ROLLOUT-PROMOTION-CONTRACT-INVALID$' 'Backend service identity cannot approve its own rollout promotion.'
    $wrongPreviousPromotion=New-NgcbRolloutPromotion $promotionContext
    $wrongPreviousPromotion.previousAuthorizationSha256='f'*64
    Assert-NgcbThrows { Register-NgcbRolloutPromotion $harness.Context $wrongPreviousPromotion } '^NGCB-ROLLOUT-PROMOTION-MONOTONICITY-INVALID$' 'Promotion must bind the authenticated current rollout authorization hash.'
    $wrongEvidencePromotion=New-NgcbRolloutPromotion $promotionContext
    $wrongEvidencePromotion.rollout.debianCanary.receiptSha256='f'*64
    Assert-NgcbThrows { Register-NgcbRolloutPromotion $harness.Context $wrongEvidencePromotion } '^NGCB-ROLLOUT-PROMOTION-EVIDENCE-INVALID$' 'Promotion cannot substitute a different canary receipt hash.'
    $promotionResult=Register-NgcbRolloutPromotion $harness.Context $promotion
    Assert-NgcbTest ($promotionResult.status -ceq 'registered' -and $promotionResult.sequence -eq 1 -and
        $promotionResult.stage -ceq 'windows-canary') 'Signed same-release promotion atomically advances the rollout anchor without changing the release or ledger root.'
    $idempotentPromotion=Register-NgcbRolloutPromotion $harness.Context $promotion
    Assert-NgcbTest ($idempotentPromotion.status -ceq 'already-registered' -and
        $idempotentPromotion.rolloutAuthorizationSha256 -ceq $promotionResult.rolloutAuthorizationSha256) 'Exact promotion retry is idempotent and does not advance the sequence twice.'
    $replayedPromotion=Copy-NgcbTestObject $promotion
    $replayedPromotion.promotionId=('ngrollout-'+(([guid]::NewGuid().ToString('N'))*2))
    Assert-NgcbThrows { Register-NgcbRolloutPromotion $harness.Context $replayedPromotion } '^NGCB-ROLLOUT-PROMOTION-REPLAY$' 'Promotion nonce reuse is rejected even under a new promotion ID.'
    $effectiveState=Get-NorthGateCreateOnlyBackendState -Context $harness.Context
    Assert-NgcbTest ($effectiveState.policySha256 -ceq $policyHash -and
        $effectiveState.rolloutSequence -eq 1 -and
        $effectiveState.rolloutStage -ceq 'windows-canary' -and
        $effectiveState.rolloutAuthorizationSha256 -ceq $promotionResult.rolloutAuthorizationSha256) 'Backend state preserves the immutable base-policy hash and reports the separate effective rollout anchor.'
    $null=& $module {param($c,$a,$i)Assert-NgcbRolloutState $c $a $i} $harness.Context 'NG-VM-010' $rolloutIdentity
    Assert-NgcbTest $true 'Signed Debian receipt plus acceptance/retirement hashes and live retirement unlock only the Windows canary.'

    $windowsMedia=@($bootstrapMedia|Where-Object assetId -ceq 'NG-VM-010')[0]
    $harness.State.selectedImage=[pscustomobject][ordered]@{path=$authorizedImages[2].path;sizeBytes=[int64]4;sha256=('8'*64)}
    $harness.State.selectedBootstrapMedia=[pscustomobject][ordered]@{mediaId=$windowsMedia.mediaId;path=$windowsMedia.path;sizeBytes=[int64]$windowsMedia.sizeBytes;sha256=$windowsMedia.sha256}
    $harness.State.selectedBootstrapProvenance=[pscustomobject][ordered]@{path=$windowsMedia.provenancePath;sha256=$windowsMedia.provenanceSha256;bundleManifestSha256=$windowsMedia.bundleManifestSha256}
    $windowsPlan=New-NorthGateCreateOnlyHostPlan -Context $harness.Context -PlanRequestBytes (New-NgcbPlanRequest 'NG-VM-010')
    $windowsPlanObject=ConvertFrom-Json $windowsPlan.canonicalPlan
    Assert-NgcbTest ($windowsPlanObject.policy.rolloutSequence -eq 1 -and
        $windowsPlanObject.policy.rolloutStage -ceq 'windows-canary' -and
        $windowsPlanObject.policy.rolloutAuthorizationSha256 -ceq $promotionResult.rolloutAuthorizationSha256 -and
        $windowsPlanObject.operation.secureBootTemplate -ceq 'MicrosoftWindows' -and
        $windowsPlanObject.operation.vtpmRequired) 'Windows canary plan binds the promoted rollout authorization and required firmware security.'
    $null=Register-NgcbTestApproval $harness.Context $windowsPlan $null
    $windowsReceipt=Invoke-NorthGateCreateOnlyApply -Context $harness.Context -PlanId $windowsPlan.planId
    Assert-NgcbTest ($windowsReceipt.receipt.outcome -ceq 'Succeeded' -and
        $windowsReceipt.receipt.rolloutSequence -eq 1 -and
        $windowsReceipt.receipt.rolloutStage -ceq 'windows-canary' -and
        $windowsReceipt.receipt.operation.vtpmRequired -and
        $windowsReceipt.receipt.operation.vtpmEnabled) 'Windows canary receipt proves successful creation under the promoted stage with vTPM enabled.'
    Assert-NgcbThrows { Get-NorthGateCreateOnlyRolloutPromotionContext -Context $harness.Context } '^NGCB-ROLLOUT-CANARY-NOT-RETIRED$' 'Persistent-fleet promotion remains blocked while the Windows canary is running and connected.'
    $harness.State.vms[-1].state='Off';$harness.State.adapters[-1].switchId=''
    $secondPromotionContext=Get-NorthGateCreateOnlyRolloutPromotionContext -Context $harness.Context
    Assert-NgcbTest ($secondPromotionContext.nextSequence -eq 2 -and
        $secondPromotionContext.previousAuthorizationSha256 -ceq $promotionResult.rolloutAuthorizationSha256 -and
        $secondPromotionContext.fromStage -ceq 'windows-canary' -and
        $secondPromotionContext.permittedToStage -ceq 'persistent-fleet' -and
        $secondPromotionContext.requiredCanaryAssetId -ceq 'NG-VM-010' -and
        $secondPromotionContext.requiredCanaryReceiptSha256 -ceq $windowsReceipt.receiptSha256) 'Second promotion context chains to sequence one and the verified Windows receipt.'
    $secondPromotion=New-NgcbRolloutPromotion $secondPromotionContext
    $rewrittenDebianEvidence=Copy-NgcbTestObject $secondPromotion
    $rewrittenDebianEvidence.rollout.debianCanary.acceptanceEvidenceSha256='e'*64
    Assert-NgcbThrows { Register-NgcbRolloutPromotion $harness.Context $rewrittenDebianEvidence } '^NGCB-ROLLOUT-PROMOTION-EVIDENCE-INVALID$' 'Second promotion cannot rewrite accepted Debian evidence from the first signed transition.'
    $secondPromotionResult=Register-NgcbRolloutPromotion $harness.Context $secondPromotion
    Assert-NgcbTest ($secondPromotionResult.status -ceq 'registered' -and
        $secondPromotionResult.sequence -eq 2 -and
        $secondPromotionResult.stage -ceq 'persistent-fleet') 'Second signed promotion atomically unlocks the persistent fleet in the same release state root.'
    Assert-NgcbThrows { Get-NorthGateCreateOnlyRolloutPromotionContext -Context $harness.Context } '^NGCB-ROLLOUT-PROMOTION-COMPLETE$' 'No third rollout promotion exists after the persistent-fleet stage.'
    $persistentIdentity=[pscustomobject][ordered]@{vms=$harness.State.vms;adapters=$harness.State.adapters}
    $null=& $module {param($c,$a,$i)Assert-NgcbRolloutState $c $a $i} $harness.Context 'NG-VM-019' $persistentIdentity
    $persistentState=Get-NorthGateCreateOnlyBackendState -Context $harness.Context
    Assert-NgcbTest ($persistentState.rolloutSequence -eq 2 -and
        $persistentState.rolloutStage -ceq 'persistent-fleet' -and
        $persistentState.rolloutAuthorizationSha256 -ceq $secondPromotionResult.rolloutAuthorizationSha256) 'Persistent-fleet gate verifies both signed canary receipts and both live retirement states.'
    Assert-NgcbTest (-not $receipt.receipt.controls.existingAssetsMutated -and -not $receipt.receipt.controls.deletePathUsed -and $receipt.receipt.controls.approvalUseCount -eq 1) 'Receipt attests create-only controls.'
    $vmCount=$harness.State.vms.Count
    $secondReceipt=Invoke-NorthGateCreateOnlyApply -Context $harness.Context -PlanId $plan.planId
    Assert-NgcbTest ($secondReceipt.receipt.receiptId -ceq $receipt.receipt.receiptId -and $harness.State.vms.Count -eq $vmCount) 'Repeated apply is receipt-idempotent and does not create twice.'

    $expiryBoundHarness=New-NgcbHarness
    $nearPolicyExpiry=[DateTimeOffset]::UtcNow.AddMinutes(2)
    $expiryBoundHarness.Context.Policy.expiresAtUtc=Format-NgcbTestUtc $nearPolicyExpiry
    $expiryBoundPlan=New-NorthGateCreateOnlyHostPlan -Context $expiryBoundHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    Assert-NgcbTest ([DateTimeOffset]::Parse($expiryBoundPlan.expiresAtUtc) -le $nearPolicyExpiry) 'Plan expiry is bounded by the earliest policy expiry rather than TTL alone.'

    $authExpiryHarness=New-NgcbHarness
    $authExpiryPlan=New-NorthGateCreateOnlyHostPlan -Context $authExpiryHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $null=Register-NgcbTestApproval $authExpiryHarness.Context $authExpiryPlan $null
    $authExpiryHarness.Context.Authorization.expiresAtUtc=Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddSeconds(-1))
    Assert-NgcbThrows { Invoke-NorthGateCreateOnlyApply -Context $authExpiryHarness.Context -PlanId $authExpiryPlan.planId } '^NGCB-AUTHORIZATION-EXPIRED$' 'Apply rechecks host-authorization expiry under the transaction lock.'

    $policyExpiryHarness=New-NgcbHarness
    $policyExpiryPlan=New-NorthGateCreateOnlyHostPlan -Context $policyExpiryHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $null=Register-NgcbTestApproval $policyExpiryHarness.Context $policyExpiryPlan $null
    $policyExpiryHarness.Context.Policy.expiresAtUtc=Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddSeconds(-1))
    Assert-NgcbThrows { Invoke-NorthGateCreateOnlyApply -Context $policyExpiryHarness.Context -PlanId $policyExpiryPlan.planId } '^NGCB-POLICY-EXPIRED$' 'Apply rechecks backend-policy expiry under the transaction lock.'

    $bundleExpiryHarness=New-NgcbHarness
    $bundleExpiryPlan=New-NorthGateCreateOnlyHostPlan -Context $bundleExpiryHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $null=Register-NgcbTestApproval $bundleExpiryHarness.Context $bundleExpiryPlan $null
    $bundleExpiryHarness.Context.DataBundle.expiresAtUtc=Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddSeconds(-1))
    Assert-NgcbThrows { Invoke-NorthGateCreateOnlyApply -Context $bundleExpiryHarness.Context -PlanId $bundleExpiryPlan.planId } '^NGCB-DATA-BUNDLE-EXPIRED$' 'Apply rechecks data-bundle expiry under the transaction lock.'

    $rollbackClockHarness=New-NgcbHarness
    $rollbackClockPlan=New-NorthGateCreateOnlyHostPlan -Context $rollbackClockHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $null=Register-NgcbTestApproval $rollbackClockHarness.Context $rollbackClockPlan $null
    $rollbackClockHarness.Context.Authorization.issuedAtUtc=Format-NgcbTestUtc ([DateTimeOffset]::UtcNow.AddMinutes(10))
    Assert-NgcbThrows { Invoke-NorthGateCreateOnlyApply -Context $rollbackClockHarness.Context -PlanId $rollbackClockPlan.planId } '^NGCB-AUTHORIZATION-CLOCK-INVALID$' 'Apply fails closed on rollback-clock evidence before approval consumption.'

    $macHarness=New-NgcbHarness
    $macHarness.State.adapters += [pscustomobject][ordered]@{vmId=[guid]::NewGuid().ToString();adapterId=[guid]::NewGuid().ToString();macAddress='02AABBCCDDEE';dynamicMacAddressEnabled=$false;switchId=$authorization.switch.id}
    Assert-NgcbThrows { New-NorthGateCreateOnlyHostPlan -Context $macHarness.Context -PlanRequestBytes (New-NgcbPlanRequest) } '^NGCB-CREATE-COLLISION$' 'Static MAC collision blocks planning.'

    $missingMediaHarness=New-NgcbHarness
    $missingMediaHarness.State.selectedBootstrapMedia.path=(Join-Path $testRoot 'missing-derivative.iso')
    Assert-NgcbThrows { New-NorthGateCreateOnlyHostPlan -Context $missingMediaHarness.Context -PlanRequestBytes (New-NgcbPlanRequest) } '^NGCB-LIVE-BOOTSTRAP-MEDIA-MISMATCH$' 'Missing or unresolvable derivative-media evidence blocks planning.'

    $provenanceHarness=New-NgcbHarness
    $provenanceHarness.State.selectedBootstrapProvenance.sha256='f'*64
    Assert-NgcbThrows { New-NorthGateCreateOnlyHostPlan -Context $provenanceHarness.Context -PlanRequestBytes (New-NgcbPlanRequest) } '^NGCB-LIVE-BOOTSTRAP-PROVENANCE-MISMATCH$' 'Derivative provenance mismatch blocks planning.'

    $mediaSwapHarness=New-NgcbHarness
    $mediaSwapPlan=New-NorthGateCreateOnlyHostPlan -Context $mediaSwapHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $null=Register-NgcbTestApproval $mediaSwapHarness.Context $mediaSwapPlan $null
    $mediaSwapHarness.State.selectedBootstrapMedia.sha256='f'*64
    Assert-NgcbThrows { Invoke-NorthGateCreateOnlyApply -Context $mediaSwapHarness.Context -PlanId $mediaSwapPlan.planId } '^NGCB-LIVE-BOOTSTRAP-MEDIA-MISMATCH$' 'Derivative ISO swap after planning is detected again under the apply lock.'

    $driftHarness=New-NgcbHarness
    $driftPlan=New-NorthGateCreateOnlyHostPlan -Context $driftHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $null=Register-NgcbTestApproval $driftHarness.Context $driftPlan $null
    $driftHarness.State.vms += [pscustomobject][ordered]@{vmId=[guid]::NewGuid().ToString();name='UNRELATED';generation=2;state='Running';path='C:\Unrelated';notes=''}
    Assert-NgcbThrows { Invoke-NorthGateCreateOnlyApply -Context $driftHarness.Context -PlanId $driftPlan.planId } '^NGCB-LIVE-STATE-DRIFT$' 'Any identity-set drift invalidates apply.'

    $capacityHarness=New-NgcbHarness
    $capacityHarness.State.volumes[0].freeBytes=[int64](110GB)
    Assert-NgcbThrows { New-NorthGateCreateOnlyHostPlan -Context $capacityHarness.Context -PlanRequestBytes (New-NgcbPlanRequest) } '^NGCB-CAPACITY-INSUFFICIENT$' 'Reserve-aware storage capacity blocks planning.'

    $invalidRatioPolicy=Copy-NgcbTestObject $policy
    $invalidRatioPolicy.limits.maximumVcpuToLogicalRatio=3
    Assert-NgcbThrows { & $module { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } $invalidRatioPolicy $authorization $authorizationHash ('d'*64) } '^NGCB-POLICY-LIMITS-INVALID$' 'Unsigned or out-of-range vCPU overcommit ratios are rejected.'

    $ratioOneHarness=New-NgcbHarness
    $ratioOneHarness.Context.Policy.limits.maximumVcpuToLogicalRatio=1
    $ratioOneHarness.State.existingProcessorCount=30
    Assert-NgcbThrows { New-NorthGateCreateOnlyHostPlan -Context $ratioOneHarness.Context -PlanRequestBytes (New-NgcbPlanRequest) } '^NGCB-CAPACITY-INSUFFICIENT$' 'A 1x signed ratio preserves two physical logical processors and blocks excess configured vCPU.'

    $ratioTwoHarness=New-NgcbHarness
    $ratioTwoHarness.State.existingProcessorCount=58
    $ratioTwoPlan=New-NorthGateCreateOnlyHostPlan -Context $ratioTwoHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $ratioTwoPlanObject=ConvertFrom-Json $ratioTwoPlan.canonicalPlan
    Assert-NgcbTest ($ratioTwoPlanObject.liveState.capacity.maximumVcpuToLogicalRatio -eq 2 -and
        $ratioTwoPlanObject.liveState.capacity.maximumConfiguredProcessorCount -eq 60 -and
        $ratioTwoPlanObject.liveState.capacity.configuredProcessorHeadroom -eq 2) 'A signed 2x ratio permits the exact boundary while reserving two of 32 physical logical processors.'

    $ratioOverflowHarness=New-NgcbHarness
    $ratioOverflowHarness.State.existingProcessorCount=59
    Assert-NgcbThrows { New-NorthGateCreateOnlyHostPlan -Context $ratioOverflowHarness.Context -PlanRequestBytes (New-NgcbPlanRequest) } '^NGCB-CAPACITY-INSUFFICIENT$' 'Configured vCPU above the signed 2x boundary fails closed.'

    $safeRetryHarness=New-NgcbHarness
    $safeRetryPlan=New-NorthGateCreateOnlyHostPlan -Context $safeRetryHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $null=Register-NgcbTestApproval $safeRetryHarness.Context $safeRetryPlan $null
    $safeRetryHarness.Context.TestScenario='FailBeforeCreate'
    $safeRetryReceipt=Invoke-NorthGateCreateOnlyApply -Context $safeRetryHarness.Context -PlanId $safeRetryPlan.planId
    Assert-NgcbTest ($safeRetryReceipt.receipt.outcome -ceq 'Failed' -and
        $safeRetryReceipt.receipt.quarantineState -ceq 'not-required') 'A pre-create failure records signed no-artifact evidence without claiming success.'
    Assert-NgcbThrows { New-NorthGateCreateOnlyHostPlan -Context $safeRetryHarness.Context -PlanRequestBytes (New-NgcbPlanRequest) } '^NGCB-RETRY-RECOVERY-FINALIZATION-REQUIRED$' 'A failed no-artifact attempt cannot release its identity based only on the apply result.'
    $safeRetryRecovery=Invoke-NorthGateCreateOnlyCrashRecovery -Context $safeRetryHarness.Context -AssetId 'NG-VM-018'
    Assert-NgcbTest (@($safeRetryRecovery).Count -eq 1 -and
        @($safeRetryRecovery)[0].state -ceq 'AbortedNoArtifacts' -and
        @($safeRetryRecovery)[0].reasonCode -ceq 'NGCB-RECOVERY-NO-ARTIFACTS' -and
        -not @($safeRetryRecovery)[0].approvalReusable) 'Authenticated recovery re-observes no artifacts and explicitly finalizes the failed reservation.'
    $recoveredPlan=Get-NorthGateCreateOnlyHostPlan -Context $safeRetryHarness.Context -PlanId $safeRetryPlan.planId
    Assert-NgcbTest ($recoveredPlan.state -ceq 'RecoveredNoArtifacts' -and
        $recoveredPlan.approvalState -ceq 'Consumed') 'Recovery preserves the consumed approval and immutable terminal plan evidence.'
    $safeRetryHarness.Context.TestScenario='None'
    $replacementPlan=New-NorthGateCreateOnlyHostPlan -Context $safeRetryHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    Assert-NgcbTest ($replacementPlan.planId -cne $safeRetryPlan.planId) 'A finalized no-artifact attempt permits only a fresh plan with a new approval capability.'
    $retryLedger=& $module {param($c)Read-NgcbLedger $c} $safeRetryHarness.Context
    Assert-NgcbTest (@($retryLedger.entries).Count -eq 2 -and
        $retryLedger.entries[0].state -ceq 'AbortedNoArtifacts' -and
        $retryLedger.entries[1].state -ceq 'Reserved') 'Retry retains immutable aborted history beside the new authoritative reservation.'

    $failureHarness=New-NgcbHarness
    $failurePlan=New-NorthGateCreateOnlyHostPlan -Context $failureHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $null=Register-NgcbTestApproval $failureHarness.Context $failurePlan $null
    $failureHarness.Context.TestScenario='CrashAfterCreate'
    $failedReceipt=Invoke-NorthGateCreateOnlyApply -Context $failureHarness.Context -PlanId $failurePlan.planId
    Assert-NgcbTest ($failedReceipt.receipt.outcome -ceq 'Failed' -and $failedReceipt.receipt.quarantineState -ceq 'completed' -and $failedReceipt.receipt.controls.identityReuseBlocked) 'Owned partial create is quarantined with identity reuse blocked.'
    Assert-NgcbThrows { New-NorthGateCreateOnlyHostPlan -Context $failureHarness.Context -PlanRequestBytes (New-NgcbPlanRequest) } '^NGCB-CREATE-COLLISION$' 'A quarantined partial create remains a hard identity-reuse blocker.'

    $unknownHarness=New-NgcbHarness
    $unknownPlan=New-NorthGateCreateOnlyHostPlan -Context $unknownHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $null=Register-NgcbTestApproval $unknownHarness.Context $unknownPlan $null
    $unknownHarness.Context.TestScenario='UnknownAfterCreate'
    $unknownReceipt=Invoke-NorthGateCreateOnlyApply -Context $unknownHarness.Context -PlanId $unknownPlan.planId
    Assert-NgcbTest ($unknownReceipt.receipt.outcome -ceq 'OutcomeUnknown' -and $unknownReceipt.receipt.quarantineState -ceq 'required') 'Unproven ownership is not touched and requires reconciliation.'
    Assert-NgcbThrows { New-NorthGateCreateOnlyHostPlan -Context $unknownHarness.Context -PlanRequestBytes (New-NgcbPlanRequest) } '^NGCB-CREATE-COLLISION$' 'An outcome-unknown partial create remains a hard identity-reuse blocker.'
    $recovery=Invoke-NorthGateCreateOnlyCrashRecovery -Context $unknownHarness.Context -AssetId 'NG-VM-018'
    Assert-NgcbTest (@($recovery).Count -eq 1 -and @($recovery)[0].state -ceq 'OutcomeUnknown' -and -not @($recovery)[0].approvalReusable) ('Crash recovery remains fail closed for uncertain ownership: ' + (ConvertTo-Json $recovery -Compress))

    $tamperHarness=New-NgcbHarness
    $tamperPlan=New-NorthGateCreateOnlyHostPlan -Context $tamperHarness.Context -PlanRequestBytes (New-NgcbPlanRequest)
    $planPath=Join-Path $tamperHarness.Context.StateRoot ('plans\'+$tamperPlan.planId+'.json')
    $tampered=ConvertFrom-Json ([IO.File]::ReadAllText($planPath));$tampered.record.state='Applied'
    [IO.File]::WriteAllBytes($planPath,(ConvertTo-NgcbTestBytes $tampered))
    Assert-NgcbThrows { Get-NorthGateCreateOnlyHostPlan -Context $tamperHarness.Context -PlanId $tamperPlan.planId } '^NGCB-PLAN-RECORD-CORRUPT$' 'Authenticated plan state rejects tampering.'
}
finally {
    if ($approvalMaterial) { $approvalMaterial.Certificate.Dispose(); $approvalMaterial.Rsa.Dispose() }
    if ($receiptMaterial) { $receiptMaterial.Certificate.Dispose(); $receiptMaterial.Rsa.Dispose() }
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}

Write-Output "PASS: $script:Assertions assertions"
