[CmdletBinding()]
param()

$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$protocolPath=Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'NorthGate.VMFactory.CreateOnlyProtocol.psd1'
Import-Module $protocolPath -Force -ErrorAction Stop
$module=Import-Module (Join-Path $root 'NorthGate.VMFactory.CreateOnlyAuthoring.psd1') -Force -PassThru -ErrorAction Stop
Import-Module $protocolPath -Force -Global -ErrorAction Stop
$script:Assertions=0

function Assert-NgcaTest { param([bool]$Condition,[string]$Message);$script:Assertions++;if(-not $Condition){throw "ASSERTION FAILED: $Message"} }
function Assert-NgcaThrows {
    param([scriptblock]$Action,[string]$Pattern,[string]$Message)
    $script:Assertions++
    try{& $Action;throw "ASSERTION FAILED: $Message (no exception)"}
    catch{if($_.Exception.Message -notmatch $Pattern){throw "ASSERTION FAILED: $Message (got '$($_.Exception.Message)')"}}
}
function Get-NgcaTestSha { param([byte[]]$Bytes);$a=[Security.Cryptography.SHA256]::Create();try{$h=$a.ComputeHash($Bytes)}finally{$a.Dispose()};(($h|%{$_.ToString('x2')})-join '') }
function Get-NgcaTestCertSha { param($Certificate);Get-NgcaTestSha $Certificate.RawData }
function Format-NgcaTestUtc { param([DateTimeOffset]$Value);$Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'",[Globalization.CultureInfo]::InvariantCulture) }
function Write-NgcaTestCanonical {
    param([string]$Path,[object]$Value)
    $parent=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $parent)){[IO.Directory]::CreateDirectory($parent)|Out-Null}
    $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $Value));[IO.File]::WriteAllBytes($Path,$bytes)
    [pscustomobject]@{path=$Path;bytes=$bytes;sha256=(Get-NgcaTestSha $bytes)}
}
function Invoke-NgcaTestGit {
    param([string]$Repository,[string[]]$Arguments)
    $previousErrorActionPreference=$ErrorActionPreference
    try{
        $ErrorActionPreference='Continue'
        $output=& git.exe -C $Repository @Arguments 2>&1
    }
    finally{$ErrorActionPreference=$previousErrorActionPreference}
    if($LASTEXITCODE -ne 0){throw "TEST-GIT-FAILED: git $($Arguments -join ' '): $output"}
    @($output)
}
function New-NgcaTestCertificate {
    param([string]$Name)
    $rsa=[Security.Cryptography.RSA]::Create(3072)
    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$Name",$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
    $eku=New-Object Security.Cryptography.OidCollection;$null=$eku.Add((New-Object Security.Cryptography.Oid '1.3.6.1.5.5.7.3.3'))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku,$true))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,$true))
    $certificate=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5),[DateTimeOffset]::UtcNow.AddHours(12))
    $password=[guid]::NewGuid().ToString('N')
    $pfx=$certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx,$password)
    [pscustomobject]@{Certificate=$certificate;Rsa=$rsa;Pfx=$pfx;Password=$password}
}
function New-NgcaPromotion {
    [pscustomobject][ordered]@{
        '$schema'='../schemas/deployment-promotion.schema.json';apiVersion='northgate/v1alpha1';kind='CreateOnlyDeploymentPromotion'
        promotionVersion='2026.08.02.1';status='approved';changeRef='NG-CHG-20260802-004';approvalReference='owner-approval-20260802'
        scope='exact-new-fleet-create-only'
        controls=[pscustomobject][ordered]@{
            rawGitDataOnly=$true;installedSignedReleaseRequired=$true;signedHostAuthorizationRequired=$true
            freshHostPlanRequired=$true;exactOneTimePlanApprovalRequired=$true;oneAssetPerPlan=$true
            retainedAssetMutationAllowed=$false;deletePathAllowed=$false;replacePathAllowed=$false;adoptPathAllowed=$false
            quarantineOnUncertainty=$true;signedReceiptRequired=$true
        }
        retainedAssetNames=[object[]]@('JS-BlueBench','JS-Server-01','OPNsense-Tooling','TRMM-Tooling','Wazuh-Machine')
        canaryAssetIds=[object[]]@('NG-VM-018','NG-VM-010')
        persistentAssetIds=[object[]]@('NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012','NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015')
        orderedAssetIds=[object[]]@('NG-VM-018','NG-VM-010','NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012','NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015')
        firmwareExceptions=[object[]]@([pscustomobject][ordered]@{exceptionId='NG-FW-20260802-KALI-UNSIGNED';assetId='NG-VM-015';profileRef='kali-gen2-unsigned';secureBootEnabled=$false;reason='official-kali-installer-kernel-is-not-secure-boot-signed'})
        requiredGates=[object[]]@('control-plane-negative-tests-passed','immutable-signed-release-installed','signed-host-authorization-verified','immutable-images-promoted','opaque-profiles-approved','retained-system-backups-verified','debian-canary-before-windows-canary','canaries-accepted-before-persistent-fleet','one-asset-per-fresh-plan','exact-plan-human-approval','quarantine-route-proven','signed-receipt-ready')
    }
}
function New-NgcaResourcePolicy {
    [pscustomobject][ordered]@{
        '$schema'='../schemas/resource-policy.schema.json';apiVersion='northgate/v1alpha1';kind='ResourcePolicy'
        policyVersion='2026.08.02.9';status='approved';applyEnabled=$true;hostReserveMemoryMiB=49152
        minimumVolumeFreeGiB=100;minimumVolumeFreePercent=15
        perVm=[pscustomobject][ordered]@{maximumProcessors=8;maximumStartupMemoryMiB=32768;maximumDynamicMemoryMiB=65536;maximumOsDiskGiB=256}
        plannerActions=[object[]]@('NoOp','Create','UpdateOnline','UpdateOffline','ReplaceRequired','DecommissionRequired')
        executableActions=[object[]]@('Create')
        deniedOperations=[object[]]@('implicit-delete','automatic-replace','disk-purge','switch-mutation','arbitrary-command')
    }
}

function New-NgcaGitFixture {
    param([string]$Base,[ValidateSet('Valid','Noncanonical','Filter','Executable','Secret','Submodule')][string]$Mode='Valid')
    $repo=Join-Path $Base ('repo-'+$Mode+'-'+[guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($repo)|Out-Null
    Invoke-NgcaTestGit $repo @('init','--quiet')|Out-Null
    Invoke-NgcaTestGit $repo @('config','user.email','northgate-test@example.invalid')|Out-Null
    Invoke-NgcaTestGit $repo @('config','user.name','NorthGate Test')|Out-Null
    $imageCatalog=[pscustomobject][ordered]@{apiVersion='northgate/v1alpha1';kind='ImageCatalog';images=[object[]]@(
        [pscustomobject][ordered]@{id='debian-12.12-amd64-netinst';sourceArtifactId='debian-12.12.0-amd64-netinst-iso'},
        [pscustomobject][ordered]@{id='windows-11-25h2-english-x64';sourceArtifactId='windows-11-25h2-english-x64-iso'},
        [pscustomobject][ordered]@{id='kali-2026.2-installer-netinst-amd64';sourceArtifactId='kali-linux-2026.2-installer-netinst-amd64-iso'})}
    $catalogPaths=@('catalog/images.json','catalog/networks.json','catalog/storage-profiles.json','catalog/firmware-profiles.json','catalog/bootstrap-profiles.json','catalog/recovery-profiles.json')
    foreach($path in $catalogPaths){
        $value=if($path -ceq 'catalog/images.json'){$imageCatalog}else{[pscustomobject][ordered]@{apiVersion='northgate/v1alpha1';kind=([IO.Path]::GetFileNameWithoutExtension($path));profiles=[object[]]@()}}
        $full=Join-Path $repo ($path.Replace('/','\'))
        if($Mode -ceq 'Noncanonical' -and $path -ceq 'catalog/networks.json'){
            $parent=Split-Path -Parent $full;[IO.Directory]::CreateDirectory($parent)|Out-Null
            [IO.File]::WriteAllText($full,(ConvertTo-Json $value -Depth 10),(New-Object Text.UTF8Encoding($false)))
        }else{Write-NgcaTestCanonical $full $value|Out-Null}
    }
    $manifest=[pscustomobject][ordered]@{apiVersion='northgate/v1alpha1';kind='VirtualMachine';metadata=[pscustomobject][ordered]@{assetId='NG-VM-018';name='NG-DEB-CAN01'}}
    if($Mode -ceq 'Secret'){$manifest|Add-Member -NotePropertyName password -NotePropertyValue 'NotAllowedSecret123!'}
    Write-NgcaTestCanonical (Join-Path $repo 'manifests\vms\NG-VM-018.json') $manifest|Out-Null
    Write-NgcaTestCanonical (Join-Path $repo 'schemas\fixture.schema.json') ([pscustomobject][ordered]@{'$schema'='https://json-schema.org/draft/2020-12/schema';type='object'})|Out-Null
    $promotionArtifact=Write-NgcaTestCanonical (Join-Path $repo 'policy\deployment-promotion.json') (New-NgcaPromotion)
    Write-NgcaTestCanonical (Join-Path $repo 'policy\resource-limits.json') (New-NgcaResourcePolicy)|Out-Null
    if($Mode -ceq 'Filter'){[IO.File]::WriteAllText((Join-Path $repo '.gitattributes'),"*.json filter=evil`n",(New-Object Text.UTF8Encoding($false)))}
    Invoke-NgcaTestGit $repo @('add','--all')|Out-Null
    if($Mode -ceq 'Executable'){Invoke-NgcaTestGit $repo @('update-index','--chmod=+x','catalog/images.json')|Out-Null}
    Invoke-NgcaTestGit $repo @('commit','--quiet','--no-gpg-sign','-m','fixture')|Out-Null
    if($Mode -ceq 'Submodule'){
        $head=([string](Invoke-NgcaTestGit $repo @('rev-parse','HEAD'))).Trim()
        Invoke-NgcaTestGit $repo @('update-index','--add','--cacheinfo',"160000,$head,vendor/submodule")|Out-Null
        Invoke-NgcaTestGit $repo @('commit','--quiet','--no-gpg-sign','-m','gitlink')|Out-Null
    }
    $commit=([string](Invoke-NgcaTestGit $repo @('rev-parse','HEAD'))).Trim()
    $tree=([string](Invoke-NgcaTestGit $repo @('rev-parse',"$commit^{tree}"))).Trim()
    [pscustomobject]@{root=$repo;commit=$commit;tree=$tree;promotionSha256=$promotionArtifact.sha256;sourcePaths=[object[]]@($catalogPaths+'manifests/vms/NG-VM-018.json'+'schemas/fixture.schema.json'+'policy/deployment-promotion.json'+'policy/resource-limits.json')}
}

function New-NgcaAuthorization {
    param($Fixture,$ReleasePin,$AuthorizationPin,$ApprovalPin,$ReceiptPin,$Base)
    $issued=[DateTimeOffset]::UtcNow.AddMinutes(-1);$expires=[DateTimeOffset]::UtcNow.AddHours(10)
    $protected=[object[]]@(
        [pscustomobject][ordered]@{name='JS-BlueBench';vmId='11111111-1111-1111-1111-111111111111';diskUniqueIds=[object[]]@('disk-blue');adapterIds=[object[]]@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1')},
        [pscustomobject][ordered]@{name='JS-Server-01';vmId='22222222-2222-2222-2222-222222222222';diskUniqueIds=[object[]]@('disk-server');adapterIds=[object[]]@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2')},
        [pscustomobject][ordered]@{name='OPNsense-Tooling';vmId='33333333-3333-3333-3333-333333333333';diskUniqueIds=[object[]]@('disk-opn');adapterIds=[object[]]@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3')},
        [pscustomobject][ordered]@{name='TRMM-Tooling';vmId='44444444-4444-4444-4444-444444444444';diskUniqueIds=[object[]]@('disk-trmm');adapterIds=[object[]]@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa4')},
        [pscustomobject][ordered]@{name='Wazuh-Machine';vmId='55555555-5555-5555-5555-555555555555';diskUniqueIds=[object[]]@('disk-wazuh');adapterIds=[object[]]@('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa5')}
    )
    $imageRoot=Join-Path $Base 'images'
    $authorizedImages=[object[]]@(
        [pscustomobject][ordered]@{imageId='debian-12.12-amd64-netinst';path=(Join-Path $imageRoot 'debian-12.12.0-amd64-netinst.iso');sha256=('6'*64);sizeBytes=[int64]704643072},
        [pscustomobject][ordered]@{imageId='kali-2026.2-installer-netinst-amd64';path=(Join-Path $imageRoot 'kali-linux-2026.2-installer-netinst-amd64.iso');sha256=('7'*64);sizeBytes=[int64]779091968},
        [pscustomobject][ordered]@{imageId='windows-11-25h2-english-x64';path=(Join-Path $imageRoot 'Win11_25H2_English_x64.iso');sha256=('8'*64);sizeBytes=[int64]7736125440}
    )
    $ids=@('NG-VM-018','NG-VM-010','NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012','NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015')
    $windowsIds=@('NG-VM-010','NG-VM-011','NG-VM-012','NG-VM-019','NG-VM-020','NG-VM-021')
    $bootstrapMedia=@()
    for($i=0;$i-lt$ids.Count;$i++){
        $sourceImageId=if($ids[$i]-in$windowsIds){'windows-11-25h2-english-x64'}elseif($ids[$i]-ceq'NG-VM-015'){'kali-2026.2-installer-netinst-amd64'}else{'debian-12.12-amd64-netinst'}
        $sourceImage=@($authorizedImages|Where-Object imageId -ceq $sourceImageId)[0]
        $bootstrapMedia += [pscustomobject][ordered]@{
            assetId=$ids[$i];mediaId=('ngmedia-'+$ids[$i].ToLowerInvariant())
            mode='asset-bound-derivative-iso'
            path=(Join-Path $imageRoot ($ids[$i].ToLowerInvariant()+'-unattended.iso'));sha256=('{0:x64}'-f(100+$i))
            sizeBytes=[int64](1048576+$i);sourceImageId=$sourceImageId;sourceImageSha256=$sourceImage.sha256
            provenancePath=(Join-Path $imageRoot ($ids[$i].ToLowerInvariant()+'-provenance.json'))
            provenanceSha256=('{0:x64}'-f(400+$i));bundleManifestSha256=('{0:x64}'-f(500+$i))
            builderId='northgate-unattended-media-v1';builderReleaseSha256=('2'*64);recipeSha256=('{0:x64}'-f(200+$i))
            unattendedPayloadSha256=('{0:x64}'-f(300+$i));sourceCommit=$Fixture.commit;sourceTree=$Fixture.tree
        }
    }
    [pscustomobject][ordered]@{
        schema='northgate/create-only-host-deployment-authorization/v2';authorizationId='ngdeploy-authoring-test-01';sequence=1
        issuedAtUtc=(Format-NgcaTestUtc $issued);expiresAtUtc=(Format-NgcaTestUtc $expires)
        repository=[pscustomobject][ordered]@{identity='Beowxlf/northgate-vm-factory';releaseId='ngcor-authoring-test-01';commit=$Fixture.commit;tree=$Fixture.tree;hostAllowlistId='ngallow-authoring-test-01';packageAllowlistSha256=('1'*64);governanceExceptionId='NG-GOV-20260802-TEST'}
        releaseManifestSha256=('2'*64)
        host=[pscustomobject][ordered]@{hostId='nghost-authoring-test-01';computerName='HC-HV01';machineGuidSha256=('3'*64);hyperVHostId='99999999-9999-9999-9999-999999999999';osBuild='20348.2762'}
        install=[pscustomobject][ordered]@{versionedReleaseRoot='C:\Program Files\NorthGate\CreateOnly\releases\test';stateRoot='C:\ProgramData\NorthGate\CreateOnly\state';quarantineRoot='C:\ProgramData\NorthGate\CreateOnly\quarantine'}
        identity=[pscustomobject][ordered]@{sshIdentitySid='S-1-5-21-1-2-3-1001';serviceIdentitySid='S-1-5-21-1-2-3-1002';releaseSignerCertificateSha256=$ReleasePin;deploymentAuthorizationSignerCertificateSha256=$AuthorizationPin;approvalSignerCertificateSha256=$ApprovalPin;receiptSignerCertificateSha256=$ReceiptPin}
        'switch'=[pscustomobject][ordered]@{switchPolicyId='northgate-app-trunk';name='NorthGate-App-Trunk';id='88888888-8888-8888-8888-888888888888';fingerprint=('4'*64);trunkAdapterId='77777777-7777-7777-7777-777777777777';trunkAdapterFingerprint=('5'*64);mode='existing-only';allowCreate=$false;vlanProfiles=[pscustomobject][ordered]@{'business-apps'=150;'commercial-dmz'=160;'cyber-workstations'=140;'external-mail'=240;'it-admin-workstations'=130;'mail-internal'=120;'sim-wan'=250;'users-workstations'=110}}
        volumes=[object[]]@(
            [pscustomobject][ordered]@{volumeId='volume-d';uniqueId='volume-d-test-001';root='D:\HyperV';persistentCeilingGiB=1000;canaryCeilingGiB=100},
            [pscustomobject][ordered]@{volumeId='volume-f';uniqueId='volume-f-test-001';root='F:\HyperV';persistentCeilingGiB=1000;canaryCeilingGiB=100})
        images=$authorizedImages
        bootstrapMedia=[object[]]$bootstrapMedia
        protectedAssets=$protected
        accessIsolation=[pscustomobject][ordered]@{routineSshIsLocalAdministrator=$false;routineSshIsHyperVAdministrator=$false;routineSshCanUsePowerShellRemoting=$false;routineSshCanReachLegacyMcp=$false}
        initialPolicy=[pscustomobject][ordered]@{applyEnabled=$false;executableActions=[object[]]@();canaryStage='disabled'}
    }
}

function New-NgcaMapping {
    param($Authorization)
    $assets=@();$ids=@('NG-VM-018','NG-VM-010','NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012','NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015')
    $names=@('NG-DEB-CAN01','NG-CANARY-01','NG-MAIL-EXT01','NG-MAIL-INT01','NG-WRK-01','NG-WRK-02','NG-MGR-01','NG-IT-01','NG-CYBER-01','NG-HR-APP01','NG-PLAT-APP01','NG-KALI-EXT01')
    for($i=0;$i-lt $ids.Count;$i++){
        $image='debian-12.12-amd64-netinst';$firmware='linux-gen2'
        if($ids[$i]-ceq'NG-VM-010'){$image='windows-11-25h2-english-x64';$firmware='windows-gen2'}
        if($ids[$i]-ceq'NG-VM-015'){$image='kali-2026.2-installer-netinst-amd64';$firmware='kali-gen2-unsigned'}
        $assets+=[pscustomobject][ordered]@{assetId=$ids[$i];name=$names[$i];allowedImageRefs=[object[]]@($image);allowedStorageProfileRefs=[object[]]@('lab-storage');allowedNetworkProfileRefs=[object[]]@('business-apps');allowedFirmwareProfileRefs=[object[]]@($firmware);allowedBootstrapProfileRefs=[object[]]@('bootstrap-standard');allowedRecoveryProfileRefs=[object[]]@('recovery-standard');maximumProcessors=4;maximumMemoryMiB=16384;maximumOsDiskGiB=120;adapterPolicyId=('ngnic-'+$names[$i].ToLowerInvariant());staticMacAddress=('02AABBCCDD{0:X2}'-f($i+1));bootstrapMediaId=('ngmedia-'+$ids[$i].ToLowerInvariant())}
    }
    [pscustomobject][ordered]@{
        schema='northgate/create-only-backend-policy-mapping/v1';policyId='northgate-authoring-test';policyVersion='2026.08.02.9';stateKeyId='ngkey-authoring-test-01';planTtlSeconds=900;approvalTtlSeconds=300
        limits=[pscustomobject][ordered]@{hostReserveMemoryMiB=49152;hostProcessorReserveCount=2;maximumVcpuToLogicalRatio=2;minimumVolumeFreeBytes=[int64](100GB);minimumVolumeFreePercent=15;maximumProcessorCount=8;maximumStartupMemoryMiB=32768;maximumDynamicMemoryMiB=65536;maximumOsDiskGiB=256}
        rollout=[pscustomobject][ordered]@{stage='debian-canary';exactAssetOrder=[object[]]@('NG-VM-018','NG-VM-010','NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012','NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015');maximumConcurrentTransactions=1;debianCanary=[pscustomobject][ordered]@{assetId='NG-VM-018';status='pending';receiptSha256='';acceptanceEvidenceSha256='';retirementEvidenceSha256=''};windowsCanary=[pscustomobject][ordered]@{assetId='NG-VM-010';status='pending';receiptSha256='';acceptanceEvidenceSha256='';retirementEvidenceSha256=''}}
       storageProfiles=[object[]]@([pscustomobject][ordered]@{profileRef='lab-storage';catalogServerPolicyId='ng-storage-lab-v1';volumeId='volume-d';root='D:\HyperV';reserveBytes=[int64](100GB);maximumOsDiskGiB=256;workloadClass='persistent'})
        networkProfiles=[object[]]@([pscustomobject][ordered]@{profileRef='business-apps';catalogServerPolicyId='ng-network-business-apps-v1';switchPolicyId='northgate-app-trunk';vlanId=150})
        images=[object[]]@(
            [pscustomobject][ordered]@{imageRef='debian-12.12-amd64-netinst';authorizationImageId='debian-12.12-amd64-netinst';path=$Authorization.images[0].path;sha256=$Authorization.images[0].sha256;sizeBytes=[int64]$Authorization.images[0].sizeBytes;guestFamily='linux';firmwareProfileRef='linux-gen2';secureBootEnabled=$true;secureBootTemplate='MicrosoftUEFICertificateAuthority';secureBootExceptionId='none';vtpmRequired=$false},
            [pscustomobject][ordered]@{imageRef='kali-2026.2-installer-netinst-amd64';authorizationImageId='kali-2026.2-installer-netinst-amd64';path=$Authorization.images[1].path;sha256=$Authorization.images[1].sha256;sizeBytes=[int64]$Authorization.images[1].sizeBytes;guestFamily='linux';firmwareProfileRef='kali-gen2-unsigned';secureBootEnabled=$false;secureBootTemplate='None';secureBootExceptionId='NG-FW-20260802-KALI-UNSIGNED';vtpmRequired=$false},
            [pscustomobject][ordered]@{imageRef='windows-11-25h2-english-x64';authorizationImageId='windows-11-25h2-english-x64';path=$Authorization.images[2].path;sha256=$Authorization.images[2].sha256;sizeBytes=[int64]$Authorization.images[2].sizeBytes;guestFamily='windows';firmwareProfileRef='windows-gen2';secureBootEnabled=$true;secureBootTemplate='MicrosoftWindows';secureBootExceptionId='none';vtpmRequired=$true})
        bootstrapMedia=[object[]]@($Authorization.bootstrapMedia)
        firmwareProfiles=[object[]]@([pscustomobject][ordered]@{profileRef='linux-gen2';catalogServerPolicyId='ng-firmware-linux-v1'},[pscustomobject][ordered]@{profileRef='windows-gen2';catalogServerPolicyId='ng-firmware-windows-v1'},[pscustomobject][ordered]@{profileRef='kali-gen2-unsigned';catalogServerPolicyId='ng-firmware-kali-v1'})
        bootstrapProfiles=[object[]]@([pscustomobject][ordered]@{profileRef='bootstrap-standard';catalogServerPolicyId='ng-bootstrap-standard-v1'})
        recoveryProfiles=[object[]]@([pscustomobject][ordered]@{profileRef='recovery-standard';catalogServerPolicyId='ng-recovery-standard-v1'})
        allowedAssets=[object[]]$assets
    }
}

$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('ngca-tests-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot)|Out-Null
$certificates=@()
try{
    foreach($schema in @(Get-ChildItem -LiteralPath (Join-Path $root 'schemas') -Filter '*.json' -File)){
        Assert-NgcaTest ($null-ne(Get-Content $schema.FullName -Raw|ConvertFrom-Json)) "Schema $($schema.Name) parses."
    }
    $source=[IO.File]::ReadAllText((Join-Path $root 'NorthGate.VMFactory.CreateOnlyAuthoring.psm1'))
    Assert-NgcaTest ($source -notmatch '(?i)\[securestring\]|password\s*=|privatekey\s*=') 'Authoring API does not accept password or private-key material.'
    Assert-NgcaTest ($source -match 'Get-NgcaSigningCertificate' -and $source -match 'NGCA-SIGNER-KEY-EXPORTABLE') 'Signing is pinned to a store certificate and rejects exportable private keys.'

    $releaseCert=New-NgcaTestCertificate 'NorthGate Release Authoring Test';$certificates+=$releaseCert
    $authorizationCert=New-NgcaTestCertificate 'NorthGate Authorization Authoring Test';$certificates+=$authorizationCert
    $approvalCert=New-NgcaTestCertificate 'NorthGate Approval Authoring Test';$certificates+=$approvalCert
    $receiptCert=New-NgcaTestCertificate 'NorthGate Receipt Authoring Test';$certificates+=$receiptCert
    $releasePin=Get-NgcaTestCertSha $releaseCert.Certificate;$authorizationPin=Get-NgcaTestCertSha $authorizationCert.Certificate
    $approvalPin=Get-NgcaTestCertSha $approvalCert.Certificate;$receiptPin=Get-NgcaTestCertSha $receiptCert.Certificate
    Assert-NgcaTest (@($releasePin,$authorizationPin,$approvalPin,$receiptPin|Sort-Object -Unique).Count-eq4) 'Release, authorization, approval, and receipt signer identities are distinct.'
    $materials=@{$releasePin=$releaseCert;$authorizationPin=$authorizationCert;$approvalPin=$approvalCert;$receiptPin=$receiptCert}
    $resolver={
        param($pin)
        $material=$materials[$pin]
        if($null-eq$material){return $null}
        $flags=[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet -bor
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        return [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            [byte[]]$material.Pfx,[string]$material.Password,$flags)
    }.GetNewClosure()
    $env:NGCA_INERT_TEST_PROCESS='1'
    & $module {param($r)Set-NgcaInertTestCertificateResolver $r} $resolver

    $fixture=New-NgcaGitFixture $testRoot Valid
    $bundleRoot=Join-Path $testRoot 'bundle-positive'
    $bundleResult=New-NorthGateCreateOnlyDataBundle -RepositoryRoot $fixture.root -Commit $fixture.commit -Tree $fixture.tree `
        -SourcePaths $fixture.sourcePaths -OutputRoot $bundleRoot -SignerCertificateSha256 $releasePin `
        -CertificateStoreLocation CurrentUser -LifetimeSeconds 3600 -ConfirmAuthoring
    Assert-NgcaTest ($bundleResult.status-ceq'signed-data-bundle-authored' -and $bundleResult.fileCount-eq10 -and
        (Test-Path -LiteralPath $bundleResult.bundlePath) -and (Test-Path -LiteralPath $bundleResult.signaturePath)) 'Raw-Git data bundle is atomically authored and signed.'
    $bundleObject=ConvertFrom-Json ([IO.File]::ReadAllText($bundleResult.bundlePath))
    Assert-NgcaTest ($bundleObject.repository.commit-ceq$fixture.commit -and $bundleObject.repository.tree-ceq$fixture.tree -and
        @($bundleObject.files|? role -eq schema).Count-eq1 -and @($bundleObject.files|? role -eq policy).Count-eq2) 'Bundle records exact commit/tree and only approved data roles.'
    $imageCopy=Join-Path $bundleRoot 'files\catalog\images.json';$imageObject=ConvertFrom-Json ([IO.File]::ReadAllText($imageCopy))
    Assert-NgcaTest ($imageObject.images[0].id-ceq'debian-12.12-amd64-netinst' -and $imageObject.images[0].sourceArtifactId-ceq'debian-12.12.0-amd64-netinst-iso') 'Debian public image ID remains distinct from sourceArtifactId.'
    Assert-NgcaThrows { New-NorthGateCreateOnlyDataBundle -RepositoryRoot $fixture.root -Commit $fixture.commit -Tree $fixture.tree -SourcePaths $fixture.sourcePaths -OutputRoot $bundleRoot -SignerCertificateSha256 $releasePin -CertificateStoreLocation CurrentUser -ConfirmAuthoring } '^NGCA-OUTPUT-EXISTS$' 'Existing bundle output is never overwritten.'

    [IO.File]::WriteAllText((Join-Path $fixture.root 'untracked.tmp'),'dirty')
    Assert-NgcaThrows { New-NorthGateCreateOnlyDataBundle -RepositoryRoot $fixture.root -Commit $fixture.commit -Tree $fixture.tree -SourcePaths $fixture.sourcePaths -OutputRoot (Join-Path $testRoot 'bundle-dirty') -SignerCertificateSha256 $releasePin -CertificateStoreLocation CurrentUser -ConfirmAuthoring } '^NGCA-REPOSITORY-DIRTY$' 'Dirty worktree is rejected before raw object authoring.'
    Remove-Item -LiteralPath (Join-Path $fixture.root 'untracked.tmp') -Force
    foreach($negative in @(
        [pscustomobject]@{mode='Noncanonical';pattern='^NGCA-DATA-SOURCE-NONCANONICAL$';message='Noncanonical source JSON is rejected.'},
        [pscustomobject]@{mode='Filter';pattern='^NGCA-GIT-FILTER-FORBIDDEN$';message='Git content filters are rejected.'},
        [pscustomobject]@{mode='Executable';pattern='^NGCA-DATA-EXECUTABLE-FORBIDDEN$';message='Executable data-root blobs are rejected.'},
        [pscustomobject]@{mode='Secret';pattern='^NGCA-SECRET-MATERIAL-FORBIDDEN$';message='Secret material in repository data is rejected.'},
        [pscustomobject]@{mode='Submodule';pattern='^NGCA-GIT-SUBMODULE-FORBIDDEN$';message='Submodules and gitlinks are rejected.'}
    )){
        $bad=New-NgcaGitFixture $testRoot $negative.mode
        Assert-NgcaThrows { New-NorthGateCreateOnlyDataBundle -RepositoryRoot $bad.root -Commit $bad.commit -Tree $bad.tree -SourcePaths $bad.sourcePaths -OutputRoot (Join-Path $testRoot ('bundle-'+$negative.mode)) -SignerCertificateSha256 $releasePin -CertificateStoreLocation CurrentUser -ConfirmAuthoring } $negative.pattern $negative.message
    }

    $authorization=New-NgcaAuthorization $fixture $releasePin $authorizationPin $approvalPin $receiptPin $testRoot
    $authorizationArtifact=Write-NgcaTestCanonical (Join-Path $testRoot 'authorization.json') $authorization
    $authorizationSignature=& $module {param($b,$c)New-NgcaDetachedCmsSignature $b $c} $authorizationArtifact.bytes $authorizationCert.Certificate
    [IO.File]::WriteAllBytes((Join-Path $testRoot 'authorization.p7s'),$authorizationSignature)
    $mapping=New-NgcaMapping $authorization
    $mappingArtifact=Write-NgcaTestCanonical (Join-Path $testRoot 'mapping.json') $mapping
    $disabledPolicy=New-NorthGateCreateOnlyBackendPolicyArtifact -RepositoryRoot $fixture.root `
        -HostAuthorizationPath $authorizationArtifact.path -HostAuthorizationSignaturePath (Join-Path $testRoot 'authorization.p7s') `
        -ExpectedHostAuthorizationSha256 $authorizationArtifact.sha256 -ExpectedHostAuthorizationSignerCertificateSha256 $authorizationPin `
        -MappingPath $mappingArtifact.path -OutputRoot (Join-Path $testRoot 'policy-disabled') `
        -SignerCertificateSha256 $releasePin -CertificateStoreLocation CurrentUser -ConfirmAuthoring
    Assert-NgcaTest (-not $disabledPolicy.applyEnabled -and $disabledPolicy.promotionRecordSha256-ceq'') 'Backend policy defaults disabled when no exact promotion record is supplied.'
    $enabledPolicy=New-NorthGateCreateOnlyBackendPolicyArtifact -RepositoryRoot $fixture.root `
        -HostAuthorizationPath $authorizationArtifact.path -HostAuthorizationSignaturePath (Join-Path $testRoot 'authorization.p7s') `
        -ExpectedHostAuthorizationSha256 $authorizationArtifact.sha256 -ExpectedHostAuthorizationSignerCertificateSha256 $authorizationPin `
        -MappingPath $mappingArtifact.path -OutputRoot (Join-Path $testRoot 'policy-enabled') `
        -SignerCertificateSha256 $releasePin -CertificateStoreLocation CurrentUser `
        -PromotionRecordPath 'policy/deployment-promotion.json' -ExpectedPromotionRecordSha256 $fixture.promotionSha256 -ConfirmAuthoring
    $enabledPolicyObject=ConvertFrom-Json ([IO.File]::ReadAllText($enabledPolicy.policyPath))
    Assert-NgcaTest ($enabledPolicy.applyEnabled -and $enabledPolicyObject.applyEnabled -and $enabledPolicyObject.limits.maximumVcpuToLogicalRatio-eq2 -and @($enabledPolicyObject.allowedAssets).Count-eq12) 'Exact promotion enables only the signed 12-asset create policy with bounded vCPU ratio.'
    Assert-NgcaThrows { New-NorthGateCreateOnlyBackendPolicyArtifact -RepositoryRoot $fixture.root -HostAuthorizationPath $authorizationArtifact.path -HostAuthorizationSignaturePath (Join-Path $testRoot 'authorization.p7s') -ExpectedHostAuthorizationSha256 $authorizationArtifact.sha256 -ExpectedHostAuthorizationSignerCertificateSha256 $authorizationPin -MappingPath $mappingArtifact.path -OutputRoot (Join-Path $testRoot 'policy-incomplete') -SignerCertificateSha256 $releasePin -CertificateStoreLocation CurrentUser -PromotionRecordPath 'policy/deployment-promotion.json' -ConfirmAuthoring } '^NGCA-PROMOTION-PARAMETERS-INCOMPLETE$' 'Promotion path without exact hash is rejected.'
    $badMapping=ConvertFrom-Json (ConvertTo-Json $mapping -Depth 30);$badMapping.images[0].imageRef='debian-12.12.0-amd64-netinst';$badMapping.images[0].authorizationImageId='debian-12.12.0-amd64-netinst'
    $badMappingArtifact=Write-NgcaTestCanonical (Join-Path $testRoot 'mapping-bad-debian.json') $badMapping
    Assert-NgcaThrows { New-NorthGateCreateOnlyBackendPolicyArtifact -RepositoryRoot $fixture.root -HostAuthorizationPath $authorizationArtifact.path -HostAuthorizationSignaturePath (Join-Path $testRoot 'authorization.p7s') -ExpectedHostAuthorizationSha256 $authorizationArtifact.sha256 -ExpectedHostAuthorizationSignerCertificateSha256 $authorizationPin -MappingPath $badMappingArtifact.path -OutputRoot (Join-Path $testRoot 'policy-bad-debian') -SignerCertificateSha256 $releasePin -CertificateStoreLocation CurrentUser -ConfirmAuthoring } '^NGCA-POLICY-IMAGE-AUTHORIZATION-MISMATCH$|^NGCA-DEBIAN-IMAGE-IDENTITY-DRIFT$' 'Backend policy rejects Debian public/source ID drift.'

    $planId='ngp-'+('a'*64);$now=[DateTimeOffset]::UtcNow
    $plan=[pscustomobject][ordered]@{schema='northgate/create-only-host-plan/v1';planId=$planId;issuedAtUtc=(Format-NgcaTestUtc $now.AddSeconds(-5));expiresAtUtc=(Format-NgcaTestUtc $now.AddMinutes(5));repository=[pscustomobject][ordered]@{identity='Beowxlf/northgate-vm-factory';commit=$fixture.commit;tree=$fixture.tree};release=[pscustomobject][ordered]@{releaseManifestSha256=$authorization.releaseManifestSha256};authorization=[pscustomobject][ordered]@{authorizationSha256=$authorizationArtifact.sha256};policy=[pscustomobject][ordered]@{policySha256=$enabledPolicy.policySha256};data=[pscustomobject][ordered]@{dataBundleSha256=$bundleResult.bundleSha256};operation=[pscustomobject][ordered]@{action='Create';assetId='NG-VM-018';name='NG-DEB-CAN01';changeId='NG-CHG-20260802-004'}}
    $canonicalPlan=ConvertTo-NorthGateCreateOnlyCanonicalJson $plan;$planHash=Get-NgcaTestSha ([Text.Encoding]::UTF8.GetBytes($canonicalPlan))
    $planEvidence=[pscustomobject][ordered]@{planId=$planId;planHash=$planHash;planAuthenticationHash=('b'*64);state='Registered';approvalState='Pending';expiresAtUtc=$plan.expiresAtUtc;assetId='NG-VM-018';name='NG-DEB-CAN01';action='Create';canonicalPlan=$canonicalPlan}
    $planEvidenceArtifact=Write-NgcaTestCanonical (Join-Path $testRoot 'plan-evidence.json') $planEvidence
    $planResult=& $module {param($p)Read-NgcaPlanEvidence $p} $planEvidenceArtifact.path
    $authRead=& $module {param($p)Read-NgcaCanonicalFile $p} $authorizationArtifact.path
    $policyRead=& $module {param($p)Read-NgcaCanonicalFile $p} $enabledPolicy.policyPath
    $bundleBytes=[IO.File]::ReadAllBytes($bundleResult.bundlePath)
    $bundleParsed=ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $bundleBytes -MaximumBytes 1048576
    $bundleRead=[pscustomobject][ordered]@{path=$bundleResult.bundlePath;bytes=$bundleBytes;sha256=(Get-NgcaTestSha $bundleBytes);canonicalJson=$bundleParsed.CanonicalJson;value=$bundleParsed.Value}
    $approvalState=Join-Path $testRoot 'approval-state';[IO.Directory]::CreateDirectory($approvalState)|Out-Null
    $approvalOutput=Join-Path $testRoot 'approval-output'
    $approvalResult=& $module {param($pr,$a,$p,$b,$sid,$s,$o,$pin)New-NgcaPlanApprovalArtifactCore $pr $a $p $b $sid $s $o $pin 'CurrentUser' 300 -SkipAclForInertTest} $planResult $authRead $policyRead $bundleRead 'S-1-5-21-1-2-3-500' $approvalState $approvalOutput $approvalPin
    $approvalObject=ConvertFrom-Json ([IO.File]::ReadAllText($approvalResult.approvalPath))
    Assert-NgcaTest ($approvalResult.status-ceq'one-use-approval-authored' -and $approvalObject.planId-ceq$planId -and $approvalObject.repository.commit-ceq$fixture.commit -and $approvalObject.releaseManifestSha256-ceq$authorization.releaseManifestSha256 -and $approvalObject.useLimit-eq1) 'Approval binds exact plan, repository, release, authorization, policy, data, SID, nonce, and one-use limit.'
    Assert-NgcaThrows { & $module {param($pr,$a,$p,$b,$sid,$s,$o,$pin)New-NgcaPlanApprovalArtifactCore $pr $a $p $b $sid $s $o $pin 'CurrentUser' 300 -SkipAclForInertTest} $planResult $authRead $policyRead $bundleRead 'S-1-5-21-1-2-3-500' $approvalState (Join-Path $testRoot 'approval-replay') $approvalPin } '^NGCA-APPROVAL-ALREADY-AUTHORED$' 'Durable per-plan authoring claim rejects duplicate approval creation.'
    $tamperedEvidence=ConvertFrom-Json (ConvertTo-Json $planEvidence -Depth 30);$tamperedEvidence.planHash='c'*64
    $tamperedArtifact=Write-NgcaTestCanonical (Join-Path $testRoot 'plan-tampered.json') $tamperedEvidence
    Assert-NgcaThrows { & $module {param($p)Read-NgcaPlanEvidence $p} $tamperedArtifact.path } '^NGCA-PLAN-EVIDENCE-BINDING-INVALID$' 'Plan hash substitution is rejected before signing.'
    Assert-NgcaThrows { New-NorthGateCreateOnlyPlanApprovalArtifact -PlanEvidencePath $planEvidenceArtifact.path -HostAuthorizationPath $authorizationArtifact.path -HostAuthorizationSignaturePath (Join-Path $testRoot 'authorization.p7s') -ExpectedHostAuthorizationSha256 $authorizationArtifact.sha256 -ExpectedHostAuthorizationSignerCertificateSha256 $authorizationPin -BackendPolicyPath $enabledPolicy.policyPath -BackendPolicySignaturePath $enabledPolicy.signaturePath -DataBundlePath $bundleResult.bundlePath -DataBundleSignaturePath $bundleResult.signaturePath -ApprovalStateRoot $approvalState -OutputRoot (Join-Path $testRoot 'approval-public') -SignerCertificateSha256 $approvalPin -CertificateStoreLocation CurrentUser -ConfirmApproval } '^NGCA-APPROVAL-NATIVE-ADMIN-REQUIRED$' 'Public approval helper requires the native elevated administrator token.'
}
finally{
    if($env:NGCA_INERT_TEST_PROCESS-ceq'1'){try{& $module {Set-NgcaInertTestCertificateResolver $null}}catch{};Remove-Item Env:\NGCA_INERT_TEST_PROCESS -ErrorAction SilentlyContinue}
    foreach($material in $certificates){$material.Certificate.Dispose();$material.Rsa.Dispose();[Array]::Clear($material.Pfx,0,$material.Pfx.Length);$material.Password=''}
    if(Test-Path -LiteralPath $testRoot){Remove-Item -LiteralPath $testRoot -Recurse -Force}
}
Write-Output "PASS: $script:Assertions assertions"
