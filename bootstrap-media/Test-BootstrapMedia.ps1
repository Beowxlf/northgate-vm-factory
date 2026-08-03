[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$modulePath = Join-Path $PSScriptRoot 'NorthGate.BootstrapMedia.psd1'
Import-Module $modulePath -Force
$script:Passed = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERT: $Message" }
    $script:Passed++
}

function Assert-ThrowsCode {
    param([scriptblock]$Action, [string]$Code)
    $caught = $null
    try { & $Action | Out-Null }
    catch { $caught = $_ }
    Assert-True ($null -ne $caught -and $caught.Exception.Message -ceq $Code) "expected $Code"
}

function Write-TestJson {
    param([object]$Value, [string]$Path)
    [IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 10) + "`n"), (New-Object Text.UTF8Encoding($false)))
}

function New-TestEd25519Line {
    $type = [Text.Encoding]::ASCII.GetBytes('ssh-ed25519')
    $material = New-Object byte[] 32
    for ($index = 0; $index -lt $material.Length; $index++) { $material[$index] = [byte]($index + 1) }
    $blob = [byte[]](@(0,0,0,11) + @($type) + @(0,0,0,32) + @($material))
    'ssh-ed25519 ' + [Convert]::ToBase64String($blob) + ' ngbm-test'
}

function Copy-JsonValue {
    param([object]$Value)
    ($Value | ConvertTo-Json -Depth 10 -Compress) | ConvertFrom-Json
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('northgate-bootstrap-tests-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($testRoot)
try {
    $sourceCatalog = Get-NorthGateBootstrapSourceCatalog
    Assert-True (@($sourceCatalog.images).Count -eq 3) 'three source images are pinned'
    $debianImage = @($sourceCatalog.images | Where-Object id -eq 'debian-12.12-amd64-netinst')[0]
    $windowsImage = @($sourceCatalog.images | Where-Object id -eq 'windows-11-25h2-english-x64')[0]
    $kaliImage = @($sourceCatalog.images | Where-Object id -eq 'kali-2026.2-installer-netinst-amd64')[0]
    Assert-True ($debianImage.sha256 -ceq 'dfc30e04fd095ac2c07e998f145e94bb8f7d3a8eca3a631d2eb012398deae531' -and [long]$debianImage.sizeBytes -eq 704643072) 'Debian source identity'
    Assert-True ($windowsImage.sha256 -ceq 'd141f6030fed50f75e2b03e1eb2e53646c4b21e5386047cb860af5223f102a32' -and [long]$windowsImage.sizeBytes -eq 7736125440 -and [int]$windowsImage.editionIndex -eq 6 -and $windowsImage.editionName -ceq 'Windows 11 Pro' -and $windowsImage.evaluationMedia -eq $false -and $windowsImage.productKeyEmbedded -eq $false -and $windowsImage.activationExpectedAtInstall -eq $false) 'Windows Pro index 6 is non-evaluation, unactivated, and has no product key'
    Assert-True ($kaliImage.sha256 -ceq 'd32f929dacc48134a31461a09f2160d13ad1d26b820cee920446813ca979b39b' -and [long]$kaliImage.sizeBytes -eq 779091968) 'Kali source identity'
    Assert-True ($debianImage.secureBoot -eq $true -and $windowsImage.secureBoot -eq $true -and $kaliImage.secureBoot -eq $false) 'family-specific Secure Boot policy'
    Assert-True ($kaliImage.firmwareProfile -ceq 'kali-gen2-unsigned' -and $kaliImage.secureBootExceptionId -ceq 'NG-FW-20260802-KALI-UNSIGNED') 'Kali exception binding'
    $linuxExtractedEfiPath = '/EFI/boot/bootx64.efi'
    Assert-True (@($debianImage.requiredIsoPaths) -ccontains $linuxExtractedEfiPath -and @($kaliImage.requiredIsoPaths) -ccontains $linuxExtractedEfiPath) 'Linux source paths use the exact case emitted by xorriso Rock Ridge extraction'
    Assert-True (@($debianImage.requiredIsoPaths) -cnotcontains '/EFI/BOOT/BOOTX64.EFI' -and @($kaliImage.requiredIsoPaths) -cnotcontains '/EFI/BOOT/BOOTX64.EFI') 'Linux source paths reject the case-only ISO9660 alias that is absent from the extracted tree'

    $fleet = Get-NorthGateBootstrapFleetMap
    Assert-True (@($fleet.assets).Count -eq 12) 'twelve exact fleet mappings'
    $known = @($fleet.assets | Where-Object assetId -eq 'NG-VM-021')[0]
    Assert-True ($known.name -ceq 'NG-KALI-EXT01' -and $known.staticMacAddress -ceq '024E47000015' -and [int]$known.vlanId -eq 250 -and $known.address -ceq '172.31.250.10') 'Kali exact identity mapping'

    $keyPath = Join-Path $testRoot 'bootstrap.pub'
    [IO.File]::WriteAllText($keyPath, (New-TestEd25519Line) + "`n", (New-Object Text.UTF8Encoding($false)))
    $key = Get-NorthGateAuthorizedPublicKey $keyPath
    Assert-True ($key.Type -ceq 'ssh-ed25519' -and $key.Fingerprint -match '^SHA256:[A-Za-z0-9+/]+$') 'ed25519 public key accepted and fingerprinted'

    $contexts = @{}
    foreach ($example in @('debian-canary','windows-canary','kali')) {
        $requestPath = Join-Path $PSScriptRoot "examples\$example.request.json"
        $contexts[$example] = Import-NorthGateBootstrapRequest $requestPath
        Assert-True ($contexts[$example].Netmask -ceq '255.255.255.0') "$example request validates"
        $output = Join-Path $testRoot "$example-bundle"
        $result = New-NorthGateBootstrapBundle -RequestPath $requestPath -AuthorizedPublicKeyPath $keyPath -OutputDirectory $output
        Assert-True ($result.FileCount -gt 5 -and $result.BundleManifestSha256 -match '^[a-f0-9]{64}$') "$example bundle rendered"
    }

    $debianBundle2 = Join-Path $testRoot 'debian-canary-bundle-2'
    $second = New-NorthGateBootstrapBundle -RequestPath (Join-Path $PSScriptRoot 'examples\debian-canary.request.json') -AuthorizedPublicKeyPath $keyPath -OutputDirectory $debianBundle2
    $firstHash = (Get-Content -LiteralPath (Join-Path $testRoot 'debian-canary-bundle\bundle-manifest.sha256') -Raw).Split(' ')[0]
    Assert-True ($firstHash -ceq $second.BundleManifestSha256) 'same validated inputs produce deterministic bundle manifest and file hashes'

    $linuxRoot = Join-Path $testRoot 'debian-canary-bundle\payload'
    $preseed = [IO.File]::ReadAllText((Join-Path $linuxRoot 'preseed.cfg'))
    $sshLinux = [IO.File]::ReadAllText((Join-Path $linuxRoot 'northgate\90-northgate-bootstrap.conf'))
    Assert-True ($preseed -match 'passwd/user-password-crypted password !' -and $preseed -notmatch 'passwd/user-password password') 'Linux password is locked, not embedded'
    Assert-True ($sshLinux -match 'AuthenticationMethods publickey' -and $sshLinux -match 'AllowUsers northgate-bootstrap@10\.10\.100\.11' -and $sshLinux -match 'PasswordAuthentication no') 'Linux SSH is public-key-only and source restricted'
    Assert-True (([IO.File]::ReadAllText((Join-Path $linuxRoot 'northgate\northgate-bootstrap.nft'))) -match 'ip saddr 10\.10\.100\.11 tcp dport 22 accept') 'Linux firewall source restriction'

    $windowsScripts = Join-Path $testRoot 'windows-canary-bundle\payload\sources\$OEM$\$$\Setup\Scripts'
    $unattend = [IO.File]::ReadAllText((Join-Path $testRoot 'windows-canary-bundle\payload\autounattend.xml'))
    $bootstrap = [IO.File]::ReadAllText((Join-Path $windowsScripts 'NorthGate-Bootstrap.ps1'))
    Assert-True ($unattend -match '<Key>/IMAGE/INDEX</Key><Value>6</Value>' -and $unattend -notmatch '<Password>' -and $unattend -notmatch '<ProductKey>') 'Windows Pro index 6 without answer-file password or product key'
    Assert-True ($bootstrap -match 'RandomNumberGenerator' -and $bootstrap -match 'Security\.SecureString' -and $bootstrap -notmatch 'AsPlainText') 'temporary Windows credential exists only as a SecureString'
    Assert-True ($bootstrap -match 'RemoteAddress \$managementSource' -and $bootstrap -match 'AllowUsers \$identity@\$managementSource' -and $bootstrap -match 'PasswordAuthentication no') 'Windows SSH and firewall source restriction'
    Assert-True ($bootstrap -match 'NGBM-WINDOWS-MAC-MISMATCH' -and $bootstrap -match 'Set-NetIPInterface.*Dhcp Disabled') 'Windows static network and exact MAC gate'
    $tokens = $null; $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $windowsScripts 'NorthGate-Bootstrap.ps1'), [ref]$tokens, [ref]$parseErrors)
    Assert-True (@($parseErrors).Count -eq 0) 'rendered Windows bootstrap parses in Windows PowerShell'
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $windowsScripts 'Remove-NorthGateBootstrap.ps1'), [ref]$tokens, [ref]$parseErrors)
    Assert-True (@($parseErrors).Count -eq 0) 'rendered Windows cleanup parses in Windows PowerShell'

    foreach ($bundleName in @('debian-canary-bundle','windows-canary-bundle','kali-bundle')) {
        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $testRoot $bundleName) -File -Recurse) {
            $bytes = [IO.File]::ReadAllBytes($file.FullName)
            $text = [Text.Encoding]::UTF8.GetString($bytes)
            Assert-True ($text -notmatch '(?i)BEGIN\s+(?:RSA\s+|OPENSSH\s+)?PRIVATE\s+KEY') "$bundleName excludes private keys"
        }
    }

    $badKey = Join-Path $testRoot 'bad.pub'
    [IO.File]::WriteAllText($badKey, 'from="10.10.100.11" ' + (New-TestEd25519Line), (New-Object Text.UTF8Encoding($false)))
    Assert-ThrowsCode { Get-NorthGateAuthorizedPublicKey $badKey } 'NGBM-PUBLIC-KEY-FORMAT'
    $privateKeyMarker = '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----' + "`n"
    [IO.File]::WriteAllText($badKey, $privateKeyMarker, (New-Object Text.UTF8Encoding($false)))
    Assert-ThrowsCode { Get-NorthGateAuthorizedPublicKey $badKey } 'NGBM-PUBLIC-KEY-FORMAT'

    $baseRequest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'examples\windows-canary.request.json') -Raw | ConvertFrom-Json
    $bad = Copy-JsonValue $baseRequest; $bad.staticMacAddress = '024E4700FFFF'; $badPath = Join-Path $testRoot 'bad-mac.json'; Write-TestJson $bad $badPath
    Assert-ThrowsCode { Import-NorthGateBootstrapRequest $badPath } 'NGBM-FLEET-BINDING-STATICMACADDRESS'
    $bad = Copy-JsonValue $baseRequest; $bad.vlanId = 130; Write-TestJson $bad $badPath
    Assert-ThrowsCode { Import-NorthGateBootstrapRequest $badPath } 'NGBM-FLEET-NETWORK-BINDING'
    $bad = Copy-JsonValue $baseRequest; $bad.network.address = '10.10.110.201'; Write-TestJson $bad $badPath
    Assert-ThrowsCode { Import-NorthGateBootstrapRequest $badPath } 'NGBM-FLEET-NETWORK-BINDING'
    $bad = Copy-JsonValue $baseRequest; $bad.network.dnsServers = @('8.8.8.8'); Write-TestJson $bad $badPath
    Assert-ThrowsCode { Import-NorthGateBootstrapRequest $badPath } 'NGBM-FLEET-DNS-BINDING'
    $bad = Copy-JsonValue $baseRequest; $bad.windowsEditionIndex = 5; Write-TestJson $bad $badPath
    Assert-ThrowsCode { Import-NorthGateBootstrapRequest $badPath } 'NGBM-WINDOWS-EDITION-INDEX'
    $bad = Copy-JsonValue $baseRequest; $bad | Add-Member -NotePropertyName enrollmentToken -NotePropertyValue 'forbidden'; Write-TestJson $bad $badPath
    Assert-ThrowsCode { Import-NorthGateBootstrapRequest $badPath } 'NGBM-CREDENTIAL-FIELD-FORBIDDEN'

    $kaliRequest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'examples\kali.request.json') -Raw | ConvertFrom-Json
    $bad = Copy-JsonValue $kaliRequest; $bad.secureBoot = $true; Write-TestJson $bad $badPath
    Assert-ThrowsCode { Import-NorthGateBootstrapRequest $badPath } 'NGBM-FIRMWARE-BINDING'

    $fakeSource = Join-Path $testRoot 'fake.iso'
    $fakeBytes = [Text.Encoding]::UTF8.GetBytes('source-artifact-test')
    [IO.File]::WriteAllBytes($fakeSource, $fakeBytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $fakeHash = (($sha.ComputeHash($fakeBytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
    $verified = Assert-NorthGateBootstrapSourceArtifact -Path $fakeSource -ExpectedSha256 $fakeHash -ExpectedSizeBytes $fakeBytes.Length
    Assert-True ($verified.Sha256 -ceq $fakeHash) 'source hash and size verification accepts an exact artifact'
    Assert-ThrowsCode { Assert-NorthGateBootstrapSourceArtifact -Path $fakeSource -ExpectedSha256 ('0' * 64) -ExpectedSizeBytes $fakeBytes.Length } 'NGBM-SOURCE-HASH-MISMATCH'
    Assert-ThrowsCode { Assert-NorthGateBootstrapSourceArtifact -Path $fakeSource -ExpectedSha256 $fakeHash -ExpectedSizeBytes ($fakeBytes.Length + 1) } 'NGBM-SOURCE-SIZE-MISMATCH'
    Assert-ThrowsCode { New-NorthGateBootstrapBundle -RequestPath (Join-Path $PSScriptRoot 'examples\debian-canary.request.json') -AuthorizedPublicKeyPath $keyPath -OutputDirectory (Join-Path $testRoot 'debian-canary-bundle') } 'NGBM-OUTPUT-EXISTS'

    $builder = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'bluebench\build-bootstrap-iso.sh'))
    Assert-True ($builder -match 'NGBM-SOURCE-HASH-MISMATCH' -and $builder -match 'NGBM-SOURCE-SIZE-MISMATCH' -and $builder -match 'NGBM-SOURCE-MUTATED') 'BlueBench builder verifies and preserves source artifact'
    Assert-True ($builder -match 'grep -Fqx ''Type = Udf'' "\$archive_listing"' -and $builder -match '7z x .*NGBM-SOURCE-EXTRACT' -and $builder -match 'xorriso -osirrox on.*NGBM-SOURCE-EXTRACT') 'BlueBench builder selects validated UDF extraction for Windows and Rock Ridge extraction for Linux'
    Assert-True ($builder -match 'mkisofs_args=\(-iso-level 3 -udf -allow-limited-size') 'Windows UDF output explicitly supports the pinned install.wim larger than four GiB'
    Assert-True ($builder -match 'wimlib-imagex info.* 6' -and $builder -match 'Windows 11 Pro' -and $builder -match 'NGBM-WINDOWS-ARCH-MISMATCH') 'BlueBench builder verifies Windows edition and architecture'
    Assert-True ($builder -match 'report_el_torito plain' -and $builder -match 'NGBM-OUTPUT-NO-UEFI-BOOT') 'BlueBench builder validates UEFI El Torito boot entry'

    Write-Output ("NGBM_TESTS_OK assertions={0}" -f $script:Passed)
}
finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
