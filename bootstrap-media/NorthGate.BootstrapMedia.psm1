Set-StrictMode -Version Latest

$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:MaximumJsonBytes = 65536
$script:ManagementSource = '10.10.100.11'
$script:BootstrapIdentity = 'northgate-bootstrap'

function Stop-Ngbm {
    param([Parameter(Mandatory)][string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function Get-NgbmSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NgbmFileSha256Hex {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($stream) }
    finally { $algorithm.Dispose(); $stream.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Write-NgbmText {
    param([string]$Path, [string]$Text, [ValidateSet('LF','CRLF')][string]$Newline = 'LF')
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { $null = [IO.Directory]::CreateDirectory($parent) }
    $normalized = $Text -replace "`r`n", "`n" -replace "`r", "`n"
    if ($Newline -eq 'CRLF') { $normalized = $normalized -replace "`n", "`r`n" }
    [IO.File]::WriteAllText($Path, $normalized, $script:Utf8NoBom)
}

function Read-NgbmJsonFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Stop-Ngbm 'NGBM-JSON-NOT-FOUND' }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -gt $script:MaximumJsonBytes -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Stop-Ngbm 'NGBM-JSON-FILE-INVALID'
    }
    $raw = [IO.File]::ReadAllText($item.FullName)
    if ($raw.IndexOf([char]0) -ge 0 -or $raw -match '(?i)BEGIN\s+(?:RSA\s+|OPENSSH\s+)?PRIVATE\s+KEY') {
        Stop-Ngbm 'NGBM-SECRET-MATERIAL-FORBIDDEN'
    }
    try {
        $converter = Microsoft.PowerShell.Core\Get-Command `
            -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -ErrorAction Stop
        if ($converter.Parameters.ContainsKey('DateKind')) {
            $value = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $raw -DateKind String
        }
        else { $value = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $raw }
    }
    catch { Stop-Ngbm 'NGBM-JSON-PARSE-FAILED' }
    [pscustomobject]@{ Path = $item.FullName; Raw = $raw; Value = $value }
}

function Assert-NgbmExactProperties {
    param([object]$Value, [string[]]$Names, [string]$Code)
    if ($null -eq $Value -or $null -eq $Value.PSObject) { Stop-Ngbm $Code }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (($actual -join '|') -cne ($expected -join '|')) { Stop-Ngbm $Code }
}

function Assert-NgbmNoCredentialFields {
    param([object]$Value)
    if ($null -eq $Value) { return }
    if ($Value -is [string] -or $Value -is [ValueType]) { return }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [pscustomobject])) {
        foreach ($entry in $Value) { Assert-NgbmNoCredentialFields $entry }
        return
    }
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.Name -match '(?i)(password|passwd|credential|secret|token|private.?key|api.?key|product.?key|domain.?join)') {
            Stop-Ngbm 'NGBM-CREDENTIAL-FIELD-FORBIDDEN'
        }
        Assert-NgbmNoCredentialFields $property.Value
    }
}

function Test-NgbmCanonicalIpv4 {
    param([string]$Value)
    $parsed = $null
    [Net.IPAddress]::TryParse($Value, [ref]$parsed) -and
        $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $parsed.ToString() -ceq $Value
}

function ConvertTo-NgbmIpv4Number {
    param([string]$Value)
    $bytes = [Net.IPAddress]::Parse($Value).GetAddressBytes()
    [uint64]$bytes[0] * 16777216 + [uint64]$bytes[1] * 65536 + [uint64]$bytes[2] * 256 + [uint64]$bytes[3]
}

function ConvertTo-NgbmNetmask {
    param([int]$PrefixLength)
    $octets = New-Object int[] 4
    $bits = $PrefixLength
    for ($index = 0; $index -lt 4; $index++) {
        $take = [Math]::Min(8, [Math]::Max(0, $bits))
        $octets[$index] = if ($take -eq 0) { 0 } else { 256 - [Math]::Pow(2, 8 - $take) }
        $bits -= $take
    }
    ($octets -join '.')
}

function Test-NgbmSameSubnet {
    param([string]$Address, [string]$Gateway, [int]$PrefixLength)
    $mask = if ($PrefixLength -eq 0) { [uint64]0 } else { ([uint64]4294967295) -shl (32 - $PrefixLength) }
    ((ConvertTo-NgbmIpv4Number $Address) -band $mask) -eq ((ConvertTo-NgbmIpv4Number $Gateway) -band $mask)
}

function Get-NorthGateBootstrapSourceCatalog {
    [CmdletBinding()] param()
    $parsed = Read-NgbmJsonFile (Join-Path $PSScriptRoot 'catalog\source-images.json')
    Assert-NgbmExactProperties $parsed.Value @('$schema','catalogVersion','status','images') 'NGBM-SOURCE-CATALOG-SHAPE'
    if ($parsed.Value.'$schema' -cne 'northgate/bootstrap-source-catalog/v1' -or $parsed.Value.status -cne 'proposed-unpromoted') {
        Stop-Ngbm 'NGBM-SOURCE-CATALOG-STATE'
    }
    $ids = @($parsed.Value.images | ForEach-Object { $_.id })
    if ($ids.Count -ne 3 -or @($ids | Sort-Object -Unique).Count -ne 3) { Stop-Ngbm 'NGBM-SOURCE-CATALOG-CARDINALITY' }
    $parsed.Value
}

function Get-NorthGateBootstrapFleetMap {
    [CmdletBinding()] param()
    $parsed = Read-NgbmJsonFile (Join-Path $PSScriptRoot 'catalog\fleet-bootstrap-map.json')
    Assert-NgbmExactProperties $parsed.Value @('$schema','catalogVersion','managementSourceAddress','bootstrapIdentity','temporaryAccessHours','assets') 'NGBM-FLEET-MAP-SHAPE'
    if ($parsed.Value.'$schema' -cne 'northgate/bootstrap-fleet-map/v1' -or
        $parsed.Value.managementSourceAddress -cne $script:ManagementSource -or
        $parsed.Value.bootstrapIdentity -cne $script:BootstrapIdentity -or
        [int]$parsed.Value.temporaryAccessHours -ne 24) { Stop-Ngbm 'NGBM-FLEET-MAP-STATE' }
    if (@($parsed.Value.assets).Count -ne 12 -or
        @($parsed.Value.assets | ForEach-Object { $_.assetId } | Sort-Object -Unique).Count -ne 12 -or
        @($parsed.Value.assets | ForEach-Object { $_.name } | Sort-Object -Unique).Count -ne 12 -or
        @($parsed.Value.assets | ForEach-Object { $_.staticMacAddress } | Sort-Object -Unique).Count -ne 12 -or
        @($parsed.Value.assets | ForEach-Object { $_.address } | Sort-Object -Unique).Count -ne 12) { Stop-Ngbm 'NGBM-FLEET-MAP-COLLISION' }
    $parsed.Value
}

function Import-NorthGateBootstrapRequest {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $parsed = Read-NgbmJsonFile $Path
    $request = $parsed.Value
    Assert-NgbmNoCredentialFields $request
    $base = @('apiVersion','kind','assetId','name','hostname','family','imageId','architecture','staticMacAddress','vlanId','network','roleHook','managementSourceAddress','bootstrapIdentity','temporaryAccessHours','firmwareProfile','secureBoot','secureBootTemplate','vtpmRequired','buildEpochUtc')
    $family = [string]$request.family
    if ($family -ceq 'windows') { $base += 'windowsEditionIndex' }
    elseif ($family -ceq 'kali') { $base += 'secureBootExceptionId' }
    elseif ($family -cne 'debian') { Stop-Ngbm 'NGBM-FAMILY-NOT-ALLOWED' }
    Assert-NgbmExactProperties $request $base 'NGBM-REQUEST-PROPERTIES'
    Assert-NgbmExactProperties $request.network @('address','prefixLength','gateway','dnsServers','domainSuffix') 'NGBM-NETWORK-PROPERTIES'

    if ($request.apiVersion -cne 'northgate/v1alpha1' -or $request.kind -cne 'BootstrapMediaRequest' -or
        $request.assetId -cnotmatch '^NG-VM-[0-9]{3}$' -or $request.name -cnotmatch '^NG-[A-Z0-9-]{1,12}$' -or
        $request.hostname -cnotmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$' -or
        $request.architecture -cne 'x86_64' -or $request.staticMacAddress -cnotmatch '^024E47[0-9A-F]{6}$' -or
        [int]$request.vlanId -lt 1 -or [int]$request.vlanId -gt 4094 -or
        $request.managementSourceAddress -cne $script:ManagementSource -or
        $request.bootstrapIdentity -cne $script:BootstrapIdentity -or [int]$request.temporaryAccessHours -ne 24) {
        Stop-Ngbm 'NGBM-REQUEST-VALUE-INVALID'
    }
    if (-not (Test-NgbmCanonicalIpv4 $request.network.address) -or
        -not (Test-NgbmCanonicalIpv4 $request.network.gateway) -or
        [int]$request.network.prefixLength -lt 8 -or [int]$request.network.prefixLength -gt 30 -or
        -not (Test-NgbmSameSubnet $request.network.address $request.network.gateway ([int]$request.network.prefixLength)) -or
        $request.network.domainSuffix -cnotmatch '^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$') {
        Stop-Ngbm 'NGBM-NETWORK-VALUE-INVALID'
    }
    $dns = @($request.network.dnsServers)
    if ($dns.Count -lt 1 -or $dns.Count -gt 2 -or @($dns | Sort-Object -Unique).Count -ne $dns.Count) { Stop-Ngbm 'NGBM-DNS-INVALID' }
    foreach ($server in $dns) { if (-not (Test-NgbmCanonicalIpv4 ([string]$server))) { Stop-Ngbm 'NGBM-DNS-INVALID' } }
    $epoch = [datetime]::MinValue
    if (-not [datetime]::TryParseExact([string]$request.buildEpochUtc, "yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$epoch)) {
        Stop-Ngbm 'NGBM-BUILD-EPOCH-INVALID'
    }

    $fleet = Get-NorthGateBootstrapFleetMap
    $assets = @($fleet.assets | Where-Object { $_.assetId -ceq $request.assetId })
    if ($assets.Count -ne 1) { Stop-Ngbm 'NGBM-ASSET-NOT-IN-FLEET' }
    $asset = $assets[0]
    foreach ($field in @('name','hostname','family','imageId','staticMacAddress','roleHook')) {
        if ([string]$request.$field -cne [string]$asset.$field) { Stop-Ngbm ('NGBM-FLEET-BINDING-' + $field.ToUpperInvariant()) }
    }
    if ([int]$request.vlanId -ne [int]$asset.vlanId -or [string]$request.network.address -cne [string]$asset.address -or
        [int]$request.network.prefixLength -ne [int]$asset.prefixLength -or [string]$request.network.gateway -cne [string]$asset.gateway -or
        [string]$request.network.domainSuffix -cne [string]$asset.domainSuffix) { Stop-Ngbm 'NGBM-FLEET-NETWORK-BINDING' }
    foreach ($server in $dns) { if ([string]$server -cnotin @($asset.allowedDnsServers)) { Stop-Ngbm 'NGBM-FLEET-DNS-BINDING' } }

    $catalog = Get-NorthGateBootstrapSourceCatalog
    $images = @($catalog.images | Where-Object { $_.id -ceq $request.imageId })
    if ($images.Count -ne 1) { Stop-Ngbm 'NGBM-IMAGE-NOT-IN-CATALOG' }
    $image = $images[0]
    if ($image.family -cne $family -or $request.firmwareProfile -cne $image.firmwareProfile -or
        [bool]$request.secureBoot -ne [bool]$image.secureBoot -or $request.secureBootTemplate -cne $image.secureBootTemplate -or
        [bool]$request.vtpmRequired -ne [bool]$image.vtpmRequired) { Stop-Ngbm 'NGBM-FIRMWARE-BINDING' }
    if ($family -ceq 'windows' -and [int]$request.windowsEditionIndex -ne 6) { Stop-Ngbm 'NGBM-WINDOWS-EDITION-INDEX' }
    if ($family -ceq 'kali' -and $request.secureBootExceptionId -cne $image.secureBootExceptionId) { Stop-Ngbm 'NGBM-KALI-EXCEPTION-BINDING' }

    [pscustomobject][ordered]@{
        Request = $request
        Asset = $asset
        Image = $image
        Netmask = ConvertTo-NgbmNetmask ([int]$request.network.prefixLength)
        DnsServers = $dns
        BuildEpoch = $epoch
    }
}

function Read-NgbmUInt32BigEndian {
    param([byte[]]$Buffer, [int]$Offset)
    if ($Offset -lt 0 -or $Offset + 4 -gt $Buffer.Length) { Stop-Ngbm 'NGBM-PUBLIC-KEY-BLOB' }
    $temporary = [byte[]]@($Buffer[$Offset + 3],$Buffer[$Offset + 2],$Buffer[$Offset + 1],$Buffer[$Offset])
    [BitConverter]::ToUInt32($temporary, 0)
}

function Get-NorthGateAuthorizedPublicKey {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Stop-Ngbm 'NGBM-PUBLIC-KEY-NOT-FOUND' }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -gt 1024 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Stop-Ngbm 'NGBM-PUBLIC-KEY-FILE-INVALID' }
    $raw = [IO.File]::ReadAllText($item.FullName)
    if ($raw -cnotmatch '\A[^\r\n]+(?:\r\n|\n)?\z') { Stop-Ngbm 'NGBM-PUBLIC-KEY-FORMAT' }
    $line = $raw.TrimEnd("`r","`n")
    if ($line.IndexOf("`r") -ge 0 -or $line.IndexOf("`n") -ge 0 -or
        $line -cnotmatch '^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: ([A-Za-z0-9._@:-]{1,80}))?$') {
        Stop-Ngbm 'NGBM-PUBLIC-KEY-FORMAT'
    }
    try { $blob = [Convert]::FromBase64String($Matches[1]) }
    catch { Stop-Ngbm 'NGBM-PUBLIC-KEY-BASE64' }
    $typeLength = [int](Read-NgbmUInt32BigEndian $blob 0)
    if ($typeLength -ne 11 -or $blob.Length -lt 4 + $typeLength + 4) { Stop-Ngbm 'NGBM-PUBLIC-KEY-BLOB' }
    $type = [Text.Encoding]::ASCII.GetString($blob, 4, $typeLength)
    $keyLengthOffset = 4 + $typeLength
    $keyLength = [int](Read-NgbmUInt32BigEndian $blob $keyLengthOffset)
    if ($type -cne 'ssh-ed25519' -or $keyLength -ne 32 -or $blob.Length -ne 4 + $typeLength + 4 + $keyLength) {
        Stop-Ngbm 'NGBM-PUBLIC-KEY-BLOB'
    }
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $digestBytes = $algorithm.ComputeHash($blob) }
    finally { $algorithm.Dispose() }
    $fingerprint = [Convert]::ToBase64String($digestBytes).TrimEnd('=')
    [pscustomobject][ordered]@{ Line = $line; Fingerprint = 'SHA256:' + $fingerprint; Type = $type }
}

function Assert-NorthGateBootstrapSourceArtifact {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedSha256,
        [Parameter(Mandatory)][ValidateRange(1,[long]::MaxValue)][long]$ExpectedSizeBytes
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Stop-Ngbm 'NGBM-SOURCE-NOT-FOUND' }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $ExpectedSizeBytes) { Stop-Ngbm 'NGBM-SOURCE-SIZE-MISMATCH' }
    $hash = Get-NgbmFileSha256Hex $item.FullName
    if ($hash -cne $ExpectedSha256) { Stop-Ngbm 'NGBM-SOURCE-HASH-MISMATCH' }
    [pscustomobject][ordered]@{ Path = $item.FullName; SizeBytes = [long]$item.Length; Sha256 = $hash }
}

function Expand-NgbmTemplate {
    param([string]$RelativePath, [hashtable]$Values)
    $path = Join-Path $PSScriptRoot $RelativePath
    $text = [IO.File]::ReadAllText($path)
    foreach ($key in @($Values.Keys | Sort-Object)) { $text = $text.Replace('@@' + $key + '@@', [string]$Values[$key]) }
    if ($text -match '@@[A-Z0-9_]+@@') { Stop-Ngbm 'NGBM-TEMPLATE-TOKEN-UNRESOLVED' }
    $text
}

function Assert-NgbmOutputPath {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $full) { Stop-Ngbm 'NGBM-OUTPUT-EXISTS' }
    $cursor = Split-Path -Parent $full
    while ($cursor -and -not (Test-Path -LiteralPath $cursor)) { $cursor = Split-Path -Parent $cursor }
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-Ngbm 'NGBM-OUTPUT-REPARSE-FORBIDDEN' }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    $full
}

function New-NorthGateBootstrapBundle {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$RequestPath,
        [Parameter(Mandatory)][string]$AuthorizedPublicKeyPath,
        [Parameter(Mandatory)][string]$OutputDirectory
    )
    $context = Import-NorthGateBootstrapRequest $RequestPath
    $publicKey = Get-NorthGateAuthorizedPublicKey $AuthorizedPublicKeyPath
    $output = Assert-NgbmOutputPath $OutputDirectory
    $null = [IO.Directory]::CreateDirectory($output)
    try {
        $request = $context.Request
        $normalizedRequest = [pscustomobject][ordered]@{
            apiVersion = $request.apiVersion; kind = $request.kind; assetId = $request.assetId; name = $request.name
            hostname = $request.hostname; family = $request.family; imageId = $request.imageId; architecture = $request.architecture
            staticMacAddress = $request.staticMacAddress; vlanId = [int]$request.vlanId
            network = [pscustomobject][ordered]@{ address=$request.network.address; prefixLength=[int]$request.network.prefixLength; gateway=$request.network.gateway; dnsServers=@($context.DnsServers); domainSuffix=$request.network.domainSuffix }
            roleHook = $request.roleHook; managementSourceAddress = $request.managementSourceAddress; bootstrapIdentity = $request.bootstrapIdentity
            temporaryAccessHours = [int]$request.temporaryAccessHours; firmwareProfile = $request.firmwareProfile; secureBoot = [bool]$request.secureBoot
            secureBootTemplate = $request.secureBootTemplate; vtpmRequired = [bool]$request.vtpmRequired
            windowsEditionIndex = if ($request.family -ceq 'windows') { 6 } else { $null }
            secureBootExceptionId = if ($request.family -ceq 'kali') { $request.secureBootExceptionId } else { $null }
            buildEpochUtc = $request.buildEpochUtc
        }
        $requestJson = $normalizedRequest | ConvertTo-Json -Depth 8 -Compress
        $provenance = [pscustomobject][ordered]@{
            schema = 'northgate/bootstrap-provenance-input/v1'
            asset = [pscustomobject][ordered]@{ assetId=$request.assetId; name=$request.name; hostname=$request.hostname; staticMacAddress=$request.staticMacAddress; vlanId=[int]$request.vlanId }
            source = [pscustomobject][ordered]@{ imageId=$context.Image.id; fileName=$context.Image.fileName; sha256=$context.Image.sha256; sizeBytes=[long]$context.Image.sizeBytes; architecture=$context.Image.architecture; editionIndex=if($request.family -ceq 'windows'){6}else{$null}; editionName=if($request.family -ceq 'windows'){'Windows 11 Pro'}else{$null}; evaluationMedia=if($request.family -ceq 'windows'){$false}else{$null}; productKeyEmbedded=if($request.family -ceq 'windows'){$false}else{$null}; activationExpectedAtInstall=if($request.family -ceq 'windows'){$false}else{$null} }
            firmware = [pscustomobject][ordered]@{ generation=2; profile=$context.Image.firmwareProfile; secureBoot=[bool]$context.Image.secureBoot; template=$context.Image.secureBootTemplate; vtpmRequired=[bool]$context.Image.vtpmRequired; exceptionId=if($request.family -ceq 'kali'){$context.Image.secureBootExceptionId}else{$null} }
            access = [pscustomobject][ordered]@{ identity=$script:BootstrapIdentity; publicKeyFingerprint=$publicKey.Fingerprint; sourceAddress=$script:ManagementSource; temporaryAccessHours=24 }
            network = $normalizedRequest.network
            roleHook = $request.roleHook
            buildEpochUtc = $request.buildEpochUtc
        }
        $provenanceJson = $provenance | ConvertTo-Json -Depth 8 -Compress
        Write-NgbmText (Join-Path $output 'request.normalized.json') ($requestJson + "`n")
        Write-NgbmText (Join-Path $output 'provenance-input.json') ($provenanceJson + "`n")

        $values = @{
            HOSTNAME=$request.hostname; DOMAIN_SUFFIX=$request.network.domainSuffix; IP_ADDRESS=$request.network.address
            PREFIX_LENGTH=[string][int]$request.network.prefixLength; NETMASK=$context.Netmask; GATEWAY=$request.network.gateway
            DNS_SERVERS=(@($context.DnsServers) -join ' '); DNS_SERVERS_PS=(@($context.DnsServers | ForEach-Object { "'$_'" }) -join ',')
            MANAGEMENT_SOURCE=$script:ManagementSource; ACCESS_HOURS='24'; ROLE_HOOK=$request.roleHook; STATIC_MAC=$request.staticMacAddress
            MIRROR_HOST=if($request.family -ceq 'kali'){'http.kali.org'}else{'deb.debian.org'}
            MIRROR_DIRECTORY=if($request.family -ceq 'kali'){'/kali'}else{'/debian'}
            MIRROR_SUITE=if($request.family -ceq 'kali'){'kali-rolling'}else{'bookworm'}
        }
        $payload = Join-Path $output 'payload'
        if ($request.family -in @('debian','kali')) {
            Write-NgbmText (Join-Path $payload 'preseed.cfg') (Expand-NgbmTemplate 'templates\linux\preseed.cfg.in' $values)
            $northgate = Join-Path $payload 'northgate'
            Write-NgbmText (Join-Path $northgate 'authorized_key') ($publicKey.Line + "`n")
            Write-NgbmText (Join-Path $northgate 'late-command.sh') (Expand-NgbmTemplate 'templates\linux\late-command.sh.in' $values)
            Write-NgbmText (Join-Path $northgate '90-northgate-bootstrap.conf') (Expand-NgbmTemplate 'templates\linux\90-northgate-bootstrap.conf.in' $values)
            Write-NgbmText (Join-Path $northgate '90-northgate-bootstrap-sudoers') ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'templates\linux\90-northgate-bootstrap-sudoers')))
            Write-NgbmText (Join-Path $northgate 'northgate-bootstrap.nft') (Expand-NgbmTemplate 'templates\linux\northgate-bootstrap.nft.in' $values)
            Write-NgbmText (Join-Path $northgate 'northgate-bootstrap-firewall.service') ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'templates\linux\northgate-bootstrap-firewall.service')))
            Write-NgbmText (Join-Path $northgate 'role-hook.sh') ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'templates\linux\role-hook.sh.in')))
            Write-NgbmText (Join-Path $northgate 'remove-northgate-bootstrap') ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'templates\linux\remove-northgate-bootstrap')))
            Write-NgbmText (Join-Path $northgate 'request.json') ($requestJson + "`n")
            Write-NgbmText (Join-Path $northgate 'provenance-input.json') ($provenanceJson + "`n")
        }
        else {
            Write-NgbmText (Join-Path $payload 'autounattend.xml') (Expand-NgbmTemplate 'templates\windows\autounattend.xml.in' $values) 'CRLF'
            $scripts = Join-Path $payload 'sources\$OEM$\$$\Setup\Scripts'
            Write-NgbmText (Join-Path $scripts 'SetupComplete.cmd') ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'templates\windows\SetupComplete.cmd'))) 'CRLF'
            Write-NgbmText (Join-Path $scripts 'NorthGate-Bootstrap.ps1') (Expand-NgbmTemplate 'templates\windows\NorthGate-Bootstrap.ps1.in' $values) 'CRLF'
            Write-NgbmText (Join-Path $scripts 'Invoke-RoleHook.ps1') (Expand-NgbmTemplate 'templates\windows\Invoke-RoleHook.ps1.in' $values) 'CRLF'
            Write-NgbmText (Join-Path $scripts 'Remove-NorthGateBootstrap.ps1') (Expand-NgbmTemplate 'templates\windows\Remove-NorthGateBootstrap.ps1.in' $values) 'CRLF'
            Write-NgbmText (Join-Path $scripts 'authorized_key') ($publicKey.Line + "`r`n") 'CRLF'
            Write-NgbmText (Join-Path $scripts 'request.json') ($requestJson + "`r`n") 'CRLF'
            Write-NgbmText (Join-Path $scripts 'provenance-input.json') ($provenanceJson + "`r`n") 'CRLF'
        }

        $fileRecords = @()
        foreach ($file in @(Get-ChildItem -LiteralPath $payload -File -Recurse | Sort-Object FullName)) {
            $relative = $file.FullName.Substring($output.Length).TrimStart('\','/').Replace('\','/')
            $fileRecords += [pscustomobject][ordered]@{ path=$relative; sha256=Get-NgbmFileSha256Hex $file.FullName; sizeBytes=[long]$file.Length }
        }
        $manifest = [pscustomobject][ordered]@{
            schema='northgate/bootstrap-bundle/v1'; bundleVersion='0.1.0'; buildEpochUtc=$request.buildEpochUtc
            assetId=$request.assetId; name=$request.name; family=$request.family; imageId=$request.imageId
            source=[pscustomobject][ordered]@{ fileName=$context.Image.fileName; sha256=$context.Image.sha256; sizeBytes=[long]$context.Image.sizeBytes; architecture=$context.Image.architecture; editionIndex=if($request.family -ceq 'windows'){6}else{$null}; editionName=if($request.family -ceq 'windows'){'Windows 11 Pro'}else{$null}; evaluationMedia=if($request.family -ceq 'windows'){$false}else{$null}; productKeyEmbedded=if($request.family -ceq 'windows'){$false}else{$null}; activationExpectedAtInstall=if($request.family -ceq 'windows'){$false}else{$null}; requiredIsoPaths=@($context.Image.requiredIsoPaths) }
            firmware=$provenance.firmware; publicKeyFingerprint=$publicKey.Fingerprint
            requestSha256=Get-NgbmSha256Hex ([Text.Encoding]::UTF8.GetBytes($requestJson + "`n")); files=$fileRecords
        }
        $manifestJson = $manifest | ConvertTo-Json -Depth 10 -Compress
        $manifestPath = Join-Path $output 'bundle-manifest.json'
        Write-NgbmText $manifestPath ($manifestJson + "`n")
        $manifestHash = Get-NgbmFileSha256Hex $manifestPath
        Write-NgbmText (Join-Path $output 'bundle-manifest.sha256') ($manifestHash + "  bundle-manifest.json`n")
        [pscustomobject][ordered]@{ OutputDirectory=$output; AssetId=$request.assetId; ImageId=$request.imageId; BundleManifestSha256=$manifestHash; PublicKeyFingerprint=$publicKey.Fingerprint; FileCount=$fileRecords.Count }
    }
    catch {
        if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force -ErrorAction SilentlyContinue }
        throw
    }
}

Export-ModuleMember -Function @(
    'Get-NorthGateBootstrapSourceCatalog','Get-NorthGateBootstrapFleetMap','Import-NorthGateBootstrapRequest',
    'Get-NorthGateAuthorizedPublicKey','Assert-NorthGateBootstrapSourceArtifact','New-NorthGateBootstrapBundle'
)
