Set-StrictMode -Version Latest

$script:OperatorVersion = '0.1.0'
$script:ApprovedRepositoryIdentity = 'Beowxlf/northgate-vm-factory'
$script:ReleaseStatus = 'local-only-hard-disabled'
$script:NotPromotedCode = 'NGCO-NOT-INDEPENDENTLY-PROMOTED'
$script:WriterLockName = 'Global\NorthGateVmFactoryCreateOnlyOperator-v1'
$script:MaximumPlanBytes = 262144
$script:MaximumJsonDepth = 32
$script:ConvertFromJsonSupportsDateKind = (
    (Get-Command -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -CommandType Cmdlet -ErrorAction Stop).Parameters.ContainsKey('DateKind')
)

function Throw-NgcoError {
    param([Parameter(Mandatory)][string]$Code)

    throw [System.InvalidOperationException]::new($Code)
}

function ConvertFrom-NgcoJson {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)

    if ($script:ConvertFromJsonSupportsDateKind) {
        return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json -DateKind String)
    }
    return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json)
}

function Get-NgcoSha256Hex {
    param([Parameter(Mandatory)][string]$Value)

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function Get-NgcoHmacHex {
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][string]$Value
    )

    $algorithm = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try {
        $hash = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function Test-NgcoFixedHexEquals {
    param(
        [Parameter(Mandatory)][string]$Left,
        [Parameter(Mandatory)][string]$Right
    )

    if ($Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ([int][char]$Left[$index] -bxor [int][char]$Right[$index])
    }
    return ($difference -eq 0)
}

function New-NgcoRandomHex {
    param([ValidateRange(16, 64)][int]$ByteCount = 32)

    $bytes = New-Object byte[] $ByteCount
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Skip-NgcoJsonWhitespace {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][ref]$Index
    )

    while ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -in @(' ', "`t", "`r", "`n")) {
        $Index.Value++
    }
}

function Read-NgcoJsonStringToken {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][ref]$Index
    )

    if ($Index.Value -ge $Text.Length -or $Text[$Index.Value] -ne '"') {
        Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID'
    }
    $start = $Index.Value
    $Index.Value++
    while ($Index.Value -lt $Text.Length) {
        $character = $Text[$Index.Value]
        if ($character -eq '"') {
            $Index.Value++
            try { return (ConvertFrom-NgcoJson -Json $Text.Substring($start, $Index.Value - $start)) }
            catch { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
        }
        if ([int][char]$character -lt 32) { Throw-NgcoError -Code 'NGCO-PLAN-CONTROL-CHARACTER' }
        if ($character -eq '\') {
            $Index.Value++
            if ($Index.Value -ge $Text.Length) { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
            $escape = $Text[$Index.Value]
            if ($escape -eq 'u') {
                if ($Index.Value + 4 -ge $Text.Length) { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
                if ($Text.Substring($Index.Value + 1, 4) -cnotmatch '^[0-9a-fA-F]{4}$') {
                    Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID'
                }
                $Index.Value += 4
            }
            elseif ($escape -notin @('"', '\', '/', 'b', 'f', 'n', 'r', 't')) {
                Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID'
            }
        }
        $Index.Value++
    }
    Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID'
}

function Read-NgcoJsonValue {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][ref]$Index,
        [int]$Depth = 0
    )

    if ($Depth -gt $script:MaximumJsonDepth) { Throw-NgcoError -Code 'NGCO-PLAN-DEPTH-EXCEEDED' }
    Skip-NgcoJsonWhitespace -Text $Text -Index $Index
    if ($Index.Value -ge $Text.Length) { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
    $character = $Text[$Index.Value]
    if ($character -eq '{') {
        $Index.Value++
        $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        Skip-NgcoJsonWhitespace -Text $Text -Index $Index
        if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -eq '}') {
            $Index.Value++
            return
        }
        while ($true) {
            Skip-NgcoJsonWhitespace -Text $Text -Index $Index
            $name = Read-NgcoJsonStringToken -Text $Text -Index $Index
            if (-not $names.Add([string]$name)) { Throw-NgcoError -Code 'NGCO-PLAN-DUPLICATE-PROPERTY' }
            Skip-NgcoJsonWhitespace -Text $Text -Index $Index
            if ($Index.Value -ge $Text.Length -or $Text[$Index.Value] -ne ':') {
                Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID'
            }
            $Index.Value++
            $null = Read-NgcoJsonValue -Text $Text -Index $Index -Depth ($Depth + 1)
            Skip-NgcoJsonWhitespace -Text $Text -Index $Index
            if ($Index.Value -ge $Text.Length) { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
            if ($Text[$Index.Value] -eq '}') {
                $Index.Value++
                return
            }
            if ($Text[$Index.Value] -ne ',') { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
            $Index.Value++
        }
    }
    if ($character -eq '[') {
        $Index.Value++
        Skip-NgcoJsonWhitespace -Text $Text -Index $Index
        if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -eq ']') {
            $Index.Value++
            return
        }
        while ($true) {
            $null = Read-NgcoJsonValue -Text $Text -Index $Index -Depth ($Depth + 1)
            Skip-NgcoJsonWhitespace -Text $Text -Index $Index
            if ($Index.Value -ge $Text.Length) { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
            if ($Text[$Index.Value] -eq ']') {
                $Index.Value++
                return
            }
            if ($Text[$Index.Value] -ne ',') { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
            $Index.Value++
        }
    }
    if ($character -eq '"') {
        $null = Read-NgcoJsonStringToken -Text $Text -Index $Index
        return
    }
    foreach ($literal in @('true', 'false')) {
        if ($Index.Value + $literal.Length -le $Text.Length -and
            $Text.Substring($Index.Value, $literal.Length) -ceq $literal) {
            $Index.Value += $literal.Length
            return
        }
    }
    if ($Index.Value + 4 -le $Text.Length -and $Text.Substring($Index.Value, 4) -ceq 'null') {
        Throw-NgcoError -Code 'NGCO-PLAN-NULL-FORBIDDEN'
    }
    $numberMatch = [regex]::Match($Text.Substring($Index.Value), '^-?(?:0|[1-9][0-9]*)')
    if (-not $numberMatch.Success) { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
    $Index.Value += $numberMatch.Length
    if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -in @('.', 'e', 'E')) {
        Throw-NgcoError -Code 'NGCO-PLAN-NONINTEGER-FORBIDDEN'
    }
}

function Assert-NgcoStrictJson {
    param([Parameter(Mandatory)][string]$Json)

    if ([System.Text.Encoding]::UTF8.GetByteCount($Json) -gt $script:MaximumPlanBytes) {
        Throw-NgcoError -Code 'NGCO-PLAN-SIZE-EXCEEDED'
    }
    if ($Json -match '[\x00-\x08\x0B\x0C\x0E-\x1F]') {
        Throw-NgcoError -Code 'NGCO-PLAN-CONTROL-CHARACTER'
    }
    $position = 0
    $reference = [ref]$position
    $null = Read-NgcoJsonValue -Text $Json -Index $reference
    Skip-NgcoJsonWhitespace -Text $Json -Index $reference
    if ($reference.Value -ne $Json.Length) { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
}

function ConvertTo-NgcoJsonString {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $builder = New-Object System.Text.StringBuilder
    $null = $builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $codePoint = [int][char]$character
        if ($codePoint -eq 8) { $null = $builder.Append('\b') }
        elseif ($codePoint -eq 9) { $null = $builder.Append('\t') }
        elseif ($codePoint -eq 10) { $null = $builder.Append('\n') }
        elseif ($codePoint -eq 12) { $null = $builder.Append('\f') }
        elseif ($codePoint -eq 13) { $null = $builder.Append('\r') }
        elseif ($codePoint -eq 34) { $null = $builder.Append('\"') }
        elseif ($codePoint -eq 92) { $null = $builder.Append('\\') }
        elseif ($codePoint -lt 32) { $null = $builder.Append(('\u{0:x4}' -f $codePoint)) }
        else { $null = $builder.Append($character) }
    }
    $null = $builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-NgcoCanonicalJson {
    param([Parameter(Mandatory)][AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) { Throw-NgcoError -Code 'NGCO-CANONICAL-NULL-FORBIDDEN' }
    if ($InputObject -is [string]) { return (ConvertTo-NgcoJsonString -Value $InputObject) }
    if ($InputObject -is [bool]) { if ($InputObject) { return 'true' } else { return 'false' } }
    if ($InputObject -is [byte] -or $InputObject -is [sbyte] -or
        $InputObject -is [int16] -or $InputObject -is [uint16] -or
        $InputObject -is [int32] -or $InputObject -is [uint32] -or
        $InputObject -is [int64]) {
        return ([System.Convert]::ToString($InputObject, [System.Globalization.CultureInfo]::InvariantCulture))
    }
    if ($InputObject -is [single] -or $InputObject -is [double] -or
        $InputObject -is [decimal] -or $InputObject -is [uint64]) {
        Throw-NgcoError -Code 'NGCO-CANONICAL-NUMBER-FORBIDDEN'
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and
        $InputObject -isnot [System.Collections.IDictionary] -and
        $InputObject -isnot [System.Management.Automation.PSCustomObject]) {
        $items = @()
        foreach ($item in $InputObject) { $items += ConvertTo-NgcoCanonicalJson -InputObject $item }
        return ('[' + ($items -join ',') + ']')
    }
    $names = @()
    if ($InputObject -is [System.Collections.IDictionary]) {
        $names = @($InputObject.Keys | ForEach-Object { [string]$_ })
    }
    else {
        $names = @($InputObject.PSObject.Properties.Name)
    }
    [array]::Sort($names, [System.StringComparer]::Ordinal)
    $properties = @()
    foreach ($name in $names) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            $value = $InputObject[$name]
        }
        else {
            $value = $InputObject.PSObject.Properties[$name].Value
        }
        $properties += ((ConvertTo-NgcoJsonString -Value $name) + ':' +
            (ConvertTo-NgcoCanonicalJson -InputObject $value))
    }
    return ('{' + ($properties -join ',') + '}')
}

function Assert-NgcoExactProperties {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Code
    )

    $actual = @($InputObject.PSObject.Properties.Name)
    [array]::Sort($actual, [System.StringComparer]::Ordinal)
    $expectedCopy = @($Expected)
    [array]::Sort($expectedCopy, [System.StringComparer]::Ordinal)
    if (($actual -join '|') -cne ($expectedCopy -join '|')) { Throw-NgcoError -Code $Code }
}

function New-NgcoFleetEntry {
    param(
        [string]$AssetId, [string]$Name, [string]$DeploymentClass,
        [int]$Processors, [int]$MinimumMiB, [int]$StartupMiB, [int]$MaximumMiB,
        [int]$OsDiskGiB, [string]$ImageRef, [string]$ImageSha256,
        [string]$FirmwareRef, [string]$StorageRef, [string]$NetworkRef,
        [string]$BootstrapRef, [string]$RecoveryRef, [string]$AccessRef
    )

    $imageSizeBytes = switch ($ImageRef) {
        'debian-12.12-amd64-netinst' { [long]704643072; break }
        'windows-11-25h2-english-x64' { [long]7736125440; break }
        'kali-2026.2-installer-netinst-amd64' { [long]779091968; break }
        default { Throw-NgcoError -Code 'NGCO-FIXED-IMAGE-UNKNOWN' }
    }
    [pscustomobject][ordered]@{
        assetId = $AssetId
        name = $Name
        deploymentClass = $DeploymentClass
        desired = [pscustomobject][ordered]@{
            generation = 2
            processors = $Processors
            memory = [pscustomobject][ordered]@{
                mode = 'dynamic'
                minimumMiB = $MinimumMiB
                startupMiB = $StartupMiB
                maximumMiB = $MaximumMiB
            }
            osDiskGiB = $OsDiskGiB
            imageRef = $ImageRef
            imageSha256 = $ImageSha256
            imageSizeBytes = $imageSizeBytes
            firmwareProfileRef = $FirmwareRef
            secureBootRequired = $true
            vtpmRequired = ($FirmwareRef -ceq 'windows-gen2')
            storageProfileRef = $StorageRef
            networkProfileRef = $NetworkRef
            bootstrapProfileRef = $BootstrapRef
            recoveryProfileRef = $RecoveryRef
            accessProfileRef = $AccessRef
            desiredPowerState = 'off'
            destroyProtection = $true
        }
    }
}

function Get-NgcoFixedFleetPolicy {
    $debianHash = 'dfc30e04fd095ac2c07e998f145e94bb8f7d3a8eca3a631d2eb012398deae531'
    $windowsHash = 'd141f6030fed50f75e2b03e1eb2e53646c4b21e5386047cb860af5223f102a32'
    $kaliHash = 'd32f929dacc48134a31461a09f2160d13ad1d26b820cee920446813ca979b39b'
    $entries = @(
        New-NgcoFleetEntry 'NG-VM-018' 'NG-DEB-CAN01' 'disposable-canary' 2 2048 2048 4096 40 'debian-12.12-amd64-netinst' $debianHash 'linux-gen2' 'lab-ephemeral' 'business-apps' 'debian12-disposable-canary' 'none-canary' 'disposable-canary-keyonly-admin'
        New-NgcoFleetEntry 'NG-VM-010' 'NG-CANARY-01' 'disposable-canary' 2 4096 4096 8192 80 'windows-11-25h2-english-x64' $windowsHash 'windows-gen2' 'lab-ephemeral' 'users-workstations' 'windows11-disposable-canary' 'none-canary' 'windows-disposable-canary'
        New-NgcoFleetEntry 'NG-VM-014' 'NG-MAIL-EXT01' 'persistent' 2 2048 2048 4096 40 'debian-12.12-amd64-netinst' $debianHash 'linux-gen2' 'persistent-mail-protected' 'external-mail' 'debian12-mail-external' 'bronze' 'linux-server-keyonly-admin'
        New-NgcoFleetEntry 'NG-VM-013' 'NG-MAIL-INT01' 'persistent' 2 2048 4096 8192 80 'debian-12.12-amd64-netinst' $debianHash 'linux-gen2' 'persistent-mail-protected' 'mail-internal' 'debian12-mail-internal' 'silver' 'linux-server-keyonly-admin'
        New-NgcoFleetEntry 'NG-VM-011' 'NG-WRK-01' 'persistent' 2 4096 4096 6144 80 'windows-11-25h2-english-x64' $windowsHash 'windows-gen2' 'persistent-workstations' 'users-workstations' 'windows11-worker' 'bronze' 'windows-domain-managed'
        New-NgcoFleetEntry 'NG-VM-012' 'NG-WRK-02' 'persistent' 2 4096 4096 6144 80 'windows-11-25h2-english-x64' $windowsHash 'windows-gen2' 'persistent-workstations' 'users-workstations' 'windows11-worker' 'bronze' 'windows-domain-managed'
        New-NgcoFleetEntry 'NG-VM-019' 'NG-MGR-01' 'persistent' 2 4096 4096 6144 80 'windows-11-25h2-english-x64' $windowsHash 'windows-gen2' 'persistent-workstations' 'users-workstations' 'windows11-manager' 'bronze' 'windows-domain-managed'
        New-NgcoFleetEntry 'NG-VM-020' 'NG-IT-01' 'persistent' 4 4096 8192 12288 100 'windows-11-25h2-english-x64' $windowsHash 'windows-gen2' 'persistent-workstations' 'it-admin-workstations' 'windows11-it-admin' 'silver' 'windows-privileged-workstation'
        New-NgcoFleetEntry 'NG-VM-021' 'NG-CYBER-01' 'persistent' 4 4096 8192 12288 120 'windows-11-25h2-english-x64' $windowsHash 'windows-gen2' 'persistent-workstations' 'cyber-workstations' 'windows11-cyber' 'silver' 'windows-privileged-workstation'
        New-NgcoFleetEntry 'NG-VM-016' 'NG-HR-APP01' 'persistent' 2 2048 4096 8192 100 'debian-12.12-amd64-netinst' $debianHash 'linux-gen2' 'persistent-app-protected' 'business-apps' 'debian12-employee-hub' 'aegis-app-protected' 'debian-app-keyonly-admin'
        New-NgcoFleetEntry 'NG-VM-017' 'NG-PLAT-APP01' 'persistent' 4 4096 8192 16384 120 'debian-12.12-amd64-netinst' $debianHash 'linux-gen2' 'persistent-app-protected' 'commercial-dmz' 'debian12-sentinel-atlas' 'aegis-app-protected' 'debian-app-keyonly-admin'
        New-NgcoFleetEntry 'NG-VM-015' 'NG-KALI-EXT01' 'persistent' 4 4096 4096 12288 100 'kali-2026.2-installer-netinst-amd64' $kaliHash 'linux-gen2' 'persistent-tooling' 'sim-wan' 'kali-external-lab' 'bronze' 'kali-lab-keyonly-admin'
    )
    $policyCore = [pscustomobject][ordered]@{
        policyVersion = 'northgate-create-only-fleet-20260802-v1'
        maximumOperationsPerPlan = 1
        executableActions = @('Create')
        deniedOperations = @(
            'UpdateOnline', 'UpdateOffline', 'ReplaceRequired', 'DecommissionRequired',
            'Delete', 'Purge', 'Adopt', 'SwitchCreate', 'SwitchDelete', 'SwitchRebind',
            'FirewallChange', 'HostFeatureChange', 'GuestCommand', 'ArbitraryCommand'
        )
        rolloutOrder = @($entries.assetId)
        fleet = $entries
    }
    $policyCore | Add-Member -NotePropertyName policyHash -NotePropertyValue (
        Get-NgcoSha256Hex -Value (ConvertTo-NgcoCanonicalJson -InputObject $policyCore)
    )
    $catalogBinding = [pscustomobject][ordered]@{
        imageRefs = @($entries.desired.imageRef | Sort-Object -Unique)
        firmwareRefs = @($entries.desired.firmwareProfileRef | Sort-Object -Unique)
        storageRefs = @($entries.desired.storageProfileRef | Sort-Object -Unique)
        networkRefs = @($entries.desired.networkProfileRef | Sort-Object -Unique)
        bootstrapRefs = @($entries.desired.bootstrapProfileRef | Sort-Object -Unique)
        recoveryRefs = @($entries.desired.recoveryProfileRef | Sort-Object -Unique)
        accessRefs = @($entries.desired.accessProfileRef | Sort-Object -Unique)
    }
    $policyCore | Add-Member -NotePropertyName catalogHash -NotePropertyValue (
        Get-NgcoSha256Hex -Value (ConvertTo-NgcoCanonicalJson -InputObject $catalogBinding)
    )
    return $policyCore
}

function Assert-NgcoLocalContext {
    param([Parameter(Mandatory)][object]$Context)

    Assert-NgcoExactProperties -InputObject $Context -Expected @(
        'Mode', 'Deployed', 'LiveApplyEnabled', 'StateProtectionVerified', 'StateRoot',
        'PlansRoot', 'ReceiptsRoot', 'MacKey', 'PlanTtlMinutes'
    ) -Code 'NGCO-CONTEXT-INVALID'
    if ($Context.Mode -cne 'LocalTestOnly' -or $Context.Deployed -ne $false -or
        $Context.LiveApplyEnabled -ne $false -or $Context.StateProtectionVerified -ne $true -or
        $Context.MacKey -isnot [byte[]] -or $Context.MacKey.Length -lt 32) {
        Throw-NgcoError -Code 'NGCO-CONTEXT-NOT-LOCAL-TEST'
    }
}

function New-NgcoLocalTestContext {
    param(
        [Parameter(Mandatory)][string]$StateRoot,
        [Parameter(Mandatory)][byte[]]$MacKey
    )

    if ($MacKey.Length -lt 32) { Throw-NgcoError -Code 'NGCO-MAC-KEY-INVALID' }
    $fullRoot = [System.IO.Path]::GetFullPath($StateRoot)
    $ancestor = New-Object System.IO.DirectoryInfo($fullRoot)
    while ($null -ne $ancestor) {
        if (Test-Path -LiteralPath (Join-Path $ancestor.FullName '.git')) {
            Throw-NgcoError -Code 'NGCO-STATE-ROOT-REPOSITORY-FORBIDDEN'
        }
        $ancestor = $ancestor.Parent
    }
    $null = [System.IO.Directory]::CreateDirectory($fullRoot)
    $plansRoot = Join-Path $fullRoot 'plans'
    $receiptsRoot = Join-Path $fullRoot 'receipts'
    $null = [System.IO.Directory]::CreateDirectory($plansRoot)
    $null = [System.IO.Directory]::CreateDirectory($receiptsRoot)
    foreach ($path in @($fullRoot, $plansRoot, $receiptsRoot)) {
        if ((Get-Item -LiteralPath $path -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            Throw-NgcoError -Code 'NGCO-STATE-ROOT-REPARSE-FORBIDDEN'
        }
    }
    return [pscustomobject][ordered]@{
        Mode = 'LocalTestOnly'
        Deployed = $false
        LiveApplyEnabled = $false
        StateProtectionVerified = $true
        StateRoot = $fullRoot
        PlansRoot = $plansRoot
        ReceiptsRoot = $receiptsRoot
        MacKey = [byte[]]$MacKey.Clone()
        PlanTtlMinutes = 5
    }
}

function Assert-NgcoLocalAuthentication {
    param(
        [Parameter(Mandatory)][object]$AuthenticationContext,
        [Parameter(Mandatory)][string]$RequiredRole
    )

    Assert-NgcoExactProperties -InputObject $AuthenticationContext -Expected @('authenticated', 'principalId', 'roles') `
        -Code 'NGCO-AUTHENTICATION-FAILED'
    if ($AuthenticationContext.authenticated -isnot [bool] -or $AuthenticationContext.authenticated -ne $true -or
        $AuthenticationContext.principalId -isnot [string] -or
        $AuthenticationContext.principalId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or
        $AuthenticationContext.roles -isnot [System.Array] -or
        $RequiredRole -cnotin @($AuthenticationContext.roles)) {
        Throw-NgcoError -Code 'NGCO-AUTHENTICATION-FAILED'
    }
}

function ConvertFrom-NgcoCanonicalPlan {
    param([Parameter(Mandatory)][string]$CanonicalPlanJson)

    Assert-NgcoStrictJson -Json $CanonicalPlanJson
    try { $plan = ConvertFrom-NgcoJson -Json $CanonicalPlanJson }
    catch { Throw-NgcoError -Code 'NGCO-PLAN-JSON-INVALID' }
    if ($plan -isnot [System.Management.Automation.PSCustomObject] -or
        (ConvertTo-NgcoCanonicalJson -InputObject $plan) -cne $CanonicalPlanJson) {
        Throw-NgcoError -Code 'NGCO-PLAN-NONCANONICAL'
    }
    Assert-NgcoExactProperties -InputObject $plan -Expected @(
        'apiVersion', 'kind', 'repository', 'changeId', 'plannedAtUtc', 'policyHash',
        'catalogHash', 'observedStateHash', 'plannerVersion', 'operatorVersion', 'operations'
    ) -Code 'NGCO-PLAN-PROPERTIES-INVALID'
    Assert-NgcoExactProperties -InputObject $plan.repository -Expected @(
        'identity', 'commit', 'tree', 'trustMode', 'signedReleaseSha256', 'hostAllowlistId'
    ) -Code 'NGCO-PLAN-REPOSITORY-INVALID'
    if ($plan.apiVersion -cne 'northgate/v1alpha1' -or $plan.kind -cne 'CreateOnlyFleetPlan' -or
        $plan.repository.identity -cne $script:ApprovedRepositoryIdentity -or
        $plan.repository.commit -cnotmatch '^[a-f0-9]{40}$' -or
        $plan.repository.tree -cnotmatch '^[a-f0-9]{40}$' -or
        $plan.repository.trustMode -cne 'signed-exact-commit-tree-exception-v1' -or
        $plan.repository.signedReleaseSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $plan.repository.hostAllowlistId -cnotmatch '^ngallow-[a-z0-9-]{8,64}$' -or
        $plan.changeId -cnotmatch '^NG-CHG-[0-9]{8}-[A-Z0-9-]{3,32}$' -or
        $plan.plannedAtUtc -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' -or
        $plan.policyHash -cnotmatch '^[a-f0-9]{64}$' -or
        $plan.catalogHash -cnotmatch '^[a-f0-9]{64}$' -or
        $plan.observedStateHash -cnotmatch '^[a-f0-9]{64}$' -or
        $plan.plannerVersion -cne $script:OperatorVersion -or
        $plan.operatorVersion -cne $script:OperatorVersion -or
        $plan.operations -isnot [System.Array] -or @($plan.operations).Count -ne 1) {
        Throw-NgcoError -Code 'NGCO-PLAN-CONTRACT-INVALID'
    }
    $policy = Get-NgcoFixedFleetPolicy
    if ($plan.policyHash -cne $policy.policyHash -or $plan.catalogHash -cne $policy.catalogHash) {
        Throw-NgcoError -Code 'NGCO-PLAN-POLICY-BINDING-MISMATCH'
    }
    $operation = @($plan.operations)[0]
    Assert-NgcoExactProperties -InputObject $operation -Expected @(
        'sequence', 'action', 'assetId', 'name', 'reservationId', 'quarantineMode',
        'desiredStateHash', 'desired'
    ) -Code 'NGCO-PLAN-OPERATION-PROPERTIES-INVALID'
    Assert-NgcoExactProperties -InputObject $operation.desired -Expected @(
        'generation', 'processors', 'memory', 'osDiskGiB', 'imageRef', 'imageSha256', 'imageSizeBytes',
        'firmwareProfileRef', 'secureBootRequired', 'vtpmRequired', 'storageProfileRef', 'networkProfileRef', 'bootstrapProfileRef',
        'recoveryProfileRef', 'accessProfileRef', 'desiredPowerState', 'destroyProtection'
    ) -Code 'NGCO-PLAN-DESIRED-PROPERTIES-INVALID'
    Assert-NgcoExactProperties -InputObject $operation.desired.memory -Expected @(
        'mode', 'minimumMiB', 'startupMiB', 'maximumMiB'
    ) -Code 'NGCO-PLAN-MEMORY-PROPERTIES-INVALID'
    if ($operation.sequence -ne 1 -or $operation.action -cne 'Create' -or
        $operation.assetId -cnotmatch '^NG-VM-[0-9]{3,}$' -or
        $operation.name -cnotmatch '^[A-Z](?:[A-Z0-9-]{0,13}[A-Z0-9])?$' -or
        $operation.reservationId -cnotmatch '^ngrsv-[a-z0-9-]{8,64}$' -or
        $operation.quarantineMode -cne 'isolate-new-artifacts' -or
        $operation.desiredStateHash -cnotmatch '^[a-f0-9]{64}$') {
        Throw-NgcoError -Code 'NGCO-CREATE-ONLY-VIOLATION'
    }
    $fixed = @($policy.fleet | Where-Object { $_.assetId -ceq $operation.assetId -and $_.name -ceq $operation.name })
    if ($fixed.Count -ne 1) { Throw-NgcoError -Code 'NGCO-ASSET-NOT-IN-FIXED-FLEET' }
    $actualDesired = ConvertTo-NgcoCanonicalJson -InputObject $operation.desired
    $expectedDesired = ConvertTo-NgcoCanonicalJson -InputObject $fixed[0].desired
    if ($actualDesired -cne $expectedDesired -or
        (Get-NgcoSha256Hex -Value $actualDesired) -cne $operation.desiredStateHash) {
        Throw-NgcoError -Code 'NGCO-DESIRED-STATE-BINDING-MISMATCH'
    }
    return [pscustomobject][ordered]@{ Plan = $plan; CanonicalJson = $CanonicalPlanJson }
}

function Enter-NgcoWriterLock {
    try {
        $lock = New-Object System.Threading.Semaphore(1, 1, $script:WriterLockName)
        if (-not $lock.WaitOne(0)) {
            $lock.Dispose()
            Throw-NgcoError -Code 'NGCO-WRITER-LOCK-BUSY'
        }
        return $lock
    }
    catch {
        if ($_.Exception.Message -ceq 'NGCO-WRITER-LOCK-BUSY') { throw }
        Throw-NgcoError -Code 'NGCO-WRITER-LOCK-UNAVAILABLE'
    }
}

function Exit-NgcoWriterLock {
    param([Parameter(Mandatory)][System.Threading.Semaphore]$Lock)

    try { $null = $Lock.Release() }
    finally { $Lock.Dispose() }
}

function Write-NgcoNewFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )

    if (Test-Path -LiteralPath $Path) { Throw-NgcoError -Code 'NGCO-STATE-COLLISION' }
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container) -or
        ((Get-Item -LiteralPath $directory -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        Throw-NgcoError -Code 'NGCO-STATE-ROOT-INVALID'
    }
    $temporary = Join-Path $directory ('.ngco-' + (New-NgcoRandomHex -ByteCount 16) + '.tmp')
    try {
        [System.IO.File]::WriteAllText($temporary, $Content, (New-Object System.Text.UTF8Encoding($false)))
        [System.IO.File]::Move($temporary, $Path)
    }
    catch {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        Throw-NgcoError -Code 'NGCO-STATE-WRITE-FAILED'
    }
}

function Read-NgcoPlanRecord {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$PlanId
    )

    Assert-NgcoLocalContext -Context $Context
    if ($PlanId -cnotmatch '^ngp-[a-f0-9]{64}$') { Throw-NgcoError -Code 'NGCO-PLAN-ID-INVALID' }
    $path = Join-Path $Context.PlansRoot ($PlanId + '.json')
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Throw-NgcoError -Code 'NGCO-PLAN-NOT-FOUND' }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Length -gt $script:MaximumPlanBytes -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        Throw-NgcoError -Code 'NGCO-REGISTRY-CORRUPT'
    }
    try { $raw = [System.IO.File]::ReadAllText($item.FullName) }
    catch { Throw-NgcoError -Code 'NGCO-STATE-READ-FAILED' }
    Assert-NgcoStrictJson -Json $raw
    try { $envelope = ConvertFrom-NgcoJson -Json $raw }
    catch { Throw-NgcoError -Code 'NGCO-REGISTRY-CORRUPT' }
    if ((ConvertTo-NgcoCanonicalJson -InputObject $envelope) -cne $raw) {
        Throw-NgcoError -Code 'NGCO-REGISTRY-NONCANONICAL'
    }
    Assert-NgcoExactProperties -InputObject $envelope -Expected @('record', 'recordMac') `
        -Code 'NGCO-REGISTRY-CORRUPT'
    Assert-NgcoExactProperties -InputObject $envelope.record -Expected @(
        'formatVersion', 'planId', 'planHash', 'registeredAtUtc', 'expiresAtUtc',
        'state', 'canonicalPlan', 'productionApplicable'
    ) -Code 'NGCO-REGISTRY-CORRUPT'
    $record = $envelope.record
    if ($record.formatVersion -ne 1 -or $record.planId -cne $PlanId -or
        $record.planHash -cnotmatch '^[a-f0-9]{64}$' -or
        $record.registeredAtUtc -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' -or
        $record.expiresAtUtc -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' -or
        $record.state -cne 'RegisteredLocalTestOnly' -or
        $record.productionApplicable -isnot [bool] -or $record.productionApplicable -ne $false -or
        $envelope.recordMac -cnotmatch '^[a-f0-9]{64}$') {
        Throw-NgcoError -Code 'NGCO-REGISTRY-CORRUPT'
    }
    $recordJson = ConvertTo-NgcoCanonicalJson -InputObject $record
    $expectedRecordMac = Get-NgcoHmacHex -Key $Context.MacKey `
        -Value ("northgate-create-only-registry-v1`n$recordJson")
    if (-not (Test-NgcoFixedHexEquals -Left $expectedRecordMac -Right ([string]$envelope.recordMac))) {
        Throw-NgcoError -Code 'NGCO-REGISTRY-AUTHENTICATION-FAILED'
    }
    $null = ConvertFrom-NgcoCanonicalPlan -CanonicalPlanJson ([string]$record.canonicalPlan)
    $expectedPlanHash = Get-NgcoHmacHex -Key $Context.MacKey `
        -Value ("northgate-create-only-plan-v1`n$PlanId`n$($record.expiresAtUtc)`n$($record.canonicalPlan)")
    if (-not (Test-NgcoFixedHexEquals -Left $expectedPlanHash -Right ([string]$record.planHash))) {
        Throw-NgcoError -Code 'NGCO-PLAN-AUTHENTICATION-FAILED'
    }
    return $record
}

function Get-NorthGateCreateOnlyOperatorStatus {
    [CmdletBinding()]
    param()

    $policy = Get-NgcoFixedFleetPolicy
    [pscustomobject][ordered]@{
        operation = 'status'
        operatorVersion = $script:OperatorVersion
        releaseStatus = $script:ReleaseStatus
        deployed = $false
        forcedCommandIdentityInstalled = $false
        applicationAuthenticationConfigured = $false
        planRegistrationProductionEnabled = $false
        applyEnabled = $false
        executableActions = @()
        modeledAction = 'Create'
        fixedFleetAssetCount = @($policy.fleet).Count
        fixedFleetPolicyHash = $policy.policyHash
        fixedCatalogBindingHash = $policy.catalogHash
        maximumOperationsPerPlan = 1
        repositoryTrustMode = 'signed-exact-commit-tree-exception-v1'
        repositoryTrustExceptionInstalled = $false
        liveRevalidationImplemented = $false
        liveHyperVBackendImplemented = $false
        atomicCreateImplemented = $false
        quarantineImplemented = $false
        receiptSigningImplemented = $false
        directMutationMethodsExposed = $false
        reasonCode = $script:NotPromotedCode
    }
}

function Register-NgcoLocalTestPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$AuthenticationContext,
        [Parameter(Mandatory)][string]$CanonicalPlanJson
    )

    Assert-NgcoLocalContext -Context $Context
    Assert-NgcoLocalAuthentication -AuthenticationContext $AuthenticationContext -RequiredRole 'planner'
    $parsed = ConvertFrom-NgcoCanonicalPlan -CanonicalPlanJson $CanonicalPlanJson
    $lock = Enter-NgcoWriterLock
    try {
        $planId = 'ngp-' + (New-NgcoRandomHex -ByteCount 32)
        $registeredAt = [System.DateTimeOffset]::UtcNow
        $registeredAtUtc = $registeredAt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        $expiresAtUtc = $registeredAt.AddMinutes($Context.PlanTtlMinutes).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        $planHash = Get-NgcoHmacHex -Key $Context.MacKey `
            -Value ("northgate-create-only-plan-v1`n$planId`n$expiresAtUtc`n$($parsed.CanonicalJson)")
        $record = [pscustomobject][ordered]@{
            formatVersion = 1
            planId = $planId
            planHash = $planHash
            registeredAtUtc = $registeredAtUtc
            expiresAtUtc = $expiresAtUtc
            state = 'RegisteredLocalTestOnly'
            canonicalPlan = $parsed.CanonicalJson
            productionApplicable = $false
        }
        $recordJson = ConvertTo-NgcoCanonicalJson -InputObject $record
        $envelope = [pscustomobject][ordered]@{
            record = $record
            recordMac = Get-NgcoHmacHex -Key $Context.MacKey `
                -Value ("northgate-create-only-registry-v1`n$recordJson")
        }
        Write-NgcoNewFile -Path (Join-Path $Context.PlansRoot ($planId + '.json')) `
            -Content (ConvertTo-NgcoCanonicalJson -InputObject $envelope)
        return [pscustomobject][ordered]@{
            operation = 'plan'
            accepted = $true
            planId = $planId
            planHash = $planHash
            expiresAtUtc = $expiresAtUtc
            state = 'RegisteredLocalTestOnly'
            productionApplicable = $false
            applyEnabled = $false
            reasonCode = $script:NotPromotedCode
        }
    }
    finally {
        Exit-NgcoWriterLock -Lock $lock
    }
}

function Register-NorthGateCreateOnlyOperatorPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$CanonicalPlanJson
    )

    $null = $CanonicalPlanJson
    [pscustomobject][ordered]@{
        operation = 'plan'
        accepted = $false
        status = 'disabled'
        productionApplicable = $false
        applyEnabled = $false
        reasonCode = $script:NotPromotedCode
    }
}

function Invoke-NorthGateCreateOnlyOperatorApply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$PlanId
    )

    $null = $PlanId
    [pscustomobject][ordered]@{
        operation = 'apply'
        accepted = $false
        status = 'disabled'
        reasonCode = $script:NotPromotedCode
        applyEnabled = $false
    }
}

function Get-NorthGateCreateOnlyOperatorReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$PlanId
    )

    $null = $PlanId
    [pscustomobject][ordered]@{
        operation = 'receipt'
        found = $false
        status = 'disabled'
        reasonCode = $script:NotPromotedCode
    }
}

Export-ModuleMember -Function @(
    'Get-NorthGateCreateOnlyOperatorStatus',
    'Register-NorthGateCreateOnlyOperatorPlan',
    'Invoke-NorthGateCreateOnlyOperatorApply',
    'Get-NorthGateCreateOnlyOperatorReceipt'
)
