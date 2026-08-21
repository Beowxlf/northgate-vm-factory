Set-StrictMode -Version Latest

$script:ProtocolVersion = '0.1.0'
$script:MaximumCommandCharacters = 96
$script:MaximumPlanRequestBytes = 32768
$script:MaximumJsonDepth = 16
$script:RepositoryIdentity = 'Beowxlf/northgate-vm-factory'

function Throw-NgcorProtocolError {
    param([Parameter(Mandatory)][string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function ConvertFrom-NgcorJsonText {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)
    $converter = Microsoft.PowerShell.Core\Get-Command `
        -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json -DateKind String
    }
    return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json
}

function Skip-NgcorJsonWhitespace {
    param([string]$Text, [ref]$Index)
    while ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -in @(' ', "`t", "`r", "`n")) {
        $Index.Value++
    }
}

function Read-NgcorJsonStringToken {
    param([string]$Text, [ref]$Index)
    if ($Index.Value -ge $Text.Length -or $Text[$Index.Value] -ne '"') {
        Throw-NgcorProtocolError 'NGCOR-JSON-INVALID'
    }
    $start = $Index.Value
    $Index.Value++
    while ($Index.Value -lt $Text.Length) {
        $character = $Text[$Index.Value]
        if ($character -eq '"') {
            $Index.Value++
            try { return (ConvertFrom-NgcorJsonText ($Text.Substring($start, $Index.Value - $start))) }
            catch { Throw-NgcorProtocolError 'NGCOR-JSON-INVALID' }
        }
        if ([int][char]$character -lt 32) { Throw-NgcorProtocolError 'NGCOR-JSON-CONTROL-CHARACTER' }
        if ($character -eq '\') {
            $Index.Value++
            if ($Index.Value -ge $Text.Length) { Throw-NgcorProtocolError 'NGCOR-JSON-INVALID' }
            $escape = $Text[$Index.Value]
            if ($escape -eq 'u') {
                if ($Index.Value + 4 -ge $Text.Length -or
                    $Text.Substring($Index.Value + 1, 4) -cnotmatch '^[0-9a-fA-F]{4}$') {
                    Throw-NgcorProtocolError 'NGCOR-JSON-INVALID'
                }
                $Index.Value += 4
            }
            elseif ($escape -notin @('"', '\', '/', 'b', 'f', 'n', 'r', 't')) {
                Throw-NgcorProtocolError 'NGCOR-JSON-INVALID'
            }
        }
        $Index.Value++
    }
    Throw-NgcorProtocolError 'NGCOR-JSON-INVALID'
}

function Read-NgcorJsonValue {
    param([string]$Text, [ref]$Index, [int]$Depth = 0)
    if ($Depth -gt $script:MaximumJsonDepth) { Throw-NgcorProtocolError 'NGCOR-JSON-DEPTH-EXCEEDED' }
    Skip-NgcorJsonWhitespace $Text $Index
    if ($Index.Value -ge $Text.Length) { Throw-NgcorProtocolError 'NGCOR-JSON-INVALID' }
    $character = $Text[$Index.Value]
    if ($character -eq '{') {
        $Index.Value++
        $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        Skip-NgcorJsonWhitespace $Text $Index
        if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -eq '}') { $Index.Value++; return }
        while ($true) {
            Skip-NgcorJsonWhitespace $Text $Index
            $name = Read-NgcorJsonStringToken $Text $Index
            if (-not $names.Add([string]$name)) { Throw-NgcorProtocolError 'NGCOR-JSON-DUPLICATE-PROPERTY' }
            Skip-NgcorJsonWhitespace $Text $Index
            if ($Index.Value -ge $Text.Length -or $Text[$Index.Value] -ne ':') {
                Throw-NgcorProtocolError 'NGCOR-JSON-INVALID'
            }
            $Index.Value++
            Read-NgcorJsonValue $Text $Index ($Depth + 1)
            Skip-NgcorJsonWhitespace $Text $Index
            if ($Index.Value -ge $Text.Length) { Throw-NgcorProtocolError 'NGCOR-JSON-INVALID' }
            if ($Text[$Index.Value] -eq '}') { $Index.Value++; return }
            if ($Text[$Index.Value] -ne ',') { Throw-NgcorProtocolError 'NGCOR-JSON-INVALID' }
            $Index.Value++
        }
    }
    if ($character -eq '[') {
        $Index.Value++
        Skip-NgcorJsonWhitespace $Text $Index
        if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -eq ']') { $Index.Value++; return }
        while ($true) {
            Read-NgcorJsonValue $Text $Index ($Depth + 1)
            Skip-NgcorJsonWhitespace $Text $Index
            if ($Index.Value -ge $Text.Length) { Throw-NgcorProtocolError 'NGCOR-JSON-INVALID' }
            if ($Text[$Index.Value] -eq ']') { $Index.Value++; return }
            if ($Text[$Index.Value] -ne ',') { Throw-NgcorProtocolError 'NGCOR-JSON-INVALID' }
            $Index.Value++
        }
    }
    if ($character -eq '"') { $null = Read-NgcorJsonStringToken $Text $Index; return }
    foreach ($literal in @('true', 'false')) {
        if ($Index.Value + $literal.Length -le $Text.Length -and
            $Text.Substring($Index.Value, $literal.Length) -ceq $literal) {
            $Index.Value += $literal.Length
            return
        }
    }
    if ($Index.Value + 4 -le $Text.Length -and $Text.Substring($Index.Value, 4) -ceq 'null') {
        Throw-NgcorProtocolError 'NGCOR-JSON-NULL-FORBIDDEN'
    }
    $number = [regex]::Match($Text.Substring($Index.Value), '^-?(?:0|[1-9][0-9]*)')
    if (-not $number.Success) { Throw-NgcorProtocolError 'NGCOR-JSON-INVALID' }
    $Index.Value += $number.Length
    if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -in @('.', 'e', 'E')) {
        Throw-NgcorProtocolError 'NGCOR-JSON-NONINTEGER-FORBIDDEN'
    }
}

function Assert-NgcorStrictJson {
    param(
        [string]$Json,
        [ValidateRange(1, 10485760)][int]$MaximumBytes = $script:MaximumPlanRequestBytes,
        [string]$SizeErrorCode = 'NGCOR-PLAN-SIZE-EXCEEDED'
    )
    if ([System.Text.Encoding]::UTF8.GetByteCount($Json) -gt $MaximumBytes) {
        Throw-NgcorProtocolError $SizeErrorCode
    }
    if ($Json -match '[\x00-\x08\x0B\x0C\x0E-\x1F]') {
        Throw-NgcorProtocolError 'NGCOR-JSON-CONTROL-CHARACTER'
    }
    $position = 0
    $reference = [ref]$position
    Read-NgcorJsonValue $Json $reference
    Skip-NgcorJsonWhitespace $Json $reference
    if ($reference.Value -ne $Json.Length) { Throw-NgcorProtocolError 'NGCOR-JSON-TRAILING-CONTENT' }
}

function ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [ValidateRange(1, 10485760)][int]$MaximumBytes = 262144
    )
    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt $MaximumBytes) {
        Throw-NgcorProtocolError 'NGCOR-CANONICAL-JSON-SIZE-INVALID'
    }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xef -and $Bytes[1] -eq 0xbb -and $Bytes[2] -eq 0xbf) {
        Throw-NgcorProtocolError 'NGCOR-CANONICAL-JSON-BOM-FORBIDDEN'
    }
    try {
        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $json = $utf8.GetString($Bytes)
    }
    catch { Throw-NgcorProtocolError 'NGCOR-CANONICAL-JSON-UTF8-INVALID' }
    Assert-NgcorStrictJson $json $MaximumBytes 'NGCOR-CANONICAL-JSON-SIZE-INVALID'
    try { $value = ConvertFrom-NgcorJsonText $json }
    catch { Throw-NgcorProtocolError 'NGCOR-JSON-INVALID' }
    if ($value -isnot [System.Management.Automation.PSCustomObject] -or
        (ConvertTo-NorthGateCreateOnlyCanonicalJson $value) -cne $json) {
        Throw-NgcorProtocolError 'NGCOR-CANONICAL-JSON-NONCANONICAL'
    }
    [pscustomobject][ordered]@{ Value = $value; CanonicalJson = $json }
}

function ConvertTo-NgcorJsonString {
    param([AllowEmptyString()][string]$Value)
    $builder = New-Object System.Text.StringBuilder
    $null = $builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $point = [int][char]$character
        switch ($point) {
            8 { $null = $builder.Append('\b'); break }
            9 { $null = $builder.Append('\t'); break }
            10 { $null = $builder.Append('\n'); break }
            12 { $null = $builder.Append('\f'); break }
            13 { $null = $builder.Append('\r'); break }
            34 { $null = $builder.Append('\"'); break }
            92 { $null = $builder.Append('\\'); break }
            default {
                if ($point -lt 32) { $null = $builder.Append(('\u{0:x4}' -f $point)) }
                else { $null = $builder.Append($character) }
            }
        }
    }
    $null = $builder.Append('"')
    $builder.ToString()
}

function ConvertTo-NorthGateCreateOnlyCanonicalJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()][object]$InputObject)
    if ($null -eq $InputObject) { Throw-NgcorProtocolError 'NGCOR-CANONICAL-NULL-FORBIDDEN' }
    if ($InputObject -is [string]) { return ConvertTo-NgcorJsonString ([string]$InputObject) }
    if ($InputObject -is [bool]) { if ($InputObject) { return 'true' } else { return 'false' } }
    if ($InputObject -is [byte] -or $InputObject -is [sbyte] -or
        $InputObject -is [int16] -or $InputObject -is [uint16] -or
        $InputObject -is [int32] -or $InputObject -is [uint32] -or
        $InputObject -is [int64]) {
        return [System.Convert]::ToString($InputObject, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($InputObject -is [single] -or $InputObject -is [double] -or
        $InputObject -is [decimal] -or $InputObject -is [uint64]) {
        Throw-NgcorProtocolError 'NGCOR-CANONICAL-NUMBER-FORBIDDEN'
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and
        $InputObject -isnot [System.Collections.IDictionary] -and
        $InputObject -isnot [System.Management.Automation.PSCustomObject]) {
        $items = @()
        foreach ($item in $InputObject) { $items += ConvertTo-NorthGateCreateOnlyCanonicalJson $item }
        return '[' + ($items -join ',') + ']'
    }
    $names = if ($InputObject -is [System.Collections.IDictionary]) {
        @($InputObject.Keys | ForEach-Object { [string]$_ })
    } else { @($InputObject.PSObject.Properties.Name) }
    [array]::Sort($names, [System.StringComparer]::Ordinal)
    $properties = @()
    foreach ($name in $names) {
        $value = $null
        if ($InputObject -is [System.Collections.IDictionary]) {
            $value = $InputObject[$name]
        }
        else { $value = $InputObject.PSObject.Properties[$name].Value }
        $properties += (ConvertTo-NgcorJsonString $name) + ':' +
            (ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $value)
    }
    return '{' + ($properties -join ',') + '}'
}

function Assert-NgcorExactProperties {
    param([object]$Object, [string[]]$Expected, [string]$Code)
    if ($null -eq $Object) { Throw-NgcorProtocolError $Code }
    $actual = @($Object.PSObject.Properties.Name)
    $expectedCopy = @($Expected)
    [array]::Sort($actual, [System.StringComparer]::Ordinal)
    [array]::Sort($expectedCopy, [System.StringComparer]::Ordinal)
    if (($actual -join '|') -cne ($expectedCopy -join '|')) { Throw-NgcorProtocolError $Code }
}

function ConvertFrom-NorthGateCreateOnlyCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Command)
    if ($Command.Length -eq 0 -or $Command.Length -gt $script:MaximumCommandCharacters -or
        $Command -notmatch '^[\x20-\x7e]+$') {
        Throw-NgcorProtocolError 'NGCOR-COMMAND-INVALID'
    }
    if ($Command -cin @('status','plan','rollout-context','promote-rollout')) {
        return [pscustomobject][ordered]@{ operation = $Command; planId = '' }
    }
    if ($Command -cmatch '^(apply|receipt|approval-context|approve) (ngp-[a-f0-9]{64})$') {
        return [pscustomobject][ordered]@{ operation = $Matches[1]; planId = $Matches[2] }
    }
    Throw-NgcorProtocolError 'NGCOR-COMMAND-NOT-ALLOWED'
}

function ConvertFrom-NorthGateCreateOnlyPlanRequestBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt $script:MaximumPlanRequestBytes) {
        Throw-NgcorProtocolError 'NGCOR-PLAN-SIZE-INVALID'
    }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xef -and $Bytes[1] -eq 0xbb -and $Bytes[2] -eq 0xbf) {
        Throw-NgcorProtocolError 'NGCOR-PLAN-BOM-FORBIDDEN'
    }
    try {
        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $json = $utf8.GetString($Bytes)
    }
    catch { Throw-NgcorProtocolError 'NGCOR-PLAN-UTF8-INVALID' }
    Assert-NgcorStrictJson $json
    try { $request = ConvertFrom-NgcorJsonText $json }
    catch { Throw-NgcorProtocolError 'NGCOR-JSON-INVALID' }
    if ($request -isnot [System.Management.Automation.PSCustomObject] -or
        (ConvertTo-NorthGateCreateOnlyCanonicalJson $request) -cne $json) {
        Throw-NgcorProtocolError 'NGCOR-PLAN-NONCANONICAL'
    }
    Assert-NgcorExactProperties $request @('apiVersion','kind','assetId','changeId','repository') `
        'NGCOR-PLAN-PROPERTIES-INVALID'
    Assert-NgcorExactProperties $request.repository `
        @('identity','commit','tree','signedReleaseSha256','hostAllowlistId') `
        'NGCOR-REPOSITORY-PROPERTIES-INVALID'
    if ($request.apiVersion -cne 'northgate/v1alpha1' -or
        $request.kind -cne 'CreateOnlyPlanRequest' -or
        $request.assetId -cnotmatch '^NG-VM-[0-9]{3}$' -or
        $request.changeId -cnotmatch '^NG-CHG-[0-9]{8}-[A-Z0-9-]{3,32}$' -or
        $request.repository.identity -cne $script:RepositoryIdentity -or
        $request.repository.commit -cnotmatch '^[a-f0-9]{40}$' -or
        $request.repository.tree -cnotmatch '^[a-f0-9]{40}$' -or
        $request.repository.signedReleaseSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $request.repository.hostAllowlistId -cnotmatch '^ngallow-[a-z0-9-]{8,64}$') {
        Throw-NgcorProtocolError 'NGCOR-PLAN-CONTRACT-INVALID'
    }
    [pscustomobject][ordered]@{ Request = $request; CanonicalJson = $json }
}

function ConvertFrom-NorthGateCreateOnlyServiceEnvelopeBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt 65536) {
        Throw-NgcorProtocolError 'NGCOR-ENVELOPE-SIZE-INVALID'
    }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xef -and $Bytes[1] -eq 0xbb -and $Bytes[2] -eq 0xbf) {
        Throw-NgcorProtocolError 'NGCOR-ENVELOPE-BOM-FORBIDDEN'
    }
    try {
        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $json = $utf8.GetString($Bytes)
    }
    catch { Throw-NgcorProtocolError 'NGCOR-ENVELOPE-UTF8-INVALID' }
    Assert-NgcorStrictJson $json
    try { $envelope = ConvertFrom-NgcorJsonText $json }
    catch { Throw-NgcorProtocolError 'NGCOR-ENVELOPE-INVALID' }
    if ($envelope -isnot [System.Management.Automation.PSCustomObject] -or
        (ConvertTo-NorthGateCreateOnlyCanonicalJson $envelope) -cne $json) {
        Throw-NgcorProtocolError 'NGCOR-ENVELOPE-NONCANONICAL'
    }
    Assert-NgcorExactProperties $envelope @('version','command','body') 'NGCOR-ENVELOPE-PROPERTIES-INVALID'
    if (($envelope.version -isnot [int] -and $envelope.version -isnot [long]) -or
        $envelope.version -ne 1 -or
        $envelope.command -isnot [string] -or $envelope.body -isnot [string]) {
        Throw-NgcorProtocolError 'NGCOR-ENVELOPE-CONTRACT-INVALID'
    }
    $parsedCommand = ConvertFrom-NorthGateCreateOnlyCommand ([string]$envelope.command)
    if ($parsedCommand.operation -ceq 'plan') {
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$envelope.body)
        $parsedBody = ConvertFrom-NorthGateCreateOnlyPlanRequestBytes $bodyBytes
        if ($parsedBody.CanonicalJson -cne [string]$envelope.body) {
            Throw-NgcorProtocolError 'NGCOR-ENVELOPE-BODY-NONCANONICAL'
        }
    }
    elseif ($parsedCommand.operation -in @('approve','promote-rollout')) {
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$envelope.body)
        $null = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $bodyBytes -MaximumBytes 65536
    }
    elseif ([string]$envelope.body -cne '') { Throw-NgcorProtocolError 'NGCOR-STDIN-NOT-EMPTY' }
    [pscustomobject][ordered]@{
        Command = [string]$envelope.command
        Operation = [string]$parsedCommand.operation
        PlanId = [string]$parsedCommand.planId
        BodyBytes = if ($parsedCommand.operation -in @('plan','approve','promote-rollout')) {
            [System.Text.Encoding]::UTF8.GetBytes([string]$envelope.body)
        } else { New-Object byte[] 0 }
        CanonicalJson = $json
    }
}

Export-ModuleMember -Function @(
    'ConvertFrom-NorthGateCreateOnlyCommand',
    'ConvertFrom-NorthGateCreateOnlyPlanRequestBytes',
    'ConvertFrom-NorthGateCreateOnlyServiceEnvelopeBytes',
    'ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes',
    'ConvertTo-NorthGateCreateOnlyCanonicalJson'
)
