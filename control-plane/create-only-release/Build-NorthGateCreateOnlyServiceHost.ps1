[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$ProvenancePath,
    [Parameter(Mandatory)][string]$CompilerPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedSourceSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedCompilerSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedMscorlibAssemblySha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedSystemAssemblySha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedSystemCoreAssemblySha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedAutomationAssemblySha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedServiceProcessAssemblySha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Ngcb {
    param([Parameter(Mandatory)][string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function Get-NgcbFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $stream = New-Object System.IO.FileStream(
        $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read, 65536, [System.IO.FileOptions]::SequentialScan
    )
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($stream) }
    finally { $algorithm.Dispose(); $stream.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Assert-NgcbHash {
    param([string]$Path, [string]$Expected, [string]$Code)
    if ((Get-NgcbFileSha256 $Path) -cne $Expected) { Stop-Ngcb $Code }
}

function ConvertTo-NgcbJsonString {
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

function ConvertTo-NgcbCanonicalJson {
    param([Parameter(Mandatory)][AllowNull()][object]$InputObject)
    if ($null -eq $InputObject) { Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-PROVENANCE-INVALID' }
    if ($InputObject -is [string]) { return ConvertTo-NgcbJsonString ([string]$InputObject) }
    if ($InputObject -is [bool]) { if ($InputObject) { return 'true' } else { return 'false' } }
    if ($InputObject -is [byte] -or $InputObject -is [sbyte] -or
        $InputObject -is [int16] -or $InputObject -is [uint16] -or
        $InputObject -is [int32] -or $InputObject -is [uint32] -or
        $InputObject -is [int64]) {
        return [Convert]::ToString($InputObject, [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($InputObject -is [Collections.IEnumerable] -and
        $InputObject -isnot [Collections.IDictionary] -and
        $InputObject -isnot [Management.Automation.PSCustomObject]) {
        $items = @()
        foreach ($item in $InputObject) { $items += ConvertTo-NgcbCanonicalJson $item }
        return '[' + ($items -join ',') + ']'
    }
    $names = if ($InputObject -is [Collections.IDictionary]) {
        @($InputObject.Keys | ForEach-Object { [string]$_ })
    }
    else { @($InputObject.PSObject.Properties.Name) }
    [array]::Sort($names, [StringComparer]::Ordinal)
    $properties = @()
    foreach ($name in $names) {
        $value = if ($InputObject -is [Collections.IDictionary]) {
            $InputObject[$name]
        }
        else { $InputObject.PSObject.Properties[$name].Value }
        $properties += (ConvertTo-NgcbJsonString $name) + ':' + (ConvertTo-NgcbCanonicalJson $value)
    }
    '{' + ($properties -join ',') + '}'
}

function Assert-NgcbNoReparsePath {
    param([string]$Path, [string]$Code)
    $cursor = [System.IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $cursor) -and -not [string]::IsNullOrWhiteSpace($cursor)) {
        $cursor = Split-Path -Parent $cursor
    }
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and (Test-Path -LiteralPath $cursor)) {
        if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            Stop-Ngcb $Code
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
}

function Test-NgcbGitAncestor {
    param([string]$Path)
    $cursor = New-Object System.IO.DirectoryInfo([System.IO.Path]::GetFullPath($Path))
    while ($null -ne $cursor) {
        if (Test-Path -LiteralPath (Join-Path $cursor.FullName '.git')) { return $true }
        $cursor = $cursor.Parent
    }
    $false
}

function ConvertTo-NgcbQuotedArgument {
    param([string]$Value)
    if ($Value.IndexOfAny(@([char]34,[char]10,[char]13)) -ge 0) {
        Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-PATH-INVALID'
    }
    '"' + $Value + '"'
}

if ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or
    -not [Environment]::Is64BitProcess) {
    Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-ENVIRONMENT-INVALID'
}

$sourcePath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'NorthGate.CreateOnly.ServiceHost.cs'))
$executedBuilder = [System.IO.Path]::GetFullPath($PSCommandPath)
$expectedBuilder = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'Build-NorthGateCreateOnlyServiceHost.ps1'))
if ($executedBuilder -cne $expectedBuilder -or -not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-SOURCE-INVALID'
}
Assert-NgcbNoReparsePath $sourcePath 'NGCOR-SERVICE-HOST-BUILD-REPARSE-FORBIDDEN'
Assert-NgcbHash $sourcePath $ExpectedSourceSha256 'NGCOR-SERVICE-HOST-BUILD-SOURCE-HASH-MISMATCH'

$output = [System.IO.Path]::GetFullPath($OutputPath)
$provenance = [System.IO.Path]::GetFullPath($ProvenancePath)
$outputParent = Split-Path -Parent $output
if ([System.IO.Path]::GetFileName($output) -cne 'NorthGate.CreateOnly.ServiceHost.exe' -or
    [System.IO.Path]::GetFileName($provenance) -cne 'NorthGate.CreateOnly.ServiceHost.build-provenance.json' -or
    (Split-Path -Parent $provenance) -cne $outputParent -or
    [string]::IsNullOrWhiteSpace($outputParent) -or
    -not (Test-Path -LiteralPath $outputParent -PathType Container) -or
    (Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath $provenance)) {
    Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-OUTPUT-INVALID'
}
Assert-NgcbNoReparsePath $outputParent 'NGCOR-SERVICE-HOST-BUILD-REPARSE-FORBIDDEN'
if (Test-NgcbGitAncestor $outputParent) { Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-OUTPUT-IN-REPOSITORY' }

$compilerPath = [System.IO.Path]::GetFullPath($CompilerPath)
$programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$allowedCompilerPaths = @(
    [System.IO.Path]::GetFullPath((Join-Path $programFilesX86 `
        'Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe')),
    [System.IO.Path]::GetFullPath((Join-Path $programFilesX86 `
        'Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe')),
    [System.IO.Path]::GetFullPath((Join-Path $programFiles `
        'Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\Roslyn\csc.exe'))
)
if ($compilerPath -cnotin $allowedCompilerPaths) {
    Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-COMPILER-INVALID'
}
try { Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop }
catch { Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-REFERENCE-UNAVAILABLE' }
$automationAssemblyPath = [System.IO.Path]::GetFullPath(
    [System.Management.Automation.PowerShell].Assembly.Location
)
$mscorlibAssemblyPath = [System.IO.Path]::GetFullPath([object].Assembly.Location)
$systemAssemblyPath = [System.IO.Path]::GetFullPath([System.ComponentModel.Component].Assembly.Location)
$systemCoreAssemblyPath = [System.IO.Path]::GetFullPath([System.Linq.Enumerable].Assembly.Location)
$serviceProcessAssemblyPath = [System.IO.Path]::GetFullPath(
    [System.ServiceProcess.ServiceBase].Assembly.Location
)
foreach ($requiredPath in @(
        $compilerPath,$mscorlibAssemblyPath,$systemAssemblyPath,$systemCoreAssemblyPath,
        $automationAssemblyPath,$serviceProcessAssemblyPath
    )) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-REFERENCE-UNAVAILABLE'
    }
    Assert-NgcbNoReparsePath $requiredPath 'NGCOR-SERVICE-HOST-BUILD-REPARSE-FORBIDDEN'
}
Assert-NgcbHash $compilerPath $ExpectedCompilerSha256 'NGCOR-SERVICE-HOST-BUILD-COMPILER-HASH-MISMATCH'
Assert-NgcbHash $mscorlibAssemblyPath $ExpectedMscorlibAssemblySha256 `
    'NGCOR-SERVICE-HOST-BUILD-MSCORLIB-HASH-MISMATCH'
Assert-NgcbHash $systemAssemblyPath $ExpectedSystemAssemblySha256 `
    'NGCOR-SERVICE-HOST-BUILD-SYSTEM-HASH-MISMATCH'
Assert-NgcbHash $systemCoreAssemblyPath $ExpectedSystemCoreAssemblySha256 `
    'NGCOR-SERVICE-HOST-BUILD-SYSTEMCORE-HASH-MISMATCH'
Assert-NgcbHash $automationAssemblyPath $ExpectedAutomationAssemblySha256 `
    'NGCOR-SERVICE-HOST-BUILD-AUTOMATION-HASH-MISMATCH'
Assert-NgcbHash $serviceProcessAssemblyPath $ExpectedServiceProcessAssemblySha256 `
    'NGCOR-SERVICE-HOST-BUILD-SERVICEPROCESS-HASH-MISMATCH'

$buildRoot = Join-Path $outputParent ('ngcor-service-host-build-' + [guid]::NewGuid().ToString('N'))
$temporaryExecutable = Join-Path $buildRoot 'NorthGate.CreateOnly.ServiceHost.exe'
$temporaryProvenance = Join-Path $buildRoot 'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
$process = $null
try {
    $null = [System.IO.Directory]::CreateDirectory($buildRoot)
    Assert-NgcbNoReparsePath $buildRoot 'NGCOR-SERVICE-HOST-BUILD-REPARSE-FORBIDDEN'
    $arguments = @(
        '/nologo',
        '/noconfig',
        '/target:exe',
        '/platform:anycpu',
        '/optimize+',
        '/debug-',
        '/checked+',
        '/deterministic+',
        '/warnaserror+',
        '/langversion:5',
        '/utf8output',
        ('/pathmap:' + (ConvertTo-NgcbQuotedArgument ($PSScriptRoot + '=/_/src'))),
        ('/out:' + (ConvertTo-NgcbQuotedArgument $temporaryExecutable)),
        ('/reference:' + (ConvertTo-NgcbQuotedArgument $mscorlibAssemblyPath)),
        ('/reference:' + (ConvertTo-NgcbQuotedArgument $systemAssemblyPath)),
        ('/reference:' + (ConvertTo-NgcbQuotedArgument $systemCoreAssemblyPath)),
        ('/reference:' + (ConvertTo-NgcbQuotedArgument $automationAssemblyPath)),
        ('/reference:' + (ConvertTo-NgcbQuotedArgument $serviceProcessAssemblyPath)),
        (ConvertTo-NgcbQuotedArgument $sourcePath)
    )
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $compilerPath
    $start.Arguments = $arguments -join ' '
    $start.WorkingDirectory = $buildRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    if (-not $process.Start()) { Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-COMPILER-FAILED' }
    $standardOutput = $process.StandardOutput.ReadToEndAsync()
    $standardError = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(60000)) {
        try { $process.Kill() } catch { }
        Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-COMPILER-TIMEOUT'
    }
    $null = $standardOutput.Result
    $null = $standardError.Result
    if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $temporaryExecutable -PathType Leaf)) {
        Write-Verbose (($standardOutput.Result + [Environment]::NewLine + $standardError.Result).Trim())
        Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-COMPILER-FAILED'
    }
    Assert-NgcbNoReparsePath $temporaryExecutable 'NGCOR-SERVICE-HOST-BUILD-REPARSE-FORBIDDEN'
    $item = Get-Item -LiteralPath $temporaryExecutable -Force
    if ($item.Length -le 0 -or $item.Length -gt 1048576) {
        Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-OUTPUT-INVALID'
    }
    $header = [System.IO.File]::ReadAllBytes($temporaryExecutable)
    if ($header.Length -lt 2 -or $header[0] -ne 0x4d -or $header[1] -ne 0x5a) {
        Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-OUTPUT-INVALID'
    }
    $assemblyName = [System.Reflection.AssemblyName]::GetAssemblyName($temporaryExecutable)
    if ($assemblyName.Name -cne 'NorthGate.CreateOnly.ServiceHost' -or
        $assemblyName.Version.ToString() -cne '1.0.0.0') {
        Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-ASSEMBLY-IDENTITY-INVALID'
    }
    $unsignedSha256 = Get-NgcbFileSha256 $temporaryExecutable
    [System.IO.File]::Move($temporaryExecutable, $output)
    if ((Get-NgcbFileSha256 $output) -cne $unsignedSha256) {
        Stop-Ngcb 'NGCOR-SERVICE-HOST-BUILD-READBACK-FAILED'
    }
    $referenceRecords = [object[]]@(
        [pscustomobject][ordered]@{
            path = $mscorlibAssemblyPath; sha256 = $ExpectedMscorlibAssemblySha256
            fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($mscorlibAssemblyPath).FileVersion
        },
        [pscustomobject][ordered]@{
            path = $systemAssemblyPath; sha256 = $ExpectedSystemAssemblySha256
            fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($systemAssemblyPath).FileVersion
        },
        [pscustomobject][ordered]@{
            path = $systemCoreAssemblyPath; sha256 = $ExpectedSystemCoreAssemblySha256
            fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($systemCoreAssemblyPath).FileVersion
        },
        [pscustomobject][ordered]@{
            path = $automationAssemblyPath; sha256 = $ExpectedAutomationAssemblySha256
            fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($automationAssemblyPath).FileVersion
        },
        [pscustomobject][ordered]@{
            path = $serviceProcessAssemblyPath; sha256 = $ExpectedServiceProcessAssemblySha256
            fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($serviceProcessAssemblyPath).FileVersion
        }
    )
    $referenceRecords = [object[]]@($referenceRecords | Sort-Object -Property path)
    $buildScriptHash = Get-NgcbFileSha256 $executedBuilder
    $compilerVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($compilerPath).ProductVersion
    $provenanceRecord = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-service-host-build-provenance/v1'
        sourcePath = 'NorthGate.CreateOnly.ServiceHost.cs'
        sourceSha256 = $ExpectedSourceSha256
        buildScriptPath = 'Build-NorthGateCreateOnlyServiceHost.ps1'
        buildScriptSha256 = $buildScriptHash
        compilerPath = $compilerPath
        compilerSha256 = $ExpectedCompilerSha256
        compilerVersion = $compilerVersion
        deterministic = $true
        unsignedSha256 = $unsignedSha256
        references = $referenceRecords
    }
    $provenanceJson = ConvertTo-NgcbCanonicalJson $provenanceRecord
    [IO.File]::WriteAllText($temporaryProvenance, $provenanceJson, (New-Object Text.UTF8Encoding($false)))
    [IO.File]::Move($temporaryProvenance, $provenance)
    $provenanceHash = Get-NgcbFileSha256 $provenance
    [pscustomobject][ordered]@{
        status = 'built-unsigned-service-host'
        outputPath = $output
        outputSha256 = $unsignedSha256
        provenancePath = $provenance
        provenanceSha256 = $provenanceHash
        sourceSha256 = $ExpectedSourceSha256
        compilerSha256 = $ExpectedCompilerSha256
        compilerProductVersion = $compilerVersion
        mscorlibAssemblySha256 = $ExpectedMscorlibAssemblySha256
        systemAssemblySha256 = $ExpectedSystemAssemblySha256
        systemCoreAssemblySha256 = $ExpectedSystemCoreAssemblySha256
        automationAssemblySha256 = $ExpectedAutomationAssemblySha256
        serviceProcessAssemblySha256 = $ExpectedServiceProcessAssemblySha256
        signingRequired = $true
    }
}
finally {
    if ($null -ne $process) { $process.Dispose() }
    if (Test-Path -LiteralPath $temporaryExecutable -PathType Leaf) {
        [System.IO.File]::Delete($temporaryExecutable)
    }
    if (Test-Path -LiteralPath $temporaryProvenance -PathType Leaf) {
        [System.IO.File]::Delete($temporaryProvenance)
    }
    if ((Test-Path -LiteralPath $buildRoot -PathType Container) -and
        @([System.IO.Directory]::EnumerateFileSystemEntries($buildRoot)).Count -eq 0) {
        [System.IO.Directory]::Delete($buildRoot, $false)
    }
}
