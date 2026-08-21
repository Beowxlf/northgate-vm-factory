[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ServiceHostAssertions = 0

function Assert-NgchTest {
    param([bool]$Condition, [string]$Message)
    $script:ServiceHostAssertions++
    if (-not $Condition) { throw "SERVICE HOST ASSERTION FAILED: $Message" }
}

function Assert-NgchThrows {
    param([scriptblock]$Action, [string]$Pattern, [string]$Message)
    $script:ServiceHostAssertions++
    try { & $Action; throw "SERVICE HOST ASSERTION FAILED: $Message (no exception)" }
    catch {
        if ($_.Exception.Message -like 'SERVICE HOST ASSERTION FAILED:*') { throw }
        if ($_.Exception.Message -cnotmatch $Pattern) {
            throw "SERVICE HOST ASSERTION FAILED: $Message (got $($_.Exception.Message))"
        }
    }
}

function Get-NgchSha256 {
    param([string]$Path)
    $stream = New-Object System.IO.FileStream(
        $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read, 65536, [System.IO.FileOptions]::SequentialScan
    )
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($stream) }
    finally { $algorithm.Dispose(); $stream.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

$root = $PSScriptRoot
$sourcePath = Join-Path $root 'NorthGate.CreateOnly.ServiceHost.cs'
$builderPath = Join-Path $root 'Build-NorthGateCreateOnlyServiceHost.ps1'
$serviceScriptPath = Join-Path $root 'Start-NorthGateCreateOnlyPipeService.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ('ngcor-service-host-test-' + [guid]::NewGuid().ToString('N'))

try {
    $source = [System.IO.File]::ReadAllText($sourcePath)
    $builder = [System.IO.File]::ReadAllText($builderPath)
    $serviceScript = [System.IO.File]::ReadAllText($serviceScriptPath)
    Assert-NgchTest ($source -match 'ServiceBase\.Run' -and $source -match 'RunspaceFactory\.CreateRunspace') `
        'Native host runs as a Windows service and hosts Windows PowerShell in-process.'
    Assert-NgchTest ($source -match 'Start-NorthGateCreateOnlyPipeService\.ps1' -and
        $source -match 'StringComparison\.OrdinalIgnoreCase') `
        'Native host accepts only its adjacent fixed service script.'
    Assert-NgchTest ($source -match 'NorthGateServiceStopEvent' -and
        $source -match 'ManualResetEvent' -and $source -match 'Join\(15000\)') `
        'Native host has bounded cooperative stop handling.'
    Assert-NgchTest ($source -cnotmatch 'Process\.Start|powershell\.exe|cmd\.exe|CreateProcess|ShellExecute') `
        'Native host does not launch a shell or child process.'
    Assert-NgchTest ($source -match 'GetSafeFailureCode' -and
        $source -match 'NGCOR-\[A-Z0-9-\]' -and $source -match 'exception\.GetType\(\)\.FullName') `
        'Native host reports only bounded NorthGate codes or exception types when the engine fails.'
    Assert-NgchTest ($builder -cnotmatch 'Invoke-Expression|DownloadString|WebClient|Start-Process') `
        'Build helper has no dynamic evaluation or network primitive.'
    Assert-NgchTest ($builder -match '/deterministic\+' -and $builder -match '/warnaserror\+' -and
        $builder -match 'ExpectedCompilerSha256') `
        'Build helper requests deterministic warnings-as-errors output from an exact-hash-pinned compiler.'
    Assert-NgchTest ($serviceScript -match 'NorthGateServiceStopEvent') `
        'Service loop is bound to the native host stop event.'
    Assert-NgchTest ($serviceScript -match 'NGCOR-INSTALLED-POLICY-DISABLED' -and
        $serviceScript -match "status = 'installed-disabled'" -and
        $serviceScript -match 'applyEnabled = \$false') `
        'A running diagnostic service exposes disabled status but rejects every non-status operation.'
    Assert-NgchTest ($serviceScript -match `
        '\$expectedStartMode = if \(\[bool\]\$policy\.applyEnabled\) \{ ''Auto'' \} else \{ ''Manual'' \}' -and
        $serviceScript -match '\$service\.StartMode -cne \$expectedStartMode') `
        'Disabled diagnostic execution requires an explicit temporary Manual service posture.'

    $null = [System.IO.Directory]::CreateDirectory($testRoot)
    $firstRoot = Join-Path $testRoot 'first'
    $secondRoot = Join-Path $testRoot 'second'
    $null = [System.IO.Directory]::CreateDirectory($firstRoot)
    $null = [System.IO.Directory]::CreateDirectory($secondRoot)
    $firstOutput = Join-Path $firstRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $secondOutput = Join-Path $secondRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $firstProvenance = Join-Path $firstRoot 'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
    $secondProvenance = Join-Path $secondRoot 'NorthGate.CreateOnly.ServiceHost.build-provenance.json'

    try { Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop }
    catch { throw 'SERVICE HOST ASSERTION FAILED: System.ServiceProcess is unavailable.' }
    $programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $compilerPath = @(
        (Join-Path $programFilesX86 'Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe'),
        (Join-Path $programFilesX86 'Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe'),
        (Join-Path $programFiles 'Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\Roslyn\csc.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($compilerPath)) {
        throw 'SERVICE HOST ASSERTION FAILED: approved Roslyn compiler is unavailable.'
    }
    $automationAssemblyPath = [System.Management.Automation.PowerShell].Assembly.Location
    $mscorlibAssemblyPath = [object].Assembly.Location
    $systemAssemblyPath = [System.ComponentModel.Component].Assembly.Location
    $systemCoreAssemblyPath = [System.Linq.Enumerable].Assembly.Location
    $serviceProcessAssemblyPath = [System.ServiceProcess.ServiceBase].Assembly.Location
    $sourceHash = Get-NgchSha256 $sourcePath
    $compilerHash = Get-NgchSha256 $compilerPath
    $mscorlibHash = Get-NgchSha256 $mscorlibAssemblyPath
    $systemHash = Get-NgchSha256 $systemAssemblyPath
    $systemCoreHash = Get-NgchSha256 $systemCoreAssemblyPath
    $automationHash = Get-NgchSha256 $automationAssemblyPath
    $serviceProcessHash = Get-NgchSha256 $serviceProcessAssemblyPath

    $first = & $builderPath -OutputPath $firstOutput -ProvenancePath $firstProvenance `
        -CompilerPath $compilerPath `
        -ExpectedSourceSha256 $sourceHash -ExpectedMscorlibAssemblySha256 $mscorlibHash `
        -ExpectedSystemAssemblySha256 $systemHash -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
        -ExpectedCompilerSha256 $compilerHash -ExpectedAutomationAssemblySha256 $automationHash `
        -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    $second = & $builderPath -OutputPath $secondOutput -ProvenancePath $secondProvenance `
        -CompilerPath $compilerPath `
        -ExpectedSourceSha256 $sourceHash -ExpectedMscorlibAssemblySha256 $mscorlibHash `
        -ExpectedSystemAssemblySha256 $systemHash -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
        -ExpectedCompilerSha256 $compilerHash -ExpectedAutomationAssemblySha256 $automationHash `
        -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    Assert-NgchTest ($first.status -ceq 'built-unsigned-service-host' -and $first.signingRequired -eq $true -and
        $second.status -ceq 'built-unsigned-service-host') 'Build outputs are explicitly unsigned promotion inputs.'
    Assert-NgchTest ((Test-Path -LiteralPath $firstOutput -PathType Leaf) -and
        (Test-Path -LiteralPath $secondOutput -PathType Leaf) -and
        (Test-Path -LiteralPath $firstProvenance -PathType Leaf) -and
        (Test-Path -LiteralPath $secondProvenance -PathType Leaf)) `
        'Build helper emits the fixed service host and canonical provenance record.'
    Assert-NgchTest ($first.outputSha256 -ceq $second.outputSha256 -and
        (Get-NgchSha256 $firstOutput) -ceq (Get-NgchSha256 $secondOutput)) `
        'Two clean builds produce identical service-host bytes.'
    $assembly = [System.Reflection.AssemblyName]::GetAssemblyName($firstOutput)
    Assert-NgchTest ($assembly.Name -ceq 'NorthGate.CreateOnly.ServiceHost' -and
        $assembly.Version.ToString() -ceq '1.0.0.0') 'Built service host has the fixed assembly identity.'
    Assert-NgchTest ($first.signingRequired -eq $true) `
        'Build stage declares detached CMS promotion still required.'
    $firstProvenanceText = [IO.File]::ReadAllText($firstProvenance)
    $firstProvenanceObject = ConvertFrom-Json $firstProvenanceText
    Assert-NgchTest ($firstProvenanceObject.schema -ceq
        'northgate/create-only-service-host-build-provenance/v1' -and
        $firstProvenanceObject.deterministic -eq $true -and
        $firstProvenanceObject.unsignedSha256 -ceq $first.outputSha256 -and
        @($firstProvenanceObject.references).Count -eq 5) `
        'Provenance binds the deterministic unsigned output and all five references.'

    $badOutputRoot = Join-Path $testRoot 'bad-hash'
    $null = [System.IO.Directory]::CreateDirectory($badOutputRoot)
    $badOutput = Join-Path $badOutputRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $badProvenance = Join-Path $badOutputRoot 'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
    Assert-NgchThrows {
        & $builderPath -OutputPath $badOutput -ProvenancePath $badProvenance -CompilerPath $compilerPath `
            -ExpectedSourceSha256 $sourceHash -ExpectedMscorlibAssemblySha256 $mscorlibHash `
            -ExpectedSystemAssemblySha256 $systemHash -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
            -ExpectedCompilerSha256 ('0' * 64) -ExpectedAutomationAssemblySha256 $automationHash `
            -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    } '^NGCOR-SERVICE-HOST-BUILD-COMPILER-HASH-MISMATCH$' `
        'Build refuses an unapproved compiler hash.'
    Assert-NgchTest (-not (Test-Path -LiteralPath $badOutput) -and
        -not (Test-Path -LiteralPath $badProvenance)) `
        'Rejected toolchain provenance creates no executable.'

    $unapprovedCompiler = Join-Path $testRoot 'unapproved-csc.exe'
    [System.IO.File]::Copy($compilerPath,$unapprovedCompiler,$false)
    $unapprovedRoot = Join-Path $testRoot 'unapproved-compiler'
    $null = [System.IO.Directory]::CreateDirectory($unapprovedRoot)
    $unapprovedOutput = Join-Path $unapprovedRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $unapprovedProvenance = Join-Path $unapprovedRoot `
        'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
    Assert-NgchThrows {
        & $builderPath -OutputPath $unapprovedOutput -ProvenancePath $unapprovedProvenance `
            -CompilerPath $unapprovedCompiler `
            -ExpectedSourceSha256 $sourceHash -ExpectedMscorlibAssemblySha256 $mscorlibHash `
            -ExpectedSystemAssemblySha256 $systemHash -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
            -ExpectedCompilerSha256 $compilerHash -ExpectedAutomationAssemblySha256 $automationHash `
            -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    } '^NGCOR-SERVICE-HOST-BUILD-COMPILER-INVALID$' `
        'Build refuses an exact-copy compiler outside the fixed vendor path allowlist.'
    Assert-NgchTest (-not (Test-Path -LiteralPath $unapprovedOutput) -and
        -not (Test-Path -LiteralPath $unapprovedProvenance)) `
        'Unapproved compiler path rejection writes nothing.'

    $repositoryOutput = Join-Path $root 'NorthGate.CreateOnly.ServiceHost.exe'
    $repositoryProvenance = Join-Path $root 'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
    Assert-NgchThrows {
        & $builderPath -OutputPath $repositoryOutput -ProvenancePath $repositoryProvenance `
            -CompilerPath $compilerPath `
            -ExpectedSourceSha256 $sourceHash -ExpectedMscorlibAssemblySha256 $mscorlibHash `
            -ExpectedSystemAssemblySha256 $systemHash -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
            -ExpectedCompilerSha256 $compilerHash -ExpectedAutomationAssemblySha256 $automationHash `
            -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    } '^NGCOR-SERVICE-HOST-BUILD-OUTPUT-IN-REPOSITORY$' `
        'Build refuses to place generated binaries in the Git worktree.'
    Assert-NgchTest (-not (Test-Path -LiteralPath $repositoryOutput) -and
        -not (Test-Path -LiteralPath $repositoryProvenance)) `
        'Repository-output rejection writes nothing.'

    Write-Output "PASS: $script:ServiceHostAssertions service-host assertions"
}
finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
