[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$KitRoot = (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'),
    [string]$WdkVersion = '10.0.26100.0',
    [string]$MSBuildPath,
    [string]$InfVerifPath,
    [string]$Inf2CatPath,
    [string]$ApiValidatorPath,
    [string]$UniversalDdisPath,
    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\driver\artifacts\build'),
    [string[]]$Inf2CatOs = @('10_VB_X64', '10_NI_X64', '10_GE_X64')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'StrictGate.Common.psm1') -Force
Assert-StrictGateWindows

function Add-DiscoveredToolCandidates {
    param([AllowEmptyCollection()][string[]]$Candidates, [string]$ToolName)
    $discovered = @(Get-ChildItem -LiteralPath $KitRoot -Filter $ToolName -File -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -ExpandProperty FullName)
    return @($Candidates + $discovered)
}

$repoRoot = Resolve-StrictGatePath -Path (Join-Path $PSScriptRoot '..') -Description 'Repository root' -PathType Container
$driverRoot = Join-Path $repoRoot 'driver'
$projectPath = Resolve-StrictGatePath -Path (Join-Path $driverRoot 'NetWatch.StrictCallout.vcxproj') -Description 'Driver project'
$infPath = Resolve-StrictGatePath -Path (Join-Path $driverRoot 'NetWatchStrict.inf') -Description 'Driver INF'
$policyPath = Resolve-StrictGatePath -Path (Join-Path $driverRoot 'package-manifest.json') -Description 'Package manifest'
$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
if (-not (Test-StrictGateAdministrator)) { throw 'The WDK build and package validation gate requires an elevated PowerShell session because Inf2Cat may require administrator rights.' }
if ($policy.architecture -ne 'amd64' -or $policy.inf -ne 'NetWatchStrict.inf' -or $policy.sys -ne 'NetWatchStrict.sys' -or $policy.catalog -ne 'NetWatchStrict.cat') {
    throw 'package-manifest.json must describe the amd64 NetWatchStrict INF/SYS/CAT package.'
}

$msbuildCandidates = @()
$vswherePath = Join-Path ${env:ProgramFiles} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path -LiteralPath $vswherePath -PathType Leaf) {
    $vsRoots = @(& $vswherePath -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath 2>$null)
    if ($LASTEXITCODE -eq 0) {
        foreach ($vsRoot in $vsRoots) {
            if ($vsRoot) { $msbuildCandidates += Join-Path ([string]$vsRoot) 'MSBuild\Current\Bin\MSBuild.exe' }
        }
    }
}
$msbuildCommand = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
if ($msbuildCommand) { $msbuildCandidates += $msbuildCommand.Source }
$msbuildCandidates += @(
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe')
)
$msbuild = Find-StrictGateTool -ExplicitPath $MSBuildPath -Candidates $msbuildCandidates -Name 'MSBuild.exe'
if (-not (Test-Path -LiteralPath $KitRoot -PathType Container)) { throw "Windows Kits root not found: $KitRoot" }
$kitBin = Join-Path $KitRoot ("bin\{0}" -f $WdkVersion)
$toolCandidates = @((Join-Path $kitBin 'x64'), (Join-Path $kitBin 'x86'), (Join-Path $KitRoot ("Tools\{0}\x64" -f $WdkVersion)), (Join-Path $KitRoot ("Tools\{0}\x86" -f $WdkVersion)), (Join-Path $KitRoot ("Tools\{0}\arm64" -f $WdkVersion)))
$infVerifCandidates = Add-DiscoveredToolCandidates -Candidates @($toolCandidates | ForEach-Object { Join-Path $_ 'InfVerif.exe' }) -ToolName 'InfVerif.exe'
$inf2CatCandidates = Add-DiscoveredToolCandidates -Candidates @($toolCandidates | ForEach-Object { Join-Path $_ 'Inf2Cat.exe' }) -ToolName 'Inf2Cat.exe'
$apiValidatorCandidates = Add-DiscoveredToolCandidates -Candidates @($toolCandidates | ForEach-Object { Join-Path $_ 'ApiValidator.exe' }) -ToolName 'ApiValidator.exe'
$infVerif = Find-StrictGateTool -ExplicitPath $InfVerifPath -Candidates $infVerifCandidates -Name 'InfVerif.exe'
$inf2Cat = Find-StrictGateTool -ExplicitPath $Inf2CatPath -Candidates $inf2CatCandidates -Name 'Inf2Cat.exe'
$apiValidator = Find-StrictGateTool -ExplicitPath $ApiValidatorPath -Candidates $apiValidatorCandidates -Name 'ApiValidator.exe'
$apiListCandidates = @(
    (Join-Path $KitRoot ("build\{0}\universalDDIs\x64\UniversalDDIs.xml" -f $WdkVersion)),
    (Join-Path $KitRoot ("build\{0}\universalDDIs\amd64\UniversalDDIs.xml" -f $WdkVersion)),
    (Join-Path $KitRoot 'build\universalDDIs\x64\UniversalDDIs.xml')
)
$apiListCandidates = @($apiListCandidates + @(Get-ChildItem -LiteralPath $KitRoot -Filter 'UniversalDDIs.xml' -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '(?i)universalDDIs.*(x64|amd64)' } | Select-Object -ExpandProperty FullName))
$apiXml = Find-StrictGateTool -ExplicitPath $UniversalDdisPath -Candidates $apiListCandidates -Name 'ApiValidator UniversalDDIs.xml'

$runRoot = New-StrictGateRunDirectory -Root $OutputRoot
$binRoot = Join-Path $runRoot 'bin'
$objRoot = Join-Path $runRoot 'obj'
$packageRoot = Join-Path $runRoot 'package'
$logRoot = Join-Path $runRoot 'logs'
foreach ($directory in @($binRoot, $objRoot, $packageRoot, $logRoot)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
$status = 'failed'
try {
    $msbuildArgs = @(
        $projectPath, '/t:Rebuild', '/m', '/nologo', '/verbosity:minimal',
        "/p:Configuration=$Configuration", '/p:Platform=x64', "/p:WindowsTargetPlatformVersion=$WdkVersion",
        '/p:SignMode=Off', '/p:EnableTestSign=false', '/p:TreatWarningAsError=true',
        '/p:NetWatchGateRunVerifiers=true', '/p:NetWatchGateRequireMicrosoftSignature=true',
        "/p:OutDir=$binRoot\", "/p:IntDir=$objRoot\"
    )
    Invoke-StrictGateNative -FilePath $msbuild -Arguments $msbuildArgs -LogPath (Join-Path $logRoot 'msbuild.log') -WorkingDirectory $driverRoot | Out-Null
    $builtSys = Get-ChildItem -LiteralPath $binRoot -Filter 'NetWatchStrict.sys' -File -Recurse | Select-Object -First 1
    if (-not $builtSys) { throw "MSBuild succeeded but NetWatchStrict.sys was not produced under $binRoot" }
    Copy-Item -LiteralPath $infPath -Destination (Join-Path $packageRoot $policy.inf)
    Copy-Item -LiteralPath $builtSys.FullName -Destination (Join-Path $packageRoot $policy.sys)
    $sysPath = Join-Path $packageRoot $policy.sys

    Invoke-StrictGateNative -FilePath $infVerif -Arguments @('/w', '/v', '/wbuild', [string]$policy.minimumWindowsBuild, (Join-Path $packageRoot $policy.inf)) -LogPath (Join-Path $logRoot 'infverif.log') -WorkingDirectory $packageRoot | Out-Null
    $apiValidatorArguments = [string[]]@(
        ('-DriverPackagePath:' + $packageRoot),
        ('-SupportedApiXmlFiles:' + $apiXml)
    )
    Invoke-StrictGateNative -FilePath $apiValidator -Arguments $apiValidatorArguments -LogPath (Join-Path $logRoot 'apivalidator.log') -WorkingDirectory (Split-Path -Parent $apiValidator) | Out-Null
    $inf2CatArguments = [string[]]@(
        ('/driver:' + $packageRoot),
        ('/os:' + ($Inf2CatOs -join ',')),
        '/verbose'
    )
    Invoke-StrictGateNative -FilePath $inf2Cat -Arguments $inf2CatArguments -LogPath (Join-Path $logRoot 'inf2cat.log') -WorkingDirectory $packageRoot | Out-Null
    $catPath = Join-Path $packageRoot $policy.catalog
    if (-not (Test-Path -LiteralPath $catPath -PathType Leaf)) { throw "Inf2Cat completed without producing $catPath" }

    $sourceRecords = @()
    $sourceFiles = @($projectPath, $infPath, $policyPath) + @(Get-ChildItem -Path (Join-Path $driverRoot 'src') -File -Recurse -Include '*.c', '*.h' | Select-Object -ExpandProperty FullName)
    foreach ($source in $sourceFiles) {
        $relative = $source.Substring($repoRoot.Length).TrimStart('\', '/') -replace '\\', '/'
        $sourceRecords += Get-StrictGateFileRecord -Path $source -Name $relative
    }
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    $revision = $null
    $dirty = $null
    if ($git) {
        $revisionLines = @(& $git.Source -C $repoRoot rev-parse --verify HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $revisionLines.Count -gt 0) { $revision = [string]$revisionLines[0] }
        $statusLines = @(& $git.Source -C $repoRoot status --porcelain --untracked-files=no 2>$null)
        if ($LASTEXITCODE -eq 0) { $dirty = ($statusLines.Count -gt 0) }
    }
    $manifest = [ordered]@{
        schemaVersion = 1
        gate = 'strict-driver-build'
        status = 'passed'
        buildMode = 'UnsignedDev'
        generatedUtc = [DateTime]::UtcNow.ToString('o')
        sourceRevision = $revision
        trackedSourceDirty = $dirty
        configuration = $Configuration
        platform = 'x64'
        targetSdk = $WdkVersion
        kmdfVersion = [string]$policy.kmdfVersion
        inf2CatOs = @($Inf2CatOs)
        sourceFiles = $sourceRecords
        package = [ordered]@{
            architecture = $policy.architecture
            supportedWindows = @($policy.supportedWindows)
            files = @(
                (Get-StrictGateFileRecord -Path (Join-Path $packageRoot $policy.inf) -Name $policy.inf),
                (Get-StrictGateFileRecord -Path $sysPath -Name $policy.sys),
                (Get-StrictGateFileRecord -Path $catPath -Name $policy.catalog)
            )
        }
        tools = [ordered]@{ msbuild = $msbuild; infVerif = $infVerif; inf2Cat = $inf2Cat; apiValidator = $apiValidator; universalDdis = $apiXml }
        logDirectory = $logRoot
    }
    $manifestPath = Join-Path $runRoot 'strict-driver-build-manifest.json'
    $manifest | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $status = 'passed'
    $summary = [pscustomobject]@{ gate = 'strict-driver-build'; status = $status; buildMode = 'UnsignedDev'; packageDirectory = $packageRoot; manifest = $manifestPath; logs = $logRoot; signedRelease = $false }
    Write-StrictGateReport -Report $summary -JsonPath (Join-Path $runRoot 'build-gate.json') -TextPath (Join-Path $runRoot 'build-gate.txt') -TextLines @('Gate: strict-driver-build', "Status: $status", 'Build mode: UnsignedDev (not installable for production)', "Package: $packageRoot", "Manifest: $manifestPath", "Logs: $logRoot")
} catch {
    $failure = [pscustomobject]@{ gate = 'strict-driver-build'; status = 'failed'; error = $_.Exception.Message; packageDirectory = $packageRoot; logs = $logRoot }
    Write-StrictGateReport -Report $failure -JsonPath (Join-Path $runRoot 'build-gate.json') -TextPath (Join-Path $runRoot 'build-gate.txt') -TextLines @('Gate: strict-driver-build', 'Status: failed', "Error: $($_.Exception.Message)", "Logs: $logRoot")
    throw
}
