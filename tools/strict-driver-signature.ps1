[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageDirectory,
    [string]$ManifestPath,
    [string]$OutputDirectory,
    [string]$SigntoolPath,
    [switch]$RequireTimestamp
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'StrictGate.Common.psm1') -Force
Assert-StrictGateWindows

$package = Resolve-StrictGatePath -Path $PackageDirectory -Description 'Driver package directory' -PathType Container
if ($ManifestPath) {
    $manifestFile = Resolve-StrictGatePath -Path $ManifestPath -Description 'Build manifest'
} else {
    $manifestCandidates = @(
        (Join-Path (Split-Path -Parent $package) 'strict-driver-build-manifest.json'),
        (Join-Path $package 'strict-driver-build-manifest.json')
    )
    $manifestCandidate = $manifestCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $manifestCandidate) {
        throw "A build manifest is required; checked the package directory and its parent: $($manifestCandidates -join '; ')"
    }
    $manifestFile = Resolve-StrictGatePath -Path $manifestCandidate -Description 'Build manifest'
}
$manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1 -or $manifest.gate -ne 'strict-driver-build' -or $manifest.status -ne 'passed' -or $manifest.buildMode -ne 'UnsignedDev') {
    throw 'The supplied manifest is not a schema v1 passed build-strict-driver.ps1 UnsignedDev manifest.'
}
if ($manifest.package.architecture -ne 'amd64') {
    throw 'The build manifest is not an amd64 package.'
}
$inf = Resolve-StrictGatePath -Path (Join-Path $package 'NetWatchStrict.inf') -Description 'Package INF'
$sys = Resolve-StrictGatePath -Path (Join-Path $package 'NetWatchStrict.sys') -Description 'Package SYS'
$cat = Resolve-StrictGatePath -Path (Join-Path $package 'NetWatchStrict.cat') -Description 'Package CAT'
$packageFiles = @()
foreach ($file in @(
    [pscustomobject]@{ Name = 'NetWatchStrict.inf'; Path = $inf },
    [pscustomobject]@{ Name = 'NetWatchStrict.sys'; Path = $sys },
    [pscustomobject]@{ Name = 'NetWatchStrict.cat'; Path = $cat }
)) {
    $buildRecords = @($manifest.package.files | Where-Object { $_.path -ceq $file.Name })
    if ($buildRecords.Count -ne 1 -or [string]$buildRecords[0].sha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw "The build manifest must contain exactly one valid SHA-256 record for $($file.Name)."
    }
    $currentHash = (Get-FileHash -LiteralPath $file.Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $buildHash = ([string]$buildRecords[0].sha256).ToLowerInvariant()
    if ($file.Name -eq 'NetWatchStrict.inf' -and $currentHash -ne $buildHash) {
        throw 'NetWatchStrict.inf changed after the unsigned build; refusing to verify a different package source.'
    }
    $packageFiles += [pscustomobject][ordered]@{
        path = $file.Name
        buildSha256 = $buildHash
        observedSha256 = $currentHash
        hashMatchesBuild = $currentHash -eq $buildHash
        length = [int64](Get-Item -LiteralPath $file.Path).Length
    }
}

$kitVersion = [string]$manifest.targetSdk
$kitCandidates = @(
    (Join-Path ${env:ProgramFiles(x86)} ("Windows Kits\10\bin\{0}\x64\signtool.exe" -f $kitVersion)),
    (Join-Path ${env:ProgramFiles(x86)} ("Windows Kits\10\bin\{0}\x86\signtool.exe" -f $kitVersion)),
    (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\x64\signtool.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\x86\signtool.exe')
)
$kitCandidates += @(Get-ChildItem -LiteralPath (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin') -Filter 'signtool.exe' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
$signtool = Find-StrictGateTool -ExplicitPath $SigntoolPath -Candidates $kitCandidates -Name 'signtool.exe'
$runRoot = if ($OutputDirectory) { New-StrictGateRunDirectory -Root $OutputDirectory } else { New-StrictGateRunDirectory -Root (Join-Path $package 'gate-logs') }
$logRoot = Join-Path $runRoot 'logs'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null

function Get-SignatureRecord {
    param([string]$Path)
    $log = Join-Path $logRoot (([IO.Path]::GetFileName($Path)) + '.verify.log')
    $arguments = @('verify', '/kp', '/all', '/debug', $Path)
    $result = Invoke-StrictGateNative -FilePath $signtool -Arguments $arguments -LogPath $log -WorkingDirectory $package -AllowNonZero
    $text = ($result.output -join [Environment]::NewLine)
    $accepted = $result.exitCode -eq 0 -and $text -match '(?i)Successfully verified' -and $text -notmatch '(?i)test certificate|self[- ]signed|test[- ]signed|unknown error|no signature'
    $timestamp = $text -match '(?i)timestamp|signing time|countersignature'
    $microsoftSigner = $text -match '(?i)Microsoft (Windows|Corporation|Root|Code Signing)|Windows Hardware Compatibility Publisher|Microsoft Windows Hardware Compatibility Publisher'
    return [pscustomobject][ordered]@{
        path = [IO.Path]::GetFileName($Path)
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        signtoolExitCode = $result.exitCode
        kernelPolicyVerification = ($result.exitCode -eq 0)
        microsoftAcceptedSignerEvidence = $microsoftSigner
        timestampEvidence = $timestamp
        rejectedTestOrSelfSignature = ($text -match '(?i)test certificate|self[- ]signed|test[- ]signed')
        accepted = ($accepted -and (-not $RequireTimestamp -or $timestamp) -and $microsoftSigner)
        log = $log
    }
}

$records = @()
$status = 'failed'
try {
    foreach ($file in @($sys, $cat)) { $records += Get-SignatureRecord -Path $file }
    $failed = @($records | Where-Object { -not $_.accepted })
    if ($failed.Count -gt 0) {
        throw "Microsoft-accepted kernel signatures are required for every SYS/CAT; failed: $(($failed | ForEach-Object { $_.path }) -join ', ')"
    }
    $buildRecords = @($manifest.package.files)
    foreach ($record in $records) {
        $buildRecord = $buildRecords | Where-Object { $_.path -eq $record.path } | Select-Object -First 1
        if (-not $buildRecord) { throw "The build manifest does not contain an expected package file: $($record.path)" }
        $record | Add-Member -NotePropertyName buildSha256 -NotePropertyValue ([string]$buildRecord.sha256)
        $record | Add-Member -NotePropertyName signedPackageSha256 -NotePropertyValue $record.sha256
        $record | Add-Member -NotePropertyName buildHashMatches -NotePropertyValue ($record.path -eq 'NetWatchStrict.inf' -or ([string]$record.sha256).ToLowerInvariant() -eq ([string]$buildRecord.sha256).ToLowerInvariant())
    }
    $infBuild = @($manifest.package.files | Where-Object { $_.path -ceq 'NetWatchStrict.inf' }) | Select-Object -First 1
    $records += [pscustomobject][ordered]@{
        path = 'NetWatchStrict.inf'
        sha256 = (Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash.ToLowerInvariant()
        buildSha256 = [string]$infBuild.sha256
        signedPackageSha256 = (Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash.ToLowerInvariant()
        buildHashMatches = $true
        accepted = $true
        catalogBindingOnly = $true
    }
    $status = 'passed'
    $report = [ordered]@{ schemaVersion = 1; gate = 'strict-driver-signature'; status = $status; microsoftAcceptedRequired = $true; package = $package; files = $records; generatedUtc = [DateTime]::UtcNow.ToString('o'); sourceManifest = $manifestFile }
} catch {
    $report = [ordered]@{ schemaVersion = 1; gate = 'strict-driver-signature'; status = 'failed'; microsoftAcceptedRequired = $true; package = $package; files = $records; error = $_.Exception.Message; generatedUtc = [DateTime]::UtcNow.ToString('o'); sourceManifest = $manifestFile }
}
$reportPath = Join-Path $runRoot 'signature-gate.json'
$textPath = Join-Path $runRoot 'signature-gate.txt'
$report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $reportPath -Encoding UTF8
$hashManifestPath = Join-Path $runRoot 'signed-package-hashes.json'
([ordered]@{ schemaVersion = 1; gate = 'strict-driver-signature'; generatedUtc = [DateTime]::UtcNow.ToString('o'); package = $package; files = $records | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $_.signedPackageSha256; buildSha256 = $_.buildSha256 } } }) | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $hashManifestPath -Encoding UTF8
$textLines = @('Gate: strict-driver-signature', "Status: $($report.status)", 'Microsoft-accepted kernel signature required: true', 'Kernel policy verification: signtool verify /kp /all', "Package: $package", "Report: $reportPath", "Signed hash manifest: $hashManifestPath")
$textLines | Set-Content -LiteralPath $textPath -Encoding UTF8
Write-Output ($textLines -join [Environment]::NewLine)
Write-Output "JSON: $reportPath"
Write-Output "Text: $textPath"
if ($report.status -ne 'passed') { throw [string]$report.error }
