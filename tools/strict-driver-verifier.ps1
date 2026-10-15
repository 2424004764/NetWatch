[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Configure', 'Query', 'Reset', 'Collect')][string]$Action,
    [string]$DriverName = 'NetWatchStrict.sys',
    [string]$OutputDirectory,
    [switch]$ArmVerifier,
    [switch]$ConfirmReset,
    [switch]$CopyMemoryDump
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'StrictGate.Common.psm1') -Force
Assert-StrictGateWindows
$verifier = Join-Path $env:windir 'System32\verifier.exe'
$verifier = Resolve-StrictGatePath -Path $verifier -Description 'Windows Driver Verifier'
$runRoot = New-StrictGateRunDirectory -Root $OutputDirectory
$logRoot = Join-Path $runRoot 'logs'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$isAdmin = Test-StrictGateAdministrator
if ($Action -in @('Configure', 'Reset') -and -not $isAdmin) { throw "$Action requires an elevated PowerShell session." }
if ($Action -eq 'Configure' -and -not $ArmVerifier) { throw 'Configure can cause a bugcheck. Re-run with -ArmVerifier only on a dedicated test system.' }
if ($Action -eq 'Reset' -and -not $ConfirmReset) { throw 'Reset changes system Driver Verifier policy. Re-run with -ConfirmReset to proceed.' }
if ($Action -eq 'Configure' -and $DriverName -notmatch '^[A-Za-z0-9_.-]+\.sys$') { throw 'DriverName must be one explicit .sys base name.' }

$verifierOutput = @()
$rebootRequired = $false
$eventError = $null
$ciEventError = $null
switch ($Action) {
    'Configure' {
        $result = Invoke-StrictGateNative -FilePath $verifier -Arguments @('/standard', '/driver', $DriverName) -LogPath (Join-Path $logRoot 'verifier-configure.log') -AllowNonZero
        $verifierOutput = @($result.output)
        if ($result.exitCode -notin @(0, 2)) { throw "verifier configure failed with exit code $($result.exitCode). See $($result.logPath)" }
        $rebootRequired = $result.exitCode -eq 2
    }
    'Query' {
        $queries = @(
            [pscustomobject]@{ Arguments = @('/querysettings'); LogName = 'verifier-querysettings.log' },
            [pscustomobject]@{ Arguments = @('/query'); LogName = 'verifier-query.log' }
        )
        foreach ($query in $queries) {
            $result = Invoke-StrictGateNative -FilePath $verifier -Arguments $query.Arguments -LogPath (Join-Path $logRoot $query.LogName) -AllowNonZero
            if ($result.exitCode -ne 0) { throw "verifier $($query.Arguments -join ' ') failed with exit code $($result.exitCode). See $($result.logPath)" }
            $verifierOutput += $result.output
        }
    }
    'Reset' {
        $result = Invoke-StrictGateNative -FilePath $verifier -Arguments @('/reset') -LogPath (Join-Path $logRoot 'verifier-reset.log') -AllowNonZero
        $verifierOutput = @($result.output)
        if ($result.exitCode -notin @(0, 2)) { throw "verifier reset failed with exit code $($result.exitCode). See $($result.logPath)" }
        $rebootRequired = $true
    }
    'Collect' {
        $queries = @(
            [pscustomobject]@{ Arguments = @('/querysettings'); LogName = 'verifier-querysettings.log' },
            [pscustomobject]@{ Arguments = @('/query'); LogName = 'verifier-query.log' }
        )
        foreach ($query in $queries) {
            $result = Invoke-StrictGateNative -FilePath $verifier -Arguments $query.Arguments -LogPath (Join-Path $logRoot $query.LogName) -AllowNonZero
            if ($result.exitCode -ne 0) { throw "verifier $($query.Arguments -join ' ') failed with exit code $($result.exitCode). See $($result.logPath)" }
            $verifierOutput += $result.output
        }
    }
}

$events = @()
try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 100 | ForEach-Object {
        [ordered]@{ id = $_.Id; timeCreatedUtc = $_.TimeCreated.ToUniversalTime().ToString('o'); message = $_.Message }
    })
} catch { $eventError = $_.Exception.Message }
try {
    $ciEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 250 | ForEach-Object {
        [ordered]@{ id = $_.Id; level = $_.LevelDisplayName; timeCreatedUtc = $_.TimeCreated.ToUniversalTime().ToString('o'); message = $_.Message }
    })
} catch { $ciEventError = $_.Exception.Message }
$dumpFiles = @()
$dumpDirectory = Join-Path $env:windir 'Minidump'
if (Test-Path -LiteralPath $dumpDirectory -PathType Container) {
    foreach ($dump in Get-ChildItem -LiteralPath $dumpDirectory -Filter '*.dmp' -File | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 50) {
        $destination = Join-Path (Join-Path $runRoot 'dumps') $dump.Name
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $dump.FullName -Destination $destination
        $dumpFiles += [ordered]@{ source = $dump.FullName; collected = $destination; length = $dump.Length; lastWriteTimeUtc = $dump.LastWriteTimeUtc.ToString('o') }
    }
}
$memoryDumpPath = Join-Path $env:windir 'MEMORY.DMP'
if ($CopyMemoryDump -and (Test-Path -LiteralPath $memoryDumpPath -PathType Leaf)) {
    $destination = Join-Path $runRoot 'dumps\MEMORY.DMP'
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    Copy-Item -LiteralPath $memoryDumpPath -Destination $destination
    $dumpFiles += [ordered]@{ source = $memoryDumpPath; collected = $destination; length = (Get-Item $destination).Length; lastWriteTimeUtc = (Get-Item $destination).LastWriteTimeUtc.ToString('o') }
}

$policyText = ($verifierOutput -join [Environment]::NewLine)
$policyActive = $policyText -match '(?i)NetWatchStrict\.sys|verified drivers|standard settings|已启用|enabled'
$policyEmpty = $policyText -match '(?i)no settings|not running|未运行|没有设置|disabled'
$verificationIssues = @()
if ($Action -in @('Query', 'Collect') -and -not ($policyActive -or $policyEmpty)) { $verificationIssues += 'Verifier query output did not identify an enabled or empty policy state.' }
if ($Action -eq 'Configure' -and -not $policyActive) { $verificationIssues += 'Verifier configure output did not confirm the target driver policy.' }
if ($Action -eq 'Reset' -and -not $policyEmpty) { $verificationIssues += 'Verifier reset output did not confirm an empty/disabled policy.' }
if ($eventError) { $verificationIssues += 'System bugcheck event log could not be read.' }
if ($ciEventError) { $verificationIssues += 'Code Integrity event log could not be read.' }
$blockingCi = @($ciEvents | Where-Object { $_.level -in @('Error', 'Critical') -or $_.message -match '(?i)blocked|拒绝|failed|failure|not trusted|不受信任|signature' })
if ($blockingCi.Count -gt 0) { $verificationIssues += "Code Integrity contains $($blockingCi.Count) blocking/error event(s)." }
if ($events.Count -gt 0) { $verificationIssues += "System contains $($events.Count) bugcheck event(s)." }
$reportStatus = if ($verificationIssues.Count -eq 0) { 'passed' } else { 'notCovered' }
$report = [ordered]@{
    schemaVersion = 1
    gate = 'strict-driver-verifier'
    action = $Action
    status = $reportStatus
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    driver = $DriverName
    rebootRequired = $rebootRequired
    verifierOutput = $verifierOutput
    policyConfirmed = if ($Action -eq 'Configure') { $policyActive } elseif ($Action -eq 'Reset') { $policyEmpty } else { $null }
    verificationIssues = $verificationIssues
    bugcheckEvents = $events
    bugcheckEventReadError = $eventError
    codeIntegrityEvents = $ciEvents
    codeIntegrityEventReadError = $ciEventError
    collectedDumps = $dumpFiles
    securityFeaturesChanged = $false
    verifierPolicyChanged = ($Action -in @('Configure', 'Reset'))
}
$jsonPath = Join-Path $runRoot 'verifier-gate.json'
$textPath = Join-Path $runRoot 'verifier-gate.txt'
$text = @("Gate: strict-driver-verifier ($Action)", "Status: $reportStatus", "Driver: $DriverName", "Reboot required: $rebootRequired", "Collected dumps: $($dumpFiles.Count)", "Logs: $logRoot", "Report: $jsonPath")
if ($verificationIssues.Count -gt 0) { $text += 'Not covered:'; $text += $verificationIssues }
Write-StrictGateReport -Report $report -JsonPath $jsonPath -TextPath $textPath -TextLines $text
if ($reportStatus -ne 'passed') { exit 2 }