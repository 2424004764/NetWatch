[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$RequireSecureBoot,
    [switch]$RequireHvcI,
    [string]$DriverName = 'NetWatchStrict',
    [string]$ServiceName = 'NetWatchStrictService',
    [int]$CodeIntegrityEventCount = 100
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'StrictGate.Common.psm1') -Force
Assert-StrictGateWindows
$runRoot = New-StrictGateRunDirectory -Root $OutputDirectory

function Get-OptionalValue {
    param([scriptblock]$Action)
    try { return & $Action } catch { return $null }
}

$secureBoot = Get-OptionalValue { Confirm-SecureBootUEFI }
$deviceGuard = Get-OptionalValue { Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard | Select-Object -First 1 }
$hvcI = $null
$codeIntegrityReadError = $null
if ($deviceGuard) {
    $configured = @($deviceGuard.SecurityServicesConfigured)
    $running = @($deviceGuard.SecurityServicesRunning)
    $hvcI = [ordered]@{ configured = ($configured -contains 2); running = ($running -contains 2); configuredServices = $configured; runningServices = $running; virtualizationBasedSecurityStatus = $deviceGuard.VirtualizationBasedSecurityStatus }
}
$driver = Get-OptionalValue { Get-CimInstance Win32_SystemDriver -Filter "Name='$DriverName'" }
$service = Get-OptionalValue { Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" }
$deviceVisible = Test-Path -LiteralPath ('\\.\' + $DriverName)
$codeIntegrityEvents = @()
try {
    $codeIntegrityEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; StartTime = (Get-Date).AddDays(-7) } -MaxEvents $CodeIntegrityEventCount | ForEach-Object {
        [ordered]@{ id = $_.Id; level = $_.LevelDisplayName; timeCreatedUtc = $_.TimeCreated.ToUniversalTime().ToString('o'); provider = $_.ProviderName; message = $_.Message }
    })
} catch {
    $codeIntegrityReadError = $_.Exception.Message
}

$coverage = @()
if ($RequireSecureBoot -and $secureBoot -ne $true) { $coverage += 'Secure Boot is not confirmed enabled.' }
if ($RequireHvcI -and (-not $hvcI -or -not $hvcI.running)) { $coverage += 'HVCI/Memory Integrity is not confirmed running.' }
if (-not $deviceGuard) { $coverage += 'Device Guard status could not be read.' }
if (-not $driver -or $driver.State -ne 'Running') { $coverage += 'The target driver is not confirmed running.' }
if (-not $service -or $service.State -ne 'Running') { $coverage += 'The target control service is not confirmed running.' }
if (-not $deviceVisible) { $coverage += 'The target control device is not visible.' }
if ($codeIntegrityReadError) { $coverage += 'Code Integrity operational log could not be read.' }
$blockingCodeIntegrity = @($codeIntegrityEvents | Where-Object { $_.level -in @('Error', 'Critical') -or $_.message -match '(?i)blocked|拒绝|failed|failure|not trusted|不受信任|signature' })
if ($blockingCodeIntegrity.Count -gt 0) { $coverage += "Code Integrity contains $($blockingCodeIntegrity.Count) blocking/error event(s)." }
$report = [ordered]@{
    schemaVersion = 1
    gate = 'strict-platform-status'
    status = if ($coverage.Count -eq 0) { 'passed' } else { 'notCovered' }
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    secureBoot = $secureBoot
    hvcI = $hvcI
    driver = if ($driver) { [ordered]@{ name = $driver.Name; state = $driver.State; startMode = $driver.StartMode; pathName = $driver.PathName } } else { $null }
    service = if ($service) { [ordered]@{ name = $service.Name; state = $service.State; startMode = $service.StartMode; pathName = $service.PathName } } else { $null }
    controlDeviceVisible = $deviceVisible
    codeIntegrityEvents = $codeIntegrityEvents
    blockingCodeIntegrityEvents = $blockingCodeIntegrity
    codeIntegrityReadError = $codeIntegrityReadError
    notCovered = $coverage
}
$jsonPath = Join-Path $runRoot 'platform-status.json'
$textPath = Join-Path $runRoot 'platform-status.txt'
$text = @('Gate: strict-platform-status', "Status: $($report.status)", "Secure Boot: $secureBoot", "HVCI running: $(if ($hvcI) { $hvcI.running } else { $null })", "Driver installed: $([bool]$driver)", "Control device visible: $deviceVisible", "Service installed: $([bool]$service)")
if ($coverage.Count -gt 0) { $text += @('Not covered:') + $coverage }
Write-StrictGateReport -Report $report -JsonPath $jsonPath -TextPath $textPath -TextLines $text
if ($report.status -ne 'passed') { exit 2 }
