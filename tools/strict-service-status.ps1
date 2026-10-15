param([string]$ServiceName = "NetWatchStrictService")
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Output "Service: not installed"
} else {
    Write-Output ("Service: {0} ({1})" -f $service.Name, $service.Status)
    Write-Output (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" | Select-Object -ExpandProperty PathName)
}
$driver = Get-CimInstance Win32_SystemDriver -Filter "Name='NetWatchStrict'" -ErrorAction SilentlyContinue
if ($driver) {
    Write-Output ("Driver: {0} ({1})" -f $driver.State, $driver.StartMode)
} else {
    Write-Output "Driver: not installed"
}
$device = Get-Item -LiteralPath "\\.\NetWatchStrict" -ErrorAction SilentlyContinue
Write-Output ("Control device path visible: {0}" -f [bool]$device)
Write-Output "A visible service or device does not prove that strict packet shaping is active. Check HELLO capabilities and successful group snapshot application."
