param([string]$ServiceName = "NetWatchStrictService")
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) { Write-Output "$ServiceName is not installed."; exit 0 }
if ($service.Status -ne "Stopped") { Stop-Service -Name $ServiceName -Force -ErrorAction Stop }
sc.exe delete $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE" }
Write-Output "Removed $ServiceName. The driver package is not removed by this script."
