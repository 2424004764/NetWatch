param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceExe,
    [string]$ServiceName = "NetWatchStrictService"
)

$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$resolvedExe = (Resolve-Path -LiteralPath $ServiceExe).Path
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne "Stopped") { Stop-Service -Name $ServiceName -Force }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

sc.exe create $ServiceName binPath= ('"{0}"' -f $resolvedExe) start= auto DisplayName= "NetWatch Strict Upload Service"
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE" }
sc.exe description $ServiceName "NetWatch strict upload policy control service" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe description failed with exit code $LASTEXITCODE" }
Write-Output "Installed $ServiceName. The service exposes control-plane management only unless the driver reports shaping capability." 
