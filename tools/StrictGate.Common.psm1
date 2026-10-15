Set-StrictMode -Version Latest

function Test-StrictGateAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-StrictGateWindows {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This gate requires Windows PowerShell and Windows driver tooling.'
    }
}

function Resolve-StrictGatePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description,
        [ValidateSet('Leaf', 'Container')][string]$PathType = 'Leaf'
    )
    if (-not (Test-Path -LiteralPath $Path -PathType $PathType)) {
        throw "$Description not found: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Find-StrictGateTool {
    param(
        [string]$ExplicitPath,
        [AllowEmptyCollection()][Parameter(Mandatory = $true)][string[]]$Candidates,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($ExplicitPath) {
        return Resolve-StrictGatePath -Path $ExplicitPath -Description $Name
    }
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "$Name was not found. Install the required SDK/WDK component or pass an explicit path. Searched: $($Candidates -join '; ')"
}

function Invoke-StrictGateNative {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [string]$WorkingDirectory = (Get-Location).Path,
        [switch]$AllowNonZero
    )
    $resolvedFile = Resolve-StrictGatePath -Path $FilePath -Description 'Required executable'
    $parent = Split-Path -Parent $LogPath
    if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $oldLocation = Get-Location
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        Set-Location -LiteralPath $WorkingDirectory
        $output = @(& $resolvedFile @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        Set-Location -LiteralPath $oldLocation
        $ErrorActionPreference = $oldPreference
    }
    $lines = @($output | ForEach-Object { [string]$_ })
    $lines | Set-Content -LiteralPath $LogPath -Encoding UTF8
    if ($exitCode -ne 0 -and -not $AllowNonZero) {
        throw "$([IO.Path]::GetFileName($resolvedFile)) failed with exit code $exitCode. See $LogPath"
    }
    return [pscustomobject]@{
        executable = $resolvedFile
        arguments = @($Arguments)
        exitCode = $exitCode
        output = $lines
        logPath = $LogPath
    }
}

function New-StrictGateRunDirectory {
    param([string]$Root)
    if ([string]::IsNullOrWhiteSpace($Root)) {
        $Root = Join-Path ([IO.Path]::GetTempPath()) 'NetWatchStrictGate'
    }
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
    }
    $run = Join-Path $Root ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $run -Force | Out-Null
    return (Resolve-Path -LiteralPath $run).Path
}

function Get-StrictGateFileRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Name
    )
    $resolved = Resolve-StrictGatePath -Path $Path -Description 'File to hash'
    if (-not $Name) { $Name = [IO.Path]::GetFileName($resolved) }
    $item = Get-Item -LiteralPath $resolved
    return [ordered]@{
        path = $Name
        sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        length = [int64]$item.Length
    }
}

function Write-StrictGateReport {
    param(
        [Parameter(Mandatory = $true)]$Report,
        [Parameter(Mandatory = $true)][string]$JsonPath,
        [Parameter(Mandatory = $true)][string]$TextPath,
        [Parameter(Mandatory = $true)][string[]]$TextLines
    )
    foreach ($path in @($JsonPath, $TextPath)) {
        $parent = Split-Path -Parent $path
        if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
    }
    $Report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $JsonPath -Encoding UTF8
    $TextLines | Set-Content -LiteralPath $TextPath -Encoding UTF8
    Write-Output ($TextLines -join [Environment]::NewLine)
    Write-Output "JSON: $JsonPath"
    Write-Output "Text: $TextPath"
}

function Get-StrictGateCommandPath {
    param([Parameter(Mandatory = $true)][string]$Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) { throw "Required Windows command was not found: $Name" }
    return $command.Source
}

Export-ModuleMember -Function Test-StrictGateAdministrator, Assert-StrictGateWindows, Resolve-StrictGatePath, Find-StrictGateTool, Invoke-StrictGateNative, New-StrictGateRunDirectory, Get-StrictGateFileRecord, Write-StrictGateReport, Get-StrictGateCommandPath
