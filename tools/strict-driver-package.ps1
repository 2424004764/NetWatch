[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Install', 'Uninstall', 'Status')][string]$Action,
    [string]$PackageDirectory,
    [string]$SignatureReportPath,
    [string]$DriverName = 'NetWatchStrict',
    [string]$ServiceName = 'NetWatchStrictService',
    [string]$PublishedInf,
    [switch]$ConfirmUninstall,
    [switch]$StartService,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'StrictGate.Common.psm1') -Force
Assert-StrictGateWindows
$runRoot = New-StrictGateRunDirectory -Root $OutputDirectory
$pnputil = $null
$sc = $null
$rundll32 = $null
if ($Action -in @('Install', 'Uninstall')) { $pnputil = Get-StrictGateCommandPath -Name 'pnputil.exe' }
if ($Action -eq 'Install') { $rundll32 = Get-StrictGateCommandPath -Name 'rundll32.exe' }
if ($Action -eq 'Install' -and $StartService) { $sc = Get-StrictGateCommandPath -Name 'sc.exe' }
if ($Action -in @('Install', 'Uninstall') -and -not (Test-StrictGateAdministrator)) { throw "$Action requires an elevated PowerShell session." }

function Get-ServiceRecord {
    $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='$DriverName'" -ErrorAction SilentlyContinue
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    return [ordered]@{
        driver = if ($driver) { [ordered]@{ name = $driver.Name; state = $driver.State; startMode = $driver.StartMode; pathName = $driver.PathName } } else { $null }
        service = if ($service) { [ordered]@{ name = $service.Name; state = $service.State; startMode = $service.StartMode; pathName = $service.PathName } } else { $null }
        controlDeviceVisible = Test-Path -LiteralPath ('\\.\' + $DriverName)
    }
}

$operations = @()
$reportStatus = 'passed'
try {
    switch ($Action) {
        'Status' { $operations += [ordered]@{ action = 'status'; result = Get-ServiceRecord } }
        'Install' {
            if (-not $PackageDirectory) { throw 'PackageDirectory is required for Install.' }
            $package = Resolve-StrictGatePath -Path $PackageDirectory -Description 'Signed driver package directory' -PathType Container
            if (-not $SignatureReportPath) { throw 'SignatureReportPath is required for Install.' }
            $signaturePath = Resolve-StrictGatePath -Path $SignatureReportPath -Description 'Signature gate report'
            $signature = Get-Content -LiteralPath $signaturePath -Raw | ConvertFrom-Json
            $signatureGateValid = ($signature.gate -eq 'strict-driver-signature') -and ($signature.schemaVersion -eq 1) -and ($signature.status -eq 'passed') -and [bool]$signature.microsoftAcceptedRequired
            if (-not $signatureGateValid) { throw 'Package was not accepted by strict-driver-signature.ps1.' }
            $signatureRecords = @($signature.files)
            foreach ($expected in @('NetWatchStrict.inf', 'NetWatchStrict.sys', 'NetWatchStrict.cat')) {
                $record = @($signatureRecords | Where-Object { $_.path -ceq $expected }) | Select-Object -First 1
                $recordAccepted = $record -and ($expected -eq 'NetWatchStrict.inf' -or [bool]$record.accepted)
                if (-not $recordAccepted) {
                    throw "Signature report does not contain an accepted record for $expected."
                }
                $evidenceValid = (-not $record.kernelPolicyVerification) -or (-not $record.microsoftAcceptedSignerEvidence) -or [bool]$record.rejectedTestOrSelfSignature
                if ($expected -ne 'NetWatchStrict.inf' -and $evidenceValid) {
                    throw "Signature evidence for $expected is incomplete or rejected."
                }
            }
            $signaturePackage = [IO.Path]::GetFullPath([string]$signature.package).TrimEnd('\', '/')
            $requestedPackage = $package.TrimEnd('\', '/')
            if (-not [string]::Equals($signaturePackage, $requestedPackage, [StringComparison]::OrdinalIgnoreCase)) { throw "Signature report package does not match requested package: $signaturePackage" }
            foreach ($expected in @('NetWatchStrict.sys', 'NetWatchStrict.cat')) {
                $signedRecord = @($signature.files | Where-Object { $_.path -eq $expected }) | Select-Object -First 1
                if (-not $signedRecord) { throw "Signature report is missing $expected." }
                $currentHash = (Get-FileHash -LiteralPath (Join-Path $package $expected) -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($currentHash -ne [string]$signedRecord.signedPackageSha256) { throw "$expected changed after signature verification; rerun strict-driver-signature.ps1." }
            }
            $infHash = (Get-FileHash -LiteralPath (Join-Path $package 'NetWatchStrict.inf') -Algorithm SHA256).Hash.ToLowerInvariant()
            $infRecord = @($signature.files | Where-Object { $_.path -eq 'NetWatchStrict.inf' }) | Select-Object -First 1
            if (-not $infRecord -or $infHash -ne [string]$infRecord.signedPackageSha256) { throw 'NetWatchStrict.inf changed after signature verification.' }
            $inf = Resolve-StrictGatePath -Path (Join-Path $package 'NetWatchStrict.inf') -Description 'Signed package INF'
            $signedSysPath = Resolve-StrictGatePath -Path (Join-Path $package 'NetWatchStrict.sys') -Description 'Signed package SYS'
            $signedCatPath = Resolve-StrictGatePath -Path (Join-Path $package 'NetWatchStrict.cat') -Description 'Signed package CAT'
            $signedSysHash = (Get-FileHash -LiteralPath $signedSysPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $signedCatHash = (Get-FileHash -LiteralPath $signedCatPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $result = Invoke-StrictGateNative -FilePath $pnputil -Arguments @('/add-driver', $inf) -LogPath (Join-Path $runRoot 'pnputil-stage.log') -AllowNonZero
            if ($result.exitCode -ne 0) { throw "pnputil staging failed with exit code $($result.exitCode). See $($result.logPath)" }
            $installResult = Invoke-StrictGateNative -FilePath $rundll32 -Arguments @('setupapi.dll,InstallHinfSection', 'DefaultInstall.NTamd64', 132, $inf) -LogPath (Join-Path $runRoot 'setupapi-install.log') -WorkingDirectory $package -AllowNonZero
            if ($installResult.exitCode -ne 0) { throw "INF DefaultInstall failed with exit code $($installResult.exitCode). See $($installResult.logPath)" }
            $operations += [ordered]@{ action = 'stage-and-install'; pnputilExitCode = $result.exitCode; pnputilLog = $result.logPath; setupApiExitCode = $installResult.exitCode; setupApiLog = $installResult.logPath }
            $after = Get-ServiceRecord
            if (-not $after.driver) { throw "pnputil reported success but $DriverName is not visible." }
            if ($StartService) {
                $serviceResult = Invoke-StrictGateNative -FilePath $sc -Arguments @('start', $ServiceName) -LogPath (Join-Path $runRoot 'service-start.log') -AllowNonZero
                if ($serviceResult.exitCode -ne 0) { throw "sc.exe start failed with exit code $($serviceResult.exitCode). See $($serviceResult.logPath)" }
                $operations += [ordered]@{ action = 'start-service'; exitCode = $serviceResult.exitCode; log = $serviceResult.logPath }
            }
            $after = Get-ServiceRecord
            $installStateValid = $after.driver -and ($after.driver.State -eq 'Running') -and $after.service -and (-not $StartService -or $after.service.State -eq 'Running') -and $after.controlDeviceVisible
            if (-not $installStateValid) {
                throw 'Install did not confirm the requested driver/service running state and control device visibility.'
            }
            $driverImage = [string]$after.driver.pathName
            $driverImage = $driverImage.Trim('"')
            if (-not (Test-Path -LiteralPath $driverImage -PathType Leaf)) { throw "Running driver image was not found: $driverImage" }
            $installedHash = (Get-FileHash -LiteralPath $driverImage -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($installedHash -ne $signedSysHash) { throw 'Running driver image hash does not match the verified signed package.' }
            $operations += [ordered]@{ action = 'status-after-install'; result = $after; installedDriverPath = $driverImage; installedDriverSha256 = $installedHash; signedPackageCatSha256 = $signedCatHash }
        }
        'Uninstall' {
            if (-not $ConfirmUninstall) { throw 'Uninstall removes a driver package. Re-run with -ConfirmUninstall.' }
            if (-not $PublishedInf -or $PublishedInf -notmatch '^oem[0-9]+\.inf$') { throw 'Uninstall requires -PublishedInf oem#.inf from a reviewed pnputil /enum-drivers result; this script never guesses a package identity.' }
            $driverPackages = @(& $pnputil '/enum-drivers' 2>&1)
            $driverPackages | Set-Content -LiteralPath (Join-Path $runRoot 'pnputil-enum-drivers.log') -Encoding UTF8
            $joined = $driverPackages -join [Environment]::NewLine
            if ($joined -notmatch [regex]::Escape($PublishedInf)) { throw "The explicit package identity was not found in pnputil output: $PublishedInf" }
            $removeResult = Invoke-StrictGateNative -FilePath $pnputil -Arguments @('/delete-driver', $PublishedInf, '/uninstall', '/force') -LogPath (Join-Path $runRoot 'pnputil-uninstall.log') -AllowNonZero
            if ($removeResult.exitCode -ne 0) { throw "pnputil uninstall failed with exit code $($removeResult.exitCode). See $($removeResult.logPath)" }
            $after = Get-ServiceRecord
            if ($after.driver -or $after.controlDeviceVisible) { throw "Uninstall did not confirm removal of $DriverName or its control device." }
            $operations += [ordered]@{ action = 'remove-driver-package'; publishedInf = $PublishedInf; exitCode = $removeResult.exitCode; log = $removeResult.logPath }
        }
    }
} catch {
    $reportStatus = 'failed'
    $errorMessage = $_.Exception.Message
}
$report = [ordered]@{ schemaVersion = 1; gate = 'strict-driver-package-lifecycle'; action = $Action; status = $reportStatus; generatedUtc = [DateTime]::UtcNow.ToString('o'); driverName = $DriverName; serviceName = $ServiceName; operations = $operations; error = $errorMessage; securityFeaturesChanged = $false; packageSignatureGateRequired = ($Action -eq 'Install') }
$jsonPath = Join-Path $runRoot 'package-lifecycle.json'
$textPath = Join-Path $runRoot 'package-lifecycle.txt'
Write-StrictGateReport -Report $report -JsonPath $jsonPath -TextPath $textPath -TextLines @("Gate: strict-driver-package-lifecycle ($Action)", "Status: $reportStatus", "Driver: $DriverName", "Service: $ServiceName", "Report: $jsonPath")
if ($reportStatus -ne 'passed') { throw $errorMessage }
