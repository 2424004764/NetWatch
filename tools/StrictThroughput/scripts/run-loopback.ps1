param(
    [int]$DurationSeconds = 10,
    [int]$WarmupSeconds = 2,
    [string]$Output = "strict-throughput-report.json"
)

$ErrorActionPreference = "Stop"
$project = Join-Path $PSScriptRoot "..\StrictThroughput.csproj"
dotnet run --project $project -- coordinator `
    --protocol both --family both --labels baseline,limited `
    --duration-seconds $DurationSeconds --warmup-seconds $WarmupSeconds `
    --output $Output
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
