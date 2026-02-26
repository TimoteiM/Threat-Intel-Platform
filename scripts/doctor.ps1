param(
    [string]$RepoRoot = ""
)

$ErrorActionPreference = "Continue"

if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

Set-Location $RepoRoot

function Section($name) {
    Write-Host ""
    Write-Host "-- $name --"
}

Write-Host "== Threat Intel Doctor (PowerShell) =="
Write-Host "Repo: $RepoRoot"

Section "Docker compose config"
docker compose config -q
if ($LASTEXITCODE -eq 0) { Write-Host "OK: compose config valid" } else { Write-Host "WARN: compose config invalid" }

Section "Docker services (postgres/redis)"
docker compose ps postgres redis
if ($LASTEXITCODE -ne 0) { Write-Host "WARN: could not query docker compose services" }

Section "Valkey ping (redis service)"
docker exec threat-intel-redis-1 sh -lc "valkey-cli ping || redis-cli ping"
if ($LASTEXITCODE -ne 0) { Write-Host "WARN: valkey/redis not reachable" }

Section "API health (http://localhost:8000/api/health)"
try {
    $resp = Invoke-RestMethod -Uri "http://localhost:8000/api/health" -Method Get -TimeoutSec 3
    Write-Host "OK: $($resp | ConvertTo-Json -Compress)"
} catch {
    Write-Host "WARN: API health check failed: $($_.Exception.Message)"
}

Section "Celery inspect ping (backend worker nodes)"
$celeryExe = Join-Path $RepoRoot "backend\\venv\\Scripts\\celery.exe"
if (Test-Path $celeryExe) {
    Push-Location (Join-Path $RepoRoot "backend")
    & $celeryExe -A app.tasks.celery_app inspect ping
    if ($LASTEXITCODE -ne 0) { Write-Host "WARN: celery inspect ping failed" }
    Pop-Location
} else {
    Write-Host "WARN: celery executable not found at $celeryExe"
}

Section "Listening check on :8000"
try {
    $conn = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction Stop
    if ($conn) {
        Write-Host "OK: port 8000 is listening"
        $conn | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
    }
} catch {
    Write-Host "WARN: port 8000 is not listening"
}

Write-Host ""
Write-Host "Doctor completed."
