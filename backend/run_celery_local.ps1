param(
    [int]$ApiPort = 8000,
    [int]$WorkerConcurrency = 8,
    [switch]$StartBeat = $false,
    [switch]$CleanStart = $true
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$pythonExe = Join-Path $PSScriptRoot "venv\Scripts\python.exe"
$celeryExe = Join-Path $PSScriptRoot "venv\Scripts\celery.exe"

if (-not (Test-Path $pythonExe)) {
    throw "Virtual environment missing: $pythonExe"
}
if (-not (Test-Path $celeryExe)) {
    throw "Celery executable missing: $celeryExe"
}

if ($CleanStart) {
    $existing = Get-CimInstance Win32_Process |
        Where-Object {
            $_.CommandLine -and
            $_.CommandLine.Contains($PSScriptRoot) -and
            (
                $_.CommandLine -match "uvicorn .*app\.main:app" -or
                (
                    $_.CommandLine -match "app\.tasks\.celery_app" -and
                    (
                        $_.CommandLine -match "(\s|^)worker(\s|$)" -or
                        $_.CommandLine -match "(\s|^)beat(\s|$)"
                    )
                )
            )
        }

    foreach ($proc in $existing) {
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
            Write-Host "Stopped stale process PID=$($proc.ProcessId)"
        } catch {
            Write-Warning "Failed to stop PID=$($proc.ProcessId): $($_.Exception.Message)"
        }
    }
}

# Force Celery mode for child processes.
$env:QUEUE_BACKEND = "celery"
$env:QUEUE_FALLBACK_TO_CELERY = "true"

$logDir = Join-Path $PSScriptRoot "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$apiOutLog = Join-Path $logDir "api-$ts.out.log"
$apiErrLog = Join-Path $logDir "api-$ts.err.log"
$workerOutLog = Join-Path $logDir "celery-worker-$ts.out.log"
$workerErrLog = Join-Path $logDir "celery-worker-$ts.err.log"
$beatOutLog = Join-Path $logDir "celery-beat-$ts.out.log"
$beatErrLog = Join-Path $logDir "celery-beat-$ts.err.log"

$apiProc = Start-Process -FilePath $pythonExe `
    -ArgumentList @("-m", "uvicorn", "--app-dir", $PSScriptRoot, "app.main:app", "--host", "127.0.0.1", "--port", "$ApiPort") `
    -WorkingDirectory $PSScriptRoot `
    -RedirectStandardOutput $apiOutLog `
    -RedirectStandardError $apiErrLog `
    -PassThru

$workerNodeName = "celery-local-$ApiPort-$ts@%h"
$workerProc = Start-Process -FilePath $celeryExe `
    -ArgumentList @("-A", "app.tasks.celery_app", "worker", "--loglevel=info", "--pool=threads", "--concurrency=$WorkerConcurrency", "--hostname=$workerNodeName") `
    -WorkingDirectory $PSScriptRoot `
    -RedirectStandardOutput $workerOutLog `
    -RedirectStandardError $workerErrLog `
    -PassThru

$beatProc = $null
if ($StartBeat) {
    $beatProc = Start-Process -FilePath $celeryExe `
        -ArgumentList @("-A", "app.tasks.celery_app", "beat", "--loglevel=info") `
        -WorkingDirectory $PSScriptRoot `
        -RedirectStandardOutput $beatOutLog `
        -RedirectStandardError $beatErrLog `
        -PassThru
}

Write-Host ""
Write-Host "Started API PID=$($apiProc.Id)"
Write-Host "Started Celery worker PID=$($workerProc.Id)"
if ($beatProc) {
    Write-Host "Started Celery beat PID=$($beatProc.Id)"
}

# Wait for API and worker readiness
$apiReady = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    try {
        $null = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/api/investigations?limit=1&offset=0" -TimeoutSec 3
        $apiReady = $true
        break
    } catch {
        # continue
    }
}

if ($apiReady) {
    Write-Host "API ready on http://127.0.0.1:$ApiPort"
} else {
    Write-Warning "API readiness check did not succeed within timeout."
}

$workerReady = $false
for ($i = 0; $i -lt 12; $i++) {
    $prevErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $pingRaw = & $celeryExe -A app.tasks.celery_app inspect ping --timeout=5 -d $workerNodeName 2>&1
    $pingExit = $LASTEXITCODE
    $ErrorActionPreference = $prevErrorAction

    $ping = ($pingRaw | ForEach-Object { $_.ToString() }) -join "`n"

    if ($pingExit -eq 0) {
        $workerReady = $true
        Write-Host "Celery worker ping OK"
        if ($ping) {
            Write-Host $ping
        }
        break
    }
    Start-Sleep -Seconds 1
}

if (-not $workerReady) {
    Write-Warning "Celery inspect ping did not succeed after retries."
    if (Get-Process -Id $workerProc.Id -ErrorAction SilentlyContinue) {
        Write-Warning "Worker process is running (PID=$($workerProc.Id)); startup may still be in progress."
    } else {
        Write-Warning "Worker process exited unexpectedly."
    }
    if (Test-Path $workerErrLog) {
        Write-Host ""
        Write-Host "Last worker error log lines:"
        Get-Content -Path $workerErrLog -Tail 20
    }
}

$pidFile = Join-Path $logDir "celery-local-last.json"
$pidData = @{
    api_pid = $apiProc.Id
    worker_pid = $workerProc.Id
    worker_nodename = $workerNodeName
    beat_pid = if ($beatProc) { $beatProc.Id } else { $null }
    api_port = $ApiPort
    api_out_log = $apiOutLog
    api_err_log = $apiErrLog
    worker_out_log = $workerOutLog
    worker_err_log = $workerErrLog
    beat_out_log = if ($beatProc) { $beatOutLog } else { $null }
    beat_err_log = if ($beatProc) { $beatErrLog } else { $null }
    started_at = (Get-Date).ToString("o")
} | ConvertTo-Json -Depth 4
$pidData | Set-Content -Path $pidFile -Encoding UTF8

Write-Host ""
Write-Host "Logs:"
Write-Host "  API out:    $apiOutLog"
Write-Host "  API err:    $apiErrLog"
Write-Host "  Worker out: $workerOutLog"
Write-Host "  Worker err: $workerErrLog"
if ($beatProc) {
    Write-Host "  Beat out:   $beatOutLog"
    Write-Host "  Beat err:   $beatErrLog"
}
Write-Host ""
Write-Host "PID file: $pidFile"
Write-Host ""
Write-Host "Stop commands:"
Write-Host "  Stop-Process -Id $($apiProc.Id),$($workerProc.Id) -Force"
if ($beatProc) {
    Write-Host "  Stop-Process -Id $($beatProc.Id) -Force"
}
