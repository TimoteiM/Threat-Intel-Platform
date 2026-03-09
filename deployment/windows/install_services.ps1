param(
    [string]$ProjectRoot = "",
    [string]$NssmPath = "nssm",
    [string]$BackendServiceName = "ThreatIntelBackend",
    [string]$CeleryServiceName = "ThreatIntelCelery",
    [string]$FrontendServiceName = "ThreatIntelFrontend",
    [string]$BeatServiceName = "ThreatIntelCeleryBeat",
    [int]$ApiPort = 8000,
    [int]$FrontendPort = 3000,
    [string]$CeleryPool = "solo",
    [int]$CeleryConcurrency = 1,
    [switch]$InstallBeat = $false,
    [switch]$StartAfterInstall = $true
)

$ErrorActionPreference = "Stop"

function Write-Info([string]$Message) {
    Write-Host "[INFO] $Message"
}

function Write-Warn([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script in an elevated PowerShell window (Run as Administrator)."
    }
}

function Assert-Exists([string]$Path, [string]$Name) {
    if (-not (Test-Path $Path)) {
        throw "$Name not found: $Path"
    }
}

function Resolve-CommandPath([string]$Name, [string]$ExplicitPath) {
    if ($ExplicitPath -and $ExplicitPath -ne $Name) {
        Assert-Exists $ExplicitPath $Name
        return (Resolve-Path $ExplicitPath).Path
    }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "Command not found in PATH: $Name"
    }
    return $cmd.Source
}

function Run-Nssm([string[]]$Args) {
    & $script:NssmExe @Args
    if ($LASTEXITCODE -ne 0) {
        throw "nssm command failed: $($Args -join ' ')"
    }
}

function Remove-ServiceIfExists([string]$ServiceName) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Info "Removing existing service: $ServiceName"
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        } catch {
        }
        Run-Nssm @("remove", $ServiceName, "confirm")
    }
}

function Configure-CommonServiceSettings([string]$ServiceName, [string]$AppDirectory, [string]$StdoutPath, [string]$StderrPath) {
    Run-Nssm @("set", $ServiceName, "AppDirectory", $AppDirectory)
    Run-Nssm @("set", $ServiceName, "Start", "SERVICE_AUTO_START")
    Run-Nssm @("set", $ServiceName, "AppStdout", $StdoutPath)
    Run-Nssm @("set", $ServiceName, "AppStderr", $StderrPath)
    Run-Nssm @("set", $ServiceName, "AppRotateFiles", "1")
    Run-Nssm @("set", $ServiceName, "AppRotateOnline", "1")
    Run-Nssm @("set", $ServiceName, "AppRotateBytes", "10485760")
}

function Configure-RestartPolicy([string]$ServiceName) {
    sc.exe failure $ServiceName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
}

Assert-Admin

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
} else {
    $ProjectRoot = (Resolve-Path $ProjectRoot).Path
}

$BackendDir = Join-Path $ProjectRoot "backend"
$FrontendDir = Join-Path $ProjectRoot "frontend"
$BackendVenvPython = Join-Path $BackendDir "venv\Scripts\python.exe"
$NodeExe = Resolve-CommandPath "node" ""
$NpmCmd = Resolve-CommandPath "npm.cmd" ""
$NextCli = Join-Path $FrontendDir "node_modules\next\dist\bin\next"

$script:NssmExe = Resolve-CommandPath "nssm" $NssmPath

Assert-Exists $BackendDir "Backend directory"
Assert-Exists $FrontendDir "Frontend directory"
Assert-Exists $BackendVenvPython "Backend Python executable"
Assert-Exists $NextCli "Next.js CLI (run npm ci in frontend first)"

$BackendLogs = Join-Path $BackendDir "logs\services"
$FrontendLogs = Join-Path $FrontendDir "logs"
New-Item -ItemType Directory -Force -Path $BackendLogs | Out-Null
New-Item -ItemType Directory -Force -Path $FrontendLogs | Out-Null

$RootEnv = Join-Path $ProjectRoot ".env"
$BackendEnv = Join-Path $BackendDir ".env"
if ((Test-Path $RootEnv) -and -not (Test-Path $BackendEnv)) {
    Copy-Item -Path $RootEnv -Destination $BackendEnv -Force
    Write-Info "Copied root .env to backend/.env"
}

$backendArgs = "-m uvicorn app.main:app --host 0.0.0.0 --port $ApiPort"
$backendOut = Join-Path $BackendLogs "backend.out.log"
$backendErr = Join-Path $BackendLogs "backend.err.log"

$celeryArgs = "-m celery -A app.tasks.celery_app worker --loglevel=INFO --pool=$CeleryPool --concurrency=$CeleryConcurrency"
$celeryOut = Join-Path $BackendLogs "celery.out.log"
$celeryErr = Join-Path $BackendLogs "celery.err.log"

$frontendArgs = "`"$NextCli`" start -p $FrontendPort -H 0.0.0.0"
$frontendOut = Join-Path $FrontendLogs "frontend.out.log"
$frontendErr = Join-Path $FrontendLogs "frontend.err.log"

if ($InstallBeat) {
    $beatArgs = "-m celery -A app.tasks.celery_app beat --loglevel=INFO"
    $beatOut = Join-Path $BackendLogs "celery-beat.out.log"
    $beatErr = Join-Path $BackendLogs "celery-beat.err.log"
}

Write-Info "ProjectRoot: $ProjectRoot"
Write-Info "NSSM: $script:NssmExe"
Write-Info "Node: $NodeExe"
Write-Info "NPM: $NpmCmd"
Write-Info "Installing services..."

Remove-ServiceIfExists $BackendServiceName
Remove-ServiceIfExists $CeleryServiceName
Remove-ServiceIfExists $FrontendServiceName
if ($InstallBeat) {
    Remove-ServiceIfExists $BeatServiceName
}

Run-Nssm @("install", $BackendServiceName, $BackendVenvPython, $backendArgs)
Configure-CommonServiceSettings $BackendServiceName $BackendDir $backendOut $backendErr
Run-Nssm @("set", $BackendServiceName, "AppEnvironmentExtra", "QUEUE_BACKEND=celery", "QUEUE_FALLBACK_TO_CELERY=true", "PYTHONUNBUFFERED=1")
Configure-RestartPolicy $BackendServiceName

Run-Nssm @("install", $CeleryServiceName, $BackendVenvPython, $celeryArgs)
Configure-CommonServiceSettings $CeleryServiceName $BackendDir $celeryOut $celeryErr
Run-Nssm @("set", $CeleryServiceName, "AppEnvironmentExtra", "QUEUE_BACKEND=celery", "QUEUE_FALLBACK_TO_CELERY=true", "PYTHONUNBUFFERED=1")
Configure-RestartPolicy $CeleryServiceName

Run-Nssm @("install", $FrontendServiceName, $NodeExe, $frontendArgs)
Configure-CommonServiceSettings $FrontendServiceName $FrontendDir $frontendOut $frontendErr
Configure-RestartPolicy $FrontendServiceName

if ($InstallBeat) {
    Run-Nssm @("install", $BeatServiceName, $BackendVenvPython, $beatArgs)
    Configure-CommonServiceSettings $BeatServiceName $BackendDir $beatOut $beatErr
    Run-Nssm @("set", $BeatServiceName, "AppEnvironmentExtra", "QUEUE_BACKEND=celery", "QUEUE_FALLBACK_TO_CELERY=true", "PYTHONUNBUFFERED=1")
    Configure-RestartPolicy $BeatServiceName
}

if ($StartAfterInstall) {
    Write-Info "Starting services..."
    Start-Service -Name $BackendServiceName
    Start-Service -Name $CeleryServiceName
    Start-Service -Name $FrontendServiceName
    if ($InstallBeat) {
        Start-Service -Name $BeatServiceName
    }
}

Write-Info "Done."
Write-Host ""
Write-Host "Services:"
Write-Host "  $BackendServiceName"
Write-Host "  $CeleryServiceName"
Write-Host "  $FrontendServiceName"
if ($InstallBeat) {
    Write-Host "  $BeatServiceName"
}
Write-Host ""
Write-Host "Health checks:"
Write-Host "  curl.exe -i http://127.0.0.1:$ApiPort/api/health"
Write-Host "  curl.exe -i http://127.0.0.1:$FrontendPort"
Write-Host ""
Write-Host "Logs:"
Write-Host "  $backendOut"
Write-Host "  $backendErr"
Write-Host "  $celeryOut"
Write-Host "  $celeryErr"
Write-Host "  $frontendOut"
Write-Host "  $frontendErr"
if ($InstallBeat) {
    Write-Host "  $beatOut"
    Write-Host "  $beatErr"
}
