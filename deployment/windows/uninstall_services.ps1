param(
    [string]$NssmPath = "nssm",
    [string]$BackendServiceName = "ThreatIntelBackend",
    [string]$CeleryServiceName = "ThreatIntelCelery",
    [string]$FrontendServiceName = "ThreatIntelFrontend",
    [string]$BeatServiceName = "ThreatIntelCeleryBeat",
    [switch]$IncludeBeat = $true
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script in an elevated PowerShell window (Run as Administrator)."
    }
}

function Resolve-CommandPath([string]$Name, [string]$ExplicitPath) {
    if ($ExplicitPath -and $ExplicitPath -ne $Name) {
        if (-not (Test-Path $ExplicitPath)) {
            throw "$Name not found: $ExplicitPath"
        }
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
    if (-not $svc) {
        Write-Host "[INFO] Service not found: $ServiceName"
        return
    }
    Write-Host "[INFO] Stopping and removing service: $ServiceName"
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    } catch {
    }
    Run-Nssm @("remove", $ServiceName, "confirm")
}

Assert-Admin
$script:NssmExe = Resolve-CommandPath "nssm" $NssmPath

Remove-ServiceIfExists $BackendServiceName
Remove-ServiceIfExists $CeleryServiceName
Remove-ServiceIfExists $FrontendServiceName
if ($IncludeBeat) {
    Remove-ServiceIfExists $BeatServiceName
}

Write-Host "[INFO] Done."
