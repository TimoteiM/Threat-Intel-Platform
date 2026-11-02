param(
    [ValidateSet("start", "stop", "restart", "status")]
    [string]$Action = "status",
    [string]$BackendServiceName = "ThreatIntelBackend",
    [string]$CeleryServiceName = "ThreatIntelCelery",
    [string]$FrontendServiceName = "ThreatIntelFrontend",
    [string]$BeatServiceName = "ThreatIntelCeleryBeat",
    [switch]$IncludeBeat = $false
)

$ErrorActionPreference = "Stop"

$services = @(
    $BackendServiceName,
    $CeleryServiceName,
    $FrontendServiceName
)
if ($IncludeBeat) {
    $services += $BeatServiceName
}

function Get-ExistingServices([string[]]$Names) {
    return $Names | ForEach-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue } | Where-Object { $_ }
}

$existing = Get-ExistingServices $services
if (-not $existing) {
    Write-Host "No matching services found."
    exit 0
}

switch ($Action) {
    "start" {
        $existing | ForEach-Object { Start-Service -Name $_.Name -ErrorAction SilentlyContinue }
    }
    "stop" {
        $existing | ForEach-Object { Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue }
    }
    "restart" {
        $existing | ForEach-Object { Restart-Service -Name $_.Name -Force -ErrorAction SilentlyContinue }
    }
    "status" {
    }
}

Get-Service -Name ($existing | Select-Object -ExpandProperty Name) |
    Select-Object Name, Status, StartType |
    Format-Table -AutoSize
