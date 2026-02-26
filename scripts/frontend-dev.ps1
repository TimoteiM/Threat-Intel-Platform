param(
  [string]$NodeDir = "",
  [switch]$Clean,
  [switch]$KillPort3000
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$frontendDir = Join-Path $repoRoot "frontend"
$candidateNodeDirs = @()
if ($NodeDir) { $candidateNodeDirs += $NodeDir }
$candidateNodeDirs += @(
  "C:\nvm4w\nodejs",
  "C:\Program Files\nodejs",
  "C:\Users\tmoscaliuc\tools\node20\node-v20.18.1-win-x64"
)

foreach ($dir in $candidateNodeDirs) {
  $maybeNode = Join-Path $dir "node.exe"
  $maybeNpm = Join-Path $dir "npm.cmd"
  if ((Test-Path $maybeNode) -and (Test-Path $maybeNpm)) {
    $NodeDir = $dir
    break
  }
}

if (-not $NodeDir) {
  Write-Error "Could not find a Node runtime. Set -NodeDir explicitly (example: C:\nvm4w\nodejs)."
}

$nodeExe = Join-Path $NodeDir "node.exe"
$npmCmd = Join-Path $NodeDir "npm.cmd"

$env:Path = "$NodeDir;$env:Path"

Push-Location $frontendDir
try {
  if ($Clean) {
    cmd /c "if exist .next rmdir /s /q .next" | Out-Null
    cmd /c "if exist node_modules\.cache rmdir /s /q node_modules\.cache" | Out-Null
    Write-Host "Cleaned frontend build cache (.next, node_modules/.cache)."
  }
  if ($KillPort3000) {
    $listeners = Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue
    foreach ($l in $listeners) {
      if ($l.OwningProcess) {
        Stop-Process -Id $l.OwningProcess -Force -ErrorAction SilentlyContinue
      }
    }
  }

  & $nodeExe -v
  & $npmCmd run dev
}
finally {
  Pop-Location
}
