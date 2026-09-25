Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $repo "scripts\local\Common-Local.ps1")
$paths = Get-SellariLocalPaths -RepositoryRoot $repo

if (-not (Test-Path -LiteralPath $paths.PidFile)) {
    Write-Host "Sellari is not running."
    exit 0
}

$raw = (Get-Content -LiteralPath $paths.PidFile -Raw).Trim()
if ($raw -notmatch '^\d+$') {
    Remove-Item -LiteralPath $paths.PidFile -Force
    throw "Invalid Sellari PID file removed."
}

$process = Get-Process -Id ([int]$raw) -ErrorAction SilentlyContinue
if ($process) {
    Stop-Process -Id $process.Id
    $process.WaitForExit(10000) | Out-Null
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
}
Remove-Item -LiteralPath $paths.PidFile -Force -ErrorAction SilentlyContinue
Write-Host "Sellari stopped."
