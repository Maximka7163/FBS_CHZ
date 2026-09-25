param([int]$Port = 8765)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $repo "scripts\local\Common-Local.ps1")

if (-not (Test-SellariWindows)) { throw "Sellari local supports Windows 10/11 only." }
$paths = Get-SellariLocalPaths -RepositoryRoot $repo
Import-SellariEnvFile -Path $paths.EnvFile
Assert-SellariLocalSafety

if ($Port -lt 1 -or $Port -gt 65535) { throw "Port must be between 1 and 65535." }
if (-not (Test-Path -LiteralPath $paths.Python)) { throw "Run .\Setup-Local.ps1 first." }
if (-not (Test-Path -LiteralPath (Join-Path $paths.Frontend "index.html"))) { throw "Frontend build missing. Run .\Setup-Local.ps1." }

& $paths.Python -m wbcz_local.preflight --json | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Local preflight failed. Run .\Check-Local.ps1 for details." }

if (Test-Path -LiteralPath $paths.PidFile) {
    $existing = (Get-Content -LiteralPath $paths.PidFile -Raw).Trim()
    if ($existing -match '^\d+$') {
        $proc = Get-Process -Id ([int]$existing) -ErrorAction SilentlyContinue
        if ($proc) {
            $url = "http://127.0.0.1:$Port/"
            Write-Host "Sellari is already running: $url"
            Start-Process $url
            exit 0
        }
    }
    Remove-Item -LiteralPath $paths.PidFile -Force -ErrorAction SilentlyContinue
}

$stdout = Join-Path $paths.Logs "sellari.out.log"
$stderr = Join-Path $paths.Logs "sellari.err.log"
$process = Start-Process -FilePath $paths.Python -ArgumentList @(
    "-m", "wbcz_local", "--host", "127.0.0.1", "--port", "$Port"
) -WorkingDirectory $repo -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr

[System.IO.File]::WriteAllText($paths.PidFile, [string]$process.Id, [System.Text.Encoding]::ASCII)
$url = "http://127.0.0.1:$Port/"
$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Start-Sleep -Milliseconds 500
    if ($process.HasExited) { break }
    try {
        $response = Invoke-WebRequest -Uri ($url + "api/health") -UseBasicParsing -TimeoutSec 2
        if ($response.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
}

if (-not $ready) {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $paths.PidFile -Force -ErrorAction SilentlyContinue
    throw "Sellari did not become ready. See $stderr"
}

Write-Host "Sellari running: $url"
Start-Process $url
