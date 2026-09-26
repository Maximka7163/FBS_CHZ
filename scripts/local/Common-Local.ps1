Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-SellariWindows {
    return [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Get-SellariLocalPaths {
    param([Parameter(Mandatory=$true)][string]$RepositoryRoot)
    $localBase = if ($env:LOCALAPPDATA) {
        Join-Path $env:LOCALAPPDATA "SellariMarking"
    } else {
        Join-Path $HOME "AppData\Local\SellariMarking"
    }
    return [ordered]@{
        Repository = [System.IO.Path]::GetFullPath($RepositoryRoot)
        Base       = $localBase
        Config     = Join-Path $localBase "config"
        Data       = Join-Path $localBase "data"
        Logs       = Join-Path $localBase "logs"
        Run        = Join-Path $localBase "run"
        EnvFile    = Join-Path $localBase "config\local.env"
        PidFile    = Join-Path $localBase "run\sellari.pid"
        Venv       = Join-Path $RepositoryRoot ".venv-local"
        Python     = Join-Path $RepositoryRoot ".venv-local\Scripts\python.exe"
        Frontend   = Join-Path $RepositoryRoot "frontend\dist"
    }
}

function Import-SellariEnvFile {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Local config not found: $Path. Run .\Setup-Local.ps1 first."
    }
    foreach ($raw in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith("#")) { continue }
        $parts = $line.Split("=", 2)
        if ($parts.Count -ne 2) { throw "Invalid local.env line: $raw" }
        [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1], "Process")
    }
}

function Assert-SellariLocalSafety {
    $required = @{
        "WBCZ_FBS_DRY_RUN_ONLY" = "true"
        "WBCZ_TRUE_API_REAL_READ_ENABLED" = "true"
        "WBCZ_TRUE_API_WRITE_ENABLED" = "false"
        "WBCZ_AGENT_ENABLED" = "false"
        "WBCZ_PRINTING_ENABLED" = "false"
        "WBCZ_PRINT_EXECUTION_ENABLED" = "false"
        "WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED" = "false"
    }
    foreach ($name in $required.Keys) {
        $actual = [System.Environment]::GetEnvironmentVariable($name, "Process")
        if ($actual -ne $required[$name]) {
            throw "Unsafe local setting $name=$actual; required $($required[$name])."
        }
    }
    if ($env:WBCZ_TRUSTED_HOSTS -notin @("127.0.0.1,localhost", "localhost,127.0.0.1")) {
        throw "WBCZ_TRUSTED_HOSTS must remain loopback-only."
    }
}

function Get-SellariPythonCommand {
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) {
        & $py.Source -3.12 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 2)"
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{ Exe = $py.Source; PrefixArgs = @("-3.12") }
        }
    }
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) {
        & $python.Source -c "import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 2)"
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{ Exe = $python.Source; PrefixArgs = @() }
        }
    }
    throw "Python 3.12+ not found. Install Python 3.12 for Windows, then rerun Setup-Local.ps1."
}

function Ensure-SellariPostgresService {
    $services = @(Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue)
    if (-not $services.Count) { return }
    if ($services | Where-Object { $_.Status -eq "Running" }) { return }
    $preferred = $services | Where-Object { $_.Name -match "16" } | Select-Object -First 1
    if (-not $preferred) { $preferred = $services | Select-Object -First 1 }
    try {
        Start-Service -Name $preferred.Name
        $preferred.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(15))
    } catch {
        throw "Local PostgreSQL service '$($preferred.Name)' is stopped and could not be started. Start it manually or run PowerShell with permission to start the service."
    }
}

function Find-SellariCryptoProTool {
    param([Parameter(Mandatory=$true)][string]$FileName)
    $candidates = @(
        (Join-Path $env:ProgramFiles "Crypto Pro\CSP\$FileName"),
        (Join-Path ${env:ProgramFiles(x86)} "Crypto Pro\CSP\$FileName")
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    $command = Get-Command $FileName -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return $null
}

function Find-SellariCryptoPro {
    $candidates = @(
        "$env:ProgramFiles\Crypto Pro\CSP\csptest.exe",
        "${env:ProgramFiles(x86)}\Crypto Pro\CSP\csptest.exe",
        "$env:ProgramFiles\Crypto Pro\CSP\cryptcp.exe",
        "${env:ProgramFiles(x86)}\Crypto Pro\CSP\cryptcp.exe"
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    foreach ($name in @("csptest.exe", "cryptcp.exe")) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) { return $command.Source }
    }
    return $null
}
