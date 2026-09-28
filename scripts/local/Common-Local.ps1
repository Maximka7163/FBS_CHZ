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

function New-SellariSecureHex {
    param([int]$ByteCount = 24)
    if ($ByteCount -lt 1) {
        throw "ByteCount must be greater than zero."
    }

    # Windows PowerShell 5.1 / .NET Framework compatible CSPRNG.
    # Do not use RandomNumberGenerator.Fill (not available on stock .NET Framework).
    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        if ($null -ne $rng) { $rng.Dispose() }
    }

    # Convert.ToHexString is .NET 5+; BitConverter works on Windows PowerShell 5.1.
    return ([System.BitConverter]::ToString($bytes)).Replace("-", "").ToLowerInvariant()
}

function Find-SellariPsql {
    foreach ($name in @("psql.exe", "psql")) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }

    # PostgreSQL's Windows installer does not always add bin to PATH.
    $roots = @(
        $env:ProgramW6432,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        "C:\Program Files"
    ) | Where-Object { $_ } | Select-Object -Unique

    foreach ($root in $roots) {
        $candidate = Join-Path $root "PostgreSQL\16\bin\psql.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }
    return $null
}

function ConvertTo-SellariPsqlScalar {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }

    $lines = @(
        @($Value) | ForEach-Object {
            if ($null -ne $_) { ([string]$_).Trim() }
        } | Where-Object { $_ -ne "" }
    )
    if ($lines.Count -eq 0) { return "" }
    return [string]$lines[0]
}

function Invoke-SellariPsqlNative {
    param(
        [Parameter(Mandatory=$true)][string]$PsqlPath,
        [Parameter(Mandatory=$true)][string[]]$Arguments
    )

    if (-not (Test-Path -LiteralPath $PsqlPath -PathType Leaf)) {
        throw "PostgreSQL client executable is unavailable: $PsqlPath"
    }

    # Windows PowerShell 5.1 promotes native stderr to NativeCommandError when
    # ErrorActionPreference=Stop. psql legitimately writes authentication and
    # SQL errors to stderr, including the expected first-install readiness
    # failure. Scope EAP relaxation to the one native invocation only, keep
    # stderr separate from stdout, and always restore the caller's policy.
    $stderrPath = [System.IO.Path]::GetTempFileName()
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        try {
            $LASTEXITCODE = $null
            $stdout = & $PsqlPath @Arguments 2> $stderrPath
            $exitCode = $LASTEXITCODE
            if ($null -eq $exitCode) {
                throw "PostgreSQL client process did not return an exit code."
            }
        } catch {
            # Process launch/runtime failures are not an expected psql result.
            # Preserve them instead of converting them to readiness=false.
            throw
        }

        $stderr = ""
        if (Test-Path -LiteralPath $stderrPath) {
            $stderr = [string](Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue)
        }
        return [pscustomobject]@{
            ExitCode = [int]$exitCode
            Stdout = @($stdout)
            Stderr = $stderr
        }
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Test-SellariPsqlReady {
    param(
        [Parameter(Mandatory=$true)][string]$PsqlPath,
        [Parameter(Mandatory=$true)][string[]]$Arguments
    )
    $result = Invoke-SellariPsqlNative -PsqlPath $PsqlPath -Arguments $Arguments
    return $result.ExitCode -eq 0
}

function Invoke-SellariPsqlScalar {
    param(
        [Parameter(Mandatory=$true)][string]$PsqlPath,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$FailureMessage
    )
    $result = Invoke-SellariPsqlNative -PsqlPath $PsqlPath -Arguments $Arguments
    if ($result.ExitCode -ne 0) {
        throw $FailureMessage
    }
    return ConvertTo-SellariPsqlScalar -Value $result.Stdout
}

function Invoke-SellariPsqlRequired {
    param(
        [Parameter(Mandatory=$true)][string]$PsqlPath,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$FailureMessage
    )
    $result = Invoke-SellariPsqlNative -PsqlPath $PsqlPath -Arguments $Arguments
    if ($result.ExitCode -ne 0) {
        throw $FailureMessage
    }
    return $result.Stdout
}
function Assert-SellariPinnedSha256 {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$ExpectedSha256
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Pinned artifact not found: $Path"
    }
    if ($ExpectedSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw "Expected SHA-256 must be exactly 64 hexadecimal characters."
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    $expected = $ExpectedSha256.ToUpperInvariant()
    if ($actual -ne $expected) {
        throw "Pinned artifact SHA-256 mismatch. Expected $expected, got $actual."
    }
    return $actual
}

function Publish-SellariPinnedArtifact {
    param(
        [Parameter(Mandatory=$true)][string]$CandidatePath,
        [Parameter(Mandatory=$true)][string]$DestinationPath,
        [Parameter(Mandatory=$true)][string]$ExpectedSha256
    )
    # Never publish executable JS until the candidate has passed an exact
    # cryptographic hash check. A mismatch leaves DestinationPath untouched.
    Assert-SellariPinnedSha256 -Path $CandidatePath -ExpectedSha256 $ExpectedSha256 | Out-Null
    $destinationDirectory = Split-Path -Parent $DestinationPath
    New-Item -ItemType Directory -Force -Path $destinationDirectory | Out-Null
    Move-Item -LiteralPath $CandidatePath -Destination $DestinationPath -Force
    try {
        Assert-SellariPinnedSha256 -Path $DestinationPath -ExpectedSha256 $ExpectedSha256 | Out-Null
    } catch {
        Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
        throw
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
        "${env:ProgramFiles(x86)}\Crypto Pro\CSP\csptest.exe"
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    $command = Get-Command "csptest.exe" -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    foreach ($key in @(
        "HKLM:\SOFTWARE\Crypto Pro\Settings",
        "HKLM:\SOFTWARE\WOW6432Node\Crypto Pro\Settings"
    )) {
        if (Test-Path -LiteralPath $key) { return "registry:$key" }
    }
    return $null
}
