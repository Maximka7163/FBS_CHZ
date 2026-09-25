param(
    [string]$ParticipantInn = "",
    [string]$OwnerUsername = "owner",
    [string]$OrganisationName = "Sellari Local",
    [string]$PostgresAdminUser = "postgres",
    [string]$PostgresHost = "127.0.0.1",
    [int]$PostgresPort = 5432
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $repo "scripts\local\Common-Local.ps1")

if (-not (Test-SellariWindows)) {
    throw "Sellari local foundation supports Windows 10/11 only."
}

$paths = Get-SellariLocalPaths -RepositoryRoot $repo
foreach ($path in @($paths.Base, $paths.Config, $paths.Data, $paths.Logs, $paths.Run)) {
    New-Item -ItemType Directory -Force -Path $path | Out-Null
}

$crypto = Find-SellariCryptoPro
if (-not $crypto) {
    throw "CryptoPro CSP was not detected. Install licensed CryptoPro CSP and authorised UKEP first. Sellari does not redistribute CryptoPro binaries."
}
Write-Host "CryptoPro detected: $crypto"

$pythonCommand = Get-SellariPythonCommand
$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npm) { $npm = Get-Command npm -ErrorAction SilentlyContinue }
if (-not $npm) {
    throw "Node.js/npm not found. Install a current Node.js LTS release for the one-time frontend build."
}
$psql = Get-Command psql.exe -ErrorAction SilentlyContinue
if (-not $psql) { $psql = Get-Command psql -ErrorAction SilentlyContinue }
if (-not $psql) {
    throw "PostgreSQL client psql was not found in PATH. Install local PostgreSQL 16 before running setup."
}

if (-not (Test-Path -LiteralPath $paths.Python)) {
    Write-Host "Creating local Python environment..."
    $venvArgs = @($pythonCommand.PrefixArgs) + @("-m", "venv", $paths.Venv)
    & $pythonCommand.Exe @venvArgs
    if ($LASTEXITCODE -ne 0) { throw "Python virtual environment creation failed." }
}

& $paths.Python -m pip install --disable-pip-version-check -e ($repo + "[web]")
if ($LASTEXITCODE -ne 0) { throw "Python dependency installation failed." }

Push-Location (Join-Path $repo "frontend")
try {
    & $npm.Source ci --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed." }
    $oldLocalBuild = $env:VITE_SELLARI_LOCAL_FBS_ONLY
    $env:VITE_SELLARI_LOCAL_FBS_ONLY = "true"
    try {
        & $npm.Source run build
        if ($LASTEXITCODE -ne 0) { throw "Frontend build failed." }
    } finally {
        if ($null -eq $oldLocalBuild) {
            Remove-Item Env:VITE_SELLARI_LOCAL_FBS_ONLY -ErrorAction SilentlyContinue
        } else {
            $env:VITE_SELLARI_LOCAL_FBS_ONLY = $oldLocalBuild
        }
    }
} finally {
    Pop-Location
}

if (Test-Path -LiteralPath $paths.EnvFile) {
    Import-SellariEnvFile -Path $paths.EnvFile
}

$appPassword = $env:WBCZ_LOCAL_DB_PASSWORD
if (-not $appPassword) {
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $appPassword = [Convert]::ToHexString($bytes).ToLowerInvariant()
}

$previousPgPassword = $env:PGPASSWORD
$env:PGPASSWORD = $appPassword
& $psql.Source -h $PostgresHost -p $PostgresPort -U sellari_local -d sellari_local -Atqc "SELECT 1" *> $null
$appDbReady = $LASTEXITCODE -eq 0

if (-not $appDbReady) {
    $secureAdmin = Read-Host "PostgreSQL password for local admin '$PostgresAdminUser'" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAdmin)
    try {
        $adminPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        $env:PGPASSWORD = $adminPassword
        $roleExists = (& $psql.Source -h $PostgresHost -p $PostgresPort -U $PostgresAdminUser -d postgres -Atqc "SELECT 1 FROM pg_roles WHERE rolname='sellari_local';").Trim()
        if ($LASTEXITCODE -ne 0) { throw "Cannot connect to local PostgreSQL as $PostgresAdminUser." }
        if ($roleExists -eq "1") {
            & $psql.Source -h $PostgresHost -p $PostgresPort -U $PostgresAdminUser -d postgres -v ON_ERROR_STOP=1 -c "ALTER ROLE sellari_local WITH LOGIN PASSWORD '$appPassword';" | Out-Null
        } else {
            & $psql.Source -h $PostgresHost -p $PostgresPort -U $PostgresAdminUser -d postgres -v ON_ERROR_STOP=1 -c "CREATE ROLE sellari_local LOGIN PASSWORD '$appPassword';" | Out-Null
        }
        if ($LASTEXITCODE -ne 0) { throw "Cannot create/update local Sellari PostgreSQL role." }

        $databaseExists = (& $psql.Source -h $PostgresHost -p $PostgresPort -U $PostgresAdminUser -d postgres -Atqc "SELECT 1 FROM pg_database WHERE datname='sellari_local';").Trim()
        if ($databaseExists -ne "1") {
            & $psql.Source -h $PostgresHost -p $PostgresPort -U $PostgresAdminUser -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE sellari_local OWNER sellari_local;" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Cannot create local Sellari PostgreSQL database." }
        } else {
            & $psql.Source -h $PostgresHost -p $PostgresPort -U $PostgresAdminUser -d postgres -v ON_ERROR_STOP=1 -c "ALTER DATABASE sellari_local OWNER TO sellari_local;" | Out-Null
        }
    } finally {
        if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        Remove-Variable adminPassword -ErrorAction SilentlyContinue
    }
}

if (-not $ParticipantInn) {
    $ParticipantInn = if ($env:WBCZ_OWN_INN) { $env:WBCZ_OWN_INN } else { Read-Host "Participant INN (10 or 12 digits)" }
}
if ($ParticipantInn -notmatch '^(\d{10}|\d{12})$') {
    throw "ParticipantInn must contain exactly 10 or 12 digits."
}

$hostPort = "{0}:{1}" -f $PostgresHost, $PostgresPort
$databaseUrl = "postgresql+psycopg://sellari_local:$appPassword@$hostPort/sellari_local"
$envLines = @(
    "WBCZ_ENV=development",
    "WBCZ_DATABASE_URL=$databaseUrl",
    "WBCZ_MIGRATION_DATABASE_URL=$databaseUrl",
    "WBCZ_OWN_INN=$ParticipantInn",
    "WBCZ_COOKIE_SECURE=false",
    "WBCZ_DEBUG=false",
    "WBCZ_TRUSTED_HOSTS=127.0.0.1,localhost",
    "WBCZ_APP_URL=http://127.0.0.1:8765",
    "WBCZ_DB_APPLICATION_NAME=sellari-local",
    "WBCZ_WEB_PROCESS_COUNT=1",
    "WBCZ_AGENT_ENABLED=false",
    "WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED=false",
    "WBCZ_FBS_DRY_RUN_ONLY=true",
    "WBCZ_TRUE_API_REAL_READ_ENABLED=false",
    "WBCZ_TRUE_API_WRITE_ENABLED=false",
    "WBCZ_PRINTING_ENABLED=false",
    "WBCZ_PRINT_EXECUTION_ENABLED=false",
    "WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=false",
    "WBCZ_TRUE_API_REPORTS_ENABLED=false",
    "SELLARI_LOCAL_FRONTEND_DIST=$($paths.Frontend)",
    "WBCZ_LOCAL_DB_PASSWORD=$appPassword"
)
[System.IO.File]::WriteAllLines($paths.EnvFile, $envLines, [System.Text.UTF8Encoding]::new($false))

Import-SellariEnvFile -Path $paths.EnvFile
Assert-SellariLocalSafety

& $paths.Python -m alembic -c (Join-Path $repo "alembic.ini") upgrade 0020_printing_physical_spool
if ($LASTEXITCODE -ne 0) { throw "Local database migration failed." }

$env:PGPASSWORD = $appPassword
$bootstrapCount = (& $psql.Source -h $PostgresHost -p $PostgresPort -U sellari_local -d sellari_local -Atqc "SELECT count(*) FROM security_bootstrap;").Trim()
if ($LASTEXITCODE -ne 0) { throw "Cannot verify local Sellari bootstrap state." }
if ($bootstrapCount -eq "0") {
    if (-not $OwnerUsername) { $OwnerUsername = Read-Host "Local owner username" }
    Write-Host "Create the local Sellari owner password. It is stored only as a password hash in local PostgreSQL."
    & $paths.Python -m wbcz_web.admin bootstrap-owner $OwnerUsername --organisation $OrganisationName --inn $ParticipantInn --participant-name "WB FBS"
    if ($LASTEXITCODE -ne 0) { throw "Local OWNER bootstrap failed." }
} else {
    Write-Host "Local OWNER already bootstrapped; keeping existing account."
}

if ($null -eq $previousPgPassword) {
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
} else {
    $env:PGPASSWORD = $previousPgPassword
}

& (Join-Path $repo "Check-Local.ps1")
if ($LASTEXITCODE -ne 0) { throw "Local environment preflight failed." }

Write-Host ""
Write-Host "Sellari local setup complete."
Write-Host "Daily start: .\Start-Sellari.ps1"
Write-Host "Local URL: http://127.0.0.1:8765/"
