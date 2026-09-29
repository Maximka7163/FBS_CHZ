Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $repo "scripts\local\Common-Local.ps1")

if (-not (Test-SellariWindows)) {
    throw "Sellari local supports Windows 10/11 only."
}

$paths = Get-SellariLocalPaths -RepositoryRoot $repo
Import-SellariEnvFile -Path $paths.EnvFile
Assert-SellariLocalSafety

if (-not (Test-Path -LiteralPath $paths.Python)) {
    throw "Local Python environment is missing. Run .\Setup-Local.ps1."
}

& $paths.Python -m wbcz_local.preflight
exit $LASTEXITCODE
