param([string]$Cis = '')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Runtime-Common.ps1')

$config = Get-WbczConfig
Set-WbczRuntimeEnvironment -Config $config
$exe = Get-WbczAgentExe
$args = @('preflight')
if ($Cis) { $args += @('--cis', $Cis) }

Write-Output 'PREFLIGHT_MODE=SAFE_READ_ONLY'
Write-Output 'PRODUCTION_WRITE=false'
& $exe @args
exit $LASTEXITCODE
