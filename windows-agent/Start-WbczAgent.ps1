$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Runtime-Common.ps1')
$config = Get-WbczConfig
Set-WbczRuntimeEnvironment -Config $config
$exe = Get-WbczAgentExe
Write-Output 'AGENT_MODE=OUTBOUND_ONLY'
Write-Output 'PRODUCTION_WRITE=false'
& $exe run
exit $LASTEXITCODE
