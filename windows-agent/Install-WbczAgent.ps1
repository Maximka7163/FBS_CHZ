param([switch]$Force)
$ErrorActionPreference = 'Stop'
$source = $PSScriptRoot
$root = Join-Path $env:LOCALAPPDATA 'Sellari\WbczAgent'

if ((Test-Path -LiteralPath $root) -and -not $Force) {
    throw "Installation already exists at $root. Re-run with -Force only after backing up config/data."
}
if ($Force -and (Test-Path -LiteralPath $root)) {
    Remove-Item -LiteralPath $root -Recurse -Force
}
New-Item -ItemType Directory -Path $root -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'data') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $source 'app') -Destination $root -Recurse -Force
$helpers = @(
  'Runtime-Common.ps1','New-WbczMachineToken.ps1','Set-WbczAgentConfig.ps1',
  'Preflight-WbczAgent.ps1','Start-WbczAgent.ps1','Save-WbczContractCapture.ps1',
  'Uninstall-WbczAgent.ps1','README.txt','VERSION.json'
)
foreach ($name in $helpers) {
    Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $root $name) -Force
}
Write-Output 'INSTALL_STATUS=OK'
Write-Output "INSTALL_PATH=$root"
Write-Output 'NEXT=Run New-WbczMachineToken.ps1, provision the copied token into the VPS secure helper, clear clipboard, then run Set-WbczAgentConfig.ps1.'
Write-Output 'PRODUCTION_WRITE=false'
