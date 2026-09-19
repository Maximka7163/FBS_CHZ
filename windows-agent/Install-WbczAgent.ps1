param([switch]$Force)
$ErrorActionPreference = 'Stop'

$source = $PSScriptRoot
$root = Join-Path $env:LOCALAPPDATA 'Sellari\WbczAgent'
$app = Join-Path $root 'app'
$data = Join-Path $root 'data'

if ((Test-Path -LiteralPath $root) -and -not $Force) {
    throw "Installation already exists at $root. Use -Force only for an operator-approved package refresh."
}

New-Item -ItemType Directory -Path $root -Force | Out-Null
New-Item -ItemType Directory -Path $data -Force | Out-Null
if (Test-Path -LiteralPath $app) {
    Remove-Item -LiteralPath $app -Recurse -Force
}
Copy-Item -LiteralPath (Join-Path $source 'app') -Destination $root -Recurse -Force

$helpers = @(
    'Runtime-Common.ps1',
    'Set-WbczAgentConfig.ps1',
    'Preflight-WbczAgent.ps1',
    'Start-WbczAgent.ps1',
    'Uninstall-WbczAgent.ps1',
    'README.txt',
    'VERSION.json'
)
foreach ($name in $helpers) {
    Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $root $name) -Force
}

Write-Output 'INSTALL_STATUS=OK'
Write-Output "INSTALL_PATH=$root"
Write-Output 'EXISTING_DATA_PRESERVED=YES'
Write-Output 'PRODUCTION_WRITE=false'
