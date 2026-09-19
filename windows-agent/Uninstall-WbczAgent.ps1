param([switch]$Force)
$ErrorActionPreference = 'Stop'

$root = Join-Path $env:LOCALAPPDATA 'Sellari\WbczAgent'
if (-not (Test-Path -LiteralPath $root)) {
    Write-Output 'UNINSTALL_STATUS=NOT_INSTALLED'
    exit 0
}
if (-not $Force) {
    $answer = Read-Host "Remove $root including local runtime data? Type REMOVE"
    if ($answer -ne 'REMOVE') { throw 'Uninstall cancelled.' }
}

Remove-Item -LiteralPath $root -Recurse -Force
Remove-Item Env:WBCZ_AGENT_MACHINE_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:WBCZ_AGENT_BACKEND_URL -ErrorAction SilentlyContinue
Remove-Item Env:WBCZ_PARTICIPANT_INN -ErrorAction SilentlyContinue
Remove-Item Env:WBCZ_UKEP_THUMBPRINT -ErrorAction SilentlyContinue

Write-Output 'UNINSTALL_STATUS=OK'
Write-Output 'CRYPTOPRO_CHANGED=NO'
Write-Output 'CERTIFICATE_CHANGED=NO'
