param(
  [string]$BackendUrl,
  [string]$ParticipantInn,
  [string]$UkepThumbprint,
  [string]$CryptoProStunnel = '',
  [string]$CryptoProCryptcp = ''
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'Sellari\WbczAgent'
if (-not (Test-Path -LiteralPath $root)) { throw "Agent is not installed at $root" }
if (-not $BackendUrl) { $BackendUrl = Read-Host 'Backend HTTPS URL, e.g. https://mark.sellari.ru' }
if (-not $ParticipantInn) { $ParticipantInn = Read-Host 'Participant INN (10 or 12 digits)' }
if (-not $UkepThumbprint) { $UkepThumbprint = Read-Host 'UKEP certificate thumbprint' }
$BackendUrl = $BackendUrl.Trim().TrimEnd('/')
$ParticipantInn = $ParticipantInn.Trim()
$UkepThumbprint = ($UkepThumbprint -replace '\s','').ToUpperInvariant()
if ($BackendUrl -notmatch '^https://[^/]+(?:/.*)?$') { throw 'Backend URL must be HTTPS.' }
if ($ParticipantInn -notmatch '^(?:\d{10}|\d{12})$') { throw 'Participant INN must be 10 or 12 digits.' }
if (-not $UkepThumbprint) { throw 'UKEP thumbprint is required.' }
$dataDir = Join-Path $root 'data'
$config = [ordered]@{
  backend_url = $BackendUrl
  participant_inn = $ParticipantInn
  ukep_thumbprint = $UkepThumbprint
  cryptopro_stunnel = $CryptoProStunnel.Trim()
  cryptopro_cryptcp = $CryptoProCryptcp.Trim()
  data_dir = $dataDir
  production_write = $false
}
$configPath = Join-Path $root 'config.json'
$config | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $configPath -Encoding UTF8
Write-Output 'CONFIG_STATUS=OK'
Write-Output "CONFIG_PATH=$configPath"
Write-Output 'MACHINE_TOKEN_STORED_IN_CONFIG=NO'
Write-Output 'PIN_STORED_IN_CONFIG=NO'
Write-Output 'PRODUCTION_WRITE=false'
