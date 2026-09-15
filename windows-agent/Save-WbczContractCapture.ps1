param(
  [Parameter(Mandatory=$true)][ValidateSet('create','poll')] [string]$Kind,
  [Parameter(Mandatory=$true)][int]$Status,
  [string]$ContentType = '',
  [Parameter(Mandatory=$true)][string]$BodyPath,
  [string]$CorrelationId = '',
  [switch]$EnableCapture
)
$ErrorActionPreference = 'Stop'
if (-not $EnableCapture) {
    Write-Output 'CAPTURE_DISABLED=YES'
    exit 0
}
if (-not (Test-Path -LiteralPath $BodyPath)) { throw 'Response body file not found.' }
$root = Join-Path $env:LOCALAPPDATA 'Sellari\WbczAgent\data\contract-captures'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$bytes = [IO.File]::ReadAllBytes($BodyPath)
$sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
$record = [ordered]@{
  schema = 'wbcz-safe-contract-capture-v1'
  kind = $Kind
  captured_at_utc = [DateTime]::UtcNow.ToString('o')
  http_status = $Status
  content_type = $ContentType
  response_sha256 = $sha
  request_correlation_id = $CorrelationId
  response_body_base64 = [Convert]::ToBase64String($bytes)
  request_headers_captured = $false
  request_body_captured = $false
  bearer_token_captured = $false
  machine_token_captured = $false
  signature_captured = $false
}
$name = '{0}-{1}-{2}.json' -f $Kind,([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')),$sha.Substring(0,12)
$path = Join-Path $root $name
$record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path -Encoding UTF8
Write-Output 'CAPTURE_STATUS=OK'
Write-Output "CAPTURE_PATH=$path"
Write-Output "RESPONSE_SHA256=$sha"
Write-Output 'SECRETS_CAPTURED=NO'
