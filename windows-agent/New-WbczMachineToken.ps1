$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'Sellari\WbczAgent'
if (-not (Test-Path -LiteralPath $root)) { throw "Agent is not installed at $root" }
$secretPath = Join-Path $root 'machine-token.dpapi'
if (Test-Path -LiteralPath $secretPath) { throw 'Machine token already exists; refusing to overwrite.' }

$bytes = New-Object byte[] 48
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
[Array]::Clear($bytes, 0, $bytes.Length)
if ($token.Length -lt 32) { throw 'Generated token is unexpectedly short.' }
$secure = ConvertTo-SecureString -String $token -AsPlainText -Force
$encrypted = ConvertFrom-SecureString -SecureString $secure
[IO.File]::WriteAllText($secretPath, $encrypted, (New-Object Text.UTF8Encoding($false)))
Set-Clipboard -Value $token
$token = $null
$encrypted = $null
Write-Output 'MACHINE_TOKEN_CREATED=YES'
Write-Output 'TOKEN_PRINTED=NO'
Write-Output 'TOKEN_COPIED_TO_CLIPBOARD=YES'
Write-Output 'ACTION=Paste once into the VPS configure-agent-machine-secret.sh hidden prompt, then clear the clipboard with Set-Clipboard -Value "".'
