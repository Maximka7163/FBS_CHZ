$ErrorActionPreference = 'Stop'

function Get-WbczInstallRoot {
    return (Join-Path $env:LOCALAPPDATA 'Sellari\WbczAgent')
}

function Get-WbczConfig {
    $root = Get-WbczInstallRoot
    $path = Join-Path $root 'config.json'
    if (-not (Test-Path -LiteralPath $path)) { throw "Agent config not found: $path" }
    return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Get-WbczAgentExe {
    $path = Join-Path (Get-WbczInstallRoot) 'app\wbcz-agent\wbcz-agent.exe'
    if (-not (Test-Path -LiteralPath $path)) { throw "Agent executable not found: $path" }
    return $path
}

function Set-WbczRuntimeEnvironment {
    param([Parameter(Mandatory=$true)]$Config)

    if ([string]$Config.backend_url -notmatch '^https://') { throw 'Backend URL must use HTTPS.' }
    if ([string]$Config.participant_inn -notmatch '^(?:\d{10}|\d{12})$') { throw 'Participant INN must be 10 or 12 digits.' }
    if (-not [string]$Config.ukep_thumbprint) { throw 'UKEP thumbprint is required.' }

    $env:WBCZ_AGENT_BACKEND_URL = [string]$Config.backend_url
    $env:WBCZ_PARTICIPANT_INN = [string]$Config.participant_inn
    $env:WBCZ_UKEP_THUMBPRINT = [string]$Config.ukep_thumbprint
    $env:WBCZ_AGENT_DATA_DIR = [string]$Config.data_dir
    $env:WBCZ_AGENT_CREDENTIAL_PATH = [string]$Config.credential_path
    $env:WBCZ_AGENT_PROTOCOL_VERSION = [string]$Config.protocol_version
    $env:WBCZ_AGENT_VERSION = [string]$Config.agent_version

    if ([string]$Config.cryptopro_stunnel) {
        $env:WBCZ_CRYPTOPRO_STUNNEL = [string]$Config.cryptopro_stunnel
    } else {
        Remove-Item Env:WBCZ_CRYPTOPRO_STUNNEL -ErrorAction SilentlyContinue
    }
    if ([string]$Config.cryptopro_cryptcp) {
        $env:WBCZ_CRYPTOPRO_CRYPTCP = [string]$Config.cryptopro_cryptcp
    } else {
        Remove-Item Env:WBCZ_CRYPTOPRO_CRYPTCP -ErrorAction SilentlyContinue
    }

    $env:WBCZ_AGENT_PRODUCTION_WRITE_ENABLED = 'false'
    $env:WBCZ_TRUE_API_WRITE_ENABLED = 'false'
    Remove-Item Env:WBCZ_AGENT_MACHINE_TOKEN -ErrorAction SilentlyContinue
}
