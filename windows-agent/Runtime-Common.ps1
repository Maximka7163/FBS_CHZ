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

function Get-WbczMachineToken {
    $root = Get-WbczInstallRoot
    $path = Join-Path $root 'machine-token.dpapi'
    if (-not (Test-Path -LiteralPath $path)) { throw "Machine token is not provisioned. Run New-WbczMachineToken.ps1 first." }
    $secure = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertTo-SecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function Set-WbczRuntimeEnvironment {
    param([Parameter(Mandatory=$true)]$Config)
    $token = Get-WbczMachineToken
    try {
        if ($Config.backend_url -notmatch '^https://') { throw 'WBCZ_AGENT_BACKEND_URL must use HTTPS.' }
        $env:WBCZ_AGENT_BACKEND_URL = [string]$Config.backend_url
        $env:WBCZ_AGENT_MACHINE_TOKEN = $token
        $env:WBCZ_PARTICIPANT_INN = [string]$Config.participant_inn
        $env:WBCZ_UKEP_THUMBPRINT = [string]$Config.ukep_thumbprint
        $env:WBCZ_AGENT_DATA_DIR = [string]$Config.data_dir
        if ($Config.cryptopro_stunnel) { $env:WBCZ_CRYPTOPRO_STUNNEL = [string]$Config.cryptopro_stunnel } else { Remove-Item Env:WBCZ_CRYPTOPRO_STUNNEL -ErrorAction SilentlyContinue }
        if ($Config.cryptopro_cryptcp) { $env:WBCZ_CRYPTOPRO_CRYPTCP = [string]$Config.cryptopro_cryptcp } else { Remove-Item Env:WBCZ_CRYPTOPRO_CRYPTCP -ErrorAction SilentlyContinue }
        # Hard gate: launchers never inherit or enable document write.
        $env:WBCZ_AGENT_PRODUCTION_WRITE_ENABLED = 'false'
        $env:WBCZ_TRUE_API_WRITE_ENABLED = 'false'
    }
    finally {
        $token = $null
    }
}

function Get-WbczAgentExe {
    $exe = Join-Path (Get-WbczInstallRoot) 'app\wbcz-agent\wbcz-agent.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw "wbcz-agent executable not found: $exe" }
    return $exe
}
