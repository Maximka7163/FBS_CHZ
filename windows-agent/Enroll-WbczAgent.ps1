$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Runtime-Common.ps1')

$config = Get-WbczConfig
Set-WbczRuntimeEnvironment -Config $config
$exe = Get-WbczAgentExe

$secureToken = Read-Host 'One-use agent enrollment token' -AsSecureString
$ptr = [IntPtr]::Zero
$token = $null
$exitCode = 1
try {
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    if ([string]::IsNullOrWhiteSpace($token) -or $token.Length -lt 43) {
        throw 'Enrollment token is invalid.'
    }

    $env:WBCZ_AGENT_ENROLLMENT_TOKEN = $token
    Write-Output 'ENROLLMENT_MODE=ONE_USE'
    Write-Output 'ENROLLMENT_TOKEN_PRINTED=NO'
    Write-Output 'PRODUCTION_WRITE=false'
    & $exe enroll
    $exitCode = $LASTEXITCODE
}
finally {
    Remove-Item Env:WBCZ_AGENT_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    $token = $null
    if ($ptr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
    $secureToken = $null
}

exit $exitCode
