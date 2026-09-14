Sellari / WBCZ Windows Agent — P0 runtime package

SOURCE COMMIT: 858a329b56c2cabae62e9814f540072e8a048d3f
PRODUCTION DOCUMENT WRITE: DISABLED

Operator flow:
1. Extract this ZIP to a local folder.
2. Open PowerShell as the Windows user who owns/uses the CryptoPro certificate.
3. Run: .\Install-WbczAgent.ps1
4. Run installed New-WbczMachineToken.ps1. It stores the token DPAPI-encrypted and copies it to clipboard without printing it.
5. On the VPS, run deploy/configure-agent-machine-secret.sh and paste the token into its hidden prompt. The helper enables only the agent API and proves WBCZ_TRUE_API_WRITE_ENABLED=false.
6. Immediately clear the Windows clipboard: Set-Clipboard -Value ""
7. Run installed Set-WbczAgentConfig.ps1 and enter HTTPS backend URL, participant INN and UKEP thumbprint. Optional CryptoPro paths can be supplied as parameters. PIN is never stored or requested by these scripts.
8. Safe preflight: .\Preflight-WbczAgent.ps1
   Optional read-only CIS check: .\Preflight-WbczAgent.ps1 -Cis '<KIZ>'
9. Do not run Start-WbczAgent.ps1 until the deployment/preflight task explicitly authorizes it.

Preflight checks Windows/CryptoPro/certificate/backend/auth/GOST TLS and optional cises/info. It cannot enable production document write. The launchers force both WBCZ_AGENT_PRODUCTION_WRITE_ENABLED=false and WBCZ_TRUE_API_WRITE_ENABLED=false.

Contract capture is OFF by default. Save-WbczContractCapture.ps1 only writes a response capture when -EnableCapture is explicitly supplied by a later authorized runtime-contract task. It captures response status, content type, body, SHA256 and correlation id only; never request headers/body, bearer token, machine token or signatures.

Uninstall:
  .\Uninstall-WbczAgent.ps1
This removes only the WBCZ agent installation/data for the current user. It does not change CryptoPro or certificates.
