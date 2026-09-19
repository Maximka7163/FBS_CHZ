Sellari / WBCZ Windows Agent — P0 RC1

This package is produced from the exact release/p0-rc1 source SHA recorded in VERSION.json.

SAFETY
- Production True API document write is disabled.
- The package contains no runtime credentials, certificate material, participant data or PIN.
- The agent is outbound HTTPS only.
- Participant-bound permanent agent credential storage is handled by the accepted M15 DPAPI enrollment path.
- Private key and PIN remain inside the Windows/CryptoPro boundary.

FUTURE OPERATOR FLOW — ONLY AFTER SEPARATE AUTHORIZATION
1. Verify the ZIP SHA256 sidecar.
2. Run .\Install-WbczAgent.ps1
3. Run installed .\Set-WbczAgentConfig.ps1
4. Run .\Enroll-WbczAgent.ps1 and paste the one-use enrollment token into the hidden prompt.
   The helper clears WBCZ_AGENT_ENROLLMENT_TOKEN after the exchange; the permanent credential is stored by wbcz-agent through DPAPI and is not printed.
5. Run .\Preflight-WbczAgent.ps1
   Optional read-only CIS check:
   .\Preflight-WbczAgent.ps1 -Cis '<approved-test-cis>'
6. Do NOT run Start-WbczAgent.ps1 until separately authorized.

The helper scripts force WBCZ_AGENT_PRODUCTION_WRITE_ENABLED=false and
WBCZ_TRUE_API_WRITE_ENABLED=false. They cannot enable a business-document write.

Uninstall-WbczAgent.ps1 removes only the WBCZ agent installation/data for the current user.
It does not modify CryptoPro or certificates.
