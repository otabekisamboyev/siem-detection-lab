# siem-detection-lab

Home lab built to simulate, detect, and triage real-world attack
scenarios using Wazuh SIEM + Sysmon on a Windows 10 endpoint.

## Stack
- SIEM: Wazuh v4.14.5
- Endpoint: Windows 10 (VMware)
- Telemetry: Sysmon (SwiftOnSecurity config)

## Scenarios
| # | Scenario | Event ID | MITRE | Status |
|---|----------|----------|-------|--------|
| 1 | Audit Log Clearing | EID 1102 | T1070 | ✅ Done |
| 2 | Brute Force | EID 4625 | T1110 | ✅ Done |
| 3 | Scheduled Task Persistence | EID 4698 | T1053.005 | ⏳ Pending |
| 4 | Encoded PowerShell | Sysmon EID 1 | T1059.001 | ⏳ Pending |
| 5 | LSASS Dump | Sysmon EID 10 | T1003.001 | ⏳ Pending |

## About
Built as part of a self-directed SOC analyst training roadmap.
Each scenario includes the attack simulation, detection rule (Sigma format),
SIEM alert evidence, and triage verdict.
