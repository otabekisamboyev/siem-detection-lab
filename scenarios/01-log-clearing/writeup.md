# Scenario 1 — Audit Log Clearing

## Objective
Detect when the Windows Security event log is cleared — a common
anti-forensics technique used post-compromise to destroy evidence.

## MITRE ATT&CK
Tactic:    Defense Evasion
Technique: T1070 — Indicator Removal: Clear Windows Event Logs

## Attack Simulation
Command run in elevated PowerShell on the Windows endpoint:
    wevtutil cl Security

## Expected Event ID
1102 — "The audit log was cleared"
Source: Microsoft-Windows-Eventlog / Security channel

## Sigma Rule
title: Windows Security Audit Log Cleared
id: f6e5e1a0-3c4b-4f8e-9d2a-7b1c6e8f0a3d
status: experimental
description: >
  Detects clearing of the Windows Security event log via EID 1102.
  Common post-compromise anti-forensics step to destroy authentication
  and process execution history.
references:
    - https://attack.mitre.org/techniques/T1070/
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1102
    condition: selection
falsepositives:
    - Legitimate log rotation by a sysadmin (verify SubjectUserName
      against authorized admin list and check for a change request)
level: high
tags:
    - attack.t1070
    - attack.defense_evasion

## SIEM Alert — Key Fields
| Field                  | Value                                      |
|------------------------|--------------------------------------------|
| Timestamp              | 2026-05-28T05:39:48.278Z                   |
| Hostname               | DESKTOP-RCE65JQ                            |
| Agent                  | wazuh-win (ID: 001)                        |
| Event ID               | 1102                                       |
| Subject User           | Infinity                                   |
| Logon ID               | 0x7D1F2                                    |
| Wazuh Rule ID          | 63103 (level 5)                            |
| Rule Groups            | windows, windows_logs, log_clearing_auditlog|
| MITRE Technique        | T1070 — Indicator Removal                  |

## Triage Verdict
TRUE POSITIVE — High Priority

Rationale:
- EID 1102 has no legitimate automated cause in a standard workstation
- SubjectUserName "Infinity" is an interactive user account, not a
  service or scheduled task
- No maintenance window or change request on record
- Log clearing destroys prior authentication history — escalate
  immediately and preserve this alert as the earliest known artifact

## Investigative Notes
Logon ID 0x7D1F2 can be cross-referenced against EID 4624 to
reconstruct exactly when the session that cleared the log was
established — useful for building a full attack timeline.