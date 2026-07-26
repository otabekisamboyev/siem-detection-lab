# Scenario 2 — Brute Force Attack

## Objective
Detect repeated failed logon attempts against a single account from
one source — a pattern indicating credential brute forcing or
password spraying activity.

## MITRE ATT&CK
Tactic:    Credential Access
Technique: T1110 — Brute Force

## Attack Simulation
Script run in elevated PowerShell on the Windows endpoint:

    $username = "FakeUser"
    $password = "WrongPassword"
    $computer = $env:COMPUTERNAME

    1..20 | ForEach-Object {
        $secpass = ConvertTo-SecureString $password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($username, $secpass)
        try {
            Start-Process cmd -Credential $cred -ErrorAction Stop
        } catch {}
        Start-Sleep -Milliseconds 500
    }

Generates 20 consecutive failed logon attempts for a non-existent account (FakeUser) within seconds. Run 3 times.

## Expected Event ID
4625 — An account failed to log on

## Sigma Rule
title: Brute Force - Multiple Failed Logons from Single Source
id: a3c1e2f0-9b4d-4e7a-8c2f-1d5b6a9e0f2c
status: experimental
description: >
  Detects 5 or more failed logon attempts (EID 4625) within 60 seconds
  from a single source — indicative of brute force or password spraying.
references:
    - https://attack.mitre.org/techniques/T1110/
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 60s
    condition: selection | count() > 5
falsepositives:
    - Misconfigured service account with expired credentials
    - User genuinely forgetting password (verify count threshold)
level: high
tags:
    - attack.t1110
    - attack.credential_access

## Custom Wazuh Rule Written
<rule id="100001" level="10" frequency="5" timeframe="60">
  <if_matched_sid>60122</if_matched_sid>
  <description>Custom: Brute Force - 5+ failed logons in 60 seconds</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>

## SIEM Alert — Key Fields
| Field                  | Value                                      |
|------------------------|--------------------------------------------|
| Timestamp              | 2026-07-26T11:51:24.200Z                   |
| Hostname               | DESKTOP-RCE65JQ                            |
| Agent                  | wazuh-win (ID: 001)                        |
| Event ID               | 4625                                       |
| Target User            | FakeUser                                   |
| Subject User           | Infinity                                   |
| Logon Type             | 2 (Interactive)                            |
| Status                 | 0xC000006D (Logon failure)                 |
| SubStatus              | 0xC0000064 (User does not exist)           |
| Source IP              | ::1 (loopback — local simulation)          |
| Wazuh Rule ID          | 100001 (custom threshold rule)             |
| Built-in Rule ID       | 60122 (individual 4625 detection)          |
| Times Fired            | 18                                         |

## Triage Verdict
TRUE POSITIVE — High Priority

Rationale:
- 18+ failed logon attempts for a non-existent account (FakeUser)
  within seconds — no legitimate use case generates this pattern
- SubStatus 0xC0000064 confirms the username does not exist —
  consistent with username enumeration before credential stuffing
- Source IP ::1 indicates local process origin in this simulation;
  in a real incident, a remote IP here would be the primary IOC
- Logon Type 2 (Interactive) suggests direct console or RDP attempt

## Investigative Notes
Key pivot points for real incident:
- Cross-reference SubjectUserName (Infinity) against EID 4624 to
  check if any logon eventually succeeded after the failures
- SubStatus codes narrow attacker knowledge:
    0xC0000064 = username unknown (enumeration phase)
    0xC000006A = username valid, wrong password (spraying phase)
- If source IP is remote: block at firewall, check lateral movement
  via EID 4648 (explicit credential use) and EID 4624 (success)