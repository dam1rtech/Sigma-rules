
# Sigma Detection Rules

A small, curated set of [Sigma](https://sigmahq.io/) detection rules I wrote
while learning detection engineering as a SOC analyst. Each rule maps to a
specific [MITRE ATT&CK](https://attack.mitre.org/) technique, documents its
likely false positives, and has been validated against the current Sigma
specification.

The goal of this repo is not to reinvent SigmaHQ's excellent ruleset, but to
practice the full detection-engineering workflow: pick a behaviour → understand
the telemetry that exposes it → express it as a portable rule → reason about
false positives → convert it to a real SIEM query.

## Why Sigma?

Sigma is to logs what YARA is to files and Snort is to network traffic: a
vendor-neutral YAML format for detection logic. One rule can be converted into
SPL (Splunk), KQL / ES|QL (Elastic), Microsoft Sentinel, QRadar and 40+ other
targets, so detection knowledge stays portable across SIEMs.

## Rules in this repository

| Rule | Platform | Tactic | ATT&CK | Level |
|------|----------|--------|--------|-------|
| Kerberoasting via RC4 service ticket | Windows | Credential Access | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | high |
| LSASS memory access (credential dumping) | Windows | Credential Access | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | high |
| Security event log cleared | Windows | Defense Evasion | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | high |
| Suspicious PowerShell (encoded / download cradle) | Windows | Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | medium |
| New service from suspicious binary path | Windows | Persistence | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | high |
| SSH brute force | Linux | Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | medium |
| Cron persistence | Linux | Persistence | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | medium |

Coverage spans four ATT&CK tactics across both Windows and Linux, with a
deliberate mix of single-event rules and correlation-based rules (the SSH rule
uses a `count()` over a timeframe).

## Detection notes

A few rules worth highlighting because the *why* matters more than the YAML:

**Kerberoasting (T1558.003).** Modern domains issue AES-encrypted Kerberos
tickets by default. The rule keys on Event ID `4769` with
`TicketEncryptionType: 0x17` (RC4) and excludes machine accounts (`*$`) and
`krbtgt`, because a burst of RC4 service-ticket requests for normal user
accounts is the signature of an attacker harvesting tickets for offline
cracking — not normal domain behaviour.

**LSASS access (T1003.001).** Rather than matching tool names (which attackers
rename), this rule matches the *behaviour*: any process opening a handle to
`lsass.exe` with access masks used by Mimikatz / procdump
(`0x1010`, `0x1410`, `0x1438`...). It then filters known-legitimate accessors.
Detecting on access rights rather than file names sits higher on the
[Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html).

**False positives are documented, not ignored.** Every rule has a
`falsepositives` section. In a real SOC, an un-tuned rule that fires on every
EDR agent reading LSASS is worse than no rule — it trains analysts to ignore
alerts. The notes describe what to baseline before enabling.

## Converting rules to your SIEM

Rules are validated and converted with [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli).

```bash
pip install sigma-cli
sigma plugin install splunk
sigma plugin install elasticsearch

# Convert a rule to Splunk SPL
sigma convert -t splunk -p splunk_windows rules/windows/win_security_log_cleared.yml
```

### Real conversion output

These are produced from the rules in this repo (not hand-written):

**Security log cleared → Splunk SPL**
```spl
source="WinEventLog:Security" EventCode=1102
| table SubjectUserName,SubjectDomainName
```

**Kerberoasting → Splunk SPL**
```spl
source="WinEventLog:Security" EventCode=4769 TicketEncryptionType="0x17"
  NOT ServiceName="*$" NOT ServiceName="krbtgt"
| table TargetUserName,ServiceName,IpAddress,TicketEncryptionType
```

**New suspicious service → Splunk SPL**
```spl
source="WinEventLog:System" EventCode=7045
  ImagePath IN ("*\\Temp\\*","*\\Users\\*","*\\AppData\\*",
                "*\\ProgramData\\*","*powershell*","*cmd.exe /c*")
| table ServiceName,ImagePath,ServiceType
```

## Validating the rules

A simple YAML/schema check (see `tests/validate.py`) confirms every rule parses
and contains the required fields:

```bash
python3 tests/validate.py
# 7/7 rules valid
```

## Repository layout

```
rules/
  windows/   # AD, credential access, persistence, evasion
  linux/     # SSH, cron persistence
tests/
  validate.py
```

## Roadmap

- [ ] Add cloud rules (AWS CloudTrail, Azure sign-in logs)
- [ ] Validate each rule end-to-end in a home lab (Wazuh + Sysmon + Atomic Red Team)
- [ ] Add Sigma correlation rules for multi-stage detections
- [ ] CI workflow to lint rules on every push

## References

- [SigmaHQ specification](https://sigmahq.io/docs/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [SigmaHQ/sigma rule repository](https://github.com/SigmaHQ/sigma)

---

*These rules are for learning and defensive use. Validate and tune any
detection in a test environment before deploying to production.*
