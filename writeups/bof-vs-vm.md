---
title: "BOF vs VM Script Execution: What Memory Scanners Actually See"
kicker: "Evasion Engineering . Runtime . Memory Forensics"
tags: "Evasion Engineering . C2 Development . Memory Forensics . BOF . VM Execution"
lead: "BOFs and VM scripts both run post-exploitation tasks inside the agent process. They solve the same problem but create different detection surfaces. I ran Moneta, API Monitor, and Sysmon against both execution methods on the same beacon. Only one tool could tell the difference."
---

> This is the second post in the Evasion Engineering series. The first post covered static evasion for the Beacon loader. This post covers runtime evasion: what happens in memory when the beacon executes a task, and how different execution models create different detection surfaces.
>
> All testing was done in a homelab environment. 

---

## Background: Two Execution Models

### BOF Execution (COFF Loader)

A BOF as you may well know is a compiled COFF object file. The agent's COFF loader allocates executable memory, maps the `.text` and `.data` sections, applies relocations, resolves imports, and calls the entry point. The BOF runs as native x86-64 code inside the agent process. After execution, the loader frees the mapped memory.

BOFs give operators full access to the Win32 and NT API surface. Any C or C++ code that compiles to a COFF object can run as a BOF. The loader must allocate memory with executable permissions, and that allocation is visible to memory scanners.

### VM Script Execution (Bytecode Interpreter)

The custom C2 used for this demonstration includes a custom bytecode virtual machine built into its agent(Eclipse). Operators write programs in a purpose-built small assembly language (`.vms` files). The teamserver assembles them to bytecode. The agent receives the bytecode as a task payload and executes it through a compiled C++ interpreter loop.

The VM gives operators an execution layer that EDR cannot signature. Traditional post-exploitation drops shellcode or spawns tools that defenders have seen before. The VM interpreter is a single function in the agent that resolves and invokes Win32 APIs dynamically through hashed lookups. From the outside, it looks like a tight loop doing arithmetic on local variables. From the inside, it can do anything the agent can do. 

```
    Operator               Teamserver              Target
  .vms source    ──>   bytecode (code+data)  ──>  execution
```

The VM follows a RISC (Reduced Instruction Set Computer) design. Every instruction does one simple thing. Arithmetic operates only on registers. Memory access requires explicit load/store instructions. API calls go through a resolve + invoke pattern that hashes module and function names at assembly time and walks the PEB at runtime. 

**The interpreter loop over opcode bytes. It reads from a PAGE_READWRITE heap buffer. The bytecode never becomes executable memory. From the OS perspective, the agent is just reading data from a heap allocation and executing its own compiled code.**

#### RISC Architecture

A custom RISC instruction set gives the VM two properties that matter for evasion:

1. **No native ISA match:** The bytecode is not x86, not ARM, not .NET IL. Standard disassemblers and analysis tools cannot parse it. EDR cannot apply existing signatures.
2. **Compact interpreter:** A RISC instruction set is small enough that the entire interpreter fits in a single function. The smaller the interpreter, the less surface area for behavioral detection.

#### Hash-Based API Resolution

VM scripts never reference API names as strings. The `resolve` opcode takes two hash values for the module and the function:

```asm
hash r1, "kernel32.dll"     ; assembler computes DJB2 hash at compile time
hash r2, "GetUserNameA"     ; becomes a MOV_IMM with the hash constant
resolve r0, r1, r2          ; runtime: walks PEB -> export table by hash
invoke 2, r0, r3, r4        ; call with 2 args, return value in r0
```

The resolution walks `InLoadOrderModuleList` in the PEB, hashes each module name, and compares against the target. Then it walks the module's export address table with the same hash comparison. No `GetProcAddress` call is made. No API name strings exist in the bytecode.

#### Stack-Spoofed API Calls

Every native API call from a VM script passes through the agent's stack frame spoofing layer:

```
VM invoke opcode -> ExecInvoke() -> Spf->Call(FuncAddr, Args[0..11])
```

The spoof layer constructs a synthetic call stack with return frames pointing into legitimate system DLLs (`ntdll!RtlUserThreadStart`, `kernel32!BaseThreadInitThunk`). When an EDR inspects the call stack, it sees a clean chain through system code. The actual call originates from the agent's own `.text` section, not from dynamically allocated memory.

#### Automatic Cleanup

The VM tracks all heap allocations (up to 64) in an internal table. On interpreter exit, whether normal (`halt`), error, or iteration limit, `FreeAllAllocs()` releases every tracked allocation. No leftover buffers remain for a memory scanner to inspect after execution.

---

## Tools

| Tool | Purpose | Download |
|------|---------|----------|
| **Moneta** | Memory anomaly scanner. Flags private executable regions, unbacked code, modified PE sections. | [github.com/forrest-orr/moneta](https://github.com/forrest-orr/moneta/releases) |
| **API Monitor** | Real-time Win32 API call capture with arguments and return values. | [rohitab.com/apimonitor](http://www.rohitab.com/apimonitor) |
| **Sysmon** | ETW event logging. Shows what a SOC analyst sees in their SIEM. | [learn.microsoft.com](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |

The Sysmon configuration used for this writeup is available here: [sysmonconfig.xml](writeups/images/bof-vs-vm/sysmonconfig.xml)

---

## Lab Setup

### Agent Configuration

- **Sleep:** 60s
- **Jitter:** 0%
- **Module stomping:** Disabled

A fixed 60-second callback gives a predictable window for scanning. No jitter keeps timestamps consistent.

![Agent sleep and jitter configuration](writeups/images/bof-vs-vm/2026-10-20_18-55.png)

Module stomping was disabled for this test. When enabled, the BOF loader maps COFF sections into a legitimate DLL's memory region instead of a fresh private allocation. That hides the BOF from Moneta's private-executable-memory check and defeats the comparison. With module stomping off, BOFs allocate raw private RX memory that Moneta flags.

![Module stomping disabled](writeups/images/bof-vs-vm/2026-10-20_18-56.png)

### Install Sysmon

The Sysmon configuration is tuned for in-process execution detection. It captures the event types most relevant to BOF and VM execution.

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml
```

![Sysmon installation](writeups/images/bof-vs-vm/sysmon-install.png)

Key event IDs in the config:

| Event ID | Name | Relevance |
|----------|------|-----------|
| 1 | Process creation | Detects child process spawns |
| 7 | Image load | Detects DLLs loaded into the beacon |
| 8 | CreateRemoteThread | Detects cross-process thread injection |
| 10 | ProcessAccess | Detects handle opens with dangerous access rights |
| 17/18 | Named pipe create/connect | Detects IPC-based lateral movement |
| 25 | Process tampering | Detects hollowing, herpaderping, ghosting |

### Install API Monitor

Open API Monitor (x64). Set API filters before attaching to the beacon process:

- `kernel32.dll` > `GetProcAddress`
- `kernel32.dll` > `VirtualAlloc`, `VirtualProtect`, `VirtualFree`
- `ntdll.dll` > `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`

![API Monitor filter setup](writeups/images/bof-vs-vm/api-monitor-filter.png)

### Deploy Beacon

Deployed an agent(Eclipse) with the settings above. Let it check in and I note the PID from the operator C2 console. Right-clicked the beacon process in the Running Processes pane and selected Start Monitoring.

![Beacon process in API Monitor](writeups/images/bof-vs-vm/api-monitor-attach-1.png)

![Monitoring started](writeups/images/bof-vs-vm/api-monitor-attach-2.png)

---

## Phase 1: Baseline (No Tasking)

Each tool was attached to the beacon process independently, not started at the same time. Moneta and API Monitor were pointed at the process after it checked in. Sysmon had been logging system-wide since install, so its baseline already contains prior agent activity (network callbacks, image loads from startup). The baseline for each tool is the state of that tool's output before any BOF or VM script was tasked. Differences between phases are what matter, not the absolute content of any single screenshot.

Beaco checked in: 

![Beacon checked in](writeups/images/bof-vs-vm/beacon-checkin.png)

### Moneta Baseline

```powershell
Moneta64.exe -m ioc -p <beacon_pid> > baseline.txt
```

![Moneta baseline scan](writeups/images/bof-vs-vm/moneta-baseline.png)

The baseline scan shows findings that come from the beacon itself, not from any tasking:

- **Abnormal private executable memory (RX, RWX):** The beacon's shellcode loader and sleep obfuscation routines. These exist from the moment the beacon starts.
- **Unsigned module:** The beacon EXE has no digital signature.
- **Phantom image / Mismatching PEB module:** Sleep masking or module unlinking artifacts.

These findings are the beacon's resting footprint. They appear in every scan regardless of whether a BOF or VM script has executed.

### API Monitor Baseline

Let the beacon idle through 1-2 callback cycles (about 2 minutes at 60s sleep). The log shows only `NtProtectVirtualMemory` calls from the sleep obfuscation cycle (flipping memory protection on each callback).

![API Monitor baseline](writeups/images/bof-vs-vm/api-monitor-baseline.png)

### Sysmon Baseline

Open Event Viewer at `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`.

![Sysmon operational log](writeups/images/bof-vs-vm/sysmon-operational.png)

Filter by the beacon PID using an XML query:

```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[EventData[Data[@Name='ProcessId'] = '<beacon_pid>']]
    </Select>
  </Query>
</QueryList>
```

![Sysmon XML filter](writeups/images/bof-vs-vm/sysmon-filter.png)

The filtered view shows only Event ID 3 (Network Connection) entries from the beacon's HTTPS callbacks and a single Event ID 7 (Image Load) from process startup. No suspicious events.

![Sysmon baseline events](writeups/images/bof-vs-vm/sysmon-baseline.png)

---

## Phase 2: BOF Execution

### Task the BOF

Task the beacon with a simple BOF (`whoami`). A simple command keeps the focus on BOF loading mechanics rather than the BOF's own API calls.

![BOF whoami tasked](writeups/images/bof-vs-vm/bof-tasked.png)

### Moneta During BOF Execution

Run Moneta in a loop to catch the transient memory allocation:

```powershell
while ($true) { .\Moneta64.exe -m ioc -p <beacon_pid>; Start-Sleep -Seconds 2 }
```

![Moneta loop catching BOF allocation](writeups/images/bof-vs-vm/moneta-bof.png)

A new private executable region appeared at `0x00000256A4AD0000` and then disappeared after a few scan cycles:

**Baseline (before BOF):** 3 private regions.
```
0x00000256A4960000:0x0001e000   | Private
  0x00000256A4979000:0x00005000 | RX  | Abnormal private executable memory
```

**During BOF execution:** 4 private regions. New entry:
```
0x00000256A4AD0000:0x0001a000   | Private
  0x00000256A4AD0000:0x00001000 | RX  | Abnormal private executable memory
```

This new region is the BOF's COFF `.text` section mapped into private executable memory. Moneta flags it because it is a private allocation with execute permissions and no backing image on disk. After the BOF finishes, the beacon frees this allocation and the region disappears from subsequent scans.

This is the fundamental detection surface of BOF execution. The COFF loader must allocate executable memory. Memory scanners like Moneta, PE-sieve, and Hunt-Sleeping-Beacons can detect this allocation.

### API Monitor During BOF Execution

![API Monitor during BOF](writeups/images/bof-vs-vm/api-monitor-bof.png)

The API Monitor log shows no `GetProcAddress` calls during BOF execution. The beacon's COFF loader resolves BOF imports by walking the PEB and parsing export address tables directly. It does not call `GetProcAddress` from `kernel32.dll`.

`GetProcAddress` is one of the most heavily hooked APIs by EDR products. By resolving imports through manual PEB/EAT walking, the loader avoids triggering API hooks that would flag dynamic import resolution.

The only calls visible are the same `NtProtectVirtualMemory` pattern from the sleep obfuscation cycle. No new API calls from the BOF loading process appear in the filtered log.

However, this API-level evasion does not prevent memory-level detection. Moneta caught the BOF through its memory allocation even though the loader avoided all hooked API calls.

### Sysmon During BOF Execution

![Sysmon during BOF execution](writeups/images/bof-vs-vm/sysmon-bof.png)

Sysmon recorded no events from the BOF execution. The `whoami` BOF runs entirely inline on the beacon's existing thread. It does not:

- Spawn a child process (no Event ID 1)
- Create a thread in another process (no Event ID 8)
- Open a handle to another process (no Event ID 10)
- Load a new DLL (no Event ID 7)

From Sysmon's perspective, nothing happened. Sysmon monitors inter-process activity and system-level events, not in-process memory operations.

---

## Phase 3: VM Script Execution

### Task the VM Script

Task the beacon with a VM `whoami` script. This is the same operation as the BOF, implemented as VM bytecode instead of native COFF code.

![VM whoami tasked](writeups/images/bof-vs-vm/vm-tasked.png)

### Moneta During VM Execution

Run the same Moneta loop:

```powershell
while ($true) { .\Moneta64.exe -m ioc -p <beacon_pid>; Start-Sleep -Seconds 2 }
```

![Moneta loop during VM execution - part 1](writeups/images/bof-vs-vm/moneta-vm-1.png)

![Moneta loop during VM execution - part 2](writeups/images/bof-vs-vm/moneta-vm-2.png)

Every scan iteration is identical to the baseline. No new private executable regions appear. The `0x00000256A4AD0000` region that appeared during BOF execution does not appear during VM execution.

The VM bytecode sits in a `PAGE_READWRITE` heap allocation. The interpreter reads opcode bytes from this buffer and dispatches operations through a compiled `switch` statement in the agent's own `.text` section. No executable memory is allocated for the script. The bytecode is data, not code.

### API Monitor During VM Execution

![API Monitor during VM execution](writeups/images/bof-vs-vm/api-monitor-vm.png)

The API Monitor log matches the baseline. The same `NtProtectVirtualMemory` calls from sleep obfuscation, nothing else. No `GetProcAddress` burst, no `VirtualAlloc` with executable protection, no `VirtualProtect` calls flipping memory to RX.

The VM's `resolve` opcode walks the PEB and export tables using the same hash-based resolution the agent uses for its own API calls. No calls to `GetProcAddress` or `LoadLibrary` are made. The `invoke` opcode calls the resolved function pointer through the stack spoofing layer, so the call originates from the agent's legitimate `.text` section.

### Sysmon During VM Execution

![Sysmon during VM execution](writeups/images/bof-vs-vm/sysmon-vm.png)

Sysmon recorded no events from the VM execution. The same result as BOF execution. Both methods run inline on the beacon's thread without creating processes, threads, or cross-process handles.

---

## Results

### Moneta: Memory-Level Detection

| Scan Point | BOF Execution | VM Script Execution |
|------------|--------------|---------------------|
| New private RX region | Yes, at `0x00000256A4AD0000` | No |
| Baseline match | No, additional region flagged | Yes, identical to baseline |
| Detection window | Transient (freed after execution) | None |

Moneta is the only tool that distinguished BOF execution from VM execution. The BOF's COFF `.text` section created a private executable memory region with no backing image. The VM script created no executable memory at all.

### API Monitor: API-Level Detection

| Indicator | BOF Execution | VM Script Execution |
|-----------|--------------|---------------------|
| `GetProcAddress` calls | None (PEB walking) | None (PEB walking) |
| `VirtualAlloc` with EXECUTE | Not captured | Not captured |
| `NtProtectVirtualMemory` | Baseline pattern only | Baseline pattern only |

API Monitor could not distinguish BOF execution from VM execution or idle baseline. Both the COFF loader and the VM interpreter resolve APIs through PEB/EAT walking, bypassing `GetProcAddress` hooks entirely. The API-level evasion is equivalent.

### Sysmon: Event-Level Detection

| Event Type | BOF Execution | VM Script Execution |
|------------|--------------|---------------------|
| Process creation (ID 1) | None | None |
| Image load (ID 7) | None | None |
| CreateRemoteThread (ID 8) | None | None |
| ProcessAccess (ID 10) | None | None |
| Process tampering (ID 25) | None | None |
| Network connection (ID 3) | Baseline callbacks only | Baseline callbacks only |

Sysmon could not distinguish either execution method from an idle beacon. Both BOFs and VM scripts run inline on the beacon's existing thread without inter-process interaction.

---

## Detection Surface Comparison

| Detection Layer | VM Script | BOF |
|-----------------|-----------|-----|
| Memory permission scanning | No exposure. No RX/RWX allocations for script code. | Exposed. `.text` sections require `PAGE_EXECUTE_READ`. |
| Memory content scanning | Low. Bytecode has no recognizable file format. | Exposed. Native x86-64 in RX memory can be disassembled and signature-matched. |
| Call stack analysis | Low. Calls originate from compiled agent `.text` with spoofed frames. | Medium. Calls originate from dynamic RX memory unless `BofProxy` is enabled. |
| API hooking | No `GetProcAddress` calls. Hash-based PEB resolution. | No `GetProcAddress` calls. PEB/EAT walking in the COFF loader. |
| ETW/syscall tracing | Same as agent. The APIs are called legitimately. | Same as agent. Same API calls, different origin address. |
| Import analysis | None. No import table exists in the bytecode. | Partial. `__imp_` symbol names and relocation entries reveal intent. |
| Behavioral analysis | Medium. The sequence of API calls reveals intent regardless of execution model. | Medium. Same behavioral footprint. |
| Persistent memory artifacts | None. Full cleanup after execution. | Low for one-shot BOFs. Medium for PostEx BOFs (XOR-encrypted but still resident). |

---

## Conclusion

The three tools tested in this writeup operate at different layers of the detection stack:

1. **Moneta** (memory scanner): The only tool that detected a difference. BOF execution created a transient private executable memory region. VM execution created none.
2. **API Monitor** (API call tracer): Could not detect either execution method. Both the COFF loader and the VM interpreter avoid `GetProcAddress` by walking the PEB directly.
3. **Sysmon** (ETW event logger): Could not detect either execution method. Both run inline on the beacon's thread without inter-process activity.

The BOF execution model eliminates fork-and-run artifacts (no child process, no cross-process injection) and avoids API-level detection through PEB walking. But it cannot avoid allocating executable memory for the COFF `.text` section. That allocation is the one remaining detection surface, and memory scanners catch it.

The VM execution model eliminates that final surface. Bytecode is data. The interpreter is the agent's own compiled code. API calls originate from the agent's `.text` section with spoofed call stacks. From a memory forensics perspective, a beacon running a VM script looks identical to a beacon doing nothing.

The tradeoff is capability. The RISC VM scripts are limited to the opcode set. BOFs can run arbitrary native code without restrictions. Tasks that require complex data structures, inline assembly, C++ classes, or kernel interaction (like CVE-2024-26229's DKOM token steal) require BOFs.

The recommended approach: use VM scripts for reconnaissance and data-gathering tasks where evasion matters most. Reserve BOFs for operations that exceed the VM's instruction set.
