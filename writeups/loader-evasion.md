---
title: "Loader Evasion: Let the OS Do the Dirty Work"
kicker: "Evasion Engineering . Custom . Static Evasion"
tags: "Evasion Engineering . C2 Development . AV Bypass . Static Analysis"
lead: "How I made a custom Beacon loader invisible to static analysis by removing all decryption code from the binary and delegating cryptographic operations to Windows itself. Four cipher implementations failed. One design change solved everything."
---

> This is the first post in the Evasion Engineering series. Each post covers a specific evasion problem encountered while experimenting in a homelab, the failed approaches, and the solution that worked. This post covers static evasion for the Beacon loader component.
>
> The Beacon loader is the wrapper binary that carries an encrypted beacon (the actual implant), decrypts it in memory, and runs it. Everything here is about making that wrapper invisible to antivirus so the beacon can reach memory and execute.

---

## The Build Pipeline

The pipeline has three phases. The compiler turns beacon source code into a PE executable, then rips out the `.text` section as raw position-independent shellcode. A Go generator encrypts that shellcode with a random key and embeds both the ciphertext and the key into a fresh C++ loader source file. The compiler turns the loader into the final payload (exe, dll, or service binary), then a post-build step strips metadata from the output.

The beacon never exists in plaintext on disk. The loader carries it encrypted, decrypts it at runtime, and jumps to it.

## Cleaning Up the Binary

Before tackling the encryption problem, I had to remove the low-hanging fruits that AV uses for quick classification.

**CRT removal.** A normal C++ binary links the C Runtime Library, which drags in hundreds of function names like `malloc`, `memcpy`, and `__security_cookie`. A tiny PE with CRT strings and no real application logic is a textbook shellcode loader signature. I compiled with `-nostdlib` and a full set of `-fno-*` flags to strip all of it.

```
-Os                              Make the binary as small as possible
-nostdlib                        Do NOT link the C Runtime Library at all
-fno-builtin                     Do not silently replace our loops with calls to memcpy/memset
-fno-exceptions                  No C++ try/catch support (removes exception handler code)
-fno-rtti                        No runtime type info (removes typeinfo strings)
-fno-ident                       No compiler version string embedded in the binary
-fno-asynchronous-unwind-tables  No .pdata section (removes stack unwind metadata)
-Wl,--no-seh                     No structured exception handling table
-s                               Strip all symbol names from the binary
-lkernel32                       Link only against kernel32.dll
```

![CRT strings visible in the binary before removal](writeups/images/loader-evasion/crt-strings.png)

**Import table cleanup.** The loader needs `VirtualAlloc` and `VirtualProtect`. If those names appear in the PE import table, AV sees a small binary that imports memory management APIs and nothing else. Strong signal. I replaced static imports with PEB walking: at runtime, the loader reads the Process Environment Block to find `kernel32.dll`, then manually parses its export table using hashed function names. No API names appear in the binary.

**Polymorphic generation.** Every build produces a unique C++ source file. Variable names, function names, namespace names, hash constants, encryption keys, junk code, and entry point names are all randomized. AV vendors cannot write one signature to detect all payloads because no two payloads share the same code layout. Added some junk code - Between every real operation in the loader, the generator inserts 1 to 3 lines of random arithmetic. These lines operate on volatile variables. The volatile keyword is important: it tells the compiler "do not optimize this away." Without it, the compiler would see that the junk variables are never used for anything real and would delete the code entirely.

```
volatile unsigned int _rk2 = 0x8a3f1bc0;
// ... a real operation like VirtualAlloc ...
_rk2 = _rk2 ^ 0x4f2c1a8b;
// ... another real operation ...
_rk2 = _rk2 + 0xde91bc37;
```

**PE metadata stripping.** After compilation, the builder zeros the PE timestamp, zeros the checksum, fills the Rich header with random bytes, clears the debug directory, and normalizes section names. These fields leak toolchain information that heuristic engines use for classification. We fill with random bytes, not zeros. Zeros would be a signal that the Rich header was deliberately removed. Random data looks like the header was never there.

```
[DOS Header]  [DOS Stub]  [DanS^key ... data^key ... Rich key]  [PE sig]
                           ^--- fill this with random bytes ---^
```

Each of these layers hid a detection underneath. I fixed them bottom-up, running ThreatCheck after every change. ThreatCheck splits the binary, tests each half against Defender, and narrows down to the exact byte offset that triggers a detection. That offset tells you what to fix next.

---

## Four Ciphers, Four Failures

With the binary structure cleaned up, ThreatCheck pointed at one area: the encrypted beacon data and the code that decrypts it. This is where the real problem started. I tried four different encryption approaches. All four were detected.

### XOR

The first implementation used XOR with a 16-byte key. Each byte of the beacon gets XORed with the corresponding key byte, cycling through the 16 bytes.

The problem: XOR with a short key creates visible patterns. If the beacon has a zero byte at position 0 and another zero byte at position 16, both encrypted bytes are identical. Runs of zeros (common in PE null-padded regions) produce a repeating pattern with a 16-byte period. AV engines detect periodic repetition inside small binaries that also import memory management APIs. ThreatCheck confirmed the detection pointed directly at the encrypted data region.

![XOR repeating pattern visible in the encrypted beacon data](writeups/images/loader-evasion/xor-pattern.png)

### RC4

I replaced XOR with RC4. RC4 generates a unique keystream byte for every position, so the encrypted output has no repeating pattern. The beacon blob now looked like random noise.

ThreatCheck stopped flagging the data. But the detection moved to a new offset. When I opened that offset in Ghidra, the flagged code was the RC4 algorithm itself: a 256-byte array allocation, a sequential initialization loop, and a series of swap operations. AV does not need to understand RC4. It just needs to see "256-byte array + sequential init + swap loop." That pattern means "stream cipher," and a stream cipher inside a tiny binary that allocates executable memory means "shellcode loader."

![RC4 S-box structure in Ghidra](writeups/images/loader-evasion/rc4-sbox-1.png)

![RC4 key scheduling and swap loop decompiled](writeups/images/loader-evasion/rc4-sbox-2.png)

### Custom S-Box Cipher

I replaced RC4 with a custom cipher. Same 256-byte array, but with a scrambled initialization (`s[i] = (i * MULT) ^ CONST` instead of `s[i] = i`) and bit rotation instead of swaps.

ThreatCheck still flagged a nearby offset. The lesson: AV does not care which algorithm you use. It cares about the shape. Any code that allocates a 256-byte array, fills it in a loop, and swaps entries based on indices looks like a cipher S-box. Sequential or scrambled initialization, swaps or rotations. The structure itself is the signature.

### Counter-Mode Arithmetic

I eliminated the S-box entirely. The counter-mode cipher computes each output byte using only arithmetic on the position index, the key, and four random constants:

```c
unsigned int h = SEED ^ (unsigned int)key[i % keylen];
h = h * MUL1 + ADD1 + (unsigned int)i;
h ^= h >> 16;
h = h * MUL2;
h ^= h >> 13;
output[i] = input[i] ^ (unsigned char)h;
```

No array. No init loop. No swaps. Just multiply-and-shift operations in a single loop. The constants are random per build, so the algorithm looks different in every binary.

ThreatCheck detected at a slightly different offset.

![ThreatCheck detection offset on counter-mode cipher](writeups/images/loader-evasion/counter-mode-ghidra-2.png)

![Counter-mode arithmetic in Ghidra decompiler](writeups/images/loader-evasion/counter-mode-ghidra-1.png)

I opened the binary in Ghidra and looked at what was flagged. The flagged region was not the cipher math. It was the entire block: a loop (any loop) that reads from the encrypted blob, writes to allocated memory, then calls VirtualProtect and jumps. The AV was detecting the **shape of a shellcode loader**, not the specific cipher.

![Ghidra showing the loader shape: the AV detects the pattern, not the cipher](writeups/images/loader-evasion/ghidra-loader-shape.png)

---

## The Real Problem

Think about what the AV sees when it scans the binary:

```
VirtualAlloc      (allocate memory)
   |
some kind of loop that transforms data byte by byte
   |
VirtualProtect    (make memory executable)
   |
indirect call     (jump to the decrypted code)
```

That is the textbook pattern for a shellcode loader: unpack code, make it executable, run it. The cipher is irrelevant. XOR, RC4, AES, or counter-mode arithmetic. The shape is the signature. As long as the binary contains any decryption code at all, AV can match the loader pattern.

I could not fix this by writing a "better" cipher. I tried four different ones. Each was detected. The only way to break the pattern was to remove all decryption code from the binary entirely.

---

## Delegate to the OS

This is the design change that solved it.

Stop writing your own decryption code. Instead, ask Windows to decrypt the beacon.

Every version of Windows has cryptographic functions built into its system DLLs. Those DLLs are signed by Microsoft. AV trusts them completely because millions of legitimate programs call them every day. The actual decryption math runs inside a Microsoft-signed library, not inside our code.

In all previous versions of the loader, the binary contained a decryption loop. AV could see the loop, see VirtualAlloc and VirtualProtect nearby, and conclude: "shellcode loader." The loop was the signature.

With delegation, there is no loop. The loader calls a single Windows API function: "here is encrypted data and a key, decrypt it." That function call is one `call` instruction. The decryption math runs inside `cryptsp.dll`, a Microsoft-signed system DLL. From the AV perspective, our binary just calls a system function. That is what thousands of normal programs do.

**Before (custom decrypt code):**
```
VirtualAlloc
for (i=0; i<len; i++)
  out[i] = in[i] ^ f(key, i)     <-- DECRYPT LOOP (the detection)
VirtualProtect
call shellcode
```

**After (OS delegation):**
```
VirtualAlloc
memcpy(buf, encrypted, len)       <-- copy (not a decrypt loop)
SystemFunction032(&data, &key)    <-- ONE CALL (decryption inside Windows)
VirtualProtect
call shellcode
```

The decrypt loop is gone. No XOR loop. No S-box. No arithmetic cipher. Just a single function call to a Windows API. The AV sees: allocate memory, copy data, call a system function, change permissions, jump. Normal program behavior.

![ThreatCheck result after SystemFunction032 delegation: no threat found](writeups/images/loader-evasion/systemfunction032-clean.png)

### SystemFunction032

`SystemFunction032` lives in `advapi32.dll`. It is an undocumented Microsoft function that implements RC4 encryption and decryption. It has been present in every Windows version for over 20 years. It takes two parameters, both `USTRING` structures:

```c
typedef struct {
    unsigned long Length;
    unsigned long MaximumLength;
    unsigned char* Buffer;
} USTRING;

long SystemFunction032(USTRING* data, USTRING* key);
```

Fill one USTRING with the encrypted data, another with the key. Call the function. It decrypts the data in-place. Done.

### Runtime Sequence

Here is what the loader does at runtime, step by step:

1. **Read the PEB** from the `gs` segment register (x64) to get the list of loaded modules.
2. **Walk the module list** to find `kernel32.dll` by hashed name.
3. **Parse kernel32's export table** to resolve four functions by hashed name: `VirtualAlloc`, `VirtualProtect`, `LoadLibraryA`, and `GetProcAddress`.
4. **Build "advapi32.dll" on the stack** as individual characters with per-byte arithmetic expressions. Each character is computed from a random operation (XOR, addition, subtraction) with random operands. The string never appears in the binary.
5. **Call LoadLibraryA** to load advapi32.dll into the process. In a CRT-free binary, only kernel32 and ntdll are loaded at startup. advapi32 is not present until you load it.
6. **Build "SystemFunction032" on the stack** using the same per-byte arithmetic technique.
7. **Call GetProcAddress** to find SystemFunction032. This is critical. You cannot use the PEB resolver for this function because advapi32's export table has a forwarding entry: the string `"cryptsp.SystemFunction032"`. The PEB resolver would return a pointer to that text string, not to code. Calling it would crash the process. GetProcAddress follows the forwarding chain automatically and returns the real function address in cryptsp.dll.
8. **Allocate memory** with VirtualAlloc (PAGE_READWRITE).
9. **Copy the encrypted beacon** from the embedded header into the allocated buffer.
10. **Copy the key to a writable stack buffer.** The key in the header is `const`, so the compiler puts it in read-only memory. SystemFunction032 writes to the key buffer during RC4 initialization. If the buffer is read-only, it causes an access violation. This crash was silent and took debugging to find.
11. **Set up two USTRING structures:** one for the data buffer, one for the key buffer.
12. **Call SystemFunction032.** RC4 decryption happens inside cryptsp.dll (Microsoft-signed code). The allocated memory now contains the decrypted beacon.
13. **Call VirtualProtect** to change the memory to PAGE_EXECUTE_READ.
14. **Cast the memory to a function pointer and call it.** The beacon starts running and connects to the C2 server.

### GetProcAddress

This caused a crash during development and deserves emphasis.

On modern Windows (10 and 11), `advapi32.dll` does not contain the code for SystemFunction032. Its export table has a **forwarding entry** that says: "the real function is in cryptsp.dll."

When the PEB resolver reads advapi32's export table and finds the entry for SystemFunction032, the address it gets does not point to machine code. It points to the ASCII text `"cryptsp.SystemFunction032"`. If you call that address as a function, you jump into a text string. Instant crash.

`GetProcAddress` handles forwarded exports correctly. It sees the forwarding entry, loads cryptsp.dll, finds the real function there, and returns the actual code address. I resolve `GetProcAddress` itself from kernel32 using the PEB resolver (GetProcAddress is never forwarded), then use it for SystemFunction032.

### Key Must Be Writable

The encryption key is embedded as `const unsigned char key[]`, so the compiler places it in the `.rdata` section (read-only memory). SystemFunction032 modifies the key buffer during RC4 state initialization. A write to read-only memory triggers an access violation.

The fix: copy the 16 key bytes to a local `unsigned char[16]` on the stack before calling SystemFunction032. Stack memory is always writable.

This bug was subtle. The payload ran for about 1-2 seconds during setup, then crashed silently. No error message. No visible indication of what went wrong.

### Strings Are Built on the Stack

If you write `LoadLibraryA("advapi32.dll")` in C++, the compiler stores `"advapi32.dll"` in the `.rdata` section. Anyone who runs `strings` on the binary can see it.

The obvious fix is a char array initializer: `char s[] = {'a','d','v',...,0};`. In theory, the compiler turns this into `mov byte` instructions that build the string at runtime. In practice, clang with `-Os` optimizes the initializer back into a constant. It sees that emitting 13 individual `mov byte` instructions is larger than one copy from `.rdata`, so it folds the array into the data section. I then verified this:

```
$ strings -t x payload.exe | grep -i advapi
    5dc advapi32H          <-- .text section: movabs immediate
    a40 advapi32.dll       <-- .rdata section: folded constant
```

The fix has two parts. First, declare the array as `volatile char[]`. This forces the compiler to emit every store as written. It cannot fold the initialization or coalesce stores. Second, compute each character from a random arithmetic expression instead of a literal value:

```c
volatile char s[13];
s[0] = (char)(0xf2 ^ 0x93);           // 'a'
s[1] = (char)(0x3b - 0xd7);           // 'd'
s[2] = (char)(0x29 + 0x4d);           // 'v'
s[3] = (char)((0x4c ^ 0x1f) + 0x76); // 'a'
// ... each character uses different random operations
```

The Go generator picks one of four expression types at random for each character. The operands are random bytes that produce the correct value when evaluated. Every build generates different operands and a different mix of operations. No recognizable ASCII ever appears in the binary.

---

## Detection Layers

Each layer below can hide the next one above it. Fix them bottom-up. If layer 1 still triggers, fixing layer 7 does nothing.

| Layer | What AV Detects | Fix |
|-------|----------------|-----|
| 1 | CRT strings (malloc, memcpy, __security_cookie) | Compile with `-nostdlib` and `-fno-*` flags |
| 2 | API names in the import table | PEB walking with hashed names |
| 3 | Identical binary across builds | Polymorphic source generation |
| 4 | PE metadata (Rich header, timestamps, debug paths) | Post-build binary stripping |
| 5 | Repeating pattern in encrypted data | Stream cipher (RC4 or better) |
| 6 | Cipher code structure (256-byte S-box) | Cipher with no lookup tables |
| 7 | Loader shape (any decrypt loop + alloc + protect + jump) | Delegate decryption to the OS |
| 8 | API strings leaked by compiler optimization | Volatile per-byte arithmetic expressions |

---

## Problems Reference

| Problem | Cause | Fix |
|---------|-------|-----|
| Exe shows a console window | `-mwindows` needs CRT startup | Use `-Wl,--subsystem,windows` |
| Inline assembly fails to compile | clang uses AT&T syntax, not Intel | Write `%%gs:0x60` not `gs:[0x60]` |
| SystemFunction032 crashes | advapi32 forwards to cryptsp.dll; PEB resolver returns forwarder string | Use GetProcAddress (follows forwarders) |
| Silent crash after 1-2 seconds | Key array is const/read-only; SystemFunction032 writes to it | Copy key to a writable stack buffer |
| "advapi32.dll" visible in binary | String literals go into .rdata | Volatile char arrays with per-byte arithmetic |
| advapi32 not found at runtime | CRT-free processes only load kernel32 and ntdll | Call LoadLibraryA first |
| ThreatCheck flags encrypted data | XOR with short key creates repeating pattern | Replace with RC4 |
| ThreatCheck flags RC4 code | AV recognizes S-box + init + swap structure | Cipher with no lookup tables |
| ThreatCheck flags counter-mode code | AV detects loader shape, not specific cipher | Delegate decryption to SystemFunction032 |
| Char array initializer leaks string | clang `-Os` folds arrays back into .rdata | Volatile + arithmetic expressions |

---

## What Is Not in the Final Binary

- No CRT code. No CRT strings.
- No API function names in the import table.
- No decryption algorithm. No cipher code. No S-box. No XOR loop.
- No Rich header. No debug directory. No PE timestamp.
- No readable string literals. No `"advapi32.dll"`. No `"SystemFunction032"`.

ThreatCheck: **No threat found.**

The loader has no decryption code. It calls a Microsoft-signed DLL to do the work. The encrypted beacon gets decrypted by Windows itself, inside system libraries that AV trusts completely. The beacon starts, connects to the C2 server, and everything works. Zero static detections.

---

## ThreatCheck Workflow

For anyone applying similar techniques, the iterative workflow:

1. Build the payload.
2. Run `ThreatCheck.exe -f payload.exe` on a Windows test machine.
3. If clean: done. If an offset is reported: continue.
4. Open the binary in Ghidra at the reported offset.
5. Identify what is there (strings, code pattern, data blob, metadata).
6. Match it to the detection layer table above.
7. Apply the fix, rebuild, and test again.

Always fix from the bottom up. ThreatCheck reports the first detection it finds. Higher-layer fixes are invisible until lower layers are clean.
