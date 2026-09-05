---
title: "Hardening Adaptix C2 - Reducing Infrastructure and Agent Fingerprints"
kicker: "Offensive Security . C2 Infrastructure . OPSEC"
tags: "Adaptix C2 . OPSEC . Red Team . Infrastructure Hardening"
lead: "A practical walkthrough of hardening an Adaptix C2 deployment: replacing default signatures to reduce the fingerprint surface that threat intel and blue teams use to identify red team infrastructure."
---

![Adaptix C2 infrastructure topology diagram](image/adaptix-hardening/adaptix-c2-infra.svg)
*Adaptix C2 infrastructure topology on the Trinity Range*

> The Adaptix C2 teamserver runs on **trinity-urchin**, an unprivileged LXC container (CTID 200) on the Proxmox host. The operator GUI client on **trinity-gadget** connects over TLS to manage listeners, generate payloads, and interact with agents. Both sit on VLAN 10 behind the Ludus-managed router, which provides NAT to the internet for payload staging and DNS callbacks.

## Node Details

### trinity-urchin (C2 Server)

| Field | Value |
|-------|-------|
| Type | LXC (CTID 200) |
| OS | Debian 13 |
| IP | `10.2.10.20` |
| Port | `8443/tcp` |
| Endpoint | `/submit.aspx` |
| Profile | IIS 10.0 / ASP.NET |
| Service | `systemd (adaptix)` |

### trinity-gadget (Operator)

| Field | Value |
|-------|-------|
| Type | VM (VMID 108) |
| OS | Windows 11 Enterprise |
| IP | `10.2.10.11` |
| Client | `AdaptixClient.exe` |
| BOFs | Extension-Kit |
| Toolchain | MSYS2 / mingw64 |

### Range Network

| Field | Value |
|-------|-------|
| Bridge | `vmbr1002` |
| VLAN | `10` |
| Subnet | `10.2.10.0/24` |
| Gateway | `10.2.10.254` |
| Router | VM 107 / Debian 11 |
| DNS | `8.8.8.8` (external) |

---

## Change the Default Certificate

The SSL certificate used by the Adaptix C2 server is auto-generated during installation.

On a successful install, the `dist/` directory will already contain `server.rsa.crt` and `server.rsa.key` after the build:

![Default SSL certificates in the dist directory](image/adaptix-hardening/default-certs.png)
*Default SSL certificates generated during Adaptix installation*

The profile references them by filename:

```yaml
...snip...
  cert: "server.rsa.crt"
  key: "server.rsa.key"
```

Every Adaptix install ships with the same keypair. What you should do instead: **generate your own.**

A Let's Encrypt certificate is preferable to a self-signed OpenSSL certificate. You will need a domain name. Let's Encrypt validates domain ownership, so you cannot issue a certificate for a bare IP like `10.2.10.20`. You need a public domain (or subdomain) pointing at your server.

The server needs to be reachable on port 80 or 443 for the HTTP-01 challenge. In this setup, trinity-urchin is behind the Ludus router on a private VLAN with no port forwarding, so the HTTP challenge would fail.

The DNS-01 challenge is the alternative. If you own a domain and can add TXT records, you can use the DNS challenge without exposing ports:

```shell
apt install certbot
certbot certonly --manual --preferred-challenges dns -d your-domain.com
```

Then update the `profile.yaml` to point at the new certificates:

```shell
Teamserver:
  cert: "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
  key: "/etc/letsencrypt/live/your-domain.com/privkey.pem"
```

Restart the service and verify. The result is a real, fully valid Let's Encrypt certificate. Same CA, same chain of trust, same browser-verified certificate as any production website using Let's Encrypt. The challenge method (HTTP-01 vs DNS-01) only affects how you prove domain ownership, not the certificate itself.

If your C2 traffic hits a network inspection tool or a defender pulls the certificate, it shows a legitimate Let's Encrypt certificate for your domain.

### Why You Must Change the Default Certificate

Default C2 certificates are fingerprinted and catalogued. Censys, Shodan, and similar services continuously scan the internet and build databases of TLS certificate metadata. Every C2 framework ships with default or auto-generated certificates that have recognizable patterns.

**Adaptix's default certificate** uses predictable values in the Subject/Issuer fields (common name, org, locality). Scanning services index these fields. Threat intelligence teams and blue teamers query Censys for known C2 certificate fingerprints to map out attacker infrastructure before an engagement even begins.

**What gets fingerprinted:**

- Subject DN fields (CN, O, OU, L, ST, C)
- Serial number patterns
- Validity period (self-signed certificates with exactly 365 or 3650 days stand out)
- SHA-256 thumbprint of the certificate itself
- JA3S hash of the TLS server hello

**What happens if you do not change it:**

- Your C2 server appears in public Censys/Shodan results tagged as "Adaptix C2" or similar before you send your first beacon
- The blue team gets your server IP from a threat intelligence feed on day one
- Your infrastructure is burned before the engagement starts, and every callback to that IP gets flagged

**A Let's Encrypt certificate solves multiple problems at once.** It is issued by a trusted CA that signs millions of legitimate sites, so the certificate metadata blends in with normal web traffic. There is no self-signed flag, no anomalous issuer, and TLS inspection tools see a certificate indistinguishable from any real website. Combined with the IIS/ASP.NET headers configured in your profile, a defender doing passive recon sees what looks like a standard IIS web application behind a valid certificate, not a C2 teamserver.

The principle: your infrastructure should be invisible in bulk scanning data. A self-signed or default certificate is a beacon to the very scanners you are trying to avoid.

---

## Change the Decoy Page

The `404page.html` that the default profile references in the `dist/` folder is Adaptix's decoy page. When anyone hits your C2 server on any URL that is not the actual C2 endpoint, the server returns that page with a 404 status code.

The profile config:

```yaml
HttpServer:
  error:
    status: 404
    headers:
...snip...
    page: "404page.html"
```

Leaving this default is not OPSEC-safe. It announces your endpoint as an Adaptix C2 server.

![Default Adaptix 404 page displaying the framework name](image/adaptix-hardening/default-404-page.png)
*The default Adaptix 404 page openly identifies the framework*

The fix is to create an alternate error landing page that looks legitimate, drop it in `dist/`, reference it in the profile, and restart the Adaptix service:

```yaml
HttpServer:
  error:
    status: 404
    headers:
      Content-Type: "text/html; charset=UTF-8"
      Server: "Microsoft IIS/10.0"
      X-Powered-By: "ASP.NET"
    page: "error.aspx"
```

The `Server` header is set to IIS and an `X-Powered-By` header is added to reinforce the cover story.

The replacement `error.aspx` renders a standard IIS-style error page:

![Custom IIS-style 404 error page](image/adaptix-hardening/custom-error-page.png)
*Custom error page mimicking a standard IIS 404 response*

---

## Change the Teamserver Endpoint

It is common for operators to leave the default teamserver port and endpoint path:

```yaml
Teamserver:
  interface: "0.0.0.0"
  port: 4321
  endpoint: "/endpoint"
```

This is bad OPSEC. Port `4321` with a `/endpoint` URI is a known signature that threat intelligence platforms associate with Adaptix.

For the endpoint, pick something that matches your cover story and looks like a real IIS application:

```yaml
Teamserver:
  interface: "0.0.0.0"
  port: 8443
  endpoint: "/submit.aspx"
```

Then restart the Adaptix service.

---

## Change the Teamserver Operator Password

This should go without saying. Do not leave the default `pass1` as the teamserver password.

---

## Listeners

Connect to the teamserver with the hardened endpoint and credentials:

![Adaptix client connection dialog showing hardened endpoint](image/adaptix-hardening/teamserver-connect.png)
*Connecting to the hardened teamserver on port 8443 with the custom endpoint*

### HTTPS Listener

For the HTTPS listener, change every default value. Start with the **URIs**:

![Custom listener URIs configured to resemble IIS endpoints](image/adaptix-hardening/listener-uris.png)
*Listener URIs set to innocuous paths consistent with the IIS cover story*

> Ensure the URIs are innocuous, appear harmless, and remain consistent with your cover story.

The **User-Agent**:

![Custom User-Agent string in the listener configuration](image/adaptix-hardening/listener-useragent.png)
*User-Agent set to a realistic browser string*

The **Heartbeat Header**:

![Custom heartbeat header field](image/adaptix-hardening/listener-heartbeat-header.png)
*Heartbeat header renamed to blend with standard web application headers*

The **Page Error** (the HTML returned for invalid requests to listener URIs):

![Custom page error HTML source mimicking IIS](image/adaptix-hardening/listener-page-error.png)
*Page error set to the HTML source of a real IIS error page*

> Add the HTML source of a real error page.

The **Page Payload** (the JSON structure wrapping C2 data):

![Custom page payload mimicking ASP.NET form data](image/adaptix-hardening/listener-page-payload.png)
*Payload wrapper structured to resemble ASP.NET ViewState and form data*

> Make the JSON payload look legitimate and consistent with your cover story. In this case, the payload mimics an ASP.NET page payload with ViewState and EventValidation fields.

Lastly, use a **legitimate SSL (HTTPS) certificate** for the listener as well.

Leave nothing to chance.

### SMB Listener

Use a legitimate SMB pipe name. The default pipe name is well-signatured. A good strategy is to emulate names known to be used by common applications or Windows itself.

Use this command to list all currently listening pipes on your target VM for inspiration:

```powershell
PS C:\> ls \\.\pipe\
```

![Named pipes listing on the target system](image/adaptix-hardening/named-pipes-listing.png)
*Listing active named pipes on the target to find realistic pipe names*

![SMB listener pipe name configured to match a real system pipe](image/adaptix-hardening/smb-listener-pipename.png)
*SMB listener pipe name set to match a legitimate PowerShell host pipe pattern*

### TCP Listener

The prepend data is bytes the server sends immediately when a client connects on the TCP listener, before any C2 communication happens.

Raw TCP connections on random ports look suspicious in network traffic. If a defender or network monitoring tool inspects the first bytes of a connection, they should see something recognizable, not raw C2 protocol data.

The default Adaptix prepend data `\x12\xabSimple\x20word\xa` is arbitrary bytes that do not imitate anything real. It is not useful for blending in.

Practical prepend choices based on what you want to imitate:

- `SSH-2.0-OpenSSH_8.9\r\n` - Looks like an SSH banner
- `HTTP/1.1 200 OK\r\n` - Looks like an HTTP response
- `220 mail.example.com ESMTP\r\n` - Looks like an SMTP greeting
- `+OK POP3 server ready\r\n` - Looks like a POP3 mail server

The prepend should match whatever makes sense for the port you are running on. A header inconsistent with the port you chose makes no sense and draws more attention than sending nothing.

---

## Load Extensions

Adaptix ships as a bare C2 framework. Out of the box, the beacon can call back, sleep, and exchange data with the teamserver. That is it. It does not come loaded with post-exploitation capabilities baked into the agent binary.

**The modular architecture:**

The operator loads capabilities on demand through the client UI: Extensions, then Script Manager, then Load New, then select the `.axs` script file.

- **Extension-Kit BOFs** (the extensions built during installation) are compiled object files, not executables. They are loaded into the beacon process at runtime, execute, return output, and unload. They never touch disk on the target.
- **Extender scripts** (`.axs` files) define how the client UI presents these capabilities, what arguments they take, and how the output is parsed.
- The teamserver's `config.yaml` registers which extenders are available. The operator picks what to load per engagement.

![AxScript manager showing available Extension-Kit BOFs](image/adaptix-hardening/axscript-manager.png)
*The AxScript manager with Extension-Kit BOFs loaded and ready to enable*

### Why This Matters for OPSEC

A beacon with 20 built-in capabilities has all of that code sitting in memory the entire time. EDR memory scanners look for known function signatures, strings, and code patterns. The more capability code lives in the beacon, the larger the detection surface. Even if the beacon is encrypted at rest, once it decrypts to execute, all that code is exposed.

With Adaptix's approach:

**1. The beacon binary is small and generic.** It contains the comms loop and basic agent functionality. Less code in memory means fewer signatures for EDR to match against.

**2. BOFs are transient.** When you run `execute bof` to load a BOF, the object code is sent to the beacon, mapped into the process, executed, and the memory is freed. The capability exists in the process for seconds, not for the entire dwell time. A memory scan that runs before or after execution sees nothing.

![The execute bof command help showing BOF execution syntax](image/adaptix-hardening/execute-bof-help.png)
*BOF execution interface: object files are loaded, executed, and discarded in-process*

**3. You only load what you need.** Doing AD enumeration? Load the AD-BOF. Need credentials? Load Creds-BOF. You never have lateral movement code sitting in memory while you are still doing recon. Each phase of the operation only exposes the tooling relevant to that phase.

**4. No fork and run.** This is critical. Cobalt Strike's older model spawned a sacrificial process (`rundll32.exe`, `dllhost.exe`), injected capability code into it, ran it, and killed the process. That pattern generates process creation events, cross-process injection events, and suspicious parent-child relationships. EDR picks up on all of these signals. Adaptix's `execute-assembly` loads the .NET CLR directly into the beacon process, runs the assembly in the same process context, and tears down the CLR hosting. No new process, no injection into another process, no telemetry trail.

![The execute-assembly command help showing in-process .NET execution](image/adaptix-hardening/execute-assembly-help.png)
*In-process .NET assembly execution: no sacrificial process, no cross-process injection*

**5. Each BOF is independently replaceable.** If a specific BOF gets signatured, you swap it out or modify it without rebuilding the beacon. The agent binary that is already deployed on targets does not change. Compare this to a monolithic agent where a single detection means you need to rebuild and redeploy everything.

### The Operational Workflow

Before the engagement, the operator decides which BOFs to stage on the teamserver based on the operation plan. During execution, capabilities are pushed to the beacon on demand over the encrypted C2 channel, executed in-process, and discarded. The beacon stays lean, the memory footprint stays small, and the window of exposure for any single capability is measured in seconds rather than the full lifetime of the implant.

![Adaptix Framework session overview with active beacon and command console](image/adaptix-hardening/adaptix-session-overview.png)
*Active beacon session in the Adaptix Framework showing the lean command set and agent details*
