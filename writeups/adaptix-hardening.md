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

## Default Certificate

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

## Decoy Page

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

### Why You Must Change the Decoy Page

The default 404 page is an immediate positive identification. It does not just hint at Adaptix. It prints the framework name in plain text. Any defender, automated scanner, or threat intelligence crawler that hits a non-existent path on your server gets a page that explicitly says "AdaptixC2 404."

**What happens during an engagement:**

- Incident responders who extract a callback domain from a phishing email will browse to it manually. The first thing they try is the root path or a random URI. If they see "AdaptixC2 404," the investigation jumps straight to C2 identification without any further analysis.
- Automated threat intelligence platforms continuously probe known C2 ports with HTTP requests to non-standard paths. The response body is hashed and compared against a signature database. The default Adaptix 404 page has a known hash. A match flags the IP immediately.
- Web application firewalls and proxy appliances that inspect HTTP responses can pattern-match on the body content. The string "AdaptixC2" in a 404 response is a trivial detection rule.

**What a proper decoy page achieves:**

A realistic IIS error page with correct headers (`Server: Microsoft IIS/10.0`, `X-Powered-By: ASP.NET`) presents a consistent cover story across every layer of inspection. The response body looks like any of the millions of IIS servers returning standard 404 pages on the internet. The HTTP headers reinforce that impression. There is nothing for a signature database to match against, and nothing for a human analyst to flag on a quick manual check.

The decoy page is the first thing an adversary or defender sees when probing your infrastructure. It needs to be the most boring, unremarkable response possible.

---

## Teamserver Endpoint

It is common for operators to leave the default teamserver port and endpoint path:

```yaml
Teamserver:
  interface: "0.0.0.0"
  port: 4321
  endpoint: "/endpoint"
```

This is bad OPSEC.

For the port and endpoint, pick something that matches your cover story and looks like a real IIS application:

```yaml
Teamserver:
  interface: "0.0.0.0"
  port: 8443
  endpoint: "/submit.aspx"
```

Then restart the Adaptix service.

### Why You Must Change the Default Endpoint

The default port and URI path are documented, public knowledge. Threat intelligence platforms maintain databases of known C2 endpoint signatures, and Adaptix's defaults are catalogued alongside every other framework.

**What gets matched against:**

- **Port 4321** is not a standard service port. It does not correspond to HTTP, HTTPS, or any well-known application protocol. A port scan that finds 4321 open already narrows the list of candidate services to a handful of C2 frameworks and niche applications. Combined with a TLS handshake or HTTP response on that port, the identification becomes near-certain.
- **The `/endpoint` URI** is generic enough to seem harmless in isolation, but in combination with port 4321 it forms a composite signature. Threat intelligence rules match on port-plus-path pairs, not just one or the other. The default combination is effectively a fingerprint.
- **Automated probing tools** such as JARM, Shodan's HTTP fingerprinter, and custom blue team scanners send requests to known C2 ports and paths. A 200 or structured response on `4321/endpoint` is a confirmed hit.

**What a hardened endpoint achieves:**

Port 8443 is a standard alternative HTTPS port used by thousands of legitimate web applications, management consoles, and API gateways. Traffic to 8443 does not stand out in firewall logs or network flow analysis. The URI `/submit.aspx` is consistent with the IIS/ASP.NET cover story established by your headers, certificate, and decoy page. Every layer of the infrastructure tells the same story, and none of the individual components match a known C2 signature.

The goal is to make your teamserver indistinguishable from a routine web application at every level of inspection: port, path, headers, certificate, and error responses.

---

## Teamserver Operator Password

This should go without saying. Do not leave the default `pass1` as the teamserver password.

---

## JARM Fingerprinting

JARM is a TLS server fingerprinting technique developed by Salesforce's threat intelligence team. Unlike JA3S, which fingerprints a single TLS server hello in response to a specific client hello, JARM actively probes the server with 10 specially crafted TLS client hello packets and hashes the combined server responses into a single 62-character fingerprint.

**Why this matters for C2 servers:**

A perfect Let's Encrypt certificate, a clean IIS decoy page, and hardened headers will defeat manual inspection and most automated scanners. But JARM fingerprints the TLS implementation itself, not the certificate or the HTTP layer above it. Two servers running the same TLS library with the same configuration will produce the same JARM hash, regardless of what certificate they present or what HTTP content they serve.

Adaptix's teamserver uses a specific TLS stack and configuration. If that combination produces a JARM hash that has been catalogued by threat intelligence services, your server can be identified as an Adaptix instance even with every other hardening measure in place. The JARM hash is independent of your certificate, your headers, and your decoy pages.

**How to check your own JARM hash:**

Clone the [JARM repository](https://github.com/salesforce/jarm) and scan your server:

```shell
git clone https://github.com/salesforce/jarm.git
python3 jarm/jarm.py your-server-ip -p 8443
```

Compare the resulting hash against public JARM databases. If the hash matches a known Adaptix or C2 framework signature, you need to modify the TLS configuration to change the fingerprint.

**Mitigation strategies:**

### Modify the Profile TLS Configuration

Adaptix exposes its full TLS configuration directly in the profile YAML under the `HttpServer.tls` block. You do not need to touch source code or rebuild the framework. The default configuration looks like this:

```yaml
tls:
  min_version: "TLS1.2"
  max_version: "TLS1.3"
  prefer_server_cipher_suites: false
  cipher_suites:
    - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    - "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    - "TLS_RSA_WITH_AES_128_GCM_SHA256"
    - "TLS_RSA_WITH_AES_256_GCM_SHA384"
```

Every field in this block influences the JARM hash:

- **`cipher_suites`** - Reordering, adding, or removing entries changes the cipher the server selects in response to each of JARM's 10 probes. This is the highest-impact change.
- **`prefer_server_cipher_suites`** - Setting this to `true` forces the server to pick its own preferred cipher rather than deferring to the client's preference, which changes the server hello for every probe.
- **`min_version` / `max_version`** - Changing which TLS versions are accepted changes how the server responds to probes that target specific versions.
- **`enable_http2`** (in the `http` block) - ALPN negotiation for HTTP/2 is a TLS extension that affects the fingerprint.

Your JARM hash should be consistent with your cover story. If your headers, certificate, and decoy page all impersonate IIS 10.0 on Windows Server, the JARM hash should match IIS, not Nginx or Apache. A defender who sees IIS response headers but an Nginx JARM hash has a contradiction that immediately warrants deeper investigation.

To approximate the JARM fingerprint of IIS 10.0 on Windows Server 2019/2022, mirror its default cipher suite order and TLS behavior:

```yaml
tls:
  min_version: "TLS1.2"
  max_version: "TLS1.3"
  prefer_server_cipher_suites: true
  cipher_suites:
    - "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    - "TLS_RSA_WITH_AES_256_GCM_SHA384"
    - "TLS_RSA_WITH_AES_128_GCM_SHA256"
```

IIS defaults to `prefer_server_cipher_suites: true` (Windows calls this "server cipher suite order" in Group Policy), prefers ECDSA over RSA variants, and still includes the non-ECDHE RSA suites for backward compatibility. The key difference from the Adaptix default is the cipher ordering and the server-side preference enforcement.

The workflow: change the TLS block in your profile, restart the Adaptix service, JARM scan yourself, compare the hash against known signatures, and iterate until the result is clean. This is a profile-level change that takes effect on the next restart with no rebuilding required.

> Note that an exact IIS JARM match is not guaranteed through profile changes alone, because the underlying Go TLS library (crypto/tls) may handle certain probe edge cases differently than Windows SChannel. If the hash is still identifiable after tuning the profile, use one of the approaches below.

### Place an IIS Reverse Proxy in Front of the Teamserver

If profile-level tuning does not produce a clean hash, an actual IIS instance running as a reverse proxy is the most cover-consistent approach. IIS with Application Request Routing (ARR) terminates TLS using Windows SChannel, producing a genuine IIS JARM hash. The JARM scan hits IIS, not Adaptix. This also means your TLS stack, HTTP headers, and error pages are all coming from real IIS, making the cover story airtight at every layer. If IIS is not an option, Nginx or Caddy will produce a clean non-C2 hash, but the JARM will not match the IIS cover story.

### Use a CDN or Cloud Load Balancer

If your C2 server sits behind Cloudflare, AWS ALB, or a similar service, the JARM scan fingerprints the CDN's TLS stack. This is the strongest mitigation because CDN JARM hashes are shared by millions of legitimate domains.

The principle is the same as every other section in this article: your infrastructure should look like everything else on the internet, not like a C2 framework.

---

## Listeners

Connect to the teamserver with the hardened endpoint and credentials:

![Adaptix client connection dialog showing hardened endpoint](image/adaptix-hardening/teamserver-connect.png)
*Connecting to the hardened teamserver on port 8443 with the custom endpoint*

### HTTPS Listener

For the HTTPS listener, change every default value. Each field that ships with a recognizable default is a detection opportunity for the blue team. The goal is to make every aspect of the listener's HTTP behavior indistinguishable from the web application you are impersonating.

**URIs:**

![Custom listener URIs configured to resemble IIS endpoints](image/adaptix-hardening/listener-uris.png)
*Listener URIs set to innocuous paths consistent with the IIS cover story*

The URIs are the paths the beacon calls back to. Default URIs are documented and signatured. Proxy logs, web application firewalls, and network monitoring tools all log request paths. If a defender sees repeated requests to a path that matches a known C2 callback URI, the traffic gets flagged regardless of how clean the rest of your infrastructure looks. Pick paths that are consistent with your cover story and that would not look unusual in a proxy log alongside normal employee web traffic.

**User-Agent:**

![Custom User-Agent string in the listener configuration](image/adaptix-hardening/listener-useragent.png)
*User-Agent set to a realistic browser string*

The User-Agent string appears in every HTTP request the beacon sends. Default or outdated User-Agent strings are a common detection vector. Enterprise proxy logs are routinely filtered for anomalous User-Agent values, and a string that does not match any browser in the organization's software inventory stands out immediately. Use a User-Agent that matches the target environment. If the organization runs Windows 10 with Chrome, use a current Chrome-on-Windows-10 string. An Edge string in an all-Chrome environment, or a Chrome 90 string when the current version is 126, draws attention.

**Heartbeat Header:**

![Custom heartbeat header field](image/adaptix-hardening/listener-heartbeat-header.png)
*Heartbeat header renamed to blend with standard web application headers*

The heartbeat header is a custom HTTP header the beacon uses to communicate session state with the teamserver. Custom HTTP headers are visible in proxy logs, SSL inspection appliances, and any network tool that parses HTTP traffic. A header name that does not correspond to any known web standard or application framework is an anomaly. Name it something that looks like a standard session management header (e.g., `X-Session-Id`, `X-Request-Token`) so it blends in with the thousands of custom headers that legitimate web applications use.

**Page Error:**

![Custom page error HTML source mimicking IIS](image/adaptix-hardening/listener-page-error.png)
*Page error set to the HTML source of a real IIS error page*

The page error is the HTML the listener returns when it receives a request to a valid listener URI but from a source that is not a beacon (e.g., a defender manually browsing to the path, or a scanner probing it). The default error response may contain identifiable strings or an unusual structure. Replace it with the HTML source of a real error page from whatever web server you are impersonating. Copy it from an actual IIS server if possible.

**Page Payload:**

![Custom page payload mimicking ASP.NET form data](image/adaptix-hardening/listener-page-payload.png)
*Payload wrapper structured to resemble ASP.NET ViewState and form data*

The page payload defines the JSON structure that wraps actual C2 data in HTTP responses. Deep packet inspection appliances and SSL inspection proxies parse response bodies. If the JSON structure uses unusual field names or a layout that does not match any known application, it can be flagged for manual review. Structure the payload to resemble something the cover application would return. In this case, the payload mimics ASP.NET ViewState and EventValidation fields, which is exactly what an IIS web application would include in a form response.

**SSL Certificate:**

Use a legitimate SSL (HTTPS) certificate for the listener as well. The same principles from the certificate section apply here. The listener's TLS certificate is what the beacon validates when connecting, and what any network inspection tool sees when intercepting the traffic.

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

The prepend should match whatever makes sense for the port you are running on.

**What not to do:** Do not put an SSH banner on port 443, or an SMTP greeting on port 8080. A defender who sees SSH protocol negotiation on an HTTPS port flags it immediately. The mismatch between the expected protocol for that port and the actual bytes on the wire is a stronger signal than sending no prepend at all. If you run the TCP listener on port 22, use an SSH banner. If you run it on port 25, use an SMTP greeting. If there is no natural protocol for your chosen port, consider whether a TCP listener is the right choice for that scenario at all.

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

---

## Verification

Hardening without verification is guesswork. After making every change in this article, audit your own infrastructure the way a defender or threat intelligence analyst would. If you can identify your server as a C2 teamserver, so can they.

### Certificate Verification

Inspect the certificate your server presents:

```shell
openssl s_client -connect your-server-ip:8443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

Confirm the issuer is Let's Encrypt (or your chosen CA), not a self-signed certificate with default Adaptix subject fields. Check the validity dates. A certificate valid for exactly 365 or 3650 days from today is a self-signed certificate indicator.

### Decoy Page Verification

Hit your server on the root path and a random URI:

```shell
curl -k -s -D - https://your-server-ip:8443/
curl -k -s -D - https://your-server-ip:8443/nonexistent-path
```

Both should return your custom IIS-style error page with the correct headers (`Server: Microsoft IIS/10.0`, `X-Powered-By: ASP.NET`). The response body should contain no reference to Adaptix, no default framework strings, and no unusual HTML structure. Compare the output against a real IIS 404 response. They should be indistinguishable.

### HTTP Header Verification

Inspect the full set of response headers:

```shell
curl -k -s -I https://your-server-ip:8443/
```

Look for any headers that leak the underlying framework. The `Server` header should show IIS. There should be no `X-Powered-By: Express`, no framework-specific headers, and no version strings that contradict your cover story. Every header should be consistent with the application you are impersonating.

### Port Scan Profile

Scan your server the way a threat intelligence platform would:

```shell
nmap -sV -sC -p 8443 your-server-ip
```

Review the service detection output. Nmap should identify the port as HTTPS with the certificate details you configured. It should not flag the service as a known C2 framework. If Nmap's service detection scripts identify anything unusual, investigate what triggered the match.

### JARM Hash Verification

```shell
python3 jarm.py your-server-ip 8443
```

Compare the output against known C2 JARM hashes published by threat intelligence teams. If your hash matches a catalogued C2 fingerprint, implement one of the mitigations from the JARM section above and re-scan.

### Shodan and Censys Check

If your server is internet-facing, search for its IP on Shodan and Censys after it has been running for 24-48 hours. These platforms continuously scan the internet and will index your server. Check whether your server has been tagged with any C2-related labels. If it has, identify which signal triggered the tag and fix it.

The verification process is not a one-time task. Run these checks after every configuration change, after certificate renewals, and periodically during long engagements. Infrastructure that was clean on day one can drift as certificates expire, services restart with default configs, or upstream scanning tools add new signatures.

---

## Hardening Checklist

A quick-reference summary of every change covered in this article. Use this as a pre-engagement audit list.

| Component | Default (Vulnerable) | Hardened | Why It Matters |
|-----------|---------------------|----------|----------------|
| TLS Certificate | Auto-generated self-signed (`server.rsa.crt`) | Let's Encrypt via DNS-01 challenge | Default cert is fingerprinted by Censys/Shodan |
| Decoy Page | `404page.html` displaying "AdaptixC2 404" | Custom IIS-style `error.aspx` | Default page positively identifies the framework |
| Teamserver Port | `4321` | `8443` | Non-standard port narrows identification to C2 frameworks |
| Teamserver Endpoint | `/endpoint` | `/submit.aspx` | Default path is a known Adaptix signature |
| Teamserver Password | `pass1` | Strong, unique password | Default credentials are public knowledge |
| HTTP `Server` Header | Default/missing | `Microsoft IIS/10.0` | Reinforces cover story in proxy logs |
| HTTP `X-Powered-By` Header | Missing | `ASP.NET` | Consistent with IIS impersonation |
| Listener URIs | Framework defaults | Innocuous paths matching cover story | Default URIs are signatured in threat intel databases |
| User-Agent | Default/outdated string | Current browser string matching target environment | Anomalous User-Agents are filtered in proxy logs |
| Heartbeat Header | Default header name | Standard-looking session header (e.g., `X-Session-Id`) | Custom headers are visible in proxy and DPI logs |
| Listener Page Error | Default error response | Real IIS error page HTML | Default response may contain identifiable strings |
| Listener Page Payload | Default JSON structure | ASP.NET-style ViewState/EventValidation wrapper | DPI appliances parse response body structure |
| Listener SSL Certificate | Default/self-signed | Legitimate CA-issued certificate | Same fingerprinting risk as teamserver certificate |
| SMB Pipe Name | Default Adaptix pipe name | Name matching a real Windows/application pipe | Default pipe names are signatured by EDR |
| TCP Prepend Data | `\x12\xabSimple\x20word\xa` | Protocol banner matching the listener port | Default bytes do not imitate any real protocol |
| JARM Hash | Raw Adaptix TLS stack | Reverse proxy (Nginx/Caddy) or CDN in front | JARM fingerprints the TLS implementation itself |

**Before every engagement:** walk through this table top to bottom. For each row, verify the hardened value is in place using the commands in the Verification section. Any single default left unchanged can be the signal that burns your infrastructure.
