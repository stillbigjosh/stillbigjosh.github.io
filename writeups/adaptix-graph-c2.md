---
title: "Hardening Adaptix C2 - Cloud Dead-Drop with Azure Blob Storage"
kicker: "Red Team . C2 Infrastructure . OPSEC"
tags: "Adaptix C2 . OPSEC . Red Team . Cloud C2 . Azure . Dead Drop"
lead: "Removing the direct link between beacon and server by routing all C2 traffic through Azure Blob Storage as a dead-drop relay. The beacon and listener never talk to each other. All traffic is outbound HTTPS to Microsoft cloud endpoints. No public IP, no inbound ports, no infrastructure to fingerprint."
---

> Repository: [github.com/stillbigjosh/adaptix-graph-c2](https://github.com/stillbigjosh/adaptix-graph-c2)

![Cloud dead-drop C2 topology showing beacon and listener communicating through Azure Blob Storage or OneDrive](image/adaptix-graph-c2/topology.svg)
*Cloud dead-drop topology. The beacon and listener never communicate directly. Both sides exchange encrypted files through Azure Blob Storage or OneDrive over standard HTTPS.*

> **This guide covers the Azure Blob Storage channel.** The plugin also supports OneDrive through the Microsoft Graph API. The installation is identical for both modes. The only differences are the Azure setup (app registration instead of storage account) and the listener configuration fields. If you can set up blob mode, OneDrive follows the same principle.

## The Problem with Traditional C2 Channels

Every hardening step in this series so far has focused on making your C2 server harder to identify: replacing default certificates, changing JARM fingerprints, impersonating IIS, customizing beacon traffic patterns. All of that matters. But the fundamental architecture remains the same: your server sits on the internet, the beacon calls back to it, and the connection between the two is the thing defenders are looking for.

That connection is the weak point. Once your IP gets flagged, whether from a threat intelligence feed, a Censys scan, a SOC alert on the callback domain, or an IR analyst pulling the beacon config, the channel is burned. You can harden the presentation layer as much as you want, but you cannot hide the fact that a machine on the target network is making repeated HTTPS connections to an IP you control.

## Removing the Direct Connection

This plugin changes the architecture. Instead of the beacon talking to your server, both sides talk to Azure Blob Storage.

```
BEACON   --[upload c_{nonce}.dat]-->  Azure Blob Storage
LISTENER <--[poll for c_*.dat]------  Azure Blob Storage
LISTENER --[upload r_{nonce}.dat]--> Azure Blob Storage
BEACON   <--[poll for r_{nonce}.dat] Azure Blob Storage
```

1. The beacon encrypts its data with RC4 and uploads it as a file (e.g., `c_a1b2c3.dat`).
2. The listener polls the storage container for new checkin files.
3. The listener downloads and processes the checkin file.
4. The listener uploads a response file with tasking data (e.g., `r_a1b2c3.dat`).
5. The beacon polls for and downloads its response file.
6. Both sides delete processed files after use.

The beacon gets a pre-signed SAS (Shared Access Signature) token embedded in its profile at build time. This token gives scoped access to the storage container for 90 days. The beacon never sees the raw storage key.

### Why This Matters for OPSEC

**Your C2 server disappears from the network.** The listener makes outbound HTTPS calls to Azure from wherever it runs, your homelab, a VPS, a container behind NAT. It does not need a public IP. It does not need open ports. It does not need a domain. There is nothing for Censys or Shodan to scan, because there is nothing listening.

**The beacon's traffic blends with legitimate cloud activity.** A defender inspecting the wire sees TLS handshakes to `{account}.blob.core.windows.net`, a Microsoft IP range that thousands of legitimate applications connect to every day. The SNI, the certificate chain, and the destination IP all belong to Microsoft. There is no custom domain to investigate, no unusual certificate to fingerprint, and no JARM hash to catalogue.

**The infrastructure is disposable.** If the storage account gets flagged, you create a new one in minutes. No server migration, no DNS changes, no certificate reissuance. Generate a new beacon with the new account details and redeploy.

**There is no server to take down.** In a traditional setup, if the blue team identifies and blocks your C2 IP, every beacon on every compromised host goes dark simultaneously. With the dead-drop model, the server IP is not in the beacon at all. The blue team would need to block the Azure Storage endpoint, which would break legitimate Azure-dependent applications across the organization.

---

## 1 - Create an Azure Storage Account

Go to the Azure Portal. Go to **Storage accounts > Create**.

![Azure Portal create storage account form](image/adaptix-graph-c2/01.png)
*The Create Storage Account form in the Azure Portal*

Fill in the form. The storage account name must be globally unique and lowercase. Set Performance to **Standard** and Redundancy to **LRS** (locally redundant storage). LRS is the cheapest tier and more than sufficient for a C2 relay.

![Storage account form filled in with name, region, performance, and redundancy](image/adaptix-graph-c2/02.png)
*Storage account `msgraphtest` configured with Standard performance and LRS redundancy*

Click **Review + create**. Check the summary, then click **Create**.

![Review and create summary page showing all configured settings](image/adaptix-graph-c2/03.png)
*Review screen before deployment*

Wait for the deployment to finish. Click **Go to resource**.

![Deployment complete confirmation with Go to resource button](image/adaptix-graph-c2/04.png)
*Deployment complete*

### A Note on Account Naming

The storage account name becomes part of the FQDN that the beacon connects to: `{name}.blob.core.windows.net`. A name like `c2-exfil-prod` is self-documenting in exactly the wrong way. Choose something that looks like a routine internal tool or dev environment: `apptelemetry`, `logsync2026`, `devresources`. If a defender ever pulls the beacon config and extracts the storage endpoint, the account name should not raise questions by itself.

---

## 2 - Get the Access Key

In your Storage Account, go to **Security + networking > Access keys**.

![Access keys page showing key1 and key2 with Show buttons](image/adaptix-graph-c2/05.png)
*The Access keys page with key1 and key2*

Click **Show** next to **key1**. Copy the key value. This is a base64-encoded string that authenticates all API requests to the storage account. Save it securely. You will enter this key when you create the listener.

You now have the two values you need:
- **Storage Account name** (e.g., `msgraphtest`)
- **Access key** (the base64 string from key1)

You also need a **container name** (e.g., `adaptix-c2`). You do not need to create the container yourself. The listener creates it automatically when it starts.

The beacon never receives the raw access key. The listener generates a scoped SAS token from it and embeds that token in the beacon profile at build time. If the beacon binary is captured and reverse-engineered, the extracted SAS token has limited permissions (read/write to one container) and a 90-day expiry. The attacker does not get the account key.

---

## 3 - Install the Plugin

You need Adaptix C2 v1.2 installed on your server. Clone the plugin repository:

```bash
git clone https://github.com/stillbigjosh/adaptix-graph-c2.git
cd adaptix-graph-c2
```

Run the install script. Pass the path to your Adaptix C2 installation:

```bash
./scripts/install.sh /path/to/AdaptixC2
```

The script runs all steps automatically. It patches the beacon agent source (8 additive patches), builds the listener plugin, rebuilds the entire server with `make server-ext`, cross-compiles all beacon source files with `-DBEACON_GRAPH`, and restarts the service. Your existing certificates, database, and profile are backed up before the rebuild and restored after.

![Install script output showing patches being applied to the source tree](image/adaptix-graph-c2/bbbb.png)
*Patches applied to the beacon agent source tree*

The build takes a few minutes depending on your hardware. Make sure your server has at least 2 CPU cores and 2 GB of RAM. Go compilation is memory-intensive. You can check available resources with:

```bash
nproc && free -h
```

When the script finishes, you see "Installation complete!" and the service is running.

![Install script output showing objects_graph built and service restarted](image/adaptix-graph-c2/aaa.png)
*Build complete: 58 object files compiled, listener installed, service restarted*

The script is idempotent. It skips patches that are already applied, so you can run it again safely after updates.

---

## 4 - Create the Listener

Open the Adaptix Client and connect to your server.

Go to **Listeners > Create Listener**. Set the **Protocol** to `external (graph)` and the **Config** to `BeaconGraph`.

The form shows fields for both OneDrive and Blob modes. For blob mode, ignore the OneDrive fields (Tenant ID, Client ID, Client Secret, User ID).

![Create Listener form showing all fields for both storage modes](image/adaptix-graph-c2/07.png)
*The BeaconGraph listener form with all configuration fields*

Set **Storage Backend** to `blob`. Fill in your storage account name, access key, and container name.

| Field | What to Enter |
|-------|---------------|
| Storage Backend | `blob` |
| Storage Account (Blob) | Your storage account name |
| Storage Key (Blob) | Your base64 access key (key1) |
| Container Name (Blob) | Your container name (e.g., `adaptix-c2`) |
| Poll Interval (s) | `5` |
| Encrypt Key | Leave empty (auto-generated) |
| Beacon Poll Attempts | `15` |
| Beacon Poll Interval (ms) | `3000` |

![Create Listener form filled in with blob storage credentials](image/adaptix-graph-c2/08.png)
*Listener configured for blob mode with storage account details*

Click **Create**. Select the new listener and start it.

The listener appears in the Listeners table. The Bind Host column shows `{account}.blob` and the C2 Hosts column shows the full Azure endpoint.

![Listener running in the Listeners table with blob endpoint visible](image/adaptix-graph-c2/09.png)
*Active listener polling `msgraphtest.blob.core.windows.net`*

Once the listener starts, it creates the container in your storage account automatically. You can verify this in the Azure Portal under **Data storage > Containers**.

![Azure Portal Containers view showing containers created by the listener](image/adaptix-graph-c2/15.png)
*Containers created in the `msgraphtest` storage account. The `adaptix-c2` container is where the beacon and listener exchange files. The listener creates it on first start if it does not exist.*

### Tuning the Poll Intervals

The **Poll Interval** (listener side) controls how often the listener checks Azure for new checkin files. 5 seconds is responsive enough for interactive sessions without generating excessive API calls.

The **Beacon Poll Attempts** and **Beacon Poll Interval** control the beacon side. After uploading a checkin file, the beacon polls for a response file up to 15 times, waiting 3 seconds between each attempt. If it does not find a response after 45 seconds, it goes back to sleep and tries again on the next cycle.

For long-haul implants where low-and-slow is the priority, increase the beacon's sleep time and reduce poll attempts. For interactive sessions where you need quick command output, keep the defaults.

---

## 5 - Generate a Beacon

Go to **Generate Agent**. Select the graph listener. Set the architecture to **x64** and the format to **Exe**. Click **Build**.

The build log shows the compilation, configuration embedding, and linking steps. The profile data (SAS token, storage endpoint, poll settings) is compiled into the beacon binary at this stage.

![Generate Agent dialog with successful build log](image/adaptix-graph-c2/10.png)
*Beacon built successfully: 99,840 bytes, Connector: ConnectorGraph*

Download the beacon file to your workstation.

---

## 6 - Deploy and Verify

Transfer the beacon file to a Windows target. Run it.

### What the Wire Looks Like

This is the part that matters for OPSEC. If you capture the beacon's traffic with Wireshark, use these filters:

```
# For HTTP and HTTPS traffic on the target:
http || tls.handshake.type == 1

# Filter for blob storage traffic:
tls.handshake.extensions_server_name contains "blob.core.windows.net"
```

Here is what a defender sees:

![Wireshark capture showing TLS Client Hello with SNI to msgraphtest.blob.core.windows.net](image/adaptix-graph-c2/11.png)
*Wireshark capture: the beacon's outbound traffic shows a TLS handshake to `msgraphtest.blob.core.windows.net`. The SNI, the destination IP, and the certificate chain all belong to Microsoft.*

There is no connection to your server. There is no suspicious domain. There is no unusual port. The beacon makes standard HTTPS PUT and GET requests to an Azure Storage endpoint, indistinguishable from any legitimate application that uses Azure Blob Storage.

A defender looking at proxy logs or SIEM alerts sees:
- **Destination:** `20.150.101.33` (Microsoft Azure IP range)
- **SNI:** `msgraphtest.blob.core.windows.net`
- **Port:** 443
- **Protocol:** TLS 1.3

This is the same traffic pattern produced by Azure DevOps agents, Azure CLI tools, backup software, cloud-native applications, and hundreds of other legitimate services. There is nothing to trigger a detection rule that is not also triggered by normal business operations.

### Callback in Adaptix

Within a few seconds of execution, the agent appears in the Sessions table. The External column shows `graph-api` and the Listener column shows your listener name.

![Sessions table showing the graph beacon callback from samwell.tarly at CASTELBLACK](image/adaptix-graph-c2/12.png)
*Beacon callback: `samwell.tarly` on `CASTELBLACK` via the graph-api transport*

### Running Commands

All standard commands work. BOFs, `shell` commands, file operations, pivoting, SOCKS proxy, port forwarding. The command interface is identical to HTTP beacons. The only difference is the transport layer underneath.

![Console showing whoami /all BOF output from the graph beacon](image/adaptix-graph-c2/13.png)
*`whoami /all` BOF execution through the cloud dead-drop channel*

The output comes back through the same dead-drop mechanism: the listener uploads a response file to Azure, the beacon downloads it on its next poll. The latency is a few seconds, governed by the poll intervals you configured. For interactive sessions, this is fast enough. For long-haul persistence, the reduced traffic volume is an advantage.

---

## 7 - Post-Operation Cleanup

When the engagement ends, the storage account and everything in it needs to go. The beacon binary contains the storage endpoint FQDN and a SAS token. If a defender recovers the binary and extracts those values, you do not want them pointing at a live account with readable activity logs.

### Delete the Storage Account

The cleanest option. One command removes the account, all containers, all blob files, and invalidates every SAS token that was signed with the account key.

```bash
az storage account delete --name msgraphtest --resource-group <rg> --yes
```

The FQDN stops resolving. If someone extracts `msgraphtest.blob.core.windows.net` from a captured beacon, there is nothing on the other end to investigate.

### Rotate the Key Without Deleting

If you need to cut off beacon access but keep the storage account for a new round (different container, fresh SAS tokens), rotate the signing key instead.

```bash
az storage account keys renew --account-name msgraphtest --resource-group <rg> --key key1
```

Every SAS token was signed with that key. Rotating it invalidates all outstanding tokens immediately. Deployed beacons lose access. The storage account stays up, and you can generate new beacons with fresh tokens from the new key.

### Delete Just the Container

If multiple containers are in use (one per target, one per phase), you can remove a single container without touching the rest.

```bash
az storage container delete --name adaptix-c2 --account-name msgraphtest --account-key <key>
```

This removes the container and all blob files inside it, the checkin and response `.dat` files.

### What You Cannot Clean Up

Azure keeps platform-level audit logs (Azure Monitor, Storage Analytics) that record API calls to the account: who uploaded what, from which IP, at what time. Deleting the storage account removes the data, but Microsoft retains platform-level audit logs for their own retention period. The operator does not control that window.

If the engagement requires no forensic trace in the cloud tenant, the storage account should be in a burner Azure subscription, not the operator's primary tenant. Create the subscription with a prepaid card or trial, use it for the engagement, and close it when you are done.

---

## Troubleshooting

### `go: not found` during install

Go is not in the system PATH. The install script adds `/usr/local/go/bin` automatically. If your Go installation is in a different location:

```bash
export PATH="/your/go/path/bin:$PATH"
./scripts/install.sh /path/to/AdaptixC2
```

### All commands return "Command not found"

The server does not register commands for the BeaconGraph listener type. The `ax_config_graph_commands.patch` adds this registration. Verify it was applied:

```bash
grep BeaconGraph dist/extenders/beacon_agent/ax_config.axs
```

You should see at least two lines with `BeaconGraph`. If not, re-run the install script.

### Beacon runs but no callback arrives

The target cannot reach Azure. Verify outbound HTTPS (port 443) to `{account}.blob.core.windows.net`. Use Wireshark to confirm the TLS handshake happens. If you see no outbound connection at all, the beacon may be blocked by a host-based firewall or application whitelisting.

### 403 AuthenticationFailed on blob operations

The SAS token signature does not match. The SAS string-to-sign must use Azure Storage API version `2020-10-02`. This version does not include the `signedEncryptionScope` field. If the field is included (it was added in version `2020-12-06`), the signature is invalid and Azure rejects the request.

### Build is slow or gets killed (OOM)

The server does not have enough resources for Go compilation. Use at least 2 CPU cores and 2 GB of RAM. Verify with `nproc` and `free -h`. If you are running in a container, increase the resource allocation from the host before rebuilding.

---

## Uninstall

To remove the plugin and reverse all source tree modifications:

```bash
./scripts/uninstall.sh /path/to/AdaptixC2
```

---

**Previous:** [Part 3: Beacon Source Modifications](writeup.html?file=writeups/adaptix-beacon-mods.md)
