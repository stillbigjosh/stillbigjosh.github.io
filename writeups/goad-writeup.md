---
title: "Building a Game Of Active Directory Cyber range with Elastic stack on Ludus v2"
kicker: "Homelab · Cyber Range · Active Directory"
tags: "Ludus v2 · GOAD-Light · Elastic Security"
lead: "A walkthrough of standing up a working cyber range on a single home Proxmox box: a forest Active Directory attack lab (GOAD-Light) with a full Elastic Security stack, all deployed through Ludus v2."
toc_extra: "Part 2 - Purple Team Lab: Detection scenarios for Active Directory with Elastic SIEM/EDR stack|https://stillbigjosh.github.io/writeup.html?file=writeups/detection-scenarios.md"
---

![GOAD-Light + Elastic EDR network topology diagram](https://cdn-images-1.medium.com/max/800/1*0IZtJWQi32mCiZDL6OXGhg.png)
*GOAD-Light + Elastic EDR network topology*

### Overview

This guide walks through building a working cyber range on a home Proxmox box: a small Active Directory attack lab (Game of Active Directory, "GOAD-Light" flavor) with Elastic Security as the EDR/SIEM overlay, all deployed via Ludus v2 on a single mini PC.

**The end state:**

- Three Windows VMs forming a forest Active Directory environment with intentional misconfigurations to exploit
- One Debian VM running the full Elastic stack (Elasticsearch, Kibana, Fleet Server) as EDR/SIEM
- Elastic Agents deployed to every Windows VM, streaming Sysmon and Windows events to Kibana
- Attacks driven from the home PC over WireGuard (no in-range Kali VM), which frees RAM for Elastic and keeps attack tooling on hardware you already know
- Full isolation from any other range on the same host, reached over WireGuard from a laptop or the home PC

**Hardware target:** a mini PC with Ryzen 7 6800U (an integrated GPU, no discrete GPU). Storage over 200 GB SSD.

**Software baseline:** Proxmox 9.1.6 host at `192.168.1.100`, Ludus v2 installed and healthy, an existing user (`stillbigjosh`) with a personal "Development and testing Range" already installed, that is currently powered off.

![Proxmox VE 9.1.6 dashboard](https://cdn-images-1.medium.com/max/800/1*xcyDBmlLfoUwq7JGqGzqIA.png)
*Proxmox VE 9.1.6*

This new Active Directory range will get a separate Ludus user (created by the GOAD tooling), so it is fully isolated from the Dev Range at the Ludus, Proxmox, and network layers. Two ranges cannot accidentally share VLANs, routes, or WireGuard peers.

---

## Goals and Design Decisions

**Goal 1: Learn how a real cyber range is deployed end-to-end.** GOAD-Light is the smaller variant of Orange Cyberdefense's Game of Active Directory: it strips full GOAD from five Windows VMs down to three and skips the SCCM/ADCS overlays. Enough surface area to practice Kerberoasting, unconstrained delegation, forest-trust abuse, and lateral movement, but small enough to fit on a 24 GB RAM mini PC.

**Goal 2: See what an attack looks like from the defender side.** The whole point of layering Elastic on top is to close the loop: attack from Kali, watch Elastic Defend and Sysmon light up in Kibana, understand which telemetry catches which technique. This is exactly the pattern that shows up in SOC-analyst and red-team-with-EDR-awareness paths.

**Goal 3: Full isolation from the Dev Range.** The Dev Range VMs stay powered off. The new range runs as a separate Ludus user (the GOAD tooling creates one automatically), which means a separate Proxmox pool, separate VLAN space, and separate WireGuard tunnel. Nothing bleeds between the two.

**Why no Kali VM in the range?** A Kali VM inside the range would eat 4 GB of RAM that Elastic desperately wants on a 24 GB box. Since Ludus's WireGuard tunnel puts the home PC directly onto the range network (the home PC gets an IP inside the range and can route to any VM), there is zero functional difference between attacking from an in-range Kali and attacking from the home PC. The home PC option gives back 4 GB, avoids the KasmVNC web console hop, and keeps attack tooling on hardware with familiar keybindings and shell history. Attack tools on the home PC can be a native Kali install, Kali on WSL2 (Windows), a local Kali/Parrot VM in VMware or VirtualBox, or a Docker image with impacket, bloodhound-python, crackmapexec, etc. All hit the DCs the same way once WireGuard is up.

**Why Elastic and not Wazuh or Splunk?** All three are valid choices. Elastic wins for this build because Bad Sector Labs already ships two official Ansible roles for Ludus: `badsectorlabs.ludus_elastic_container` deploys the whole Elastic stack in Docker on a Debian VM, and `badsectorlabs.ludus_elastic_agent` pushes agents to endpoints and enrolls them into Fleet. That means the entire EDR pipeline is one YAML change plus a role deploy, not a manual Kibana walkthrough. Wazuh has a community role too (`aleemladha.wazuh_server_install` + `aleemladha.ludus_wazuh_agent`) and would work; Splunk requires more manual setup and licensing.

**Why GOAD.sh instead of the v2 blueprint?** Bad Sector Labs publishes a `bsl/goad` blueprint in their Ludus source that can be deployed with one command (`ludus range create --from-blueprint bsl/goad`). That is genuinely faster. This guide uses the canonical GOAD.sh method instead, because:

1. It is the officially documented path in the Ludus GOAD guide.
2. It automatically creates a dedicated `GOADxxxxxx` Ludus user, giving perfect isolation from the Dev Range without manual user management.
3. It surfaces each installation step, which is more educational than a black-box blueprint.
4. If something fails, the GOAD tool has its own interactive shell for retries.

---

## Hardware Reality Check

Proxmox and Ludus need some RAM for themselves. Every VM eats a chunk as well. This is the RAM budget planned against:

![RAM budget breakdown table](https://cdn-images-1.medium.com/max/800/1*ZGPr4eNh8f2QjNGsPSYAuQ.png)
*RAM Budget*

> [!NOTE]
> **About the VM names.** These VMs are named `DC01`, `DC02`, `SRV02` in the Ludus/Proxmox layer (they show up as `GOADxxxxxx-GOAD-DC01`, etc). Blog posts and older GOAD documentation often refer to the same machines by their in-lab hostnames from the Game of Thrones theme (KINGSLANDING for DC01, MEEREEN for DC02, CASTELBLACK for SRV02). Those thematic names are still applied at the domain layer by GOAD's Ansible playbooks. Either name is valid; this guide uses the DC01/DC02/SRV02 names.

Two things follow from this:

1. **The personal Dev Range must stay powered off during any active GOAD work.** Its two VMs (one Ubuntu host and its router) would blow the RAM budget instantly.
2. **No Kali VM in the range.** Attacks come from the home PC over WireGuard. This is the single biggest RAM decision, freeing 4 GB that goes to Elastic and leaving genuine headroom on the host.

If ingestion is still unstable under sustained attack telemetry, drop the Elastic container to 6 GB. Below that, Elasticsearch will start throwing errors and the dashboard will go blank.

Disk-wise, GOAD-Light plus Elastic runs comfortably in around 100 GB provisioned; Proxmox thin-provisions so actual usage is much lower.

---

## Phase 1: Verify Ludus v2 State

Before touching anything else, confirm that you are running Ludus v2 and that the v2 upgrade is fully healthy.

SSH into the Proxmox host as root:

```bash
ssh root@192.168.1.100
```

Confirm Ludus version and services:

```bash
ludus version
systemctl status ludus ludus-admin --no-pager | head -30
```

![Ludus version check output](https://cdn-images-1.medium.com/max/800/1*Nn0z8X5Zts6gvcIkSmECZQ.png)
*Ludus version check*

The version should report `2.x`. Both services should be `active (running)` with no recent restart loops.

Confirm the Dev Range is powered off (per plan):

```bash
ludus range list
```

![Dev range powered off list](https://cdn-images-1.medium.com/max/800/1*Vautlh20Wos1sfvuMmDiPg.png)
*Dev Range powered off*

The `POWER` column for both dev VMs should show `Off`. If not, power them down before continuing:

```bash
ludus power off -n all
```

Confirm the Ludus disk state is healthy and the ROOT API key is accessible:

```bash
df -h /opt/ludus
ls -la /opt/ludus/db/
cat /opt/ludus/install/root-api-key | wc -c
```

`df` should show plenty of free space. The `db` directory should contain `data.db` and `auxiliary.db`, both owned by `ludus:ludus`. The API key file should be non-empty (a base64-ish string of a couple hundred bytes).

![Storage and health check output](https://cdn-images-1.medium.com/max/800/1*fHYHrfh6yfFjJBxQAaUqdg.png)
*Storage and health check*

Confirm the client-side API key is set and points at the local server:

```bash
echo $LUDUS_API_KEY
echo $LUDUS_URL
```

`LUDUS_API_KEY` should start with `stillbigjosh.` (the admin user's key, not `ROOT.`). `LUDUS_URL` should be `https://127.0.0.1:8080` since this is run on the host.

If either variable is missing:

```bash
export LUDUS_API_KEY='<stillbigjosh api key>'
export LUDUS_URL='https://127.0.0.1:8080'
```

**Why this step matters:** everything downstream (template builds, GOAD deploy, Elastic roles) authenticates through this env. A silently unset key produces confusing "record not found" or 403 errors much later, and looks like a bug in whatever role is running at the time.

---

## Phase 2: Verify Required Templates

Because all three GOAD-Light DCs use Win2019 in this build, and Elastic uses Debian 12, the templates needed are:

- `win2019-server-x64-template` (all three Windows VMs)
- `debian-12-x64-server-template` (Elastic server)

Both should already exist in the Ludus template library from earlier work on this host (visible as VMs 105 and 101 in the Proxmox screenshot). Verify:

```bash
ludus templates list
```

![Ludus templates list](https://cdn-images-1.medium.com/max/800/1*h1pNZ82qAAxLahFpK4G3JQ.png)
*Ludus templates*

Both templates should appear with `Built: true`. If either is missing, add and build it:

```bash
cd /root
git clone https://gitlab.com/badsectorlabs/ludus 2>/dev/null || true
cd ludus/templates

# Only if win2019 is missing
ludus templates add -d win2019-server-x64
ludus templates build -n win2019-server-x64-template
ludus templates logs -f

# Only if debian-12 is missing
ludus templates add -d debian-12-x64-server
ludus templates build -n debian-12-x64-server-template
ludus templates logs -f
```

Windows template builds take 30 to 60 minutes each on the Ren Pro 6000, dominated by Windows Update inside Packer. Debian builds take 10 to 20 minutes. Watch for the final `==> Builds finished` line in the logs. `Ctrl-C` on `logs -f` does not stop the build; it just detaches the view.

**Why templates matter:** every VM in a Ludus range is a linked clone from a template. Building the template once means every subsequent GOAD or Elastic deploy just clones and boots, taking minutes instead of hours.

Templates that can be ignored for this build: `win2016-server-x64-template` (not needed since Win2019 is used for all VMs), `win2022-server-x64-template`, `win11-22h2-x64-enterprise-template`, `kali-x64-desktop-template` (attacks come from the home PC), and `ubuntu-24.04-x64-server-template`.

---

## Phase 3: Install Ansible Roles for Elastic

The two roles needed are `badsectorlabs.ludus_elastic_container` (deploys the Elastic stack in Docker on a Debian VM) and `badsectorlabs.ludus_elastic_agent` (enrolls agents on Windows/Linux endpoints). Install both:

```bash
ludus ansible role add badsectorlabs.ludus_elastic_container
ludus ansible role add badsectorlabs.ludus_elastic_agent
```

Verify:

```bash
ludus ansible role list
```

![Ludus ansible role list output](https://cdn-images-1.medium.com/max/800/1*1BnMGviaEP7o1X0kyS-5zA.png)
*Ludus ansible role list*

Both roles should appear with `GLOBAL: false`. That is expected at this point.

These roles got installed under the current user (`stillbigjosh`), not the future GOAD user. Roles are per-user in Ludus. When the Elastic pieces are deployed later, the GOAD user gets impersonated, and roles need to be visible in that user's context. To make these roles available to any user (recommended for shared roles like Elastic):

```bash
ludus ansible role scope global badsectorlabs.ludus_elastic_container
ludus ansible role scope global badsectorlabs.ludus_elastic_agent
```

Verify the global install:

```bash
ludus ansible role list
```

![Ludus ansible roles now globally available](https://cdn-images-1.medium.com/max/800/1*73jvRHfS38gbZoaNszifnw.png)
*Ludus ansible roles globally available*

---

## Phase 4: Deploy GOAD-Light

This phase uses the official GOAD tooling, which talks to the Ludus API to create a new user, configure a range, and run the GOAD Ansible playbooks that add the specific misconfigurations that make GOAD an attack lab (weak passwords, kerberoastable service accounts, ACL misconfigurations, GPO abuse paths, forest trust, and so on).

#### Install GOAD dependencies

```bash
sudo apt update
sudo apt install -y python3-venv git
```

#### Clone GOAD

```bash
cd /root
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD
```

#### Set the Ludus API key GOAD will use

GOAD needs the Ludus admin API key to create its own user and range, so ensure it's set:

```bash
export LUDUS_API_KEY='<api key>'
echo $LUDUS_API_KEY
```

#### Launch GOAD's interactive shell for the Ludus profile

```bash
./goad.sh -p ludus
```

The script installs requirements and drops you into a GOAD prompt: `GOAD/ludus/local >`

![GOAD interactive shell prompt](https://cdn-images-1.medium.com/max/800/1*x6I0hlacp1sobCVJxSlYig.png)
*GOAD CLI*

#### Configure GOAD-Light and swap MEEREEN's template

Inside the GOAD shell:

```bash
check
set_lab GOAD-Light
```

What each command does:

- `check` verifies Ludus reachability and API key permissions.
- `set_lab GOAD-Light` selects the three-VM Light variant. Other options at this prompt include `GOAD`, `NHA`, `SCCM`.

> [!WARN]
> **Do NOT run `install` yet.** GOAD-Light's canonical config might point to `win2016-server-x64-template`. If that's the case, swap it out first.

Open a second SSH session to the Proxmox host (leave the GOAD shell open in the first session), then find and edit the reference:

```bash
cd /root/GOAD
cat ad/GOAD-Light/providers/ludus/config.yml
```

![GOAD-Light template configuration file](https://cdn-images-1.medium.com/max/800/1*_OSy7d7ix9vlFwakYZegyA.png)
*GOAD-Light template configuration*

The exact file paths vary by GOAD version. If `win2016-server-x64-template` is present in the config.yml, swap it from:

```yaml
template: win2016-server-x64-template
```

to:

```yaml
template: win2019-server-x64-template
```

Save the edited file.

#### Run the install

Back in the GOAD shell:

```bash
install
```

`install` triggers the full deployment: creates a new Ludus user (name like `GOADabc123`), pushes the (now-swapped) range config into that user's context, and runs Packer/Ansible.

Expected duration: several minutes to a few hours. Windows VMs go through initial install, Sysprep, domain promotion, and 50+ Ansible tasks per host. Grab lunch.

Warnings during the run are fine. Actual errors will halt at a specific task and print a red `TASK [...] failed` line. Common failures are documented in the [Troubleshooting Reference](#troubleshooting-reference) below.

While the installation is running, you will see things like the following:

![Installation adding intentional misconfigurations](https://cdn-images-1.medium.com/max/800/1*Sn6XyuvD8U66ryo8rBxZQg.png)
*Installation adding intentional misconfigurations*

#### What "success" looks like

When the install finishes, the GOAD shell prints something like:

![GOAD-Light install success output](https://cdn-images-1.medium.com/max/800/1*8Syf4KfMbyH_55PokFPE_w.png)
*GOAD-Light install success*

```bash
dc01   : ok=X changed=Y unreachable=0 failed=0
dc02   : ok=X changed=Y unreachable=0 failed=0
srv02  : ok=X changed=Y unreachable=0 failed=0
```

All zero `failed`, all zero `unreachable`. Exit the GOAD shell with `exit`.

#### Verify what got created

```bash
ludus users list all --url https://127.0.0.1:8081
```

Two users should now be visible: `stillbigjosh` and the new `GOADxxxxxx`.

![Ludus users list](https://cdn-images-1.medium.com/max/800/1*7FHguGHcETswoURlscNhZA.png)
*Ludus users*

Note the exact GOAD userID; it is needed for every remaining command. For readability, save it to a variable:

```bash
export GOAD_USER=GOADabc123    # replace with your actual userID
```

Check the new range:

```bash
ludus --user $GOAD_USER range list
```

![New range powered on](https://cdn-images-1.medium.com/max/800/1*aDQZPuW3XSULOjg3ssODLQ.png)
*New range powered ON*

Three Windows VMs plus a router should be powered on, with `Deployment Status: OK`. Name the range for future clarity:

```bash
ludus --user $GOAD_USER range update $GOAD_USER --name "GOAD-Light + Elastic" --description "GOAD-Light forest attack lab with Elastic EDR" --purpose "training"
```

GOAD-Light's config sets both DCs to 4 GB, but DC02 has zero users, zero services, and one domain trust. It's a much smaller AD than DC01 (sevenkingdoms.local, which holds the meaningful users). To save headroom, DC02 can happily run at 2.5–3 GB, so its RAM gets resized:

```bash
qm shutdown 111
qm set 111 --memory 3072
qm start 111
```

![Resized memory allocation for DC02](https://cdn-images-1.medium.com/max/800/1*NnigL7I562MfsRNu_R3IIQ.png)
*Resize memory allocation*

#### Smoketest

Before tuning anything, a quick smoke test:

```bash
# From the Proxmox host, quick reachability check
ludus --user $GOAD_USER range status

# Confirm all 4 VMs are On with IPs
ping 10.1.10.254   # router
ping 10.1.10.10    # DC01
ping 10.1.10.11    # DC02
ping 10.1.10.22    # SRV02
```

Pull the WireGuard config:

```bash
# Get your WireGuard config, admin can pull for another user
ludus --user $GOAD_USER users wireguard > /root/goad-user-wg.conf
```

Copy the config to the home PC, then install `wireguard-tools`:

```bash
# Install wireguard-tools if not yet installed
sudo apt install wireguard-tools

# Connect to GOAD
chmod 600 ~/Ludus/goad-user-wg.conf
sudo wg-quick up ./goad-user-wg.conf

# Router (should always answer)
ping -c 3 10.1.10.254

# DC01 (KINGSLANDING, sevenkingdoms.local)
ping -c 3 10.1.10.10

# DC02 (essos.local root DC)
ping -c 3 10.1.10.11

# SRV02 (member server)
ping -c 3 10.1.10.22
```

If Windows firewall blocks ICMP on the Windows VMs, pings may fail, but that doesn't mean the tunnel is broken. Fall back to a TCP check that works even with ICMP blocked:

```bash
# Test SMB port 445 on each DC
nc -zv 10.1.10.10 445
nc -zv 10.1.10.11 445
nc -zv 10.1.10.22 445
```

That should validate the GOAD range works end-to-end. Adding Elastic on top of a broken range is much harder to debug.

---

## Phase 5: Layer Elastic Server on the GOAD Range

Now to add the Elastic container VM to the GOAD range. This is where Ludus v2's flexibility shines: a range's config is just YAML that can be edited and re-applied.

#### Pull the current range config

```bash
ludus --user $GOAD_USER range config get > /root/goad-elastic-config.yml
```

Open the file:

```bash
nano /root/goad-elastic-config.yml
```

Three Windows VMs defined by GOAD should be visible. The important thing to note is the VLAN they are on: GOAD-Light uses VLAN 10 by default. The Elastic server goes on its own VLAN (VLAN 20) so the "monitoring" tier is logically separated from the "victim" tier, mirroring real deployments.

#### Add the Elastic container VM

This block gets appended to the `ludus:` list in the YAML (keeping the existing GOAD VMs above it):

```yaml
- vm_name: "{{ range_id }}-elastic-server"
  hostname: "{{ range_id }}-elastic"
  template: debian-12-x64-server-template
  vlan: 20
  ip_last_octet: 2
  ram_gb: 8
  cpus: 4
  linux: true
  testing:
    snapshot: false
    block_internet: false
  roles:
    - badsectorlabs.ludus_elastic_container
  role_vars:
    ludus_elastic_password: "ChangeThisPassword123!"
    ludus_elastic_stack_version: "8.15.0"
```

A quick unpack of every field:

- `vm_name` uses `{{ range_id }}` so the VM name becomes globally unique across ranges. Ludus expands this to the GOAD userID at deploy time.
- `template` uses `debian-12-x64-server-template`, already in the template inventory. Elasticsearch runs well on Debian; the role expects a Debian or Ubuntu base.
- `vlan: 20` puts the box on a subnet distinct from GOAD's `vlan: 10`. Ludus's router VM forwards traffic between them by default, so agents on VLAN 10 can still reach the server on VLAN 20.
- `ip_last_octet: 2` gives the Elastic server the address `10.<rangenum>.20.2`. The `.254` in any VLAN is reserved for the Ludus router itself.
- `ram_gb: 8` matches the role's recommended default. Since attacks come from the home PC (no in-range Kali eating RAM), 8 GB fits the budget comfortably and gives Elasticsearch enough heap plus headroom for Kibana and Fleet on the same box. Below 4 GB, Elasticsearch will OOM under load.
- `cpus: 4` gives enough headroom for indexing plus queries.
- `linux: true` tells Ludus to skip Windows-specific setup (no sysprep, no domain join).
- `testing.snapshot: false` skips this VM when the range enters testing mode; you don't want to revert your EDR server during an attack simulation, since it would lose all captured telemetry.
- `roles` invokes the container role.
- `role_vars.ludus_elastic_password` sets the elastic superuser password, used later to log into Kibana.
- `role_vars.ludus_elastic_stack_version` pins a specific Elastic version. Using `"8.15.0"` (or whatever the current stable series is at build time) prevents drift and makes this environment reproducible later. Check the role's README on GitHub for the currently recommended version.

Save and exit.

#### Push and deploy just the new VM

```bash
ludus --user $GOAD_USER range config set -f /root/goad-elastic-config.yml
ludus --user $GOAD_USER range deploy -t vm-deploy
ludus --user $GOAD_USER range logs -f
```

`-t vm-deploy` limits the deploy to VM provisioning tasks, not a full Ansible re-run on the existing GOAD hosts. This avoids re-running the GOAD playbooks unnecessarily. Once the Elastic VM is up:

![Elastic VM deployed](https://cdn-images-1.medium.com/max/800/1*m6mk5b7w8p6Up3ICq7LwYg.png)
*Elastic VM deployed*

```bash
ludus --user $GOAD_USER range status
```

Four VMs should now be visible, with the Elastic server showing an IP like `10.<rangenum>.20.2`, powered on, no deployment errors.

![Elastic VM IP allocated](https://cdn-images-1.medium.com/max/800/1*V1I-EPWkCTB0T1Cl2iYzIg.png)
*Elastic VM IP allocated*

#### Run the Elastic container role

Now install Elastic on the newly created VM:

```bash
ludus --user $GOAD_USER range deploy -t user-defined-roles --limit $GOAD_USER-elastic-server
ludus --user $GOAD_USER range logs -f
```

Expected duration: 15 to 30 minutes. The role downloads Docker images for Elasticsearch, Kibana, Logstash, and Fleet Server, then starts them all in a docker-compose stack.

One error encountered: `geerlingguy.docker` was installed for `stillbigjosh` but not for the GOAD user, and not global. The offending line in the role's meta was:

```yaml
dependencies:
  - role: geerlingguy.docker
    ^ here
```

The Ansible role search path Ludus uses when deploying to the GOAD range doesn't include `stillbigjosh`'s roles. The fix:

```bash
# 1. Add the docker role for the GOAD user
ludus --user $GOAD_USER ansible role add geerlingguy.docker

# 2. Verify (geerlingguy.docker should appear in the list)
ludus --user $GOAD_USER ansible role list

# 3. Also check for other deps in the elastic_container's meta
cat /opt/ludus/resources/global-roles/badsectorlabs.ludus_elastic_container/meta/main.yml

# 4. Add any others that show up in dependencies (if any)
# 5. Rerun the elastic deploy
ludus --user $GOAD_USER range deploy -t user-defined-roles --limit $GOAD_USER-elastic-server
ludus --user $GOAD_USER range logs -f
```

Under the hood, these are the Docker images the Elastic deploy is trying to pull:

```bash
# 1. Elasticsearch
sudo docker pull docker.elastic.co/elasticsearch/elasticsearch:8.15.0

# 2. Kibana (~1.1 GB)
sudo docker pull docker.elastic.co/kibana/kibana:8.15.0

# 3. Fleet Server (~700 MB)
sudo docker pull docker.elastic.co/beats/elastic-agent:8.15.0
```

Success looks like Ansible reporting `ok=X changed=Y failed=0` for the elastic-server host.

#### Verify Kibana works

From the Proxmox host or over WireGuard (see Phase 8), browse to:

```bash
https://10.<rangenum>.20.2:5601
```

Log in as `elastic` with the password set in `ludus_elastic_password`. You should land on the Kibana home page.

![Kibana installation success](https://cdn-images-1.medium.com/max/800/1*0wAkBvdEbftpbE-DBC_PVQ.png)
*Kibana installation done*

#### To grab the enrollment token

Log into Kibana at `https://10.1.20.2:5601`, then go to the Agent policies tab (in the Fleet app): `https://10.1.20.2:5601/app/fleet/policies`

Elastic Fleet has two kinds of policies:

- **Fleet Server policy**; for the Fleet Server component itself. Only one Fleet Server needs it, and the one in the Docker container is already enrolled with it.
- **Endpoint / Agent policies**; for hosts you want to monitor. Windows VMs need one of these.

Enrolling Windows machines against the Fleet-Server-Policy would try to make them into Fleet Servers, which fails or creates a broken configuration.

**Step 1:** Go to the Agent policies tab (in the same Fleet app): `https://10.1.20.2:5601/app/fleet/policies` — only `Fleet-Server-Policy` should be listed initially.

**Step 2:** Click "Create agent policy" in the top-right.

**Step 3:** Fill in these fields:

- **Name:** `Windows Endpoints` (or anything descriptive)
- **Description:** `Policy for GOAD-Light Windows VMs` (optional)
- **Namespace:** leave as `default`
- **Collect system logs and metrics:** leave this checked (baseline telemetry)
- Advanced options: leave defaults

**Step 4:** Click "Create agent policy" at the bottom.

**Step 5:** Add integrations; this is where the actual detection value comes from. Once the policy is created, click "Add integration". The three most valuable integrations for GOAD-Light attack detection:

1. **Elastic Defend:** Elastic's EDR. Includes prebuilt malware detection, memory protection, response actions. Big feature; enable it.
2. **Windows:** collects Windows event logs (Security, Sysmon, PowerShell, Application). This is where Kerberoasting/DCSync/etc detection rules read from.
3. **System:** CPU, memory, network stats. Useful for identifying compromised behavior via anomalies.

For each integration: click "Add [integration name]", accept most defaults, assign to the "Windows Endpoints" policy, and save.

**Step 6:** Go to the Enrollment tokens tab. Two rows should now be visible: a `Default (…)` row bound to `Fleet-Server-Policy` (ignore this), and a new row bound to `Windows Endpoints`. Click the eye icon to reveal the secret and copy the full string.

**Also grab the Fleet Server URL**; in the Fleet UI, click the Settings tab (top of Fleet page) and look for the "Fleet Server hosts" section. It will show something like `https://10.1.20.2:8220`. Copy that URL.

> If the Fleet Server URL isn't present, click "Add Fleet Server". In the dialog: **Name**; `fleet-server` (or anything descriptive); **URL**; `https://10.1.20.2:8220`; **Is default**; check this box; then Save. The URL `https://10.1.20.2:8220` is the address agents use to enroll and stream data. Port 8220 is the standard Fleet Server port, and Fleet Server in the container is listening on that port on the Elastic VM.

Before committing to deploying agents, one last check from the Ludus host:

```bash
curl -sk https://10.1.20.2:8220/api/status
```

Expected: `{"status":"HEALTHY","name":"fleet-server","version":"..."}`. If HEALTHY, proceed to agents.

---

## Phase 6: Layer Elastic Agents on GOAD Windows Hosts

Elastic Agents ship telemetry from every Windows box to Kibana. On Elastic v8.x with Defend, agents include EDR functionality (process, file, network events, and hunting queries) alongside Sysmon.

#### Note the fleet server URL and enrollment token

Two variables are needed:

```bash
Fleet URL:         https://<elastic-server-ip>:8220
Enrollment token:  <token from Phase 5>
```

#### Edit the range config again

```bash
ludus --user $GOAD_USER range config get > /tmp/config.yml
nano /tmp/config.yml
```

For each of the three GOAD Windows VMs (DC01, DC02, SRV02), add a `roles:` block if not present, plus the Elastic agent role and a `depends_on` so agents deploy only after the server is up. Example (repeat the pattern for the other two):

```yaml
- vm_name: "{{ range_id }}-KINGSLANDING"
  # ... existing fields from GOAD ...
  roles:
    - name: badsectorlabs.ludus_elastic_agent
      depends_on:
        - vm_name: "{{ range_id }}-elastic-server"
          role: badsectorlabs.ludus_elastic_container
  role_vars:
    ludus_elastic_enrollment_token: "<paste the token>"
    ludus_elastic_fleet_server: "https://10.<rangenum>.20.2:8220"
    ludus_elastic_agent_version: "8.15.0"
    ludus_elastic_install_sysmon: true
```

Notes:

- `depends_on` tells Ludus to wait until the Elastic server has completed its container role before running the agent role. Without this, agents will try to enroll against a Fleet Server that does not exist yet.
- `ludus_elastic_install_sysmon: true` installs Sysmon and applies a default config; Elastic v8 auto-ingests Sysmon events. This dramatically improves visibility into command-line activity.
- Keep `ludus_elastic_agent_version` matched to the `ludus_elastic_stack_version` on the server. Mismatched agents will refuse to enroll.

Save and exit.

#### Also install the ludus_elastic_agent role for the GOAD user

If not already done:

```bash
ludus --user $GOAD_USER ansible role add badsectorlabs.ludus_elastic_agent
ludus --user $GOAD_USER ansible role list | grep elastic
```

#### Push and deploy only the roles

```bash
# On the Ludus host
ludus --user $GOAD_USER range config set -f /tmp/config.yml

# The key: --limit prevents re-running the container role
ludus --user $GOAD_USER range deploy -t user-defined-roles --limit "$GOAD_USER-GOAD-DC01,$GOAD_USER-GOAD-DC02,$GOAD_USER-GOAD-SRV02"

ludus --user $GOAD_USER range logs -f
```

Expected duration: 10 to 20 minutes for three agents. Watch for `ok=` totals per host at the end and no `failed=`.

![Ansible roles deployed successfully](https://cdn-images-1.medium.com/max/800/1*denRgzYJoxaq81bYeYamzQ.png)
*Ansible roles deployed*

#### Verify agents in Kibana

In Kibana, go to Management → Fleet → Agents. All three Windows hosts should appear as `Healthy`. (`https://10.1.20.2:5601/app/fleet/agents`)

![Fleet management showing healthy agents](https://cdn-images-1.medium.com/max/800/1*89fdAU29U5w4lD8kOFf5Lw.png)
*Fleet management*

Also visit Security → Explore → Hosts. Each host should be sending events (process, file, network).

![Hosts view in Kibana Security](https://cdn-images-1.medium.com/max/800/1*zm5Tkl98b1wAVVRtsjXs_Q.png)
*Hosts*

![Events streaming into Kibana](https://cdn-images-1.medium.com/max/800/1*bl6F8b8JUmPMp964lHMzaw.png)
*Events*

![Detection rules list in Kibana](https://cdn-images-1.medium.com/max/800/1*xZ4epRKX4cSmB62mJNvxOw.png)
*Rules*

![Alerts view in Kibana Security](https://cdn-images-1.medium.com/max/800/1*_ay9D-m2N-S-fd2otcE19Q.png)
*Alerts*

At this point the range is functionally complete: three GOAD-Light AD hosts, Elastic Defend running on all of them, telemetry flowing into Kibana. On the Ludus host, snapshot the clean baseline:

```bash
ludus --user $GOAD_USER snapshots create baseline -d "Clean GOAD-Light + Elastic baseline"
ludus --user $GOAD_USER snapshots list
```

#### Things to Note

**Always use `--limit` when deploying.** Any time you tweak the range config and deploy, exclude the elastic-server unless you specifically need to reconfigure it:

```bash
ludus --user $GOAD_USER range deploy -t user-defined-roles \
  --limit "$GOAD_USER-GOAD-DC01,$GOAD_USER-GOAD-DC02,$GOAD_USER-GOAD-SRV02"
```

When you shut down/restart the range in the future, don't run `range deploy`. Just power on:

```bash
ludus --user $GOAD_USER power on -n all
```

That boots existing VMs without triggering Ansible. The state you snapshotted persists.

---

## Phase 7: Snapshots and Testing Mode

Before attacking, always snapshot the clean state. This gives a rollback point so attacks can be rerun against a pristine environment repeatedly.

```bash
ludus --user $GOAD_USER snapshots create baseline-2026-07-06 -d "Description"
ludus --user $GOAD_USER snapshots list
```

The snapshot covers all four VMs at once. When you are done attacking, revert the VMs to the created baseline state:

```bash
ludus --user $GOAD_USER snapshots revert <snapshot-name>
# e.g
ludus --user $GOAD_USER snapshots revert baseline-2026-07-06
```

The attack iteration workflow scenario:

```bash
# 1. Take a fresh snapshot right before attacking (fast, gives clean revert point)
ludus --user $GOAD_USER snapshots create pre-kerberoast-attempt-1 -d "Before first kerberoast attempt"

# 2. Attack from home PC (over WireGuard)
crackmapexec smb 10.1.10.0/24 -u <user> -p <pass>
impacket-GetUserSPNs -request -dc-ip 10.1.10.10 sevenkingdoms.local/<user>:<pass>

# 3. Observe in Kibana:
#    - Did detections fire? Which ones?
#    - Which events reached Elastic?
#    - What did Sysmon capture?

# 4. Rollback to clean state
ludus --user $GOAD_USER snapshots revert pre-kerberoast-attempt-1

# 5. Repeat with variations
```

#### Testing mode

This is a Ludus feature that combines two things: it takes a snapshot and blocks all outbound internet traffic from range VMs (so a real-world payload does not accidentally phone home). Enter it before attack work:

```bash
ludus --user $GOAD_USER testing start
```

Exit it (which reverts to the pre-testing snapshot) when done attacking:

```bash
ludus --user $GOAD_USER testing stop
```

Or allow specific outbound destinations while still in testing mode:

```bash
ludus --user $GOAD_USER testing allow -d github.com
```

**Why testing mode matters for this build:** Elastic Agent phones home to `elastic.co` for updates by default. Once inside testing mode, those requests get blocked, and detections stay purely internal, which is what you want for realistic simulation.

#### When testing mode really matters vs. when it doesn't

**Testing mode matters most for:**

- **Detonating actual malware:** you don't want a lab specimen phoning home to a real C2
- **Testing evasion techniques:** seeing what your specific EDR catches vs. what it doesn't, without Elastic's cloud-side reputation service influencing detection
- **Payload development / obfuscation work:** you don't want your custom implant getting fingerprinted by Elastic and added to public detection sets
- **Iteration testing:** where a guaranteed clean revert after each attempt is wanted

**Testing mode is overkill for:**

- **AD attack technique practice** (Kerberoasting, DCSync, delegation abuse): these don't leak anything meaningful even if internet is on; the attack vectors are internal to the domain
- **Tuning detection rules:** internet may be wanted to search docs, view rule details on Elastic's site, download rule updates
- **Note-taking or screenshotting:** no benefit

Keep testing mode as a tool you know exists, to reach for when needed (malware, evasion, or paranoid iteration).

---

## Phase 8: Access from Home PC via WireGuard

Since there is no Kali VM in the range, all attacks originate from the home PC. WireGuard puts the home PC directly onto the range network: it gets an IP inside the range subnet and can route to every VM as if physically on the same LAN.

#### Generate the WireGuard config for the GOAD user

```bash
ludus --user $GOAD_USER users wireguard > /root/goad-user-wg.conf
```

Move it to the home PC by whatever method you prefer (scp, USB stick, secure paste, `cat` into a QR code). Import into the WireGuard client:

- Windows: WireGuard GUI, "Import tunnel(s) from file"
- Mac: WireGuard from the App Store, "Import Tunnel(s) from File"
- Linux: `sudo wg-quick up ./goad-user-wg.conf`
- Mobile: WireGuard app, "Add from QR code" (generate on the Ludus host with `qrencode -t ansiutf8 < /root/goad-user-wg.conf`)

#### Connect and verify reachability

Bring the tunnel up, then from the home PC:

```bash
# Confirm the tunnel is up and routing
ping 10.<rangenum>.10.10        # KINGSLANDING DC
ping 10.<rangenum>.20.2         # Elastic server

# Confirm DNS from the DC works
nslookup sevenkingdoms.local 10.<rangenum>.10.10
```

If pings fail, the tunnel is up but the router VM inside the range is not forwarding. Confirm the range's router is running (`ludus --user $GOAD_USER range status`) and that no manual firewall rules have been added to it.

#### Access the range services

Once connected:

- Kibana at `https://10.<rangenum>.20.2:5601` in the home PC browser
- RDP directly into Windows VMs using their `10.<rangenum>.10.X` addresses (any RDP client works; default GOAD creds documented in the GOAD repo)
- SSH to the Elastic server at `10.<rangenum>.20.2` as `localuser` with password `password`

#### Callbacks

If you need to train with a C2 or get a reverse shell, it's also imperative to allow callbacks. Blocking callbacks is a Ludus default, so you'll need to enable them explicitly. On the Proxmox host, add a rule to the range config allowing VMs on VLAN 10 to reach the WireGuard IP:

```bash
ludus --user $GOAD_USER range config get > /tmp/config-check.yml
nano /tmp/config-check.yml
```

```yaml
network:
  rules:
    - name: Allow VLAN 10 callbacks to WireGuard
      vlan_src: 10
      vlan_dst: wireguard
      protocol: all
      ports: all
      action: ACCEPT
```

Add the `network` block at the bottom of the config, at the same indentation level as `ludus`. So the full file ends with:

```yaml
      ludus_elastic_stack_version: "8.15.0"

network:
  rules:
    - name: Allow VLAN 10 callbacks to WireGuard
      vlan_src: 10
      vlan_dst: wireguard
      protocol: all
      ports: all
      action: ACCEPT
```

Then redeploy:

```bash
ludus --user $GOAD_USER range config set -f /tmp/config-check.yml
ludus --user $GOAD_USER range deploy -t network --limit $GOAD_USER-router-debian11-x64
```

#### Set up attack tooling on the home PC

Pick one of these paths, depending on the home PC OS:

**Option 1: WSL2 Kali on Windows**

```bash
# In an admin PowerShell
wsl --install -d kali-linux
# Then inside WSL:
sudo apt update
sudo apt install -y crackmapexec impacket-scripts bloodhound.py \
  kerbrute enum4linux-ng smbclient
```

**Option 2: Native Kali or Parrot on the home PC.** Already have the tools; just install WireGuard and connect.

**Option 3: Local Kali VM on the home PC.** Boot the Kali VM in VMware Workstation, VirtualBox, or UTM. Install WireGuard on the guest and connect from inside the VM. This gives full GUI tools (BloodHound CE, Burp) without touching the home PC OS.

**Option 4: Docker containers.** Good for isolated per-tool workflows:

```bash
docker run --rm -it --network host \
  -v $(pwd):/data kalilinux/kali-rolling bash
```

Note that `--network host` is required for WireGuard traffic to reach the container transparently.

For a first run, WSL2 Kali on Windows or a native install gets you productive fastest. GUI-heavy work (BloodHound CE web UI, Kibana investigations, Burp Suite) can just run on the host OS browser since WireGuard covers routing.

If the home PC has more than 24 GB of RAM, running BloodHound CE (with its Neo4j and PostgreSQL containers) locally via Docker is a nice separation of concerns: the range holds the target AD, the home PC holds attack tooling and analysis platforms. The tunnel keeps them connected.

---

## Phase 9: First Attack from Home PC, Detection in Kibana

The whole point of a range like this is to run attacks and watch them detect (or evade) in the SIEM. A simple first pass to prove the loop works.

#### From the home PC (WireGuard connected)

With the tunnel from Phase 8 up, all commands run against the range from the home PC's Kali/WSL2/Docker shell just as they would from an in-range Kali:

```bash
# Confirm you can hit AD
nslookup sevenkingdoms.local 10.<rangenum>.10.10
crackmapexec smb 10.<rangenum>.10.0/24 -u '' -p ''

# Basic Kerberoast (GOAD ships intentionally weak SPN accounts)
impacket-GetUserSPNs -request \
  -dc-ip 10.<rangenum>.10.10 \
  sevenkingdoms.local/eddard.stark:'Sansa$Stark'
```

The exact GOAD-Light default credentials are documented in the GOAD README under `ad/GOAD-Light/data/`. `eddard.stark` and his kerberoastable password are standard.

Because the source IP of every attack is the home PC's WireGuard address (`198.51.100.X`, not a `10.<rangenum>.10.X` inside-range address), all detections in Kibana will show `source.ip` values from that WireGuard subnet. This is worth calling out: it makes attacker attribution trivial in the lab but also reflects a real-world VPN pivot scenario.

#### In Kibana

It's important to set up alerts before proceeding further, and also enable detection rules at the start of the exercise. To do this, use the global search for "prebuilt detection rules" if not already active:

1. Click the Search bar at the very top center of the Kibana screen (or press `Ctrl + /` on Windows or `Cmd + /` on Mac).
2. Type `Detection rules (SIEM)`.
3. Select pre-built security detection rules.

![Add detection rules screen in Kibana](https://cdn-images-1.medium.com/max/800/1*oErNfI4kGjcVoivUr6m2yQ.png)
*Add detection rules*

4. Add to the existing agent policy as shown above.
5. Save and continue.

If nothing fires immediately, check Discover with a broad `event.dataset:*windows*` query and confirm events are actually landing. If they are but no alerts fire, the prebuilt rules may not be enabled; enable them under Security → Rules → Detection rules (SIEM) → Add Elastic Rules → Install all.

![Install Elastic Rules button](https://cdn-images-1.medium.com/max/800/1*17YYMCAYcJoSk0qVnImZKQ.png)
*Install Elastic Rules*

You should now return to the Detection rules (SIEM) page and enable the rule(s) relevant to what you are trying to achieve.

![Enabling an Elastic detection rule](https://cdn-images-1.medium.com/max/800/1*p6t2ILcBx5byojZE8e1xbQ.png)
*Enable an Elastic Rule*

As you can see, the ruleset is quite large. Search the MITRE ATT&CK ID of a technique (e.g. `T1558.003` for Kerberoasting) to locate its rule.

**Iteration pattern for the rest of your learning:** try an attack technique, note whether it fires, note the MITRE ATT&CK ID, revert to the clean baseline (`ludus snapshots rollback`), tweak, retry.

---

## Troubleshooting Reference

#### Templates take forever or fail with "no space left on device"

```bash
df -h /var/lib/vz
qm list
```

If Proxmox storage is full, remove templates you do not need:

```bash
ludus templates rm -n <template-name>
```

#### GOAD.sh fails partway through

Re-enter its shell and resume:

```bash
cd /root/GOAD
./goad.sh -p ludus
```

Inside the prompt:

```bash
load <instance-id>
install
```

`load` picks up the existing instance; `install` restarts from where it failed.

#### GOAD.sh fails with "template win2016-server-x64-template not found"

A win2016 reference was missed during the Win2019 swap (Phase 4). Two options:

**Option A (preferred):** grep GOAD again and fix the source, then retry install.

```bash
grep -rln "win2016" /root/GOAD/ludus/ /root/GOAD/ansible/ 2>/dev/null | \
  xargs -I{} sed -i 's/win2016-server-x64-template/win2019-server-x64-template/g' {}
```

**Option B:** patch the range config Ludus already received. GOAD does not overwrite Ludus's range config on retry, so this works and is fast:

```bash
ludus --user $GOAD_USER range config get > /tmp/goad-fix.yml
sed -i 's/win2016-server-x64-template/win2019-server-x64-template/g' /tmp/goad-fix.yml
ludus --user $GOAD_USER range config set -f /tmp/goad-fix.yml
```

Then back in the GOAD shell: `install`.

#### GOAD.sh fails with "Unable to clone vm" due to insufficient permission

Grant the GOAD user PVEAdmin rights to the local/local-lvm storage space:

```bash
pveum user token modify goadlight0cfda0@pam ludus-token --privsep
pveum acl modify / -user goadlight0cfda0@pam -roles PVEAdmin
pveum acl modify /storage/local-lvm -user goadlight0cfda0@pam -roles PVEAdmin
pveum acl modify /storage/local -user goadlight0cfda0@pam -roles PVEAdmin
```

#### GOAD Ansible fails on "synchronizes all domains" or DNS-related tasks

The documented fix is to remove `10.<rangenum>.10.254` from the failing VM's DNS servers manually via the Proxmox console, then re-run the failing task. This happens because Ludus's router provides DNS by default, which conflicts with the AD DCs' own DNS role.

#### GOAD stuck on SRV02 SSMS installation

In the GOAD shell, press `CTRL-C` twice, then on a separate terminal run the following:

```bash
# 1. Find where the SSMS role is referenced
cd /root/GOAD
grep -rln "mssql_ssms\|mssql-ssms\|SQL Server Management Studio" ansible/ 2>/dev/null

# 2. Also check the playbook that GOAD calls at install time:
grep -rn "mssql_ssms\|Management Studio\|ssms" ansible/*.yml 2>/dev/null

# 3. Comment out the SSMS block
sed -i.bak '34,37s/^/# /' /root/GOAD/ansible/servers.yml

# 4. Verify
sed -n '30,42p' /root/GOAD/ansible/servers.yml
```

Before returning to GOAD and running `install`, end the SSMS installer task on SRV02 first. Then in the GOAD shell:

```bash
install
```

Ansible reruns. Every SSMS-related task is now skipped because the whole play block is commented out. Ansible should sail past mssql (all `ok:` since SQL Server is already installed and configured) and move to the next play in servers.yml or whatever comes after.

#### Kibana's kibana.yml config file has an invalid entry in xpack.fleet.outputs

```bash
sudo sed -i 's|    ssl.verification_mode: none|    ssl:\n      verification_mode: none|' /opt/elastic_container/kibana.yml

# Verify the change looks right:
sudo cat /opt/elastic_container/kibana.yml | grep -A2 verification
```

Should show:

```yaml
ssl:
      verification_mode: none
```

Restart Kibana (you'll see `[info][root] Kibana is now available` after 90 seconds; `Ctrl-C` to stop tailing):

```bash
sudo docker restart ecp-kibana
sudo docker logs ecp-kibana -f
```

Once healthy:

```bash
sudo docker start ecp-fleet-server
```

Test Kibana login at `https://10.1.20.2:5601`

#### Elastic role fails with "docker: command not found"

The `ludus_elastic_container` role installs Docker as a prerequisite, but occasionally it fails on Debian 12 kernels. Manually install:

```bash
ssh debian@10.<rangenum>.20.2 \
  "sudo apt install -y docker.io docker-compose-plugin"
```

Then rerun `ludus range deploy -t user-defined-roles --limit $GOAD_USER-elastic-server`.

#### Elastic Agent fails to enroll

Most common cause: the enrollment token expired or the agent version does not match the server. To debug:

```bash
ssh Administrator@10.<rangenum>.10.10   # or use RDP
"C:\Program Files\Elastic\Agent\elastic-agent.exe" status
"C:\Program Files\Elastic\Agent\elastic-agent.exe" logs
```

Re-fetch the token from the Elastic server and re-run the agent role.

#### Ludus errors say "attempt to write a readonly database"

Happens post-migration if `/opt/ludus/db/` ownership got mangled. Fix:

```bash
chown -R ludus:ludus /opt/ludus/db/
systemctl restart ludus ludus-admin
```

#### RAM pressure / VMs swap heavily

`free -h` will show swap growing. Options in order of impact:

1. Reduce the Elastic container's `ram_gb` from 8 to 6, then to 5 if still tight. Below 4, Elasticsearch will OOM.
2. Reduce SRV02/CASTELBLACK to 2 GB (least impact since it is a member server, not a DC).
3. Confirm the Dev Range is still powered off: `ludus --user stillbigjosh range list`. If any VMs there show `On`, that is silently costing several GB.

#### ludus range list shows deployment ERROR after everything looked fine

Ludus caches deployment status. Run any command that touches Ansible to refresh:

```bash
ludus --user $GOAD_USER range status
```

Or check the logs for what actually errored:

```bash
ludus --user $GOAD_USER range errors
```

#### Ludus deploy: elastic-server "Passphrase has been reset" error after deployment

SSH into the Elastic VM:

```bash
ssh debian@10.1.20.2
sudo docker ps -a
```

Look at container states:

- `ecp-elasticsearch` → likely Running
- `ecp-kibana` → may or may not be Running (this is what we need to check)
- `ecp-fleet-server` → likely Running
- `ecp-elasticsearch-security-setup` → `Exited (0)`; this is normal, don't restart it

**Step 1: Check if kibana.yml got re-broken**

```bash
sudo grep -A 2 "verification_mode" /opt/elastic_container/kibana.yml
```

If it shows dot notation (`ssl.verification_mode: none` on one line), re-fix:

```bash
sudo sed -i 's|    ssl.verification_mode: none|    ssl:\n      verification_mode: none|' /opt/elastic_container/kibana.yml
```

If it shows the nested form (`ssl:` then `verification_mode: none` on the next line), it's good; skip.

**Step 2: Restart Kibana**

```bash
sudo docker restart ecp-kibana
sudo docker logs ecp-kibana --tail 30 -f
```

Wait 60 seconds for "Kibana is now available". `Ctrl-C` to exit the log tail.

**Step 3: Get the current elastic password**

Since "Passphrase has been reset" fired, the old password may not work anymore. Check `.env`:

```bash
sudo grep -i password /opt/elastic_container/.env 2>/dev/null
```

Or reset to a known value:

```bash
sudo docker exec ecp-elasticsearch bin/elasticsearch-reset-password -u elastic --batch -a
```

That prints a new password. Copy it, use it to log into Kibana.

**Step 4: Verify Kibana loads**

Browse to `https://10.1.20.2:5601`; the login page should appear. Log in with `elastic` plus the current password.

---

## What Was Learned

Some questions worth answering if you deployed this cyber range just like this build did:

- What was the peak RAM usage during ingestion? Did Elasticsearch OOM at any point? What was the fix?
- Which attacks fired detections immediately, and which needed rule tuning? Which required Sysmon specifically vs. what Windows Security Events already catches?
- What is the smallest attack chain that produces the highest number of Kibana alerts? What is the biggest chain that produces zero?

The lab is not the point; the loop between attack, telemetry, detection, and rule tuning is. Every subsequent GOAD reset gives another lap.

Continue by [reading my follow-up Detection scenario process](https://stillbigjosh.github.io/writeup.html?file=writeups/detection-scenarios.md), that covers how to turn AD attack techniques you already know and turn them into structured detection practice, so you understand what defenders see and learn to operate in a monitored environment.
