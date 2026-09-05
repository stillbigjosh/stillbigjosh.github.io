---
title: "Adaptix C2 Setup - Deploying a Teamserver on Ludus"
kicker: "Offensive Security . C2 Infrastructure . Lab Build"
tags: "Adaptix C2 . Ludus . Proxmox . Red Team"
lead: "A step-by-step guide to deploying an Adaptix C2 teamserver on a Ludus cyber range: building the server in an unprivileged LXC container, compiling the operator client and Extension-Kit BOFs on a Windows VM, and connecting everything over a private VLAN."
---

> This guide covers installation and initial deployment only. Once your teamserver is running, see [Hardening Adaptix C2 - Reducing Infrastructure and Agent Fingerprints](writeup.html?file=writeups/adaptix-hardening.md) for the OPSEC hardening steps you should apply before any engagement.

## Environment

This deployment runs on a Ludus v2 cyber range hosted on a Proxmox server. The teamserver sits in an unprivileged LXC container on VLAN 10, and the operator client runs on a Windows 11 VM on the same VLAN.

| Host | Type | IP | Role |
|------|------|----|------|
| Router | VM 107 | 10.2.10.254 | Gateway (Debian 11) |
| trinity-urchin | LXC 200 | 10.2.10.20 | Adaptix Teamserver (:8443) |
| trinity-gadget | VM 108 | 10.2.10.11 | Operator Client (Windows 11) |

**Network:** VLAN 10 / vmbr1002 / 10.2.10.0/24

---

## Create the LXC Container

SSH into the Proxmox host and create a Debian 13 LXC container on VLAN 10.

```bash
# SSH into Proxmox host
ssh root@192.168.1.100

# Download Debian 13 template
pveam download local debian-13-standard_13.0-1_amd64.tar.zst
```

Create the container with networking on the range VLAN:

```bash
pct create 200 local:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst \
  --hostname trinity-urchin \
  --memory 2048 \
  --cores 2 \
  --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr1002,tag=10,ip=10.2.10.20/24,gw=10.2.10.254 \
  --nameserver 8.8.8.8 \
  --unprivileged 1 \
  --features nesting=1 \
  --start 1
```

Verify the container is running and has network connectivity:

```bash
pct list
pct exec 200 -- ping -c2 10.2.10.254
```

---

## Install the Adaptix Server

Enter the container and install dependencies. The Go version in Debian 13's default repositories is too old for Adaptix, so install Go 1.24 manually.

```bash
# Enter the container
pct exec 200 -- bash

# Install build dependencies
apt update && apt install -y git golang-go make gcc wget
```

Install Go 1.24:

```bash
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
ln -sf /usr/local/go/bin/go /usr/local/bin/go
ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
```

Clone the repository and build the server binary:

```bash
cd /opt
git clone https://github.com/nicemicro/AdaptixC2.git
cd AdaptixC2/AdaptixServer
go build -o ../dist/adaptixserver .
```

---

## Configure the Profile

The profile YAML controls the teamserver's port, endpoint, TLS certificates, HTTP headers, and error pages.

```bash
vi /opt/AdaptixC2/dist/profile.yaml
```

A minimal starting configuration:

```yaml
Teamserver:
  interface: "0.0.0.0"
  port: 8443
  endpoint: "/submit.aspx"
  password: "pass"
  only_password: true
  operators:
    operator1: "pass1"
    operator2: "pass2"
  cert: "server.rsa.crt"
  key: "server.rsa.key"

HttpServer:
  error:
    status: 404
    headers:
      Content-Type: "text/html; charset=UTF-8"
      Server: "Microsoft IIS/10.0"
      X-Powered-By: "ASP.NET"
    page: "error.aspx"
```

Copy the default 404 page to the filename referenced in the profile:

```bash
cp /opt/AdaptixC2/dist/404page.html /opt/AdaptixC2/dist/error.aspx
```

> This is a baseline configuration. Before any engagement, apply the hardening steps in [Hardening Adaptix C2](writeup.html?file=writeups/adaptix-hardening.md): replace the default certificates, customize the error page content, change the operator password, and harden the listener settings.

---

## Create a Systemd Service

Set up the teamserver as a systemd service so it starts automatically and restarts on failure.

```bash
cat > /etc/systemd/system/adaptix.service << 'EOF'
[Unit]
Description=Adaptix C2 Teamserver
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/AdaptixC2/dist
ExecStart=/opt/AdaptixC2/dist/adaptixserver -profile /opt/AdaptixC2/dist/profile.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start the service:

```bash
systemctl daemon-reload
systemctl enable --now adaptix
systemctl status adaptix
```

---

## Build the Adaptix Client

The operator client is built on the Windows VM (trinity-gadget) using MSYS2 with the mingw64 toolchain and Qt6.

### Install MSYS2 Dependencies

Open an MSYS2 MinGW64 shell and install the required packages:

```bash
pacman -Syu
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-make \
          mingw-w64-x86_64-qt6-base mingw-w64-x86_64-qt6-websockets \
          mingw-w64-x86_64-qt6-5compat make git
```

### Compile the Client

```bash
cd /c/Users/localuser/TOOLS
git clone https://github.com/nicemicro/AdaptixC2.git
cd AdaptixC2/AdaptixClient
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
mingw32-make -j$(nproc)
```

### Deploy the Binary

Copy the compiled binary and package its Qt dependencies:

```bash
mkdir -p /c/Users/localuser/Desktop/AdaptixClient
cp AdaptixClient.exe /c/Users/localuser/Desktop/AdaptixClient/
cd /c/Users/localuser/Desktop/AdaptixClient
windeployqt6 AdaptixClient.exe
```

### Add MSYS2 to System PATH

This is required for the Extension-Kit build step and for the client to find its runtime dependencies.

```powershell
# PowerShell (Admin)
$current = [Environment]::GetEnvironmentVariable('Path','Machine')
$add = 'C:\msys64\mingw64\bin;C:\msys64\usr\bin'
[Environment]::SetEnvironmentVariable('Path', "$current;$add", 'Machine')
```

---

## Build Extension-Kit BOFs

The Extension-Kit provides the BOF (Beacon Object File) capabilities that the operator loads on demand during an engagement.

```bash
# In MSYS2 MinGW64 shell
export PATH="/opt/bin:/opt/x86_64-w64-mingw32/bin:$PATH"
cd /c/Users/localuser/TOOLS/Extension-Kit
make
```

### Known Build Fixes

Two BOFs require manual fixes before they will compile cleanly:

**ScreenshotBOF:** Add the missing constant definition to `entry.c`:

```c
#ifndef PW_RENDERFULLCONTENT
#define PW_RENDERFULLCONTENT 0x00000002
#endif
```

**SAL-BOF:** The Python build script downloads `drivers.csv` to the MSYS2 `/tmp` directory, but the C compiler resolves `/tmp` to `C:\tmp`. Copy the file to the expected location:

```bash
mkdir -p /c/tmp && cp /tmp/drivers.csv /c/tmp/drivers.csv
```

---

## Connect to the Teamserver

Launch `AdaptixClient.exe` on trinity-gadget and enter the connection details:

| Field | Value |
|-------|-------|
| Host | `https://10.2.10.20:8443` |
| Endpoint | `/submit.aspx` |
| Password | (from profile.yaml) |

Once connected, you can create listeners, generate payloads, and load Extension-Kit BOFs through the client UI.

---

## Next Steps

The teamserver is now running with default settings. Before using it in any engagement or testing scenario, apply the OPSEC hardening steps covered in [Hardening Adaptix C2 - Reducing Infrastructure and Agent Fingerprints](writeup.html?file=writeups/adaptix-hardening.md). That guide covers replacing the default TLS certificate, customizing error pages and HTTP headers, hardening listener configurations, tuning the JARM fingerprint, and verifying the result.
