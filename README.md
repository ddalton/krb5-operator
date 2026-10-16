# krb5-operator

A Kubernetes operator for MIT Kerberos: it runs a KDC for each realm you
declare, and turns principals you declare into keytab Secrets. Built on the
[krb5](https://crates.io/crates/krb5) crate, whose kadmin client it uses to
talk to kadmind.

## Resources

**`KerberosRealm`** — an MIT KDC (`krb5kdc` and `kadmind`) in a one-replica
StatefulSet, its database on a volume:

```yaml
apiVersion: krb5.ddalton.dev/v1alpha1
kind: KerberosRealm
metadata:
  name: corp
spec:
  realm: CORP.EXAMPLE.COM
  storage: 1Gi            # default
  maxTicketLife: 10h      # default
  maxRenewableLife: 7d    # default
```

The operator creates, owned by the realm:

| Object | Holds |
|---|---|
| Secret `corp-kdc` | the database master key and the operator's admin password (generated once, never rotated) |
| ConfigMap `corp-kdc` | `kdc.conf`, `kadm5.acl`, and a client **`krb5.conf`** for workloads to mount |
| StatefulSet `corp-kdc` | the KDC; the image creates the database on first start |
| Service `corp-kdc` | 88 TCP/UDP (KDC), 749 (kadmind) |

`Ready` means a real exchange worked: an AS request for a probe principal
answered "principal unknown" by a KDC of that realm.

**`KerberosPrincipal`** — principals with random keys and a Secret with
their keytab:

```yaml
apiVersion: krb5.ddalton.dev/v1alpha1
kind: KerberosPrincipal
metadata:
  name: hdfs-services
spec:
  realmRef: corp
  # realmNamespace: auth    # default: this object's namespace
  principals:
  - nn/namenode-0.namenode.hdfs.svc.cluster.local   # @CORP.EXAMPLE.COM appended
  - hdfs
  secretName: hdfs-keytab   # default: the object's name
  keytabKey: krb5.keytab    # default
  deletionPolicy: Delete    # or Retain
```

The operator logs in to kadmind as `krb5-operator/admin`, creates the
principals that are missing (`addprinc -randkey`) and extracts their current
keys (`ktadd -norandkey`), so the keytab always follows the KDC and a
reconcile never changes a key. The Secret holds the keytab and the realm's
`krb5.conf` (key `krb5.conf`), so a pod needs only that one mount; it is
rewritten only when the keys change. `Ready` means every principal got a
ticket with its key from the keytab. Deleting the object deletes the
principals (unless `Retain`) and the Secret.

### Host principals for a StatefulSet

Hadoop, NFS and most Kerberized services want one principal per host
(`dn/_HOST@REALM`). `hostPrincipals` makes `<service>/<pod FQDN>` for every
pod of a StatefulSet and follows its `replicas`:

```yaml
kind: KerberosPrincipal
metadata: { name: datanodes, namespace: hdfs }
spec:
  realmRef: corp
  hostPrincipals:
    statefulSet: pillar-dn      # its serviceName gives the pods DNS names
    services: [dn, HTTP]        # dn/pillar-dn-0.pillar-dn.hdfs.svc.cluster.local, ...
```

The operator watches the StatefulSet. On a scale-up it creates the new pods'
principals from `spec.replicas`, so the keys are there by the time the pods
start. On a scale-down, or when a name leaves the spec, it deletes the
principals that are no longer wanted (only its own, and not with
`deletionPolicy: Retain`).

A StatefulSet's pods share one pod template, so they all mount the same
Secret. It holds both layouts:

- `krb5.keytab`: every pod's keys. Hadoop's `_HOST` substitution picks the
  pod's own key from it.
- `<pod>.keytab`: only that pod's keys. To keep the other pods' keys out of
  the container, mount just its own file:

  ```yaml
  env:
  - name: POD_NAME
    valueFrom: { fieldRef: { fieldPath: metadata.name } }
  volumeMounts:
  - name: krb5
    mountPath: /etc/security/keytab
    subPathExpr: $(POD_NAME).keytab
  ```

  Kubernetes does not update `subPath` mounts, so a rotated key reaches the
  pod when it restarts. A mount of the whole Secret updates in place.

The cluster domain defaults to `cluster.local`; set the chart's
`clusterDomain` for anything else.

### Node keytabs for NFS clients

A kernel NFS mount with `sec=krb5`, `krb5i` or `krb5p` is made by the node,
and the node's `rpc.gssd` takes its machine credential (`host/<node>` or
`nfs/<node>`) from `/etc/krb5.keytab`. A `KerberosNodeKeytab`
(cluster-scoped, for cluster administrators) gives each selected node those
principals and installs their keys:

```yaml
apiVersion: krb5.ddalton.dev/v1alpha1
kind: KerberosNodeKeytab
metadata:
  name: nfs-clients
spec:
  realmRef: corp
  realmNamespace: auth
  services: [host, nfs]              # the default
  nodeSelector:
    nfs.example.com/kerberos: "true"
  domain: corp.example.com           # for nodes whose hostname has no dot
  keytabPath: /etc/krb5.keytab       # the default
  krb5ConfPath: /etc/krb5.conf.d/corp.conf   # optional
  restartServices: [rpc-gssd]        # optional; see below
```

- For every node the selector and `tolerations` admit, the operator
  creates `<service>/<node hostname>` and writes the node's keys to a
  Secret of the node's own (`node-keytab-<digest>` in the operator's
  namespace, annotated `krb5.ddalton.dev/node: <node>`).
- A DaemonSet of the same name, pinned to that node, mounts that Secret
  and runs `krb5-operator node-agent`. The agent merges the node's keys into `keytabPath`: entries of
  other realms stay, and this realm's are replaced. Files are written
  atomically, only when they change. With `krb5ConfPath` it also writes
  the realm's `krb5.conf` there, naming the KDC by its Service's cluster
  IP, since nodes do not resolve cluster DNS, and maps the cluster's
  Services (`.svc.<clusterDomain>`) to the realm, which `rpc.gssd` needs
  to find the realm of an NFS server named after a Service.
- A node that goes away or stops being selected has its principals deleted
  from the KDC, and so does deleting the object (unless
  `deletionPolicy: Retain`). Keys already on the node stay in its keytab,
  where they no longer work.
- Ready means every key got a ticket and each node's agent has installed
  them.
- **A node reads only its own keys.** The Node authorizer lets a kubelet
  read only the Secrets of pods bound to its node, so root on a node gets
  that node's keys and no other's. A node's keys are what it proves it is
  with (an NFS server that serves only the nodes a volume is attached to
  trusts them), so this needs the API server's Node authorizer and
  `NodeRestriction`, as kubeadm, kind and the managed clusters set up.

#### Making `rpc.gssd` use the keys

nfs-utils' `rpc-gssd.service` has `ConditionPathExists=/etc/krb5.keytab`.
On a node that booted before the agent wrote its keys, the unit was skipped
and stays down, so `sec=krb5*` mounts fail until someone starts it.
`systemctl try-restart` would not help: it restarts only running units.

`restartServices` has the agent do it. When its pod starts, the agent asks
the host's systemd to start each unit (nothing happens if it runs), and
whenever it rewrites the keytab or `krb5.conf` it asks for a restart, so
`rpc.gssd` reads the new keys now, not when it next needs a credential.
Names without a suffix get `.service`; only service units are accepted. A
unit the node does not have, or has masked, is skipped and logged once. A
call that fails is retried every pass, and the node's agent is not ready
until it works.

The agent reaches systemd through its private socket,
`/run/systemd/private` (what `systemctl` uses as root), mounted from the
host. That is the only thing the field adds: no host PID namespace, no
capabilities, not privileged. The socket admits only uid 0, which the
agent already is. It is the host's service manager, though, able to start
anything, so the field is off by default and the agent asks only for the
units named. The hostPath is of type `Socket`: on a node without systemd
the agent's pod does not start, and its events say why. Give such nodes
another `KerberosNodeKeytab` without `restartServices`.

Other ways, and why not:

- `nsenter -t 1 -m -u -i -n -p systemctl restart rpc-gssd` from the
  agent: needs `hostPID: true` and `CAP_SYS_ADMIN` (in practice
  `privileged`) to enter the host's namespaces, for the same result.
- A systemd path unit on the host that restarts `rpc-gssd` on
  `PathChanged=/etc/krb5.keytab`. It needs no privilege from the operator,
  and is the choice when you provision nodes yourself (below). The agent
  cannot install it for you: enabling a unit is a call to systemd, the
  same access as above, and it would leave units in `/etc/systemd` behind.

```ini
# /etc/systemd/system/krb5-keytab.path, then:
#   systemctl enable --now krb5-keytab.path
[Path]
PathChanged=/etc/krb5.keytab

[Install]
WantedBy=paths.target

# /etc/systemd/system/krb5-keytab.service
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart rpc-gssd.service
```

`PathChanged=` fires when the file is written and closed, and when one is
renamed over it, which is how the agent writes.

On distributions where `rpc.gssd` gets credentials through gssproxy
(`use-gss-proxy=1` in `nfs.conf`'s `[gssd]`, `GSS_USE_PROXY=yes`), gssproxy
reads the keytab: name `gssproxy` too. This has not been tested.

What it does not do: per-user identity. Processes that are not root need
their own tickets, and node keytabs cover root and the NFS client's own
state. The nodes need `rpc.gssd` (nfs-utils). The agent runs as root with
no capabilities and writes through hostPath (with `restartServices`, it
also mounts systemd's socket), so the operator's namespace must allow
privileged pods (`deploy/operator.yaml` labels it). Whoever can
create pods in the operator's namespace can mount any node's Secret: keep
that namespace to the operator.

### One realm, many products

A realm can serve `KerberosPrincipal`s in other namespaces (HDFS in `hdfs`,
Ranger in `ranger`, ...). It serves only its own namespace unless it says
otherwise:

```yaml
kind: KerberosRealm
metadata: { name: corp, namespace: auth }
spec:
  realm: CORP.EXAMPLE.COM
  allowedNamespaces:
    from: Selector            # Same (default) | All | Selector
    selector:
      matchLabels: { kerberos.example.com/realm: corp }
---
kind: KerberosPrincipal
metadata: { name: namenode, namespace: hdfs }
spec:
  realmRef: corp
  realmNamespace: auth
  principals: [nn/namenode-0.namenode.hdfs.svc.cluster.local]
```

Whose keys go where:

- **Ownership.** A principal the operator creates is marked in the KDC
  with its owner, the `<namespace>/<name>` of its `KerberosPrincipal`. Only
  that object gets its keys, and only that object deletes it. A principal
  someone else owns, or one created outside the operator, is a `Conflict`:
  no keys, no Secret.
- **Reserved principals** are refused (`Invalid`): `krbtgt/*`, `kadmin/*`,
  `kiprop/*`, `changepw/*`, `K/M`, `WELLKNOWN/*` and the operator's own
  `krb5-operator*`. Whoever holds the `krbtgt` key can forge any ticket.
- **Namespaces the realm does not allow** get `NotAllowed`.

These outcomes are the `Ready` condition's `reason`, along with
`RealmNotReady` and `KeytabRejected`.

## Install

With Helm:

```sh
helm install krb5-operator charts/krb5-operator --namespace krb5-operator --create-namespace
```

Helm installs the CRDs only on first install; on upgrade apply
`charts/krb5-operator/crds/` first (`kubectl apply --server-side -f`).
Values worth knowing: `image.*` (the operator), `kdcImage.*` (the default
KDC image for realms that set no `spec.image`: point both at a mirror for
air-gapped clusters), `imagePullSecrets`, `resources`, `nodeSelector`,
`tolerations`, `affinity`.

Without Helm (the same objects, rendered from the chart):

```sh
kubectl apply --server-side -f deploy/crds.yaml
kubectl apply -f deploy/operator.yaml
```

Images: `ghcr.io/ddalton/krb5-operator` (this repo's `Dockerfile`) and
`ghcr.io/ddalton/krb5-kdc` (`images/kdc`), linux/amd64 and linux/arm64.

## Tests

- `cargo test`: unit tests, plus live tests against a real MIT KDC and
  kadmind when `scripts/test-kdc.sh <dir>` has started one
  (`set -a; . <dir>/test.env; set +a` first).
- `tests/e2e/kind.sh`: builds both images, installs the operator on a kind
  cluster with the Helm chart and runs the Chainsaw tests: a realm comes up, MIT's `kinit` logs
  in with the operator's keytab, the database survives the KDC's restart,
  and deleting a `KerberosPrincipal` deletes its principals.

## License

MIT OR Apache-2.0.
