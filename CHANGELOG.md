# Changelog

## Unreleased

- **`KerberosNodeKeytab.spec.restartServices`** (e.g. `[rpc-gssd]`): the
  agent has the node's systemd start each unit when it starts, and restart
  it whenever it rewrites the keytab or `krb5.conf`. nfs-utils'
  `rpc-gssd.service` has `ConditionPathExists=/etc/krb5.keytab`, so on a
  node that booted before its keys came it never ran. Off by default. When
  set, the agent mounts the host's `/run/systemd/private` (hostPath type
  `Socket`; no host PID namespace, no capabilities) and calls
  `StartUnit`/`RestartUnit` over it. Units the node does not have, or has
  masked, are skipped. Nodes must run systemd. The README also gives a
  systemd path unit for those who would rather not grant this.
- **`KerberosNodeKeytab`: each node reads only its own keys.** Every node
  now gets its own Secret and its own DaemonSet, pinned to it, which
  mounts only that Secret. Before, one Secret held every node's keys and
  every node's agent mounted it, so root on any node (with its kubelet's
  credentials) could read every node's keys and pass for any of them. The
  Node authorizer now limits each kubelet to its own node's keys. On
  upgrade the shared Secret and DaemonSet of 0.3 are deleted. RBAC: a Role
  in the operator's namespace may delete Secrets and DaemonSets there,
  for nodes that go.
- krb5 0.12.1 (its AP-REQ parsing panic fix). Keytab logins (verifying a keytab) use SPAKE when the KDC
  offers it.

## 0.3.0 — 2026-10-15

- `KerberosNodeKeytab` (cluster-scoped): `host/` and `nfs/` principals for
  the nodes it selects. A DaemonSet (`krb5-operator node-agent`) merges
  their keys into each node's `/etc/krb5.keytab`, keeping other realms'
  entries, and optionally writes a `krb5.conf` that names the KDC by
  cluster IP and maps the cluster's Services (`.svc.<clusterDomain>`) to
  the realm. This is what `rpc.gssd` needs for `sec=krb5*` NFS mounts.
  Nodes that go, or are no longer selected, have their principals deleted.
- RBAC: nodes (read) and DaemonSets. The operator's namespace is labelled
  for privileged pods in `deploy/operator.yaml`.

## 0.2.0 — 2026-10-15

- `KerberosPrincipal.spec.hostPrincipals`: a principal per pod of a
  StatefulSet, `<service>/<pod>.<serviceName>.<namespace>.svc.<clusterDomain>`
  for each of `services`, following `spec.replicas`. The Secret holds
  `krb5.keytab` with every key and `<pod>.keytab` with only that pod's.
  Scaling down deletes the principals of the pods that are gone (unless
  `deletionPolicy: Retain`).
- Principals a `KerberosPrincipal` no longer lists are deleted from the KDC.
- The cluster domain is set with `CLUSTER_DOMAIN` (the chart's
  `clusterDomain`, default `cluster.local`).
- The keytab is verified against the KDC only when its keys change or the
  principal was not `Ready`; status is written only when it changes.
- krb5 0.9.

## 0.1.2 — 2026-10-15

- Security: a `KerberosPrincipal` could get the keys of any principal
  that already existed in the KDC, `krbtgt/REALM` (which forges any
  ticket) and `kadmin/admin` included. Now principals the operator creates
  are marked with their owner (`<namespace>/<name>`), only the owner gets
  their keys or deletes them, others get `Conflict`, and the KDC's,
  kadmind's and the operator's own principals are refused (`Invalid`).
  Upgrade from 0.1.0 and 0.1.1. Principals those versions created have no
  owner mark, so they report `Conflict`. To have the operator manage one
  again, mark it with
  `kadmin.local setstr <principal> krb5-operator/owner <namespace>/<name>`,
  or delete it so it is recreated with new keys.
- Cross-namespace realms: `KerberosPrincipal.spec.realmNamespace`, and
  `KerberosRealm.spec.allowedNamespaces` (`Same`, the default, `All`, or
  `Selector`); other namespaces get `NotAllowed`.
- The keytab Secret also holds the realm's `krb5.conf`.
- Problems with a `KerberosPrincipal` are its `Ready` condition's reason
  (`Invalid`, `Conflict`, `NotAllowed`, `RealmNotReady`).

## 0.1.1 — 2026-10-15

- Fix: a keytab Secret was rewritten on nearly every reconcile, because
  the keytab's bytes hold each entry's write time. It now carries a SHA-256
  of its keys (`krb5.ddalton.dev/keys-sha256`) and is rewritten only when
  they change.
- Helm chart `charts/krb5-operator`; `deploy/operator.yaml` is rendered
  from it.
- The default KDC image is set at run time (`KRB5_KDC_IMAGE`, the chart's
  `kdcImage`).

## 0.1.0 — 2026-10-15

- `KerberosRealm`: an MIT KDC and kadmind per realm.
- `KerberosPrincipal`: principals created through kadmind, keytabs in
  Secrets.
- Images for linux/amd64 and linux/arm64 on ghcr.io.
