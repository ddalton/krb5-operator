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
reconcile never changes a key. The Secret is rewritten only when its bytes
change. `Ready` means every principal got a ticket with its key from the
keytab. Deleting the object deletes the principals (unless `Retain`) and the
Secret.

## Install

```sh
kubectl apply --server-side -f deploy/crds.yaml
kubectl apply -f deploy/operator.yaml
```

Images: `ghcr.io/ddalton/krb5-operator` (this repo's `Dockerfile`) and
`ghcr.io/ddalton/krb5-kdc` (`images/kdc`).

## Tests

- `cargo test`: unit tests, plus live tests against a real MIT KDC and
  kadmind when `scripts/test-kdc.sh <dir>` has started one
  (`set -a; . <dir>/test.env; set +a` first).
- `tests/e2e/kind.sh`: builds both images, installs the operator on a kind
  cluster and runs the Chainsaw tests: a realm comes up, MIT's `kinit` logs
  in with the operator's keytab, the database survives the KDC's restart,
  and deleting a `KerberosPrincipal` deletes its principals.

## License

MIT OR Apache-2.0.
