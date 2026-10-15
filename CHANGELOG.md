# Changelog

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
