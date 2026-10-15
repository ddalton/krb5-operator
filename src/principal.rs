//! The `KerberosPrincipal` controller: principals in a realm's KDC, made
//! through kadmind with the krb5 crate's kadmin client, and their keytab
//! in a Secret.
//!
//! Each reconcile logs in as the operator's admin principal, creates the
//! principals that are missing (random keys, `addprinc -randkey`), and
//! extracts their current keys (`ktadd -norandkey`), so the keytab follows
//! the KDC: a key changed there reaches the Secret, and a reconcile never
//! changes a key itself. The Secret is written only when the keys differ:
//! it carries a SHA-256 of them (`krb5.ddalton.dev/keys-sha256`), since the
//! keytab's own bytes hold the time each entry was written and so differ
//! at every reconcile.
//!
//! Ready means the keytab works: an AS exchange with each principal's key
//! from the keytab gets a ticket.
//!
//! A finalizer deletes the principals from the KDC when the object goes
//! (`deletionPolicy: Retain` keeps them); the Secret is owned by the object
//! and goes with it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use krb5::kadmin::{AdminClient, PrincipalChanges};
use krb5::{EncType, KdcClient, Keytab, Principal, ServiceKey};
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event, finalizer};
use kube::{Client, Resource, ResourceExt};
use serde_json::json;
use tracing::{info, warn};

use crate::crd::{
    Condition, DeletionPolicy, KerberosPrincipal, KerberosPrincipalStatus, KerberosRealm, PrincipalStatus,
};
use crate::realm;

const MANAGER: &str = "krb5-operator";
const FINALIZER: &str = "krb5.ddalton.dev/principals";
/// The Secret's annotation with [`fingerprint`] of the keys in its keytab.
const KEYS_SHA256: &str = "krb5.ddalton.dev/keys-sha256";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Kubernetes: {0}")]
    Kube(#[from] kube::Error),
    #[error("invalid KerberosPrincipal: {0}")]
    Invalid(String),
    #[error("realm {0} is not ready: {1}")]
    RealmNotReady(String, String),
    #[error("kadmin: {0}")]
    Kadmin(String),
    #[error("finalizer: {0}")]
    Finalizer(String),
}

pub struct Context {
    pub client: Client,
}

/// A principal and its keys, with their kvnos.
pub type PrincipalKeys = (Principal, Vec<(u32, krb5::Key)>);

/// `names` as principals of `realm`: the realm is appended, or must match.
pub fn principals(names: &[String], realm: &str) -> Result<Vec<Principal>, Error> {
    if names.is_empty() {
        return Err(Error::Invalid("no principals".into()));
    }
    names
        .iter()
        .map(|n| {
            let p = if n.contains('@') { Principal::parse(n) } else { Principal::parse_in_realm(n, realm) }
                .map_err(|e| Error::Invalid(format!("{n:?}: {e}")))?;
            if p.realm != realm {
                return Err(Error::Invalid(format!("{n:?} is not in realm {realm}")));
            }
            if p.components.is_empty() || p.components.iter().any(|c| c.is_empty()) {
                return Err(Error::Invalid(format!("{n:?}: empty name component")));
            }
            Ok(p)
        })
        .collect()
}

/// The keytab for `keys` (each principal's, with their kvnos), as MIT's
/// `ktadd` writes it. Enctypes the crate does not know are left out.
pub fn keytab(keys: &[PrincipalKeys]) -> Keytab {
    let mut entries = Vec::new();
    for (p, ks) in keys {
        for (kvno, k) in ks {
            if let Some(enctype) = EncType::from_i32(k.enctype()) {
                entries.push(ServiceKey {
                    principal: p.name(),
                    realm: p.realm.clone(),
                    kvno: *kvno,
                    enctype,
                    key: k.bytes().to_vec(),
                });
            }
        }
    }
    Keytab::from_keys(entries)
}

/// SHA-256 over every principal, kvno, enctype and key, in order: equal
/// exactly when the keytabs would hold the same keys.
pub fn fingerprint(keys: &[PrincipalKeys]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let field = |h: &mut Sha256, b: &[u8]| {
        h.update((b.len() as u32).to_be_bytes());
        h.update(b);
    };
    for (p, ks) in keys {
        field(&mut h, format!("{}@{}", p.name(), p.realm).as_bytes());
        h.update((ks.len() as u32).to_be_bytes());
        for (kvno, k) in ks {
            h.update(kvno.to_be_bytes());
            h.update(k.enctype().to_be_bytes());
            field(&mut h, k.bytes());
        }
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Where and as whom the operator administers a realm.
#[derive(Clone)]
pub struct Admin {
    pub realm: String,
    pub kdc: String,
    pub admin_server: String,
    pub password: String,
}

impl Admin {
    fn kdc(&self) -> KdcClient {
        KdcClient::new(self.realm.clone(), [self.kdc.clone()]).with_timeout(Duration::from_secs(5))
    }

    fn connect(&self) -> Result<AdminClient, Error> {
        let admin = Principal::parse_in_realm(realm::ADMIN, &self.realm).map_err(|e| Error::Kadmin(e.to_string()))?;
        AdminClient::connect_with_password(&self.kdc(), &admin, &self.password, &self.admin_server)
            .map_err(|e| Error::Kadmin(format!("logging in as {}: {e}", realm::ADMIN)))
    }

    /// Create what is missing, then every principal's current keys.
    pub fn ensure(&self, ps: &[Principal]) -> Result<Vec<PrincipalKeys>, Error> {
        let mut kadm = self.connect()?;
        let mut out = Vec::with_capacity(ps.len());
        for p in ps {
            let keys = match kadm.extract_keys(p, None) {
                Err(e) if e.code().is_some_and(|c| c.is_unknown_principal()) => {
                    kadm.create_principal(p, &PrincipalChanges::default(), None)
                        .map_err(|e| Error::Kadmin(format!("creating {}: {e}", p.name())))?;
                    info!("Created principal {}@{}", p.name(), p.realm);
                    kadm.extract_keys(p, None)
                }
                r => r,
            }
            .map_err(|e| Error::Kadmin(format!("extracting keys of {}: {e}", p.name())))?;
            out.push((p.clone(), keys));
        }
        kadm.close();
        Ok(out)
    }

    /// Delete the principals (those already gone are fine).
    pub fn delete(&self, ps: &[Principal]) -> Result<(), Error> {
        let mut kadm = self.connect()?;
        for p in ps {
            match kadm.delete_principal(p) {
                Ok(()) => info!("Deleted principal {}@{}", p.name(), p.realm),
                Err(e) if e.code().is_some_and(|c| c.is_unknown_principal()) => {}
                Err(e) => return Err(Error::Kadmin(format!("deleting {}: {e}", p.name()))),
            }
        }
        kadm.close();
        Ok(())
    }

    /// An AS exchange for each principal with its key from `keytab`.
    pub fn verify(&self, ps: &[Principal], keytab: &Keytab) -> Result<(), String> {
        let kdc = self.kdc();
        for p in ps {
            kdc.login_with_keytab(p, keytab).map_err(|e| format!("{}@{}: {e}", p.name(), p.realm))?;
        }
        Ok(())
    }
}

/// The realm `kp` refers to, ready, and how to administer it.
async fn admin_for(client: &Client, kp: &KerberosPrincipal) -> Result<(KerberosRealm, Admin), Error> {
    let ns = kp.namespace().unwrap_or_else(|| "default".into());
    let r = Api::<KerberosRealm>::namespaced(client.clone(), &ns)
        .get_opt(&kp.spec.realm_ref)
        .await?
        .ok_or_else(|| Error::RealmNotReady(kp.spec.realm_ref.clone(), "no such KerberosRealm".into()))?;
    let status = r.status.clone().unwrap_or_default();
    let ready = status.conditions.iter().any(|c| c.type_ == "Ready" && c.status == "True");
    let (Some(kdc), Some(admin_server), true) = (status.kdc, status.admin_server, ready) else {
        return Err(Error::RealmNotReady(kp.spec.realm_ref.clone(), "its KDC does not answer yet".into()));
    };
    let password = realm::admin_password(client, &r)
        .await
        .map_err(|e| Error::RealmNotReady(kp.spec.realm_ref.clone(), e.to_string()))?
        .ok_or_else(|| Error::RealmNotReady(kp.spec.realm_ref.clone(), "no admin password".into()))?;
    let realm = r.spec.realm.clone();
    Ok((r, Admin { realm, kdc, admin_server, password }))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Error> {
    tokio::task::spawn_blocking(f).await.map_err(|e| Error::Kadmin(e.to_string()))
}

pub fn secret(kp: &KerberosPrincipal, keytab: Vec<u8>, fingerprint: &str) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(kp.secret_name()),
            namespace: kp.namespace(),
            labels: Some(BTreeMap::from([
                ("app.kubernetes.io/managed-by".to_string(), MANAGER.to_string()),
                ("krb5.ddalton.dev/principal".to_string(), kp.name_any()),
            ])),
            annotations: Some(BTreeMap::from([(KEYS_SHA256.to_string(), fingerprint.to_string())])),
            owner_references: Some(vec![kp.controller_owner_ref(&()).expect("a stored KerberosPrincipal has a uid")]),
            ..Default::default()
        },
        type_: Some("Opaque".into()),
        data: Some(BTreeMap::from([(kp.keytab_key(), ByteString(keytab))])),
        ..Default::default()
    }
}

fn condition(ready: bool, reason: &str, message: &str) -> Condition {
    Condition {
        type_: "Ready".into(),
        status: if ready { "True" } else { "False" }.into(),
        reason: reason.into(),
        message: message.into(),
        last_transition_time: k8s_openapi::jiff::Timestamp::now().to_string(),
    }
}

async fn set_status(client: &Client, kp: &KerberosPrincipal, status: KerberosPrincipalStatus) -> Result<(), Error> {
    let ns = kp.namespace().unwrap_or_else(|| "default".into());
    Api::<KerberosPrincipal>::namespaced(client.clone(), &ns)
        .patch_status(&kp.name_any(), &PatchParams::default(), &Patch::Merge(json!({ "status": status })))
        .await?;
    Ok(())
}

async fn apply(kp: Arc<KerberosPrincipal>, client: &Client) -> Result<Action, Error> {
    let (_, admin) = match admin_for(client, &kp).await {
        Ok(a) => a,
        Err(e @ Error::RealmNotReady(..)) => {
            let status = KerberosPrincipalStatus {
                conditions: vec![condition(false, "RealmNotReady", &e.to_string())],
                observed_generation: kp.metadata.generation,
                ..Default::default()
            };
            set_status(client, &kp, status).await?;
            return Ok(Action::requeue(Duration::from_secs(10)));
        }
        Err(e) => return Err(e),
    };
    let ps = principals(&kp.spec.principals, &admin.realm)?;
    let keys = {
        let (admin, ps) = (admin.clone(), ps.clone());
        blocking(move || admin.ensure(&ps)).await??
    };
    let kt = keytab(&keys);
    let fp = fingerprint(&keys);

    let ns = kp.namespace().unwrap_or_else(|| "default".into());
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &ns);
    let name = kp.secret_name();
    let current = secrets.get_opt(&name).await?;
    let unchanged = current.as_ref().is_some_and(|s| {
        s.annotations().get(KEYS_SHA256) == Some(&fp)
            && s.data.as_ref().is_some_and(|d| d.get(&kp.keytab_key()).is_some_and(|b| !b.0.is_empty()))
    });
    if !unchanged {
        let s = secret(&kp, kt.to_bytes(), &fp);
        secrets.patch(&name, &PatchParams::apply(MANAGER).force(), &Patch::Apply(&s)).await?;
        info!("Wrote the keytab of {} to Secret {}/{}", kp.name_any(), ns, name);
    }

    let verified = {
        let (admin, ps) = (admin.clone(), ps.clone());
        blocking(move || admin.verify(&ps, &kt)).await?
    };
    let cond = match &verified {
        Ok(()) => condition(true, "KeytabVerified", "every principal got a ticket with its keytab key"),
        Err(e) => condition(false, "KeytabRejected", e),
    };
    if let Err(e) = &verified {
        warn!("{}: {}", kp.name_any(), e);
    }
    let status = KerberosPrincipalStatus {
        secret_name: Some(name),
        principals: keys
            .iter()
            .map(|(p, ks)| PrincipalStatus {
                name: format!("{}@{}", p.name(), p.realm),
                kvno: ks.iter().map(|(v, _)| *v).max().unwrap_or(0),
            })
            .collect(),
        conditions: vec![cond],
        observed_generation: kp.metadata.generation,
    };
    set_status(client, &kp, status).await?;
    Ok(Action::requeue(if verified.is_ok() { Duration::from_secs(300) } else { Duration::from_secs(30) }))
}

async fn cleanup(kp: Arc<KerberosPrincipal>, client: &Client) -> Result<Action, Error> {
    if kp.spec.deletion_policy == DeletionPolicy::Retain {
        return Ok(Action::await_change());
    }
    let admin = match admin_for(client, &kp).await {
        Ok((_, admin)) => admin,
        // The realm is gone (and its KDC with it): nothing to delete.
        Err(Error::RealmNotReady(r, why)) => {
            let ns = kp.namespace().unwrap_or_else(|| "default".into());
            if Api::<KerberosRealm>::namespaced(client.clone(), &ns).get_opt(&r).await?.is_none() {
                return Ok(Action::await_change());
            }
            return Err(Error::RealmNotReady(r, why));
        }
        Err(e) => return Err(e),
    };
    let ps = principals(&kp.spec.principals, &admin.realm)?;
    blocking(move || admin.delete(&ps)).await??;
    Ok(Action::await_change())
}

pub async fn reconcile(kp: Arc<KerberosPrincipal>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = kp.namespace().unwrap_or_else(|| "default".into());
    let api: Api<KerberosPrincipal> = Api::namespaced(ctx.client.clone(), &ns);
    let client = ctx.client.clone();
    finalizer(&api, FINALIZER, kp, |event| async move {
        match event {
            Event::Apply(kp) => apply(kp, &client).await,
            Event::Cleanup(kp) => cleanup(kp, &client).await,
        }
    })
    .await
    .map_err(|e| match e {
        kube::runtime::finalizer::Error::ApplyFailed(e) | kube::runtime::finalizer::Error::CleanupFailed(e) => e,
        e => Error::Finalizer(e.to_string()),
    })
}

pub fn error_policy(kp: Arc<KerberosPrincipal>, e: &Error, _: Arc<Context>) -> Action {
    warn!("Reconciling {}: {}", kp.name_any(), e);
    Action::requeue(Duration::from_secs(if matches!(e, Error::Invalid(_)) { 300 } else { 15 }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::KerberosPrincipalSpec;

    #[test]
    fn principal_names_take_the_realm() {
        let ps = principals(&["nn/host.example.com".into(), "hdfs@CORP.TEST".into()], "CORP.TEST").unwrap();
        assert_eq!(ps[0].name(), "nn/host.example.com");
        assert_eq!(ps[0].realm, "CORP.TEST");
        assert_eq!(ps[1].name(), "hdfs");
        assert!(principals(&["hdfs@OTHER.TEST".into()], "CORP.TEST").is_err(), "another realm");
        assert!(principals(&[], "CORP.TEST").is_err(), "none");
        assert!(principals(&["nn//x".into()], "CORP.TEST").is_err(), "empty component");
    }

    #[test]
    fn the_keytab_holds_every_key_and_is_stable() {
        let k = |et, b: u8| krb5::Key::new(et, vec![b; if et == 17 { 16 } else { 32 }]).unwrap();
        let nn = Principal::parse("nn/host@CORP.TEST").unwrap();
        let dn = Principal::parse("dn/host@CORP.TEST").unwrap();
        let keys = vec![(nn.clone(), vec![(2, k(18, 1)), (2, k(17, 2))]), (dn.clone(), vec![(5, k(18, 3))])];
        let kt = keytab(&keys);
        assert_eq!(kt.keys().len(), 3);
        let e = kt.find_key("nn/host").unwrap();
        assert_eq!((e.kvno, e.realm.as_str()), (2, "CORP.TEST"));
        assert_eq!(kt.find_key("dn/host").unwrap().kvno, 5);
        // The same keys have the same fingerprint, so an unchanged keytab is
        // not rewritten; a new key, kvno or principal changes it.
        assert_eq!(fingerprint(&keys), fingerprint(&keys.clone()));
        assert_eq!(fingerprint(&keys).len(), 64);
        let rotated = vec![(nn.clone(), vec![(3, k(18, 9))]), (dn.clone(), vec![(5, k(18, 3))])];
        assert_ne!(fingerprint(&keys), fingerprint(&rotated));
        let rekvno = vec![(nn.clone(), vec![(3, k(18, 1)), (3, k(17, 2))]), (dn.clone(), vec![(5, k(18, 3))])];
        assert_ne!(fingerprint(&keys), fingerprint(&rekvno));
        assert_ne!(fingerprint(&keys), fingerprint(&keys[..1]));
        // MIT's keytab format.
        assert_eq!(&kt.to_bytes()[..2], &[5, 2]);
    }

    #[test]
    fn the_secret_is_owned_and_named() {
        let mut kp = KerberosPrincipal::new(
            "pillar-nn",
            KerberosPrincipalSpec { realm_ref: "corp".into(), principals: vec!["nn/x".into()], ..Default::default() },
        );
        kp.metadata.namespace = Some("hdfs".into());
        kp.metadata.uid = Some("u-2".into());
        let s = secret(&kp, vec![5, 2], "ab");
        assert_eq!(s.metadata.annotations.as_ref().unwrap()[KEYS_SHA256], "ab");
        assert_eq!(s.metadata.name.as_deref(), Some("pillar-nn"));
        assert_eq!(s.metadata.owner_references.unwrap()[0].uid, "u-2");
        assert_eq!(s.data.unwrap()["krb5.keytab"].0, vec![5, 2]);
        kp.spec.secret_name = Some("nn-keytab".into());
        kp.spec.keytab_key = Some("nn.keytab".into());
        let s = secret(&kp, vec![], "ab");
        assert_eq!(s.metadata.name.as_deref(), Some("nn-keytab"));
        assert!(s.data.unwrap().contains_key("nn.keytab"));
        assert_eq!(kp.spec.deletion_policy, DeletionPolicy::Delete);
    }

    /// The test KDC from `scripts/test-kdc.sh`, if its env is set.
    fn live() -> Option<Admin> {
        let var = |k: &str| std::env::var(k).ok();
        Some(Admin {
            realm: var("KRB5_OPERATOR_TEST_REALM")?,
            kdc: var("KRB5_OPERATOR_TEST_KDC")?,
            admin_server: var("KRB5_OPERATOR_TEST_KADMIN")?,
            password: var("KRB5_OPERATOR_TEST_PASSWORD")?,
        })
    }

    macro_rules! live_or_skip {
        () => {
            match live() {
                Some(a) => a,
                None => {
                    eprintln!("skipped: no KRB5_OPERATOR_TEST_* (scripts/test-kdc.sh)");
                    return;
                }
            }
        };
    }

    fn unique(prefix: &str) -> String {
        let n: u64 = rand::random();
        format!("{prefix}-{n:x}")
    }

    #[test]
    fn live_principals_are_created_and_their_keytab_works() {
        let admin = live_or_skip!();
        let names = vec![format!("nn/{}.example.com", unique("host")), unique("svc")];
        let ps = principals(&names, &admin.realm).unwrap();
        let keys = admin.ensure(&ps).unwrap();
        assert_eq!(keys.len(), 2);
        for (_, ks) in &keys {
            assert!(!ks.is_empty(), "the realm's enctypes");
            assert!(ks.iter().any(|(_, k)| k.enctype() == 18), "aes256-cts-hmac-sha1-96 among them");
        }
        let kt = keytab(&keys);
        admin.verify(&ps, &kt).unwrap();
        // Again: nothing is created and no key changes, so the Secret is
        // left alone.
        let again = admin.ensure(&ps).unwrap();
        assert_eq!(fingerprint(&again), fingerprint(&keys));
        admin.delete(&ps).unwrap();
    }

    #[test]
    fn live_a_key_changed_in_the_kdc_reaches_the_keytab() {
        let admin = live_or_skip!();
        let ps = principals(&[unique("rotated")], &admin.realm).unwrap();
        let first = admin.ensure(&ps).unwrap();
        let old = keytab(&first);
        let mut kadm = admin.connect().unwrap();
        kadm.randomize_keys(&ps[0]).unwrap();
        kadm.close();
        let keys = admin.ensure(&ps).unwrap();
        let new = keytab(&keys);
        assert!(
            keys[0].1.iter().all(|(v, _)| *v == 2),
            "kvno 2: {:?}",
            keys[0].1.iter().map(|(v, _)| v).collect::<Vec<_>>()
        );
        assert_ne!(fingerprint(&keys), fingerprint(&first));
        admin.verify(&ps, &new).unwrap();
        assert!(admin.verify(&ps, &old).is_err(), "the old keytab no longer works");
        admin.delete(&ps).unwrap();
    }

    #[test]
    fn live_deleting_removes_the_principals_once() {
        let admin = live_or_skip!();
        let ps = principals(&[unique("gone")], &admin.realm).unwrap();
        let kt = keytab(&admin.ensure(&ps).unwrap());
        admin.delete(&ps).unwrap();
        let e = admin.verify(&ps, &kt).unwrap_err();
        assert!(e.contains("6") || e.to_lowercase().contains("unknown"), "{e}");
        admin.delete(&ps).unwrap(); // already gone: fine
    }

    #[test]
    fn live_a_wrong_admin_password_is_refused() {
        let mut admin = live_or_skip!();
        admin.password = "wrong".into();
        let ps = principals(&[unique("never")], &admin.realm).unwrap();
        assert!(matches!(admin.ensure(&ps), Err(Error::Kadmin(_))));
    }
}
