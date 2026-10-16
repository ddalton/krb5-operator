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
//!
//! Whose keys go where:
//! - the KDC's, kadmind's and the operator's own principals (`krbtgt/*`,
//!   `kadmin/*`, `K/M`, `krb5-operator*`, ...) are never served;
//! - a principal the operator creates is marked, in the KDC, with its
//!   owner (`<namespace>/<name>` of the object, the string attribute
//!   `krb5-operator/owner`); only that object gets its keys or deletes it.
//!   A principal that exists without that mark, or with another owner's, is
//!   a `Conflict`;
//! - a realm serves objects in its own namespace, and others only as its
//!   `allowedNamespaces` says (`NotAllowed` otherwise).
//!
//! The Secret also holds the realm's `krb5.conf` (key `krb5.conf`): a pod in
//! another namespace cannot mount the realm's ConfigMap.
//!
//! Host principals (`hostPrincipals`) follow a StatefulSet's `replicas`
//! (its desired count, so the keys are there before the pods): scaling up
//! adds principals, and principals no longer wanted, by a scale-down or a
//! spec change, are deleted from the KDC (`Retain` keeps them).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{Namespace, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
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
    Condition, DeletionPolicy, HostPrincipals, KerberosPrincipal, KerberosPrincipalStatus, KerberosRealm,
    NamespacesFrom, PrincipalStatus,
};
use crate::realm;

pub const MANAGER: &str = "krb5-operator";
const FINALIZER: &str = "krb5.ddalton.dev/principals";
/// The Secret's annotation with [`fingerprint`] of the keys in its keytab.
pub const KEYS_SHA256: &str = "krb5.ddalton.dev/keys-sha256";
/// The string attribute naming a principal's owner in the KDC.
pub const OWNER_ATTR: &str = "krb5-operator/owner";
/// The Secret's key for the realm's client configuration.
pub const KRB5_CONF_KEY: &str = "krb5.conf";

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
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    NotAllowed(String),
    #[error("{0}")]
    StatefulSetNotFound(String),
}

impl Error {
    /// For a condition: what is wrong with the object, not with the
    /// operator or the cluster.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Error::Invalid(_) => Some("Invalid"),
            Error::Conflict(_) => Some("Conflict"),
            Error::NotAllowed(_) => Some("NotAllowed"),
            Error::RealmNotReady(..) => Some("RealmNotReady"),
            Error::StatefulSetNotFound(_) => Some("StatefulSetNotFound"),
            _ => None,
        }
    }
}

pub struct Context {
    pub client: Client,
    /// The cluster's DNS domain, for pods' names (`CLUSTER_DOMAIN`,
    /// default `cluster.local`).
    pub cluster_domain: String,
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
            if reserved(&p) {
                return Err(Error::Invalid(format!("{n:?} is reserved for the KDC, kadmind or the operator")));
            }
            Ok(p)
        })
        .collect()
}

/// A principal to serve, and the pod it is for (host principals).
#[derive(Clone, Debug, PartialEq)]
pub struct Wanted {
    pub principal: Principal,
    pub pod: Option<String>,
}

/// `<service>/<pod FQDN>` for every service and every pod `sts` wants
/// (its `replicas`), in namespace `ns` of cluster domain `domain`.
pub fn host_principals(
    hp: &HostPrincipals,
    sts: &StatefulSet,
    ns: &str,
    domain: &str,
    realm: &str,
) -> Result<Vec<Wanted>, Error> {
    let spec = sts.spec.as_ref();
    let service = spec.and_then(|s| s.service_name.as_deref()).filter(|s| !s.is_empty()).ok_or_else(|| {
        Error::Invalid(format!("StatefulSet {} has no serviceName, so its pods have no DNS names", hp.stateful_set))
    })?;
    if hp.services.is_empty() {
        return Err(Error::Invalid("hostPrincipals.services is empty".into()));
    }
    let replicas = spec.and_then(|s| s.replicas).unwrap_or(1).max(0);
    let mut out = Vec::with_capacity(replicas as usize * hp.services.len());
    for i in 0..replicas {
        let pod = format!("{}-{i}", sts.name_any());
        let fqdn = format!("{pod}.{service}.{ns}.svc.{domain}");
        for svc in &hp.services {
            if svc.is_empty() || svc.contains(['/', '@']) {
                return Err(Error::Invalid(format!("host principal service {svc:?}: a name, no '/' or '@'")));
            }
            let principal = principals(&[format!("{svc}/{fqdn}")], realm)?.remove(0);
            out.push(Wanted { principal, pod: Some(pod.clone()) });
        }
    }
    Ok(out)
}

/// Everything `kp` wants: its `principals`, then its host principals
/// (`sts` is its StatefulSet), each once.
pub fn wanted(
    kp: &KerberosPrincipal,
    sts: Option<&StatefulSet>,
    domain: &str,
    realm: &str,
) -> Result<Vec<Wanted>, Error> {
    let mut out: Vec<Wanted> = if kp.spec.principals.is_empty() {
        Vec::new()
    } else {
        principals(&kp.spec.principals, realm)?.into_iter().map(|principal| Wanted { principal, pod: None }).collect()
    };
    if let (Some(hp), Some(sts)) = (&kp.spec.host_principals, sts) {
        let ns = kp.namespace().unwrap_or_else(|| "default".into());
        for w in host_principals(hp, sts, &ns, domain, realm)? {
            if !out.iter().any(|o| o.principal == w.principal) {
                out.push(w);
            }
        }
    }
    if out.is_empty() && kp.spec.host_principals.is_none() {
        return Err(Error::Invalid("no principals".into()));
    }
    Ok(out)
}

/// The Secret's files: every key in `keytab_key`, each pod's own in
/// `<pod>.keytab`, and the realm's `krb5.conf`.
pub fn secret_files(
    wanted: &[Wanted],
    keys: &[PrincipalKeys],
    keytab_key: &str,
    krb5_conf: &str,
) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::from([
        (keytab_key.to_string(), keytab(keys).to_bytes()),
        (KRB5_CONF_KEY.to_string(), krb5_conf.as_bytes().to_vec()),
    ]);
    let mut pods: BTreeMap<&str, Vec<PrincipalKeys>> = BTreeMap::new();
    for (w, k) in wanted.iter().zip(keys) {
        if let Some(pod) = &w.pod {
            pods.entry(pod).or_default().push(k.clone());
        }
    }
    for (pod, ks) in pods {
        files.entry(format!("{pod}.keytab")).or_insert_with(|| keytab(&ks).to_bytes());
    }
    files
}

/// Principals `kp` had (its status) that it no longer wants.
pub fn unwanted(kp: &KerberosPrincipal, wanted: &[Wanted]) -> Vec<Principal> {
    let had = kp.status.as_ref().map(|s| s.principals.as_slice()).unwrap_or_default();
    let wanted: Vec<&Principal> = wanted.iter().map(|w| &w.principal).collect();
    no_longer_wanted(had, &wanted)
}

/// Of the principals in a status (`had`), those not `wanted`.
pub fn no_longer_wanted(had: &[PrincipalStatus], wanted: &[&Principal]) -> Vec<Principal> {
    let names: Vec<String> = wanted.iter().map(|p| format!("{}@{}", p.name(), p.realm)).collect();
    had.iter().filter(|p| !names.contains(&p.name)).filter_map(|p| Principal::parse(&p.name).ok()).collect()
}

/// The KDC's, kadmind's and the operator's own principals: whoever has
/// their keys has the realm (a `krbtgt` key forges any ticket).
pub fn reserved(p: &Principal) -> bool {
    let first = p.components[0].as_str();
    matches!(first, "krbtgt" | "kadmin" | "kiprop" | "changepw" | "WELLKNOWN" | "K")
        || first.starts_with("krb5-operator")
}

/// Whether `realm` serves `KerberosPrincipal`s in namespace `ns` (whose
/// labels are `labels`).
pub fn allowed(realm: &KerberosRealm, ns: &str, labels: &BTreeMap<String, String>) -> bool {
    if realm.metadata.namespace.as_deref().unwrap_or("default") == ns {
        return true;
    }
    let Some(a) = &realm.spec.allowed_namespaces else { return false };
    match a.from {
        NamespacesFrom::Same => false,
        NamespacesFrom::All => true,
        NamespacesFrom::Selector => a.selector.as_ref().is_some_and(|s| selects(s, labels)),
    }
}

/// A label selector's meaning (an empty selector selects everything).
pub fn selects(s: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    let exact = s.match_labels.iter().flatten().all(|(k, v)| labels.get(k) == Some(v));
    let exprs = s.match_expressions.iter().flatten().all(|e| {
        let values = e.values.as_deref().unwrap_or_default();
        match e.operator.as_str() {
            "In" => labels.get(&e.key).is_some_and(|v| values.contains(v)),
            "NotIn" => labels.get(&e.key).is_none_or(|v| !values.contains(v)),
            "Exists" => labels.contains_key(&e.key),
            "DoesNotExist" => !labels.contains_key(&e.key),
            _ => false,
        }
    });
    exact && exprs
}

/// The keytab for `keys` (each principal's, with their kvnos), as MIT's
/// `ktadd` writes it. Enctypes the crate does not know are left out.
pub fn keytab(keys: &[PrincipalKeys]) -> Keytab {
    let mut entries = Vec::new();
    for (p, ks) in keys {
        for (kvno, k) in ks {
            if let Some(enctype) = EncType::from_i32(k.enctype()) {
                entries.push(ServiceKey::new(p.name(), p.realm.clone(), *kvno, enctype, k.bytes().to_vec()));
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

    /// Create what is missing, owned by `owner`, then every principal's
    /// current keys; a principal someone else owns is a [`Error::Conflict`].
    pub fn ensure(&self, ps: &[Principal], owner: &str) -> Result<Vec<PrincipalKeys>, Error> {
        let mut kadm = self.connect()?;
        let mut out = Vec::with_capacity(ps.len());
        for p in ps {
            match owner_of(&mut kadm, p)? {
                Some(Some(o)) if o == owner => {}
                Some(Some(o)) => {
                    return Err(Error::Conflict(format!("{}@{} belongs to {o}", p.name(), p.realm)));
                }
                Some(None) => {
                    return Err(Error::Conflict(format!(
                        "{}@{} exists and was not made by the operator",
                        p.name(),
                        p.realm
                    )));
                }
                None => {
                    kadm.create_principal(p, &PrincipalChanges::default(), None).map_err(|e| match e.code() {
                        // Made since we looked: someone else's.
                        Some(c) if c.name() == Some("KADM5_DUP") => {
                            Error::Conflict(format!("{}@{} was just created by someone else", p.name(), p.realm))
                        }
                        _ => Error::Kadmin(format!("creating {}: {e}", p.name())),
                    })?;
                    if let Err(e) = kadm.set_string(p, OWNER_ATTR, Some(owner)) {
                        // Unmarked, it would be nobody's: take it back.
                        let _ = kadm.delete_principal(p);
                        return Err(Error::Kadmin(format!("marking {} as {owner}'s: {e}", p.name())));
                    }
                    info!("Created principal {}@{} for {owner}", p.name(), p.realm);
                }
            }
            let keys = kadm
                .extract_keys(p, None)
                .map_err(|e| Error::Kadmin(format!("extracting keys of {}: {e}", p.name())))?;
            out.push((p.clone(), keys));
        }
        kadm.close();
        Ok(out)
    }

    /// Delete the principals `owner` owns (those gone, or someone else's,
    /// are left alone).
    pub fn delete(&self, ps: &[Principal], owner: &str) -> Result<(), Error> {
        let mut kadm = self.connect()?;
        for p in ps {
            match owner_of(&mut kadm, p)? {
                Some(Some(o)) if o == owner => match kadm.delete_principal(p) {
                    Ok(()) => info!("Deleted principal {}@{} of {owner}", p.name(), p.realm),
                    Err(e) if e.code().is_some_and(|c| c.is_unknown_principal()) => {}
                    Err(e) => return Err(Error::Kadmin(format!("deleting {}: {e}", p.name()))),
                },
                None => {}
                Some(o) => info!("Not deleting {}@{}: not {owner}'s ({o:?})", p.name(), p.realm),
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

/// Whose `p` is: `None` if it does not exist, `Some(None)` if it has no
/// owner mark.
fn owner_of(kadm: &mut AdminClient, p: &Principal) -> Result<Option<Option<String>>, Error> {
    match kadm.get_strings(p) {
        Ok(strings) => Ok(Some(strings.into_iter().find(|(k, _)| k == OWNER_ATTR).map(|(_, v)| v))),
        Err(e) if e.code().is_some_and(|c| c.is_unknown_principal()) => Ok(None),
        Err(e) => Err(Error::Kadmin(format!("reading {}: {e}", p.name()))),
    }
}

/// `namespace/name` of the realm `kp` refers to.
fn realm_ref(kp: &KerberosPrincipal) -> String {
    format!("{}/{}", kp.realm_namespace(), kp.spec.realm_ref)
}

/// The realm `kp` refers to, ready (and, with `check_allowed`, serving
/// `kp`'s namespace), and how to administer it.
async fn admin_for(
    client: &Client,
    kp: &KerberosPrincipal,
    check_allowed: bool,
) -> Result<(KerberosRealm, Admin), Error> {
    let r = Api::<KerberosRealm>::namespaced(client.clone(), &kp.realm_namespace())
        .get_opt(&kp.spec.realm_ref)
        .await?
        .ok_or_else(|| Error::RealmNotReady(realm_ref(kp), "no such KerberosRealm".into()))?;
    if check_allowed {
        let ns = kp.namespace().unwrap_or_else(|| "default".into());
        let needs_labels = r.metadata.namespace.as_deref() != Some(&ns)
            && r.spec.allowed_namespaces.as_ref().is_some_and(|a| a.from == NamespacesFrom::Selector);
        let labels = if needs_labels {
            Api::<Namespace>::all(client.clone()).get_opt(&ns).await?.map(|n| n.labels().clone()).unwrap_or_default()
        } else {
            BTreeMap::new()
        };
        if !allowed(&r, &ns, &labels) {
            return Err(Error::NotAllowed(format!(
                "realm {} does not serve namespace {ns} (its spec.allowedNamespaces)",
                realm_ref(kp)
            )));
        }
    }
    let admin = admin_of(client, &r).await?;
    Ok((r, admin))
}

/// How to administer realm `r`, once it is ready.
pub async fn admin_of(client: &Client, r: &KerberosRealm) -> Result<Admin, Error> {
    let name = format!("{}/{}", r.namespace().unwrap_or_default(), r.name_any());
    let status = r.status.clone().unwrap_or_default();
    let ready = status.conditions.iter().any(|c| c.type_ == "Ready" && c.status == "True");
    let (Some(kdc), Some(admin_server), true) = (status.kdc, status.admin_server, ready) else {
        return Err(Error::RealmNotReady(name, "its KDC does not answer yet".into()));
    };
    let password = realm::admin_password(client, r)
        .await
        .map_err(|e| Error::RealmNotReady(name.clone(), e.to_string()))?
        .ok_or_else(|| Error::RealmNotReady(name, "no admin password".into()))?;
    Ok(Admin { realm: r.spec.realm.clone(), kdc, admin_server, password })
}

pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Error> {
    tokio::task::spawn_blocking(f).await.map_err(|e| Error::Kadmin(e.to_string()))
}

pub fn secret(kp: &KerberosPrincipal, files: BTreeMap<String, Vec<u8>>, fingerprint: &str) -> Secret {
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
        data: Some(files.into_iter().map(|(k, v)| (k, ByteString(v))).collect()),
        ..Default::default()
    }
}

pub fn condition(ready: bool, reason: &str, message: &str) -> Condition {
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

async fn apply(kp: Arc<KerberosPrincipal>, ctx: &Context) -> Result<Action, Error> {
    let client = &ctx.client;
    match sync(&kp, ctx).await {
        // What is wrong with the object (or its realm) goes in its status.
        Err(e) if e.reason().is_some() => {
            let reason = e.reason().unwrap_or_default();
            if reason != "RealmNotReady" {
                warn!("{}: {}", kp.name_any(), e);
            }
            let status = KerberosPrincipalStatus {
                conditions: vec![condition(false, reason, &e.to_string())],
                observed_generation: kp.metadata.generation,
                ..Default::default()
            };
            set_status(client, &kp, status).await?;
            let wait = match reason {
                "RealmNotReady" => 10,
                "StatefulSetNotFound" => 30,
                _ => 60,
            };
            Ok(Action::requeue(Duration::from_secs(wait)))
        }
        r => r,
    }
}

async fn sync(kp: &KerberosPrincipal, ctx: &Context) -> Result<Action, Error> {
    let client = &ctx.client;
    let (realm, admin) = admin_for(client, kp, true).await?;
    let krb5_conf = realm::config_files(&realm).remove(KRB5_CONF_KEY).unwrap_or_default();
    let ns = kp.namespace().unwrap_or_else(|| "default".into());
    let sts = match &kp.spec.host_principals {
        Some(hp) => {
            Some(Api::<StatefulSet>::namespaced(client.clone(), &ns).get_opt(&hp.stateful_set).await?.ok_or_else(
                || Error::StatefulSetNotFound(format!("StatefulSet {ns}/{} does not exist", hp.stateful_set)),
            )?)
        }
        None => None,
    };
    let wanted = wanted(kp, sts.as_ref(), &ctx.cluster_domain, &admin.realm)?;
    let ps: Vec<Principal> = wanted.iter().map(|w| w.principal.clone()).collect();
    let keys = {
        let (admin, ps, owner) = (admin.clone(), ps.clone(), kp.owner());
        blocking(move || admin.ensure(&ps, &owner)).await??
    };
    let fp = fingerprint(&keys);

    let secrets: Api<Secret> = Api::namespaced(client.clone(), &ns);
    let name = kp.secret_name();
    let current = secrets.get_opt(&name).await?;
    let unchanged = current.as_ref().is_some_and(|s| {
        s.annotations().get(KEYS_SHA256) == Some(&fp)
            && s.data.as_ref().is_some_and(|d| {
                d.get(&kp.keytab_key()).is_some_and(|b| !b.0.is_empty())
                    && d.get(KRB5_CONF_KEY).is_some_and(|b| b.0 == krb5_conf.as_bytes())
            })
    });
    if !unchanged {
        let s = secret(kp, secret_files(&wanted, &keys, &kp.keytab_key(), &krb5_conf), &fp);
        secrets.patch(&name, &PatchParams::apply(MANAGER).force(), &Patch::Apply(&s)).await?;
        info!("Wrote the keytab of {} ({} principals) to Secret {}/{}", kp.name_any(), keys.len(), ns, name);
    }

    // Principals it no longer wants (a scale-down, a spec change) go, now
    // that the Secret no longer holds them.
    let gone = unwanted(kp, &wanted);
    if !gone.is_empty() && kp.spec.deletion_policy == DeletionPolicy::Delete {
        let (admin, owner) = (admin.clone(), kp.owner());
        if let Err(e) = blocking(move || admin.delete(&gone, &owner)).await? {
            warn!("{}: deleting principals it no longer wants: {e}", kp.name_any());
        }
    }

    // A ticket with each key: when the keys changed or it was not Ready
    // (the keys cannot change otherwise), not every resync.
    let was_ready = kp.status.as_ref().is_some_and(|s| {
        s.observed_generation == kp.metadata.generation
            && s.conditions.iter().any(|c| c.type_ == "Ready" && c.status == "True")
    });
    let cond = if unchanged && was_ready {
        kp.status.as_ref().and_then(|s| s.conditions.iter().find(|c| c.type_ == "Ready").cloned())
    } else {
        None
    };
    let cond = match cond {
        Some(c) => c,
        None => {
            let (admin, ps, kt) = (admin.clone(), ps.clone(), keytab(&keys));
            match blocking(move || admin.verify(&ps, &kt)).await? {
                Ok(()) => condition(true, "KeytabVerified", "every principal got a ticket with its keytab key"),
                Err(e) => {
                    warn!("{}: {}", kp.name_any(), e);
                    condition(false, "KeytabRejected", &e)
                }
            }
        }
    };
    let ready = cond.status == "True";
    let status = KerberosPrincipalStatus {
        secret_name: Some(name),
        principals: wanted
            .iter()
            .zip(&keys)
            .map(|(w, (p, ks))| PrincipalStatus {
                name: format!("{}@{}", p.name(), p.realm),
                kvno: ks.iter().map(|(v, _)| *v).max().unwrap_or(0),
                pod: w.pod.clone(),
                node: None,
            })
            .collect(),
        conditions: vec![cond],
        observed_generation: kp.metadata.generation,
    };
    if kp.status.as_ref() != Some(&status) {
        set_status(client, kp, status).await?;
    }
    Ok(Action::requeue(if ready { Duration::from_secs(300) } else { Duration::from_secs(30) }))
}

async fn cleanup(kp: Arc<KerberosPrincipal>, client: &Client) -> Result<Action, Error> {
    if kp.spec.deletion_policy == DeletionPolicy::Retain {
        return Ok(Action::await_change());
    }
    // Its own principals go whether or not the realm still serves its
    // namespace.
    let admin = match admin_for(client, &kp, false).await {
        Ok((_, admin)) => admin,
        // The realm is gone (and its KDC with it): nothing to delete.
        Err(e @ Error::RealmNotReady(..)) => {
            let realms = Api::<KerberosRealm>::namespaced(client.clone(), &kp.realm_namespace());
            if realms.get_opt(&kp.spec.realm_ref).await?.is_none() {
                return Ok(Action::await_change());
            }
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    // What it has (its status: host principals too) and what it names;
    // names that are not valid (or reserved) were never created.
    let mut ps = unwanted(&kp, &[]);
    for p in principals(&kp.spec.principals, &admin.realm).unwrap_or_default() {
        if !ps.contains(&p) {
            ps.push(p);
        }
    }
    let owner = kp.owner();
    blocking(move || admin.delete(&ps, &owner)).await??;
    Ok(Action::await_change())
}

pub async fn reconcile(kp: Arc<KerberosPrincipal>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = kp.namespace().unwrap_or_else(|| "default".into());
    let api: Api<KerberosPrincipal> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, kp, |event| async {
        match event {
            Event::Apply(kp) => apply(kp, &ctx).await,
            Event::Cleanup(kp) => cleanup(kp, &ctx.client).await,
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
    use crate::crd::{AllowedNamespaces, KerberosPrincipalSpec, KerberosRealmSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement;

    const ME: &str = "tests/me";

    #[test]
    fn the_kdcs_and_the_operators_principals_are_never_served() {
        for n in [
            "krbtgt/CORP.TEST",
            "krbtgt/OTHER.TEST@CORP.TEST",
            "kadmin/admin",
            "kadmin/changepw",
            "kiprop/kdc.example.com",
            "K/M",
            "WELLKNOWN/ANONYMOUS",
            "krb5-operator/admin",
            "krb5-operator-probe",
            "changepw/kerberos",
        ] {
            assert!(matches!(principals(&[n.into()], "CORP.TEST"), Err(Error::Invalid(_))), "{n}");
        }
        // Lookalikes are fine.
        assert!(principals(&["kadminx".into(), "admin/admin".into(), "Krbtgt".into()], "CORP.TEST").is_ok());
    }

    fn realm_in(ns: &str, allowed: Option<AllowedNamespaces>) -> KerberosRealm {
        let mut r = KerberosRealm::new(
            "corp",
            KerberosRealmSpec { realm: "CORP.TEST".into(), allowed_namespaces: allowed, ..Default::default() },
        );
        r.metadata.namespace = Some(ns.into());
        r
    }

    fn labels(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn a_realm_serves_its_namespace_and_those_it_allows() {
        let none = BTreeMap::new();
        let own = realm_in("auth", None);
        assert!(allowed(&own, "auth", &none));
        assert!(!allowed(&own, "hdfs", &none), "by default only its own");
        let same = realm_in("auth", Some(AllowedNamespaces { from: NamespacesFrom::Same, selector: None }));
        assert!(!allowed(&same, "hdfs", &none));
        let all = realm_in("auth", Some(AllowedNamespaces { from: NamespacesFrom::All, selector: None }));
        assert!(allowed(&all, "hdfs", &none));
        let sel = |s: LabelSelector| {
            realm_in("auth", Some(AllowedNamespaces { from: NamespacesFrom::Selector, selector: Some(s) }))
        };
        let by_label = sel(LabelSelector {
            match_labels: Some(labels(&[("kerberos", "corp")]).into_iter().collect()),
            ..Default::default()
        });
        assert!(allowed(&by_label, "hdfs", &labels(&[("kerberos", "corp"), ("x", "y")])));
        assert!(!allowed(&by_label, "hdfs", &labels(&[("kerberos", "other")])));
        assert!(!allowed(&by_label, "hdfs", &none));
        assert!(allowed(&by_label, "auth", &none), "its own namespace always");
        // Selector without a selector: nobody else.
        let empty = realm_in("auth", Some(AllowedNamespaces { from: NamespacesFrom::Selector, selector: None }));
        assert!(!allowed(&empty, "hdfs", &labels(&[("kerberos", "corp")])));
    }

    #[test]
    fn label_selectors_mean_what_kubernetes_means() {
        let expr = |key: &str, op: &str, values: &[&str]| LabelSelectorRequirement {
            key: key.into(),
            operator: op.into(),
            values: Some(values.iter().map(|v| v.to_string()).collect()),
        };
        let sel = |exprs: Vec<LabelSelectorRequirement>| LabelSelector {
            match_expressions: Some(exprs),
            ..Default::default()
        };
        let l = labels(&[("tier", "data"), ("team", "hdfs")]);
        assert!(selects(&LabelSelector::default(), &l), "empty selects all");
        assert!(selects(&sel(vec![expr("tier", "In", &["data", "web"])]), &l));
        assert!(!selects(&sel(vec![expr("tier", "In", &["web"])]), &l));
        assert!(selects(&sel(vec![expr("tier", "NotIn", &["web"])]), &l));
        assert!(selects(&sel(vec![expr("zone", "NotIn", &["a"])]), &l), "NotIn holds without the key");
        assert!(selects(&sel(vec![expr("team", "Exists", &[])]), &l));
        assert!(!selects(&sel(vec![expr("zone", "Exists", &[])]), &l));
        assert!(selects(&sel(vec![expr("zone", "DoesNotExist", &[])]), &l));
        assert!(!selects(&sel(vec![expr("team", "Exists", &[]), expr("zone", "Exists", &[])]), &l), "all must hold");
        assert!(!selects(&sel(vec![expr("team", "Bogus", &[])]), &l));
    }

    #[test]
    fn principals_find_their_realm_and_name_their_owner() {
        let mut kp = KerberosPrincipal::new(
            "nn",
            KerberosPrincipalSpec { realm_ref: "corp".into(), principals: vec!["nn/x".into()], ..Default::default() },
        );
        kp.metadata.namespace = Some("hdfs".into());
        assert_eq!(kp.realm_namespace(), "hdfs");
        assert_eq!(kp.owner(), "hdfs/nn");
        kp.spec.realm_namespace = Some("auth".into());
        assert_eq!(kp.realm_namespace(), "auth");
        assert_eq!(realm_ref(&kp), "auth/corp");
        assert_eq!(kp.owner(), "hdfs/nn", "the owner is where the object is");
    }

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
        let files = |key: &str| BTreeMap::from([(key.to_string(), vec![5, 2])]);
        let s = secret(&kp, files("krb5.keytab"), "ab");
        assert_eq!(s.metadata.annotations.as_ref().unwrap()[KEYS_SHA256], "ab");
        assert_eq!(s.metadata.name.as_deref(), Some("pillar-nn"));
        assert_eq!(s.metadata.owner_references.unwrap()[0].uid, "u-2");
        assert_eq!(s.data.unwrap()["krb5.keytab"].0, vec![5, 2]);
        kp.spec.secret_name = Some("nn-keytab".into());
        kp.spec.keytab_key = Some("nn.keytab".into());
        assert_eq!(kp.keytab_key(), "nn.keytab");
        let s = secret(&kp, files("nn.keytab"), "ab");
        assert_eq!(s.metadata.name.as_deref(), Some("nn-keytab"));
        assert!(s.data.unwrap().contains_key("nn.keytab"));
        assert_eq!(kp.spec.deletion_policy, DeletionPolicy::Delete);
    }

    fn sts(name: &str, service: Option<&str>, replicas: Option<i32>) -> StatefulSet {
        let mut s = StatefulSet::default();
        s.metadata.name = Some(name.into());
        s.spec = Some(k8s_openapi::api::apps::v1::StatefulSetSpec {
            service_name: service.map(Into::into),
            replicas,
            ..Default::default()
        });
        s
    }

    fn with_hosts(principals: &[&str], sts: &str, services: &[&str]) -> KerberosPrincipal {
        let mut kp = KerberosPrincipal::new(
            "dn",
            KerberosPrincipalSpec {
                realm_ref: "corp".into(),
                principals: principals.iter().map(|p| p.to_string()).collect(),
                host_principals: Some(HostPrincipals {
                    stateful_set: sts.into(),
                    services: services.iter().map(|s| s.to_string()).collect(),
                }),
                ..Default::default()
            },
        );
        kp.metadata.namespace = Some("hdfs".into());
        kp
    }

    fn names(w: &[Wanted]) -> Vec<(String, Option<String>)> {
        w.iter().map(|w| (w.principal.name(), w.pod.clone())).collect()
    }

    #[test]
    fn host_principals_name_each_pod_of_the_stateful_set() {
        let kp = with_hosts(&["hdfs"], "pillar-dn", &["dn", "HTTP"]);
        let set = sts("pillar-dn", Some("pillar-dn"), Some(2));
        let w = wanted(&kp, Some(&set), "cluster.local", "CORP.TEST").unwrap();
        let pod = |i: u8| Some(format!("pillar-dn-{i}"));
        assert_eq!(
            names(&w),
            vec![
                ("hdfs".into(), None),
                ("dn/pillar-dn-0.pillar-dn.hdfs.svc.cluster.local".into(), pod(0)),
                ("HTTP/pillar-dn-0.pillar-dn.hdfs.svc.cluster.local".into(), pod(0)),
                ("dn/pillar-dn-1.pillar-dn.hdfs.svc.cluster.local".into(), pod(1)),
                ("HTTP/pillar-dn-1.pillar-dn.hdfs.svc.cluster.local".into(), pod(1)),
            ]
        );
        assert!(w.iter().all(|w| w.principal.realm == "CORP.TEST"));
        // The cluster domain, and the default of one replica.
        let w = wanted(&kp, Some(&sts("pillar-dn", Some("dns"), None)), "k8s.example", "CORP.TEST").unwrap();
        assert_eq!(w[1].principal.name(), "dn/pillar-dn-0.dns.hdfs.svc.k8s.example");
        assert_eq!(w.len(), 3);
        // Scaled to zero: only the plain ones; with none at all, nothing
        // (not an error: the StatefulSet may scale up).
        let zero = sts("pillar-dn", Some("pillar-dn"), Some(0));
        assert_eq!(wanted(&kp, Some(&zero), "cluster.local", "CORP.TEST").unwrap().len(), 1);
        let only_hosts = with_hosts(&[], "pillar-dn", &["dn"]);
        assert!(wanted(&only_hosts, Some(&zero), "cluster.local", "CORP.TEST").unwrap().is_empty());
        // A name in both lists once.
        let both = with_hosts(&["dn/pillar-dn-0.pillar-dn.hdfs.svc.cluster.local"], "pillar-dn", &["dn"]);
        assert_eq!(wanted(&both, Some(&set), "cluster.local", "CORP.TEST").unwrap().len(), 2);
    }

    #[test]
    fn host_principals_need_a_service_name_and_plain_services() {
        let kp = with_hosts(&[], "pillar-dn", &["dn"]);
        let r = wanted(&kp, Some(&sts("pillar-dn", None, Some(1))), "cluster.local", "CORP.TEST");
        assert!(matches!(r, Err(Error::Invalid(m)) if m.contains("serviceName")));
        let set = sts("pillar-dn", Some("pillar-dn"), Some(1));
        for bad in [&["dn/x"][..], &["dn@X"], &[""], &[], &["krbtgt"], &["kadmin"]] {
            let kp = with_hosts(&[], "pillar-dn", bad);
            assert!(matches!(wanted(&kp, Some(&set), "cluster.local", "CORP.TEST"), Err(Error::Invalid(_))), "{bad:?}");
        }
        // Without host principals, some principal is required.
        let mut none = with_hosts(&[], "x", &["dn"]);
        none.spec.host_principals = None;
        assert!(matches!(wanted(&none, None, "cluster.local", "CORP.TEST"), Err(Error::Invalid(_))));
    }

    #[test]
    fn each_pod_gets_its_own_keytab_and_all_keys_are_in_one() {
        let k = |b: u8| krb5::Key::new(18, vec![b; 32]).unwrap();
        let kp = with_hosts(&["hdfs"], "dn", &["dn", "HTTP"]);
        let w = wanted(&kp, Some(&sts("dn", Some("dn"), Some(2))), "cluster.local", "CORP.TEST").unwrap();
        let keys: Vec<PrincipalKeys> =
            w.iter().enumerate().map(|(i, w)| (w.principal.clone(), vec![(1, k(i as u8))])).collect();
        let files = secret_files(&w, &keys, "krb5.keytab", "conf");
        assert_eq!(files.keys().collect::<Vec<_>>(), vec!["dn-0.keytab", "dn-1.keytab", "krb5.conf", "krb5.keytab"]);
        assert_eq!(files["krb5.conf"], b"conf");
        let has = |file: &str, b: u8| files[file].windows(32).any(|w| w == [b; 32]);
        // Keys 0..5: hdfs, dn-0's dn and HTTP, dn-1's dn and HTTP.
        assert!((0..5).all(|b| has("krb5.keytab", b)), "every key in krb5.keytab");
        assert!(has("dn-0.keytab", 1) && has("dn-0.keytab", 2));
        assert!(has("dn-1.keytab", 3) && has("dn-1.keytab", 4));
        for (file, others) in [("dn-0.keytab", [0, 3, 4]), ("dn-1.keytab", [0, 1, 2])] {
            assert!(others.iter().all(|b| !has(file, *b)), "{file} holds only its pod's keys");
        }
        assert_eq!(files["dn-1.keytab"].len(), keytab(&keys[3..5]).to_bytes().len());
        assert_eq!(files["dn-1.keytab"][..2], [5, 2]);
    }

    #[test]
    fn principals_no_longer_wanted_are_the_ones_to_delete() {
        let mut kp = with_hosts(&[], "dn", &["dn"]);
        let set = |n| sts("dn", Some("dn"), Some(n));
        let three = wanted(&kp, Some(&set(3)), "cluster.local", "CORP.TEST").unwrap();
        kp.status = Some(KerberosPrincipalStatus {
            principals: three
                .iter()
                .map(|w| PrincipalStatus {
                    name: format!("{}@{}", w.principal.name(), w.principal.realm),
                    kvno: 1,
                    pod: w.pod.clone(),
                    node: None,
                })
                .collect(),
            ..Default::default()
        });
        assert!(unwanted(&kp, &three).is_empty());
        let one = wanted(&kp, Some(&set(1)), "cluster.local", "CORP.TEST").unwrap();
        let gone: Vec<String> = unwanted(&kp, &one).iter().map(|p| p.name()).collect();
        assert_eq!(gone, vec!["dn/dn-1.dn.hdfs.svc.cluster.local", "dn/dn-2.dn.hdfs.svc.cluster.local"]);
        assert!(unwanted(&kp, &one).iter().all(|p| p.realm == "CORP.TEST"));
        // Cleanup: everything it has.
        assert_eq!(unwanted(&kp, &[]).len(), 3);
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
        let keys = admin.ensure(&ps, ME).unwrap();
        assert_eq!(keys.len(), 2);
        for (_, ks) in &keys {
            assert!(!ks.is_empty(), "the realm's enctypes");
            assert!(ks.iter().any(|(_, k)| k.enctype() == 18), "aes256-cts-hmac-sha1-96 among them");
        }
        let kt = keytab(&keys);
        admin.verify(&ps, &kt).unwrap();
        // Again: nothing is created and no key changes, so the Secret is
        // left alone.
        let again = admin.ensure(&ps, ME).unwrap();
        assert_eq!(fingerprint(&again), fingerprint(&keys));
        admin.delete(&ps, ME).unwrap();
    }

    #[test]
    fn live_a_key_changed_in_the_kdc_reaches_the_keytab() {
        let admin = live_or_skip!();
        let ps = principals(&[unique("rotated")], &admin.realm).unwrap();
        let first = admin.ensure(&ps, ME).unwrap();
        let old = keytab(&first);
        let mut kadm = admin.connect().unwrap();
        kadm.randomize_keys(&ps[0]).unwrap();
        kadm.close();
        let keys = admin.ensure(&ps, ME).unwrap();
        let new = keytab(&keys);
        assert!(
            keys[0].1.iter().all(|(v, _)| *v == 2),
            "kvno 2: {:?}",
            keys[0].1.iter().map(|(v, _)| v).collect::<Vec<_>>()
        );
        assert_ne!(fingerprint(&keys), fingerprint(&first));
        admin.verify(&ps, &new).unwrap();
        assert!(admin.verify(&ps, &old).is_err(), "the old keytab no longer works");
        admin.delete(&ps, ME).unwrap();
    }

    #[test]
    fn live_deleting_removes_the_principals_once() {
        let admin = live_or_skip!();
        let ps = principals(&[unique("gone")], &admin.realm).unwrap();
        let kt = keytab(&admin.ensure(&ps, ME).unwrap());
        admin.delete(&ps, ME).unwrap();
        let e = admin.verify(&ps, &kt).unwrap_err();
        assert!(e.contains("6") || e.to_lowercase().contains("unknown"), "{e}");
        admin.delete(&ps, ME).unwrap(); // already gone: fine
    }

    #[test]
    fn live_a_principal_belongs_to_the_object_that_made_it() {
        let admin = live_or_skip!();
        let ps = principals(&[unique("owned")], &admin.realm).unwrap();
        let mine = keytab(&admin.ensure(&ps, ME).unwrap());
        // Another object naming it gets neither its keys nor its deletion.
        let theirs = admin.ensure(&ps, "elsewhere/thief");
        assert!(matches!(&theirs, Err(Error::Conflict(m)) if m.contains(ME)), "{theirs:?}");
        admin.delete(&ps, "elsewhere/thief").unwrap();
        admin.verify(&ps, &mine).unwrap();
        // A principal made outside the operator is nobody's to take.
        let outside = principals(&[unique("outside")], &admin.realm).unwrap();
        let mut kadm = admin.connect().unwrap();
        kadm.create_principal(&outside[0], &PrincipalChanges::default(), None).unwrap();
        let r = admin.ensure(&outside, ME);
        assert!(matches!(&r, Err(Error::Conflict(m)) if m.contains("not made by the operator")), "{r:?}");
        admin.delete(&outside, ME).unwrap();
        assert!(kadm.get_principal(&outside[0]).is_ok(), "left alone");
        kadm.delete_principal(&outside[0]).unwrap();
        kadm.close();
        admin.delete(&ps, ME).unwrap();
    }

    #[test]
    fn live_a_wrong_admin_password_is_refused() {
        let mut admin = live_or_skip!();
        admin.password = "wrong".into();
        let ps = principals(&[unique("never")], &admin.realm).unwrap();
        assert!(matches!(admin.ensure(&ps, ME), Err(Error::Kadmin(_))));
    }
}
