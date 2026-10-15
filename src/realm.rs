//! The `KerberosRealm` controller: owns a KDC's objects and reports
//! whether it answers.
//!
//! - Secret `<name>-kdc`: the database master key (generated once, never
//!   changed: it decrypts the database) and the password of the operator's
//!   own admin principal, `krb5-operator/admin`, which the image (re)sets
//!   at every start and `kadm5.acl` lets do everything, key extraction
//!   included.
//! - ConfigMap `<name>-kdc`: `kdc.conf` for the KDC and a client
//!   `krb5.conf` that points at the Service; workloads mount it.
//! - StatefulSet `<name>-kdc` (one replica): krb5kdc and kadmind, the
//!   database on a volume; the image creates the database on first start.
//! - Service `<name>-kdc`: 88 (KDC, TCP and UDP) and 749 (kadmind).
//!
//! Ready means a real KDC exchange worked: an AS-REQ (from the krb5 crate)
//! for a probe principal is answered `KDC_ERR_C_PRINCIPAL_UNKNOWN` by a KDC
//! of this realm.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::{StatefulSet, StatefulSetSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EnvVar, EnvVarSource, PersistentVolumeClaim,
    PersistentVolumeClaimSpec, PodSpec, PodTemplateSpec, Probe, Secret, SecretKeySelector, Service, ServicePort,
    ServiceSpec, TCPSocketAction, Volume, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, Resource, ResourceExt};
use rand::Rng;
use serde_json::json;
use tracing::{info, warn};

use crate::crd::{Condition, KerberosRealm, KerberosRealmStatus};

pub const KDC_PORT: i32 = 88;
pub const KADMIN_PORT: i32 = 749;
const MANAGER: &str = "krb5-operator";
const MASTER_KEY: &str = "master-key";
const ADMIN_PASSWORD: &str = "admin-password";
/// The operator's principal in every realm it runs.
pub const ADMIN: &str = "krb5-operator/admin";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Kubernetes: {0}")]
    Kube(#[from] kube::Error),
    #[error("invalid KerberosRealm: {0}")]
    Invalid(String),
}

pub struct Context {
    pub client: Client,
    /// The KDC image for realms that do not name one (`KRB5_KDC_IMAGE`,
    /// else [`crate::crd::DEFAULT_KDC_IMAGE`]).
    pub kdc_image: String,
}

/// Labels on every object of a realm.
pub fn labels(realm: &KerberosRealm) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("app.kubernetes.io/name".to_string(), "krb5-kdc".to_string()),
        ("app.kubernetes.io/instance".to_string(), realm.name_any()),
        ("app.kubernetes.io/managed-by".to_string(), MANAGER.to_string()),
    ])
}

fn owner(realm: &KerberosRealm) -> OwnerReference {
    realm.controller_owner_ref(&()).expect("a stored KerberosRealm has a uid")
}

fn meta(realm: &KerberosRealm) -> ObjectMeta {
    ObjectMeta {
        name: Some(realm.base_name()),
        namespace: realm.namespace(),
        labels: Some(labels(realm)),
        owner_references: Some(vec![owner(realm)]),
        ..Default::default()
    }
}

/// The Service's in-cluster name.
pub fn kdc_host(realm: &KerberosRealm) -> String {
    format!("{}.{}.svc", realm.base_name(), realm.namespace().unwrap_or_else(|| "default".into()))
}

/// A realm name must be a valid Kerberos realm (and fit a krb5.conf).
pub fn validate(realm: &KerberosRealm) -> Result<(), Error> {
    let r = &realm.spec.realm;
    if r.is_empty() || !r.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err(Error::Invalid(format!("realm {:?}: letters, digits, '.' and '-' only", r)));
    }
    Ok(())
}

/// `kdc.conf` (for the KDC) and `krb5.conf` (for clients in the cluster).
pub fn config_files(realm: &KerberosRealm) -> BTreeMap<String, String> {
    let r = &realm.spec.realm;
    let host = kdc_host(realm);
    let life = realm.spec.max_ticket_life.as_deref().unwrap_or("10h");
    let renew = realm.spec.max_renewable_life.as_deref().unwrap_or("7d");
    let kdc_conf = format!(
        "[kdcdefaults]\n    kdc_ports = {KDC_PORT}\n    kdc_tcp_ports = {KDC_PORT}\n\n\
         [realms]\n    {r} = {{\n        database_name = /var/lib/krb5kdc/principal\n        \
         key_stash_file = /var/lib/krb5kdc/.k5.{r}\n        acl_file = /etc/krb5kdc/kadm5.acl\n        \
         kadmind_port = {KADMIN_PORT}\n        max_life = {life}\n        max_renewable_life = {renew}\n        \
         supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal\n    }}\n\n\
         [logging]\n    kdc = STDERR\n    admin_server = STDERR\n"
    );
    let krb5_conf = format!(
        "[libdefaults]\n    default_realm = {r}\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n    \
         rdns = false\n    udp_preference_limit = 1\n\n\
         [realms]\n    {r} = {{\n        kdc = {host}:{KDC_PORT}\n        admin_server = {host}:{KADMIN_PORT}\n    }}\n"
    );
    BTreeMap::from([
        ("kdc.conf".to_string(), kdc_conf),
        ("krb5.conf".to_string(), krb5_conf),
        // kadmind: the operator may do everything, extract keys too (`e`
        // is not part of `x`).
        ("kadm5.acl".to_string(), format!("{ADMIN}@{r} xe\n")),
    ])
}

pub fn config_map(realm: &KerberosRealm) -> ConfigMap {
    ConfigMap { metadata: meta(realm), data: Some(config_files(realm)), ..Default::default() }
}

/// A new random master key or admin password (only used when the Secret
/// lacks it).
fn new_secret() -> String {
    rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(48).map(char::from).collect()
}

fn secret_env(var: &str, secret: &str, key: &str) -> EnvVar {
    EnvVar {
        name: var.into(),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector { name: secret.into(), key: key.into(), optional: Some(false) }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The password of the operator's admin principal in `realm`.
pub async fn admin_password(client: &Client, realm: &KerberosRealm) -> Result<Option<String>, Error> {
    let ns = realm.namespace().unwrap_or_else(|| "default".into());
    let secret = Api::<Secret>::namespaced(client.clone(), &ns).get_opt(&realm.base_name()).await?;
    Ok(secret
        .and_then(|s| s.data)
        .and_then(|d| d.get(ADMIN_PASSWORD).cloned())
        .and_then(|b| String::from_utf8(b.0).ok()))
}

pub fn stateful_set(realm: &KerberosRealm, default_image: &str) -> StatefulSet {
    let name = realm.base_name();
    let labels = labels(realm);
    let image = realm.spec.image.clone().unwrap_or_else(|| default_image.to_string());
    let port = |name: &str, port: i32, protocol: &str| ContainerPort {
        name: Some(name.into()),
        container_port: port,
        protocol: Some(protocol.into()),
        ..Default::default()
    };
    let config = |sub: &str, path: &str| VolumeMount {
        name: "config".into(),
        mount_path: path.into(),
        sub_path: Some(sub.into()),
        read_only: Some(true),
        ..Default::default()
    };
    let container = Container {
        name: "kdc".into(),
        image: Some(image),
        env: Some(vec![
            EnvVar { name: "KRB5_REALM".into(), value: Some(realm.spec.realm.clone()), ..Default::default() },
            secret_env("KRB5_MASTER_KEY", &name, MASTER_KEY),
            secret_env("KRB5_ADMIN_PASSWORD", &name, ADMIN_PASSWORD),
            EnvVar { name: "KRB5_ADMIN_PRINCIPAL".into(), value: Some(ADMIN.into()), ..Default::default() },
        ]),
        ports: Some(vec![
            port("kdc-tcp", KDC_PORT, "TCP"),
            port("kdc-udp", KDC_PORT, "UDP"),
            port("kadmin", KADMIN_PORT, "TCP"),
        ]),
        volume_mounts: Some(vec![
            VolumeMount { name: "data".into(), mount_path: "/var/lib/krb5kdc".into(), ..Default::default() },
            config("kdc.conf", "/etc/krb5kdc/kdc.conf"),
            config("kadm5.acl", "/etc/krb5kdc/kadm5.acl"),
            config("krb5.conf", "/etc/krb5.conf"),
        ]),
        readiness_probe: Some(Probe {
            tcp_socket: Some(TCPSocketAction { port: IntOrString::Int(KDC_PORT), ..Default::default() }),
            period_seconds: Some(5),
            ..Default::default()
        }),
        ..Default::default()
    };
    let storage = realm.spec.storage.clone().unwrap_or_else(|| "1Gi".into());
    StatefulSet {
        metadata: meta(realm),
        spec: Some(StatefulSetSpec {
            service_name: Some(name.clone()),
            replicas: Some(1),
            selector: LabelSelector { match_labels: Some(labels.clone()), ..Default::default() },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta { labels: Some(labels.clone()), ..Default::default() }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: Some(vec![Volume {
                        name: "config".into(),
                        config_map: Some(ConfigMapVolumeSource { name: name.clone(), ..Default::default() }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
            },
            volume_claim_templates: Some(vec![PersistentVolumeClaim {
                metadata: ObjectMeta { name: Some("data".into()), labels: Some(labels.clone()), ..Default::default() },
                spec: Some(PersistentVolumeClaimSpec {
                    access_modes: Some(vec!["ReadWriteOnce".into()]),
                    storage_class_name: realm.spec.storage_class_name.clone(),
                    resources: Some(VolumeResourceRequirements {
                        requests: Some(BTreeMap::from([("storage".to_string(), Quantity(storage))])),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub fn service(realm: &KerberosRealm) -> Service {
    let port = |name: &str, port: i32, protocol: &str| ServicePort {
        name: Some(name.into()),
        port,
        target_port: Some(IntOrString::Int(port)),
        protocol: Some(protocol.into()),
        ..Default::default()
    };
    Service {
        metadata: meta(realm),
        spec: Some(ServiceSpec {
            selector: Some(labels(realm)),
            ports: Some(vec![
                port("kdc-tcp", KDC_PORT, "TCP"),
                port("kdc-udp", KDC_PORT, "UDP"),
                port("kadmin", KADMIN_PORT, "TCP"),
            ]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Probe the KDC: an AS-REQ for a principal that does not exist must come
/// back `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6) from a KDC of this realm.
pub async fn probe(realm_name: &str, kdc: &str) -> Result<(), String> {
    let (realm_name, kdc) = (realm_name.to_string(), kdc.to_string());
    tokio::task::spawn_blocking(move || {
        let client = krb5::KdcClient::new(realm_name.clone(), [kdc]).with_timeout(Duration::from_secs(3));
        let probe =
            krb5::Principal::parse(&format!("krb5-operator-probe@{}", realm_name)).map_err(|e| e.to_string())?;
        match client.login_with_password(&probe, "not a password") {
            Err(e) if e.kdc_code() == Some(6) => Ok(()),
            Err(e) => Err(format!("KDC did not answer as expected: {}", e)),
            Ok(_) => Err("the probe principal exists".into()),
        }
    })
    .await
    .map_err(|e| e.to_string())?
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

pub async fn reconcile(realm: Arc<KerberosRealm>, ctx: Arc<Context>) -> Result<Action, Error> {
    validate(&realm)?;
    let ns = realm.namespace().unwrap_or_else(|| "default".into());
    let name = realm.base_name();
    let pp = PatchParams::apply(MANAGER).force();

    // The master key and admin password: created once, never replaced.
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);
    match secrets.get_opt(&name).await? {
        None => {
            let secret = Secret {
                metadata: meta(&realm),
                data: Some(BTreeMap::from([
                    (MASTER_KEY.to_string(), ByteString(new_secret().into_bytes())),
                    (ADMIN_PASSWORD.to_string(), ByteString(new_secret().into_bytes())),
                ])),
                ..Default::default()
            };
            secrets.create(&Default::default(), &secret).await?;
            info!("Created the master key for realm {}", realm.spec.realm);
        }
        Some(s) if !s.data.as_ref().is_some_and(|d| d.contains_key(ADMIN_PASSWORD)) => {
            let add = json!({ "data": { ADMIN_PASSWORD: ByteString(new_secret().into_bytes()) } });
            secrets.patch(&name, &PatchParams::default(), &Patch::Merge(&add)).await?;
        }
        Some(_) => {}
    }
    Api::<ConfigMap>::namespaced(ctx.client.clone(), &ns).patch(&name, &pp, &Patch::Apply(&config_map(&realm))).await?;
    Api::<Service>::namespaced(ctx.client.clone(), &ns).patch(&name, &pp, &Patch::Apply(&service(&realm))).await?;
    Api::<StatefulSet>::namespaced(ctx.client.clone(), &ns)
        .patch(&name, &pp, &Patch::Apply(&stateful_set(&realm, &ctx.kdc_image)))
        .await?;

    let kdc = format!("{}:{}", kdc_host(&realm), KDC_PORT);
    let ready = probe(&realm.spec.realm, &kdc).await;
    let cond = match &ready {
        Ok(()) => condition(true, "KdcAnswers", "the KDC answered an AS exchange"),
        Err(e) => condition(false, "KdcNotAnswering", e),
    };
    if let Err(e) = &ready {
        warn!("Realm {}: {}", realm.spec.realm, e);
    }
    let status = KerberosRealmStatus {
        kdc: Some(kdc),
        admin_server: Some(format!("{}:{}", kdc_host(&realm), KADMIN_PORT)),
        krb5_conf_config_map: Some(name.clone()),
        conditions: vec![cond],
        observed_generation: realm.metadata.generation,
    };
    let realms: Api<KerberosRealm> = Api::namespaced(ctx.client.clone(), &ns);
    realms.patch_status(&realm.name_any(), &PatchParams::default(), &Patch::Merge(json!({ "status": status }))).await?;
    Ok(Action::requeue(if ready.is_ok() { Duration::from_secs(300) } else { Duration::from_secs(10) }))
}

pub fn error_policy(realm: Arc<KerberosRealm>, e: &Error, _: Arc<Context>) -> Action {
    warn!("Reconciling {}: {}", realm.name_any(), e);
    Action::requeue(Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{DEFAULT_KDC_IMAGE, KerberosRealmSpec};

    fn realm() -> KerberosRealm {
        let mut r =
            KerberosRealm::new("corp", KerberosRealmSpec { realm: "CORP.EXAMPLE.COM".into(), ..Default::default() });
        r.metadata.namespace = Some("auth".into());
        r.metadata.uid = Some("u-1".into());
        r
    }

    #[test]
    fn clients_get_a_krb5_conf_for_the_service() {
        let files = config_files(&realm());
        let krb5 = &files["krb5.conf"];
        assert!(krb5.contains("default_realm = CORP.EXAMPLE.COM"));
        assert!(krb5.contains("kdc = corp-kdc.auth.svc:88"));
        assert!(krb5.contains("admin_server = corp-kdc.auth.svc:749"));
        // The crate reads it as a realm with that KDC.
        let conf = krb5::Krb5Conf::parse(krb5).unwrap();
        assert_eq!(conf.default_realm(), Some("CORP.EXAMPLE.COM"));
        let kdc = &files["kdc.conf"];
        assert!(kdc.contains("CORP.EXAMPLE.COM = {") && kdc.contains("max_life = 10h"));
    }

    #[test]
    fn the_kdc_runs_with_its_master_key_and_a_volume() {
        let r = realm();
        let sts = stateful_set(&r, DEFAULT_KDC_IMAGE);
        let spec = sts.spec.as_ref().unwrap();
        assert_eq!(spec.replicas, Some(1));
        let c = &spec.template.spec.as_ref().unwrap().containers[0];
        assert_eq!(c.image.as_deref(), Some(DEFAULT_KDC_IMAGE));
        let env = c.env.as_ref().unwrap();
        let key = env.iter().find(|e| e.name == "KRB5_MASTER_KEY").unwrap();
        assert_eq!(key.value_from.as_ref().unwrap().secret_key_ref.as_ref().unwrap().name, "corp-kdc");
        assert!(env.iter().any(|e| e.name == "KRB5_ADMIN_PASSWORD"));
        // kadmind lets the operator's principal extract keys.
        assert_eq!(config_files(&r)["kadm5.acl"], "krb5-operator/admin@CORP.EXAMPLE.COM xe\n");
        assert_eq!(spec.volume_claim_templates.as_ref().unwrap()[0].metadata.name.as_deref(), Some("data"));
        // Owned by the realm, so deleting it deletes them.
        assert_eq!(sts.metadata.owner_references.as_ref().unwrap()[0].uid, "u-1");
        let svc = service(&r);
        let ports: Vec<(i32, String)> =
            svc.spec.unwrap().ports.unwrap().into_iter().map(|p| (p.port, p.protocol.unwrap())).collect();
        assert_eq!(ports, vec![(88, "TCP".into()), (88, "UDP".into()), (749, "TCP".into())]);
    }

    #[test]
    fn realm_names_are_validated() {
        let mut r = realm();
        assert!(validate(&r).is_ok());
        r.spec.realm = "BAD REALM]".into();
        assert!(validate(&r).is_err());
        assert_eq!(new_secret().len(), 48);
        assert_ne!(new_secret(), new_secret());
    }
}
