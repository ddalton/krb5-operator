//! Custom resources.
//!
//! A `KerberosRealm` is an MIT Kerberos KDC (krb5kdc + kadmind) the
//! operator runs: a StatefulSet with the database on a volume, its master
//! key in a Secret, and a Service clients reach it through.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The KDC image: MIT krb5kdc and kadmind (`images/kdc`).
pub const DEFAULT_KDC_IMAGE: &str = "ghcr.io/ddalton/krb5-kdc:0.2.0";

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "krb5.ddalton.dev",
    version = "v1alpha1",
    kind = "KerberosRealm",
    namespaced,
    status = "KerberosRealmStatus",
    shortname = "krealm",
    printcolumn = r#"{"name":"Realm","type":"string","jsonPath":".spec.realm"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"KDC","type":"string","jsonPath":".status.kdc"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct KerberosRealmSpec {
    /// The realm name, by convention upper case (`EXAMPLE.COM`).
    pub realm: String,
    /// The KDC image (default: the operator's MIT krb5 image).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Size of the volume holding the KDC database (default `1Gi`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    /// Storage class for that volume (default: the cluster's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class_name: Option<String>,
    /// Maximum ticket lifetime (krb5 duration, default `10h`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ticket_life: Option<String>,
    /// Maximum renewable lifetime (default `7d`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_renewable_life: Option<String>,
    /// Which namespaces' `KerberosPrincipal`s may use this realm (default:
    /// only its own).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_namespaces: Option<AllowedNamespaces>,
}

/// Namespaces whose `KerberosPrincipal`s a realm serves, as Gateway API's
/// `allowedRoutes.namespaces`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AllowedNamespaces {
    #[serde(default)]
    pub from: NamespacesFrom,
    /// With `from: Selector`: the namespaces whose labels match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum NamespacesFrom {
    /// The realm's own namespace (the default).
    #[default]
    Same,
    /// Every namespace.
    All,
    /// Namespaces matching `selector`.
    Selector,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KerberosRealmStatus {
    /// `host:port` of the KDC inside the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdc: Option<String>,
    /// `host:port` of kadmind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_server: Option<String>,
    /// The ConfigMap with a client `krb5.conf` for this realm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub krb5_conf_config_map: Option<String>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// A status condition (the Kubernetes convention).
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    /// `True`, `False` or `Unknown`.
    pub status: String,
    pub reason: String,
    pub message: String,
    pub last_transition_time: String,
}

impl KerberosRealm {
    /// The name every object of this realm is based on.
    pub fn base_name(&self) -> String {
        format!("{}-kdc", self.metadata.name.as_deref().unwrap_or("realm"))
    }
}

/// What happens to the principals when their `KerberosPrincipal` is
/// deleted.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum DeletionPolicy {
    /// Delete them from the KDC (the default).
    #[default]
    Delete,
    /// Leave them in the KDC (keytabs elsewhere keep working).
    Retain,
}

/// Principals with random keys, created through kadmind, and a Secret
/// holding their keytab.
#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "krb5.ddalton.dev",
    version = "v1alpha1",
    kind = "KerberosPrincipal",
    namespaced,
    status = "KerberosPrincipalStatus",
    shortname = "kprinc",
    printcolumn = r#"{"name":"Realm","type":"string","jsonPath":".spec.realmRef"}"#,
    printcolumn = r#"{"name":"Realm Namespace","type":"string","jsonPath":".spec.realmNamespace","priority":1}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Secret","type":"string","jsonPath":".status.secretName"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct KerberosPrincipalSpec {
    /// The `KerberosRealm` the principals belong to.
    pub realm_ref: String,
    /// Its namespace (default: this object's). The realm must allow this
    /// object's namespace (`allowedNamespaces`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_namespace: Option<String>,
    /// Principal names (`nn/host.example.com`): the realm is appended, or,
    /// if given (`...@REALM`), must be the realm's.
    #[serde(default)]
    pub principals: Vec<String>,
    /// Host principals for every pod of a StatefulSet, following its
    /// replicas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_principals: Option<HostPrincipals>,
    /// The Secret to write the keytab to (default: this object's name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    /// The key in that Secret (default `krb5.keytab`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keytab_key: Option<String>,
    /// `Delete` (default) or `Retain` the principals when this is deleted.
    #[serde(default)]
    pub deletion_policy: DeletionPolicy,
}

/// `<service>/<pod FQDN>` for each service and each pod of a StatefulSet
/// (`dn/pillar-dn-0.pillar-dn.hdfs.svc.cluster.local`), as Hadoop's
/// `dn/_HOST` names them. The keytab Secret holds every pod's keys
/// (`krb5.keytab`) and each pod's own (`<pod>.keytab`, for a
/// `subPathExpr: $(POD_NAME).keytab` mount).
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HostPrincipals {
    /// The StatefulSet (this object's namespace); its `serviceName` gives
    /// the pods their DNS names.
    pub stateful_set: String,
    /// Service names (`dn`, `HTTP`).
    pub services: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KerberosPrincipalStatus {
    /// The Secret holding the keytab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    /// Each principal (with its realm) and its key version.
    #[serde(default)]
    pub principals: Vec<PrincipalStatus>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalStatus {
    pub name: String,
    pub kvno: u32,
    /// The pod a host principal is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
}

impl KerberosPrincipal {
    pub fn secret_name(&self) -> String {
        self.spec.secret_name.clone().unwrap_or_else(|| self.metadata.name.clone().unwrap_or_default())
    }

    /// The namespace of the realm it refers to.
    pub fn realm_namespace(&self) -> String {
        self.spec
            .realm_namespace
            .clone()
            .or_else(|| self.metadata.namespace.clone())
            .unwrap_or_else(|| "default".into())
    }

    /// What it is called as the owner of its principals in the KDC.
    pub fn owner(&self) -> String {
        format!(
            "{}/{}",
            self.metadata.namespace.as_deref().unwrap_or("default"),
            self.metadata.name.as_deref().unwrap_or("")
        )
    }

    pub fn keytab_key(&self) -> String {
        self.spec.keytab_key.clone().unwrap_or_else(|| "krb5.keytab".into())
    }
}
