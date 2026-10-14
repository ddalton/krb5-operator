//! Custom resources.
//!
//! A `KerberosRealm` is an MIT Kerberos KDC (krb5kdc + kadmind) the
//! operator runs: a StatefulSet with the database on a volume, its master
//! key in a Secret, and a Service clients reach it through.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The KDC image: MIT krb5kdc and kadmind (`images/kdc`).
pub const DEFAULT_KDC_IMAGE: &str = "ghcr.io/ddalton/krb5-kdc:0.1.0";

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
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Secret","type":"string","jsonPath":".status.secretName"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct KerberosPrincipalSpec {
    /// The `KerberosRealm` (same namespace) the principals belong to.
    pub realm_ref: String,
    /// Principal names (`nn/host.example.com`): the realm is appended, or,
    /// if given (`...@REALM`), must be the realm's.
    pub principals: Vec<String>,
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
}

impl KerberosPrincipal {
    pub fn secret_name(&self) -> String {
        self.spec.secret_name.clone().unwrap_or_else(|| self.metadata.name.clone().unwrap_or_default())
    }

    pub fn keytab_key(&self) -> String {
        self.spec.keytab_key.clone().unwrap_or_else(|| "krb5.keytab".into())
    }
}
