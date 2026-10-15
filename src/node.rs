//! The `KerberosNodeKeytab` controller: host principals for nodes, and a
//! DaemonSet that installs each node's keys into its keytab.
//!
//! For each node it selects (labels, and taints the DaemonSet tolerates)
//! the operator creates `<service>/<node hostname>` (`host/`, `nfs/` by
//! default) as it creates any principal: random keys, marked with their
//! owner (`KerberosNodeKeytab/<name>`), extracted, never changed. A Secret
//! in the operator's namespace holds `<node>.keytab` for each node, and the
//! realm's `krb5.conf` for hosts: the KDC by its Service's cluster IP, since
//! a node's resolver does not know cluster DNS.
//!
//! The DaemonSet (same namespace, same name as the Secret) runs
//! `krb5-operator node-agent` on those nodes. It merges the node's keys
//! into the host keytab ([`crate::agent`]): entries of other realms stay,
//! entries of this realm are replaced. That is what the kernel's NFS client
//! needs for `sec=krb5*`: rpc.gssd takes the node's machine credential
//! from `/etc/krb5.keytab`.
//!
//! Every DaemonSet pod mounts the whole Secret, so a node can read the
//! other selected nodes' keys; select only the nodes that need them.
//!
//! Nodes that go, or stop being selected, have their principals deleted
//! (`Retain` keeps them); so does the object's deletion, with the Secret
//! and DaemonSet (owned by it). Keys already installed on a node stay
//! there, useless once the principal is gone.
//!
//! Ready: every key gets a ticket, and the DaemonSet's pods on every node
//! have installed them.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::{DaemonSet, DaemonSetSpec};
use k8s_openapi::api::core::v1::{
    Capabilities, Container, EmptyDirVolumeSource, EnvVar, EnvVarSource, ExecAction, HostPathVolumeSource, Node,
    ObjectFieldSelector, PodSpec, PodTemplateSpec, Probe, ResourceRequirements, SELinuxOptions, SeccompProfile, Secret,
    SecretVolumeSource, SecurityContext, Service, Taint, Toleration, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use krb5::Principal;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event, finalizer};
use kube::{Client, Resource, ResourceExt};
use serde_json::json;
use tracing::{info, warn};

use crate::crd::{
    Condition, DeletionPolicy, KerberosNodeKeytab, KerberosNodeKeytabStatus, KerberosRealm, PrincipalStatus,
};
use crate::principal::{
    Error, KEYS_SHA256, KRB5_CONF_KEY, MANAGER, PrincipalKeys, admin_of, blocking, condition, fingerprint, keytab,
    no_longer_wanted, principals,
};
use crate::realm;

const FINALIZER: &str = "krb5.ddalton.dev/node-principals";
/// The label naming the `KerberosNodeKeytab` a DaemonSet or Secret is for.
pub const OWNER_LABEL: &str = "krb5.ddalton.dev/node-keytab";
/// Where the agent's pod has the Secret, the host directories and its
/// readiness mark.
pub const KEYTABS_DIR: &str = "/var/run/krb5-operator/keytabs";
const HOST_KEYTAB_DIR: &str = "/host/keytab";
const HOST_CONF_DIR: &str = "/host/krb5-conf";
pub const STATE_DIR: &str = "/var/run/krb5-operator/state";

pub struct Context {
    pub client: Client,
    /// Where the operator runs: the Secret and DaemonSet go there.
    pub namespace: String,
    /// The operator's image, which the DaemonSet runs (`node-agent`).
    pub agent_image: String,
}

/// The name a node calls itself: its `Hostname` address (else its name),
/// lower case, with `domain` appended when it has no dot.
pub fn node_host(node: &Node, domain: Option<&str>) -> String {
    let addr = node
        .status
        .as_ref()
        .and_then(|s| s.addresses.as_ref())
        .and_then(|a| a.iter().find(|a| a.type_ == "Hostname"))
        .map(|a| a.address.clone())
        .filter(|a| !a.is_empty());
    let host = addr.unwrap_or_else(|| node.name_any()).to_lowercase();
    match domain.map(|d| d.trim_matches('.')).filter(|d| !d.is_empty()) {
        Some(d) if !host.contains('.') => format!("{host}.{}", d.to_lowercase()),
        _ => host,
    }
}

/// Whether `tolerations` tolerate `taint` (Kubernetes' rule).
fn tolerates(tolerations: &[Toleration], taint: &Taint) -> bool {
    tolerations.iter().any(|t| {
        let effect = t.effect.as_deref().is_none_or(|e| e.is_empty() || e == taint.effect);
        let key = match t.key.as_deref() {
            None | Some("") => t.operator.as_deref() == Some("Exists"),
            Some(k) => k == taint.key,
        };
        let value = match t.operator.as_deref() {
            Some("Exists") => true,
            _ => t.value.as_deref().unwrap_or("") == taint.value.as_deref().unwrap_or(""),
        };
        effect && key && value
    })
}

/// Whether the DaemonSet runs on `node`, so it gets keys: its labels match,
/// and its NoSchedule and NoExecute taints are tolerated (DaemonSets
/// tolerate a node being unschedulable, not-ready or unreachable).
pub fn selected(nk: &KerberosNodeKeytab, node: &Node) -> bool {
    let labels = node.labels();
    if !nk.spec.node_selector.iter().flatten().all(|(k, v)| labels.get(k) == Some(v)) {
        return false;
    }
    let tolerations = nk.spec.tolerations.as_deref().unwrap_or_default();
    node.spec.as_ref().and_then(|s| s.taints.as_ref()).into_iter().flatten().all(|t| {
        t.effect == "PreferNoSchedule" || t.key.starts_with("node.kubernetes.io/") || tolerates(tolerations, t)
    })
}

/// A path on a node the agent may write: absolute, a file in a directory
/// that is not `/`, no `.` or `..`.
fn host_path(field: &str, p: &str) -> Result<(String, String), Error> {
    let bad = || Error::Invalid(format!("{field} {p:?}: an absolute path to a file, not in /"));
    if !p.starts_with('/') || p.ends_with('/') || p.split('/').any(|c| c == "." || c == "..") {
        return Err(bad());
    }
    let (dir, file) = p.rsplit_once('/').ok_or_else(bad)?;
    if dir.is_empty() || file.is_empty() || p.contains("//") {
        return Err(bad());
    }
    Ok((dir.to_string(), file.to_string()))
}

/// What is wrong with the spec, if anything.
pub fn validate(nk: &KerberosNodeKeytab) -> Result<(), Error> {
    // Pods are named after the DaemonSet, plus a suffix.
    if nk.object_name().len() > 57 {
        return Err(Error::Invalid("the name is too long (at most 45 characters)".into()));
    }
    host_path("keytabPath", &nk.keytab_path())?;
    if let Some(p) = &nk.spec.krb5_conf_path {
        host_path("krb5ConfPath", p)?;
        if *p == nk.keytab_path() {
            return Err(Error::Invalid("krb5ConfPath is keytabPath".into()));
        }
    }
    if nk.spec.services.is_empty() {
        return Err(Error::Invalid("services is empty".into()));
    }
    if let Some(s) = nk.spec.services.iter().find(|s| s.is_empty() || s.contains(['/', '@'])) {
        return Err(Error::Invalid(format!("service {s:?}: a name, no '/' or '@'")));
    }
    Ok(())
}

/// The principals for `nodes` (those selected), with the node each is for.
pub fn wanted(nk: &KerberosNodeKeytab, nodes: &[Node], realm: &str) -> Result<Vec<(Principal, String)>, Error> {
    let mut out = Vec::new();
    for node in nodes.iter().filter(|n| selected(nk, n)) {
        let host = node_host(node, nk.spec.domain.as_deref());
        for svc in &nk.spec.services {
            let p = principals(&[format!("{svc}/{host}")], realm)?.remove(0);
            // Two nodes calling themselves the same: one keeps it.
            if !out.iter().any(|(o, _)| *o == p) {
                out.push((p, node.name_any()));
            }
        }
    }
    Ok(out)
}

/// `krb5.conf` for nodes: the KDC and kadmind by the realm Service's
/// cluster IP, and `domain` mapped to the realm.
pub fn host_krb5_conf(realm: &str, cluster_ip: &str, domain: Option<&str>) -> String {
    let ip = if cluster_ip.contains(':') { format!("[{cluster_ip}]") } else { cluster_ip.to_string() };
    let mut s = format!(
        "# Written by krb5-operator for realm {realm}.\n\
         [libdefaults]\n    default_realm = {realm}\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n\n\
         [realms]\n    {realm} = {{\n        kdc = {ip}:{}\n        admin_server = {ip}:{}\n    }}\n",
        realm::KDC_PORT,
        realm::KADMIN_PORT
    );
    if let Some(d) = domain.map(|d| d.trim_matches('.').to_lowercase()).filter(|d| !d.is_empty()) {
        s.push_str(&format!("\n[domain_realm]\n    .{d} = {realm}\n    {d} = {realm}\n"));
    }
    s
}

/// The Secret's files: `<node>.keytab` with each node's keys, and the
/// hosts' `krb5.conf`.
pub fn secret_files(wanted: &[(Principal, String)], keys: &[PrincipalKeys], conf: &str) -> BTreeMap<String, Vec<u8>> {
    let mut nodes: BTreeMap<&str, Vec<PrincipalKeys>> = BTreeMap::new();
    for ((_, node), k) in wanted.iter().zip(keys) {
        nodes.entry(node).or_default().push(k.clone());
    }
    let mut files: BTreeMap<String, Vec<u8>> =
        nodes.into_iter().map(|(n, ks)| (format!("{n}.keytab"), keytab(&ks).to_bytes())).collect();
    files.insert(KRB5_CONF_KEY.into(), conf.as_bytes().to_vec());
    files
}

fn labels(nk: &KerberosNodeKeytab) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("app.kubernetes.io/name".to_string(), "krb5-node-keytab".to_string()),
        ("app.kubernetes.io/managed-by".to_string(), MANAGER.to_string()),
        (OWNER_LABEL.to_string(), nk.name_any()),
    ])
}

fn meta(nk: &KerberosNodeKeytab, ns: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(nk.object_name()),
        namespace: Some(ns.to_string()),
        labels: Some(labels(nk)),
        owner_references: Some(vec![nk.controller_owner_ref(&()).expect("a stored KerberosNodeKeytab has a uid")]),
        ..Default::default()
    }
}

pub fn secret(nk: &KerberosNodeKeytab, ns: &str, files: BTreeMap<String, Vec<u8>>, fp: &str) -> Secret {
    let mut metadata = meta(nk, ns);
    metadata.annotations = Some(BTreeMap::from([(KEYS_SHA256.to_string(), fp.to_string())]));
    Secret {
        metadata,
        type_: Some("Opaque".into()),
        data: Some(files.into_iter().map(|(k, v)| (k, ByteString(v))).collect()),
        ..Default::default()
    }
}

fn host_dir_volume(name: &str, dir: &str) -> Volume {
    Volume {
        name: name.into(),
        host_path: Some(HostPathVolumeSource { path: dir.into(), type_: Some("DirectoryOrCreate".into()) }),
        ..Default::default()
    }
}

fn mount(name: &str, path: &str, read_only: bool) -> VolumeMount {
    VolumeMount { name: name.into(), mount_path: path.into(), read_only: Some(read_only), ..Default::default() }
}

/// The DaemonSet that installs the keys on each selected node.
pub fn daemon_set(nk: &KerberosNodeKeytab, ns: &str, image: &str) -> Result<DaemonSet, Error> {
    let (kt_dir, kt_file) = host_path("keytabPath", &nk.keytab_path())?;
    let mut args = vec![
        "node-agent".to_string(),
        format!("--keytabs={KEYTABS_DIR}"),
        format!("--keytab={HOST_KEYTAB_DIR}/{kt_file}"),
    ];
    let mut volumes = vec![
        Volume {
            name: "keytabs".into(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(nk.object_name()),
                default_mode: Some(0o400),
                ..Default::default()
            }),
            ..Default::default()
        },
        host_dir_volume("host-keytab", &kt_dir),
        Volume { name: "state".into(), empty_dir: Some(EmptyDirVolumeSource::default()), ..Default::default() },
    ];
    let mut mounts = vec![
        mount("keytabs", KEYTABS_DIR, true),
        mount("host-keytab", HOST_KEYTAB_DIR, false),
        mount("state", STATE_DIR, false),
    ];
    if let Some(p) = &nk.spec.krb5_conf_path {
        let (dir, file) = host_path("krb5ConfPath", p)?;
        args.push(format!("--krb5-conf={HOST_CONF_DIR}/{file}"));
        volumes.push(host_dir_volume("host-krb5-conf", &dir));
        mounts.push(mount("host-krb5-conf", HOST_CONF_DIR, false));
    }
    let selector = labels(nk);
    let container = Container {
        name: "agent".into(),
        image: Some(image.into()),
        args: Some(args),
        env: Some(vec![EnvVar {
            name: "NODE_NAME".into(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector { field_path: "spec.nodeName".into(), ..Default::default() }),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        volume_mounts: Some(mounts),
        readiness_probe: Some(Probe {
            exec: Some(ExecAction {
                command: Some(vec!["/usr/local/bin/krb5-operator".into(), "node-agent-ready".into()]),
            }),
            period_seconds: Some(5),
            ..Default::default()
        }),
        resources: Some(ResourceRequirements {
            requests: Some(BTreeMap::from([
                ("cpu".to_string(), Quantity("1m".into())),
                ("memory".to_string(), Quantity("8Mi".into())),
            ])),
            limits: Some(BTreeMap::from([("memory".to_string(), Quantity("32Mi".into()))])),
            ..Default::default()
        }),
        // Root, to write root's files in the host directories; no
        // capabilities beyond (the files are root's own). spc_t: on
        // SELinux hosts a container may not otherwise write /etc.
        security_context: Some(SecurityContext {
            run_as_user: Some(0),
            run_as_non_root: Some(false),
            read_only_root_filesystem: Some(true),
            allow_privilege_escalation: Some(false),
            capabilities: Some(Capabilities { drop: Some(vec!["ALL".into()]), ..Default::default() }),
            se_linux_options: Some(SELinuxOptions { type_: Some("spc_t".into()), ..Default::default() }),
            seccomp_profile: Some(SeccompProfile { type_: "RuntimeDefault".into(), ..Default::default() }),
            ..Default::default()
        }),
        ..Default::default()
    };
    Ok(DaemonSet {
        metadata: meta(nk, ns),
        spec: Some(DaemonSetSpec {
            selector: LabelSelector { match_labels: Some(selector.clone()), ..Default::default() },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta { labels: Some(selector), ..Default::default() }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: Some(volumes),
                    node_selector: nk.spec.node_selector.clone(),
                    tolerations: nk.spec.tolerations.clone(),
                    termination_grace_period_seconds: Some(5),
                    automount_service_account_token: Some(false),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// How far the DaemonSet is: `(installed, nodes)`, or `None` before its
/// controller has looked at the current spec.
pub fn rollout(ds: &DaemonSet) -> Option<(i32, i32)> {
    let st = ds.status.as_ref()?;
    if st.observed_generation < ds.metadata.generation {
        return None;
    }
    let desired = st.desired_number_scheduled;
    let updated = st.updated_number_scheduled.unwrap_or(0);
    Some((st.number_ready.min(updated), desired))
}

async fn set_status(client: &Client, nk: &KerberosNodeKeytab, status: KerberosNodeKeytabStatus) -> Result<(), Error> {
    Api::<KerberosNodeKeytab>::all(client.clone())
        .patch_status(&nk.name_any(), &PatchParams::default(), &Patch::Merge(json!({ "status": status })))
        .await?;
    Ok(())
}

async fn realm_of(client: &Client, nk: &KerberosNodeKeytab) -> Result<KerberosRealm, Error> {
    Api::<KerberosRealm>::namespaced(client.clone(), &nk.spec.realm_namespace)
        .get_opt(&nk.spec.realm_ref)
        .await?
        .ok_or_else(|| {
            Error::RealmNotReady(
                format!("{}/{}", nk.spec.realm_namespace, nk.spec.realm_ref),
                "no such KerberosRealm".into(),
            )
        })
}

async fn apply(nk: Arc<KerberosNodeKeytab>, ctx: &Context) -> Result<Action, Error> {
    match sync(&nk, ctx).await {
        Err(e) if e.reason().is_some() => {
            let reason = e.reason().unwrap_or_default();
            if reason != "RealmNotReady" {
                warn!("{}: {}", nk.name_any(), e);
            }
            let mut status = nk.status.clone().unwrap_or_default();
            status.conditions = vec![condition(false, reason, &e.to_string())];
            status.observed_generation = nk.metadata.generation;
            set_status(&ctx.client, &nk, status).await?;
            Ok(Action::requeue(Duration::from_secs(if reason == "RealmNotReady" { 10 } else { 60 })))
        }
        r => r,
    }
}

async fn sync(nk: &KerberosNodeKeytab, ctx: &Context) -> Result<Action, Error> {
    let client = &ctx.client;
    validate(nk)?;
    let realm = realm_of(client, nk).await?;
    let admin = admin_of(client, &realm).await?;
    let nodes = Api::<Node>::all(client.clone()).list(&ListParams::default()).await?.items;
    let wanted = wanted(nk, &nodes, &admin.realm)?;
    let ps: Vec<Principal> = wanted.iter().map(|(p, _)| p.clone()).collect();
    let keys = {
        let (admin, ps, owner) = (admin.clone(), ps.clone(), nk.owner());
        blocking(move || admin.ensure(&ps, &owner)).await??
    };
    let fp = fingerprint(&keys);

    let svc = Api::<Service>::namespaced(client.clone(), &nk.spec.realm_namespace)
        .get_opt(&realm.base_name())
        .await?
        .and_then(|s| s.spec?.cluster_ip)
        .filter(|ip| !ip.is_empty() && ip != "None")
        .ok_or_else(|| Error::RealmNotReady(realm.name_any(), "its Service has no cluster IP".into()))?;
    let conf = host_krb5_conf(&admin.realm, &svc, nk.spec.domain.as_deref());

    let ns = &ctx.namespace;
    let name = nk.object_name();
    let secrets: Api<Secret> = Api::namespaced(client.clone(), ns);
    let current = secrets.get_opt(&name).await?;
    let unchanged = current.as_ref().is_some_and(|s| {
        s.annotations().get(KEYS_SHA256) == Some(&fp)
            && s.data.as_ref().is_some_and(|d| d.get(KRB5_CONF_KEY).is_some_and(|b| b.0 == conf.as_bytes()))
    });
    if !unchanged {
        let s = secret(nk, ns, secret_files(&wanted, &keys, &conf), &fp);
        secrets.patch(&name, &PatchParams::apply(MANAGER).force(), &Patch::Apply(&s)).await?;
        info!("Wrote the keys of {} for {} principals to Secret {ns}/{name}", nk.name_any(), keys.len());
    }
    let ds = Api::<DaemonSet>::namespaced(client.clone(), ns)
        .patch(&name, &PatchParams::apply(MANAGER).force(), &Patch::Apply(&daemon_set(nk, ns, &ctx.agent_image)?))
        .await?;

    // Nodes gone or no longer selected: their principals go.
    let had = nk.status.as_ref().map(|s| s.principals.as_slice()).unwrap_or_default();
    let gone = no_longer_wanted(had, &ps.iter().collect::<Vec<_>>());
    if !gone.is_empty() && nk.spec.deletion_policy == DeletionPolicy::Delete {
        let (admin, owner) = (admin.clone(), nk.owner());
        if let Err(e) = blocking(move || admin.delete(&gone, &owner)).await? {
            warn!("{}: deleting principals it no longer wants: {e}", nk.name_any());
        }
    }

    // A ticket with each key, when they changed or were not verified.
    let verified = nk.status.as_ref().is_some_and(|s| {
        s.observed_generation == nk.metadata.generation
            && s.conditions
                .iter()
                .any(|c| c.type_ == "Ready" && matches!(c.reason.as_str(), "Installed" | "Installing"))
    });
    let rejected = if unchanged && verified {
        None
    } else {
        let (admin, ps, kt) = (admin.clone(), ps.clone(), keytab(&keys));
        blocking(move || admin.verify(&ps, &kt)).await?.err()
    };
    let node_count = {
        let mut n: Vec<&str> = wanted.iter().map(|(_, n)| n.as_str()).collect();
        n.dedup();
        n.len() as u32
    };
    let cond: Condition = match (rejected, rollout(&ds)) {
        (Some(e), _) => {
            warn!("{}: {}", nk.name_any(), e);
            condition(false, "KeytabRejected", &e)
        }
        (None, Some((done, all))) if done >= all => {
            condition(true, "Installed", &format!("the keys are installed on {all} nodes"))
        }
        (None, Some((done, all))) => condition(false, "Installing", &format!("installed on {done} of {all} nodes")),
        (None, None) => condition(false, "Installing", "the DaemonSet is starting"),
    };
    // Keep the transition time while the condition holds.
    let cond = match nk.status.as_ref().and_then(|s| s.conditions.iter().find(|c| c.type_ == "Ready")) {
        Some(old) if old.status == cond.status && old.reason == cond.reason && old.message == cond.message => {
            old.clone()
        }
        _ => cond,
    };
    let ready = cond.status == "True";
    let status = KerberosNodeKeytabStatus {
        nodes: node_count,
        principals: wanted
            .iter()
            .zip(&keys)
            .map(|((p, node), (_, ks))| PrincipalStatus {
                name: format!("{}@{}", p.name(), p.realm),
                kvno: ks.iter().map(|(v, _)| *v).max().unwrap_or(0),
                pod: None,
                node: Some(node.clone()),
            })
            .collect(),
        conditions: vec![cond],
        observed_generation: nk.metadata.generation,
    };
    if nk.status.as_ref() != Some(&status) {
        set_status(client, nk, status).await?;
    }
    Ok(Action::requeue(Duration::from_secs(if ready { 300 } else { 10 })))
}

async fn cleanup(nk: Arc<KerberosNodeKeytab>, client: &Client) -> Result<Action, Error> {
    if nk.spec.deletion_policy == DeletionPolicy::Retain {
        return Ok(Action::await_change());
    }
    let realm = match realm_of(client, &nk).await {
        Ok(r) => r,
        // The realm is gone (and its KDC with it): nothing to delete.
        Err(Error::RealmNotReady(..)) => return Ok(Action::await_change()),
        Err(e) => return Err(e),
    };
    let admin = admin_of(client, &realm).await?;
    let had = nk.status.as_ref().map(|s| s.principals.as_slice()).unwrap_or_default();
    let ps = no_longer_wanted(had, &[]);
    let owner = nk.owner();
    blocking(move || admin.delete(&ps, &owner)).await??;
    Ok(Action::await_change())
}

pub async fn reconcile(nk: Arc<KerberosNodeKeytab>, ctx: Arc<Context>) -> Result<Action, Error> {
    let api: Api<KerberosNodeKeytab> = Api::all(ctx.client.clone());
    finalizer(&api, FINALIZER, nk, |event| async {
        match event {
            Event::Apply(nk) => apply(nk, &ctx).await,
            Event::Cleanup(nk) => cleanup(nk, &ctx.client).await,
        }
    })
    .await
    .map_err(|e| match e {
        kube::runtime::finalizer::Error::ApplyFailed(e) | kube::runtime::finalizer::Error::CleanupFailed(e) => e,
        e => Error::Finalizer(e.to_string()),
    })
}

pub fn error_policy(nk: Arc<KerberosNodeKeytab>, e: &Error, _: Arc<Context>) -> Action {
    warn!("Reconciling {}: {}", nk.name_any(), e);
    Action::requeue(Duration::from_secs(if matches!(e, Error::Invalid(_)) { 300 } else { 15 }))
}

/// What about a node decides its principals: its labels, taints and
/// hostname. A node's other changes (its status, every few minutes) do not
/// reach the controller.
pub fn node_fingerprint(node: &Node) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    node.labels().hash(&mut h);
    for t in node.spec.as_ref().and_then(|s| s.taints.as_ref()).into_iter().flatten() {
        (&t.key, &t.value, &t.effect).hash(&mut h);
    }
    node_host(node, None).hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::KerberosNodeKeytabSpec;
    use k8s_openapi::api::apps::v1::DaemonSetStatus;
    use k8s_openapi::api::core::v1::{NodeAddress, NodeSpec, NodeStatus};

    fn node(name: &str, hostname: Option<&str>, labels: &[(&str, &str)], taints: &[(&str, &str)]) -> Node {
        let mut n = Node::default();
        n.metadata.name = Some(name.into());
        n.metadata.labels = Some(labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
        n.spec = Some(NodeSpec {
            taints: Some(
                taints
                    .iter()
                    .map(|(k, e)| Taint { key: k.to_string(), effect: e.to_string(), ..Default::default() })
                    .collect(),
            ),
            ..Default::default()
        });
        n.status = Some(NodeStatus {
            addresses: Some(
                hostname
                    .iter()
                    .map(|h| NodeAddress { type_: "Hostname".into(), address: h.to_string() })
                    .chain([NodeAddress { type_: "InternalIP".into(), address: "10.0.0.1".into() }])
                    .collect(),
            ),
            ..Default::default()
        });
        n
    }

    fn nk(spec: KerberosNodeKeytabSpec) -> KerberosNodeKeytab {
        let mut k = KerberosNodeKeytab::new("nfs-clients", spec);
        k.metadata.uid = Some("u-1".into());
        k
    }

    fn spec() -> KerberosNodeKeytabSpec {
        serde_json::from_value(json!({ "realmRef": "corp", "realmNamespace": "auth" })).unwrap()
    }

    #[test]
    fn the_defaults_are_host_and_nfs_in_etc_krb5_keytab() {
        let k = nk(spec());
        assert_eq!(k.spec.services, vec!["host", "nfs"]);
        assert_eq!(k.keytab_path(), "/etc/krb5.keytab");
        assert_eq!(k.owner(), "KerberosNodeKeytab/nfs-clients");
        assert_eq!(k.object_name(), "node-keytab-nfs-clients");
        assert_eq!(k.spec.deletion_policy, DeletionPolicy::Delete);
        validate(&k).unwrap();
    }

    #[test]
    fn a_node_is_named_as_it_calls_itself() {
        assert_eq!(node_host(&node("n1", Some("Worker-1.Corp.Example"), &[], &[]), None), "worker-1.corp.example");
        assert_eq!(node_host(&node("n1", None, &[], &[]), None), "n1", "no Hostname address: the node's name");
        assert_eq!(node_host(&node("n1", Some("w1"), &[], &[]), Some("corp.example.")), "w1.corp.example");
        assert_eq!(node_host(&node("n1", Some("w1.a.b"), &[], &[]), Some("corp.example")), "w1.a.b", "already a FQDN");
    }

    #[test]
    fn nodes_are_selected_by_labels_and_tolerated_taints() {
        let mut s = spec();
        s.node_selector = Some(BTreeMap::from([("nfs".to_string(), "krb5".to_string())]));
        let k = nk(s.clone());
        assert!(selected(&k, &node("a", None, &[("nfs", "krb5"), ("x", "y")], &[])));
        assert!(!selected(&k, &node("b", None, &[("nfs", "sys")], &[])));
        assert!(!selected(&k, &node("c", None, &[], &[])));
        // Taints: a control plane's is not tolerated unless asked for;
        // PreferNoSchedule and the node lifecycle's own never keep a
        // DaemonSet away.
        let cp = node("cp", None, &[("nfs", "krb5")], &[("node-role.kubernetes.io/control-plane", "NoSchedule")]);
        assert!(!selected(&k, &cp));
        assert!(selected(&k, &node("d", None, &[("nfs", "krb5")], &[("busy", "PreferNoSchedule")])));
        assert!(selected(
            &k,
            &node("e", None, &[("nfs", "krb5")], &[("node.kubernetes.io/unschedulable", "NoSchedule")])
        ));
        s.tolerations = Some(vec![Toleration {
            key: Some("node-role.kubernetes.io/control-plane".into()),
            operator: Some("Exists".into()),
            effect: Some("NoSchedule".into()),
            ..Default::default()
        }]);
        assert!(selected(&nk(s.clone()), &cp));
        // Tolerate everything.
        s.tolerations = Some(vec![Toleration { operator: Some("Exists".into()), ..Default::default() }]);
        assert!(selected(&nk(s.clone()), &node("f", None, &[("nfs", "krb5")], &[("gpu", "NoExecute")])));
        // Equal: the value must match.
        s.tolerations =
            Some(vec![Toleration { key: Some("gpu".into()), value: Some("a100".into()), ..Default::default() }]);
        let mut gpu = node("g", None, &[("nfs", "krb5")], &[("gpu", "NoSchedule")]);
        assert!(!selected(&nk(s.clone()), &gpu));
        gpu.spec.as_mut().unwrap().taints.as_mut().unwrap()[0].value = Some("a100".into());
        assert!(selected(&nk(s), &gpu));
    }

    #[test]
    fn each_selected_node_gets_a_principal_per_service() {
        let mut s = spec();
        s.node_selector = Some(BTreeMap::from([("nfs".to_string(), "krb5".to_string())]));
        s.domain = Some("corp.example".into());
        let k = nk(s);
        let nodes = vec![
            node("w1", Some("w1"), &[("nfs", "krb5")], &[]),
            node("w2", Some("w2.corp.example"), &[("nfs", "krb5")], &[]),
            node("w3", Some("w3"), &[], &[]),
        ];
        let w = wanted(&k, &nodes, "CORP.TEST").unwrap();
        let names: Vec<(String, &str)> = w.iter().map(|(p, n)| (p.name(), n.as_str())).collect();
        assert_eq!(
            names,
            vec![
                ("host/w1.corp.example".into(), "w1"),
                ("nfs/w1.corp.example".into(), "w1"),
                ("host/w2.corp.example".into(), "w2"),
                ("nfs/w2.corp.example".into(), "w2"),
            ]
        );
        assert!(w.iter().all(|(p, _)| p.realm == "CORP.TEST"));
        // Two nodes with one hostname: the name once.
        let twins =
            vec![node("a", Some("same"), &[("nfs", "krb5")], &[]), node("b", Some("same"), &[("nfs", "krb5")], &[])];
        assert_eq!(wanted(&k, &twins, "CORP.TEST").unwrap().len(), 2);
        // Reserved services are refused.
        let mut s = spec();
        s.services = vec!["krbtgt".into()];
        assert!(matches!(wanted(&nk(s), &nodes, "CORP.TEST"), Err(Error::Invalid(_))));
    }

    #[test]
    fn host_paths_are_files_in_a_directory() {
        for ok in ["/etc/krb5.keytab", "/var/lib/krb5/node.keytab"] {
            assert!(host_path("p", ok).is_ok(), "{ok}");
        }
        assert_eq!(host_path("p", "/etc/krb5.keytab").unwrap(), ("/etc".into(), "krb5.keytab".into()));
        for bad in ["krb5.keytab", "/krb5.keytab", "/etc/", "/etc/../root/x", "/etc/./x", "/etc//x", "/"] {
            assert!(matches!(host_path("p", bad), Err(Error::Invalid(_))), "{bad}");
        }
        let mut s = spec();
        s.krb5_conf_path = Some("/etc/krb5.keytab".into());
        assert!(validate(&nk(s)).is_err(), "the same file twice");
        let mut s = spec();
        s.services = vec!["host/x".into()];
        assert!(validate(&nk(s)).is_err());
        let mut s = spec();
        s.services = vec![];
        assert!(validate(&nk(s)).is_err());
        let long = KerberosNodeKeytab::new(&"x".repeat(46), spec());
        assert!(validate(&long).is_err());
    }

    #[test]
    fn hosts_reach_the_kdc_by_cluster_ip() {
        let c = host_krb5_conf("CORP.TEST", "10.96.0.12", Some("Corp.Example"));
        assert!(c.contains("default_realm = CORP.TEST"));
        assert!(c.contains("kdc = 10.96.0.12:88"));
        assert!(c.contains("admin_server = 10.96.0.12:749"));
        assert!(c.contains(".corp.example = CORP.TEST"));
        let v6 = host_krb5_conf("CORP.TEST", "fd00::12", None);
        assert!(v6.contains("kdc = [fd00::12]:88"));
        assert!(!v6.contains("domain_realm"));
    }

    #[test]
    fn each_node_has_its_own_keytab_file() {
        let k = |b: u8| krb5::Key::new(18, vec![b; 32]).unwrap();
        let w: Vec<(Principal, String)> = [("host/w1", "w1"), ("nfs/w1", "w1"), ("host/w2", "w2")]
            .iter()
            .map(|(p, n)| (Principal::parse_in_realm(p, "CORP.TEST").unwrap(), n.to_string()))
            .collect();
        let keys: Vec<PrincipalKeys> =
            w.iter().enumerate().map(|(i, (p, _))| (p.clone(), vec![(1, k(i as u8))])).collect();
        let files = secret_files(&w, &keys, "conf");
        assert_eq!(files.keys().collect::<Vec<_>>(), vec!["krb5.conf", "w1.keytab", "w2.keytab"]);
        let has = |f: &str, b: u8| files[f].windows(32).any(|w| w == [b; 32]);
        assert!(has("w1.keytab", 0) && has("w1.keytab", 1) && !has("w1.keytab", 2));
        assert!(has("w2.keytab", 2) && !has("w2.keytab", 0));
    }

    #[test]
    fn the_daemon_set_runs_the_agent_where_the_keys_go() {
        let mut s = spec();
        s.node_selector = Some(BTreeMap::from([("nfs".to_string(), "krb5".to_string())]));
        s.krb5_conf_path = Some("/etc/krb5.conf.d/corp.conf".into());
        let k = nk(s);
        let ds = daemon_set(&k, "krb5-operator", "img:1").unwrap();
        assert_eq!(ds.metadata.name.as_deref(), Some("node-keytab-nfs-clients"));
        assert_eq!(ds.metadata.owner_references.as_ref().unwrap()[0].uid, "u-1");
        let pod = ds.spec.unwrap().template.spec.unwrap();
        assert_eq!(pod.node_selector.unwrap()["nfs"], "krb5");
        let c = &pod.containers[0];
        assert_eq!(c.image.as_deref(), Some("img:1"));
        assert_eq!(
            c.args.as_ref().unwrap(),
            &vec![
                "node-agent".to_string(),
                format!("--keytabs={KEYTABS_DIR}"),
                "--keytab=/host/keytab/krb5.keytab".into(),
                "--krb5-conf=/host/krb5-conf/corp.conf".into(),
            ]
        );
        let vols = pod.volumes.unwrap();
        let host = |n: &str| vols.iter().find(|v| v.name == n).unwrap().host_path.as_ref().unwrap().path.clone();
        assert_eq!(host("host-keytab"), "/etc");
        assert_eq!(host("host-krb5-conf"), "/etc/krb5.conf.d");
        let secret = vols.iter().find(|v| v.name == "keytabs").unwrap().secret.as_ref().unwrap();
        assert_eq!(secret.secret_name.as_deref(), Some("node-keytab-nfs-clients"));
        let sc = c.security_context.as_ref().unwrap();
        assert_eq!(sc.capabilities.as_ref().unwrap().drop.as_ref().unwrap(), &vec!["ALL".to_string()]);
        assert_eq!(sc.read_only_root_filesystem, Some(true));
        assert_eq!(pod.automount_service_account_token, Some(false), "the agent needs no API access");
    }

    #[test]
    fn the_rollout_counts_ready_updated_pods() {
        let mut ds = DaemonSet::default();
        ds.metadata.generation = Some(2);
        assert_eq!(rollout(&ds), None);
        ds.status = Some(DaemonSetStatus {
            observed_generation: Some(1),
            desired_number_scheduled: 3,
            number_ready: 3,
            updated_number_scheduled: Some(3),
            ..Default::default()
        });
        assert_eq!(rollout(&ds), None, "an older spec");
        let st = ds.status.as_mut().unwrap();
        st.observed_generation = Some(2);
        st.updated_number_scheduled = Some(1);
        assert_eq!(rollout(&ds), Some((1, 3)));
        ds.status.as_mut().unwrap().updated_number_scheduled = Some(3);
        assert_eq!(rollout(&ds), Some((3, 3)));
    }

    #[test]
    fn only_what_decides_principals_changes_a_node_fingerprint() {
        let a = node("w1", Some("w1"), &[("nfs", "krb5")], &[]);
        let mut b = a.clone();
        b.status.as_mut().unwrap().addresses.as_mut().unwrap()[1].address = "10.0.0.9".into();
        b.metadata.resource_version = Some("99".into());
        assert_eq!(node_fingerprint(&a), node_fingerprint(&b), "status churn");
        let c = node("w1", Some("w1"), &[("nfs", "sys")], &[]);
        assert_ne!(node_fingerprint(&a), node_fingerprint(&c), "labels");
        let d = node("w1", Some("w1"), &[("nfs", "krb5")], &[("x", "NoSchedule")]);
        assert_ne!(node_fingerprint(&a), node_fingerprint(&d), "taints");
        let e = node("w1", Some("w1b"), &[("nfs", "krb5")], &[]);
        assert_ne!(node_fingerprint(&a), node_fingerprint(&e), "hostname");
    }
}
