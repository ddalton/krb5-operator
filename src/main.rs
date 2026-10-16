//! krb5-operator: MIT Kerberos realms on Kubernetes.
//!
//!   krb5-operator              run the controllers (KerberosRealm,
//!                              KerberosPrincipal, KerberosNodeKeytab)
//!   krb5-operator crds         print the CustomResourceDefinitions (YAML)
//!   krb5-operator node-agent   install a node's keys (the KerberosNodeKeytab
//!                              DaemonSet's pods)

mod agent;
mod crd;
mod node;
mod principal;
mod realm;
mod systemd;

use std::collections::HashMap;
use std::sync::Mutex;

use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, StatefulSet};
use k8s_openapi::api::core::v1::{ConfigMap, Node, Secret, Service};
use kube::runtime::controller::Controller;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Api, Client, CustomResourceExt, ResourceExt};
use tracing::{info, warn};

use crd::{KerberosNodeKeytab, KerberosPrincipal, KerberosRealm};

/// The CustomResourceDefinitions, as `deploy/crds.yaml` holds them.
fn crds_yaml() -> Result<String, serde_yaml::Error> {
    Ok(format!(
        "{}---\n{}---\n{}",
        serde_yaml::to_string(&KerberosRealm::crd())?,
        serde_yaml::to_string(&KerberosPrincipal::crd())?,
        serde_yaml::to_string(&KerberosNodeKeytab::crd())?
    ))
}

/// The operator's DaemonSets and Secrets for `KerberosNodeKeytab`s.
fn node_keytab_objects() -> watcher::Config {
    watcher::Config::default().labels(node::OWNER_LABEL)
}

fn owner_by_label<K: ResourceExt>(o: K) -> Option<ObjectRef<KerberosNodeKeytab>> {
    o.labels().get(node::OWNER_LABEL).map(|n| ObjectRef::new(n))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,krb5=warn".into()),
        )
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("crds") => {
            print!("{}", crds_yaml()?);
            return Ok(());
        }
        Some("node-agent") => return agent::run(&args[1..]).await,
        Some("node-agent-ready") => std::process::exit(if agent::ready() { 0 } else { 1 }),
        _ => {}
    }

    let client = Client::try_default().await?;
    let realms: Api<KerberosRealm> = Api::all(client.clone());
    let ctx = Arc::new(realm::Context {
        client: client.clone(),
        kdc_image: std::env::var("KRB5_KDC_IMAGE").unwrap_or_else(|_| crd::DEFAULT_KDC_IMAGE.to_string()),
    });
    info!("krb5-operator {} starting", env!("CARGO_PKG_VERSION"));
    let realm_controller = Controller::new(realms, watcher::Config::default())
        .owns(Api::<StatefulSet>::all(client.clone()), watcher::Config::default())
        .owns(Api::<Service>::all(client.clone()), watcher::Config::default())
        .owns(Api::<ConfigMap>::all(client.clone()), watcher::Config::default())
        .owns(Api::<Secret>::all(client.clone()), watcher::Config::default())
        .shutdown_on_signal()
        .run(realm::reconcile, realm::error_policy, ctx)
        .for_each(|r| async move {
            if let Err(e) = r {
                warn!("reconcile: {}", e);
            }
        });
    let principals: Api<KerberosPrincipal> = Api::all(client.clone());
    let pctx = Arc::new(principal::Context {
        client: client.clone(),
        cluster_domain: std::env::var("CLUSTER_DOMAIN").unwrap_or_else(|_| "cluster.local".into()),
    });
    let controller = Controller::new(principals, watcher::Config::default());
    // A StatefulSet's scaling reaches the KerberosPrincipals with host
    // principals for its pods.
    let store = controller.store();
    let principal_controller = controller
        .owns(Api::<Secret>::all(client.clone()), watcher::Config::default())
        .watches(Api::<StatefulSet>::all(client.clone()), watcher::Config::default(), move |sts| {
            let (ns, name) = (sts.namespace(), sts.name_any());
            store
                .state()
                .into_iter()
                .filter(|kp| {
                    kp.namespace() == ns && kp.spec.host_principals.as_ref().is_some_and(|h| h.stateful_set == name)
                })
                .map(|kp| ObjectRef::from_obj(&*kp))
                .collect::<Vec<_>>()
        })
        .shutdown_on_signal()
        .run(principal::reconcile, principal::error_policy, pctx)
        .for_each(|r| async move {
            if let Err(e) = r {
                warn!("reconcile: {}", e);
            }
        });

    // Node keytabs: the Secret and DaemonSet live in the operator's own
    // namespace. A node's labels, taints or hostname changing reaches every
    // KerberosNodeKeytab; its status churn does not.
    let namespace = std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "krb5-operator".into());
    let nctx = Arc::new(node::Context {
        client: client.clone(),
        namespace: namespace.clone(),
        agent_image: std::env::var("KRB5_OPERATOR_IMAGE")
            .unwrap_or_else(|_| format!("ghcr.io/ddalton/krb5-operator:{}", env!("CARGO_PKG_VERSION"))),
        cluster_domain: std::env::var("CLUSTER_DOMAIN").unwrap_or_else(|_| "cluster.local".into()),
    });
    let node_keytabs = Controller::new(Api::<KerberosNodeKeytab>::all(client.clone()), watcher::Config::default());
    let store = node_keytabs.store();
    let seen: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    let node_controller = node_keytabs
        // Its DaemonSet and Secret, by label: `owns` would look the
        // cluster-scoped owner up in their namespace.
        .watches(Api::<DaemonSet>::namespaced(client.clone(), &namespace), node_keytab_objects(), owner_by_label)
        .watches(Api::<Secret>::namespaced(client.clone(), &namespace), node_keytab_objects(), owner_by_label)
        .watches(Api::<Node>::all(client.clone()), watcher::Config::default(), move |n| {
            let fp = node::node_fingerprint(&n);
            if seen.lock().unwrap().insert(n.name_any(), fp) == Some(fp) {
                return Vec::new();
            }
            store.state().iter().map(|nk| ObjectRef::from_obj(&**nk)).collect::<Vec<_>>()
        })
        .shutdown_on_signal()
        .run(node::reconcile, node::error_policy, nctx)
        .for_each(|r| async move {
            if let Err(e) = r {
                warn!("reconcile: {}", e);
            }
        });
    tokio::join!(realm_controller, principal_controller, node_controller);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn deploy_and_chart_crds_are_current() {
        assert!(
            include_str!("../deploy/crds.yaml") == super::crds_yaml().unwrap(),
            "deploy/crds.yaml is stale: cargo run -- crds > deploy/crds.yaml"
        );
        assert!(
            include_str!("../charts/krb5-operator/crds/crds.yaml") == super::crds_yaml().unwrap(),
            "the chart's CRDs are stale: cargo run -- crds > charts/krb5-operator/crds/crds.yaml"
        );
    }
}
