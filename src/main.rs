//! krb5-operator: MIT Kerberos realms on Kubernetes.
//!
//!   krb5-operator          run the controllers (KerberosRealm, KerberosPrincipal)
//!   krb5-operator crds     print the CustomResourceDefinitions (YAML)

mod crd;
mod principal;
mod realm;

use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ConfigMap, Secret, Service};
use kube::runtime::controller::Controller;
use kube::runtime::watcher;
use kube::{Api, Client, CustomResourceExt};
use tracing::{info, warn};

use crd::{KerberosPrincipal, KerberosRealm};

/// The CustomResourceDefinitions, as `deploy/crds.yaml` holds them.
fn crds_yaml() -> Result<String, serde_yaml::Error> {
    Ok(format!(
        "{}---\n{}",
        serde_yaml::to_string(&KerberosRealm::crd())?,
        serde_yaml::to_string(&KerberosPrincipal::crd())?
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,krb5=warn".into()),
        )
        .init();
    if std::env::args().nth(1).as_deref() == Some("crds") {
        print!("{}", crds_yaml()?);
        return Ok(());
    }

    let client = Client::try_default().await?;
    let realms: Api<KerberosRealm> = Api::all(client.clone());
    let ctx = Arc::new(realm::Context { client: client.clone() });
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
    let pctx = Arc::new(principal::Context { client: client.clone() });
    let principal_controller = Controller::new(principals, watcher::Config::default())
        .owns(Api::<Secret>::all(client.clone()), watcher::Config::default())
        .shutdown_on_signal()
        .run(principal::reconcile, principal::error_policy, pctx)
        .for_each(|r| async move {
            if let Err(e) = r {
                warn!("reconcile: {}", e);
            }
        });
    tokio::join!(realm_controller, principal_controller);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn deploy_crds_are_current() {
        assert!(
            include_str!("../deploy/crds.yaml") == super::crds_yaml().unwrap(),
            "deploy/crds.yaml is stale: cargo run -- crds > deploy/crds.yaml"
        );
    }
}
