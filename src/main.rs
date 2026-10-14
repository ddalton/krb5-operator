//! krb5-operator: MIT Kerberos realms on Kubernetes.
//!
//!   krb5-operator          run the controllers
//!   krb5-operator crds     print the CustomResourceDefinitions (YAML)

mod crd;
mod realm;

use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ConfigMap, Secret, Service};
use kube::runtime::controller::Controller;
use kube::runtime::watcher;
use kube::{Api, Client, CustomResourceExt};
use tracing::{info, warn};

use crd::KerberosRealm;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,krb5=warn".into()))
        .init();
    if std::env::args().nth(1).as_deref() == Some("crds") {
        print!("{}", serde_yaml::to_string(&KerberosRealm::crd())?);
        return Ok(());
    }

    let client = Client::try_default().await?;
    let realms: Api<KerberosRealm> = Api::all(client.clone());
    let ctx = Arc::new(realm::Context { client: client.clone() });
    info!("krb5-operator {} starting", env!("CARGO_PKG_VERSION"));
    Controller::new(realms, watcher::Config::default())
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
        })
        .await;
    Ok(())
}
