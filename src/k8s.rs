//! Kubernetes client, service discovery, and port-forwarding.
//!
//! This module handles all Kubernetes API interactions including:
//! - Service discovery (listing and watching services)
//! - Pod endpoint resolution
//! - Port-forwarding to pods

#![allow(dead_code)]

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Endpoints, Namespace, Pod, Service};
use kube::{
    api::{Api, ListParams},
    Client, Config,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use crate::vip::ServiceId;

/// Shared set of namespace names that is updated by the namespace watcher.
/// Uses ArcSwap for lock-free reads - readers get a snapshot without blocking.
pub type NamespaceSet = Arc<ArcSwap<HashSet<String>>>;

/// Creates a new empty namespace set.
pub fn new_namespace_set() -> NamespaceSet {
    Arc::new(ArcSwap::from_pointee(HashSet::new()))
}

/// Represents a pod that can be connected to.
///
/// Note: Port is not included here because it comes from the intercepted
/// connection's destination port, not from Kubernetes.
#[derive(Debug, Clone)]
pub struct PodEndpoint {
    pub name: String,
    pub namespace: String,
    pub ip: String,
}

/// Kubernetes client wrapper with service discovery capabilities.
pub struct K8sClient {
    client: Client,
    /// Cache of service to pod endpoints.
    endpoint_cache: DashMap<ServiceKey, Vec<PodEndpoint>>,
    /// Round-robin index for load balancing.
    rr_index: DashMap<ServiceKey, AtomicUsize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ServiceKey {
    name: String,
    namespace: String,
}

impl K8sClient {
    /// Creates a new Kubernetes client from the default kubeconfig.
    ///
    /// If `context` is provided, uses that specific Kubernetes context.
    /// Otherwise, uses the current context from kubeconfig.
    pub async fn new(context: Option<&str>) -> Result<Self> {
        let config = match context {
            Some(ctx) => {
                info!("Using Kubernetes context: {}", ctx);
                Config::from_kubeconfig(&kube::config::KubeConfigOptions {
                    context: Some(ctx.to_string()),
                    cluster: None,
                    user: None,
                })
                .await
                .context(format!(
                    "Failed to load Kubernetes config for context '{}'",
                    ctx
                ))?
            }
            None => Config::infer().await.context(
                "Failed to load Kubernetes config. Is KUBECONFIG set or ~/.kube/config present?",
            )?,
        };

        info!("Connecting to Kubernetes cluster: {}", config.cluster_url);

        let client = Client::try_from(config).context("Failed to create Kubernetes client")?;

        Ok(Self {
            client,
            endpoint_cache: DashMap::new(),
            rr_index: DashMap::new(),
        })
    }

    /// Creates a Kubernetes client with a specific kubeconfig path.
    pub async fn with_kubeconfig(path: &str) -> Result<Self> {
        let config = Config::from_kubeconfig(&kube::config::KubeConfigOptions {
            context: None,
            cluster: None,
            user: None,
        })
        .await
        .context(format!("Failed to load kubeconfig from {}", path))?;

        let client = Client::try_from(config)?;

        Ok(Self {
            client,
            endpoint_cache: DashMap::new(),
            rr_index: DashMap::new(),
        })
    }

    /// Lists all services in the given namespaces.
    pub async fn list_services(&self, namespaces: &[String]) -> Result<Vec<ServiceInfo>> {
        let mut services = Vec::new();

        for namespace in namespaces {
            let api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
            let list = api.list(&ListParams::default()).await.context(format!(
                "Failed to list services in namespace {}",
                namespace
            ))?;

            for svc in list {
                let name = svc.metadata.name.unwrap_or_default();
                let ports: Vec<u16> = svc
                    .spec
                    .as_ref()
                    .and_then(|s| s.ports.as_ref())
                    .map(|ports| ports.iter().map(|p| p.port as u16).collect())
                    .unwrap_or_default();

                services.push(ServiceInfo {
                    name,
                    namespace: namespace.clone(),
                    ports,
                });
            }
        }

        info!("Discovered {} services", services.len());
        Ok(services)
    }

    /// Finds pods backing a service and returns their endpoints.
    pub async fn get_service_endpoints(&self, service: &ServiceId) -> Result<Vec<PodEndpoint>> {
        let key = ServiceKey {
            name: service.name.clone(),
            namespace: service.namespace.clone(),
        };

        // Check cache first (lock-free read)
        if let Some(endpoints) = self.endpoint_cache.get(&key) {
            if !endpoints.is_empty() {
                return Ok(endpoints.clone());
            }
        }

        // Fetch endpoints directly - this works for all service types
        // (including services without selectors)
        let endpoints_api: Api<Endpoints> =
            Api::namespaced(self.client.clone(), &service.namespace);
        let ep = endpoints_api.get(&service.name).await.context(format!(
            "Failed to get endpoints for service {}/{}",
            service.namespace, service.name
        ))?;

        debug!(
            "Found endpoints for service {}/{}",
            service.namespace, service.name
        );

        // Extract addresses from the Endpoints resource
        let endpoints: Vec<PodEndpoint> = ep
            .subsets
            .unwrap_or_default()
            .iter()
            .flat_map(|subset| {
                let addresses = subset.addresses.as_deref().unwrap_or(&[]);

                addresses.iter().map(move |addr| {
                    let ip = addr.ip.clone();
                    let name = addr
                        .target_ref
                        .as_ref()
                        .and_then(|tr| tr.name.clone())
                        .unwrap_or_else(|| ip.clone());

                    PodEndpoint {
                        name,
                        namespace: service.namespace.clone(),
                        ip,
                    }
                })
            })
            .collect();

        if endpoints.is_empty() {
            return Err(anyhow!(
                "No running pods found for service {}/{}",
                service.namespace,
                service.name
            ));
        }

        // Update cache (DashMap handles concurrent access)
        self.endpoint_cache.insert(key, endpoints.clone());

        info!(
            "Found {} endpoints for {}/{}",
            endpoints.len(),
            service.namespace,
            service.name
        );

        Ok(endpoints)
    }

    /// Gets the next pod endpoint for a service (round-robin).
    pub async fn get_next_endpoint(&self, service: &ServiceId) -> Result<PodEndpoint> {
        let endpoints = self.get_service_endpoints(service).await?;

        if endpoints.is_empty() {
            return Err(anyhow!("No endpoints available"));
        }

        let key = ServiceKey {
            name: service.name.clone(),
            namespace: service.namespace.clone(),
        };

        // Get or create the round-robin index atomically
        let index = self
            .rr_index
            .entry(key)
            .or_insert_with(|| AtomicUsize::new(0));
        let current = index.fetch_add(1, Ordering::Relaxed);
        let endpoint = endpoints[current % endpoints.len()].clone();

        Ok(endpoint)
    }

    /// Establishes a port-forward connection to a pod.
    ///
    /// The port parameter is the destination port from the intercepted connection.
    /// Returns streams for reading and writing to the forwarded connection.
    pub async fn port_forward(
        &self,
        endpoint: &PodEndpoint,
        port: u16,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin> {
        info!(
            "Port-forwarding to {}/{} port {}",
            endpoint.namespace, endpoint.name, port
        );

        let pod_api: Api<Pod> = Api::namespaced(self.client.clone(), &endpoint.namespace);

        let mut pf = pod_api
            .portforward(&endpoint.name, &[port])
            .await
            .context(format!(
                "Failed to establish port-forward to {}/{}:{}",
                endpoint.namespace, endpoint.name, port
            ))?;

        // Get the stream for our port
        let stream = pf
            .take_stream(port)
            .ok_or_else(|| anyhow!("Failed to get port-forward stream"))?;

        // Spawn a task to handle the port-forward lifecycle
        tokio::spawn(async move {
            if let Err(e) = pf.join().await {
                debug!("Port-forward ended: {}", e);
            }
        });

        Ok(stream)
    }

    /// Establishes a port-forward and returns split read/write halves.
    pub async fn port_forward_split(
        &self,
        endpoint: &PodEndpoint,
        port: u16,
    ) -> Result<(impl AsyncRead + Unpin, impl AsyncWrite + Unpin)> {
        let stream = self.port_forward(endpoint, port).await?;
        Ok(tokio::io::split(stream))
    }

    /// Clears the endpoint cache for a service.
    pub async fn invalidate_cache(&self, service: &ServiceId) {
        let key = ServiceKey {
            name: service.name.clone(),
            namespace: service.namespace.clone(),
        };

        self.endpoint_cache.remove(&key);

        debug!(
            "Invalidated cache for {}/{}",
            service.namespace, service.name
        );
    }

    /// Clears all cached endpoints.
    pub async fn clear_cache(&self) {
        self.endpoint_cache.clear();
        info!("Cleared all endpoint cache");
    }

    /// Finds a pod by its IP address.
    ///
    /// This is used for IP-based pod DNS resolution (e.g., 172-17-0-3.namespace.pod.cluster.local).
    pub async fn get_pod_by_ip(&self, ip: &str, namespace: &str) -> Result<PodEndpoint> {
        let pod_api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);

        // List pods and find the one with matching IP
        let pods = pod_api
            .list(&ListParams::default())
            .await
            .context(format!("Failed to list pods in namespace {}", namespace))?;

        for pod in pods {
            let pod_ip = pod
                .status
                .as_ref()
                .and_then(|s| s.pod_ip.as_ref())
                .map(|s| s.as_str());

            if pod_ip == Some(ip) {
                let name = pod.metadata.name.unwrap_or_default();
                debug!(
                    "Found pod {} with IP {} in namespace {}",
                    name, ip, namespace
                );
                return Ok(PodEndpoint {
                    name,
                    namespace: namespace.to_string(),
                    ip: ip.to_string(),
                });
            }
        }

        Err(anyhow!(
            "No pod found with IP {} in namespace {}",
            ip,
            namespace
        ))
    }

    /// Finds a pod by name.
    ///
    /// This is used for StatefulSet pod DNS resolution (e.g., mysql-0.mysql.namespace.svc.cluster.local).
    pub async fn get_pod_by_name(&self, name: &str, namespace: &str) -> Result<PodEndpoint> {
        let pod_api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);

        let pod = pod_api
            .get(name)
            .await
            .context(format!("Failed to get pod {}/{}", namespace, name))?;

        let ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .ok_or_else(|| anyhow!("Pod {}/{} has no IP address", namespace, name))?;

        // Check if pod is running
        let phase = pod
            .status
            .as_ref()
            .and_then(|s| s.phase.as_ref())
            .map(|s| s.as_str());

        if phase != Some("Running") {
            return Err(anyhow!(
                "Pod {}/{} is not running (phase: {:?})",
                namespace,
                name,
                phase
            ));
        }

        debug!("Found pod {}/{} with IP {}", namespace, name, ip);

        Ok(PodEndpoint {
            name: name.to_string(),
            namespace: namespace.to_string(),
            ip,
        })
    }

    /// Finds a pod by hostname and subdomain.
    ///
    /// This is used for pods with custom hostname/subdomain (e.g., hostname.subdomain.namespace.svc.cluster.local).
    /// The subdomain typically corresponds to a headless service name.
    pub async fn get_pod_by_hostname(
        &self,
        hostname: &str,
        subdomain: &str,
        namespace: &str,
    ) -> Result<PodEndpoint> {
        let pod_api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);

        // List pods and find the one with matching hostname and subdomain
        let pods = pod_api
            .list(&ListParams::default())
            .await
            .context(format!("Failed to list pods in namespace {}", namespace))?;

        for pod in pods {
            let pod_hostname = pod
                .spec
                .as_ref()
                .and_then(|s| s.hostname.as_ref())
                .map(|s| s.as_str());

            let pod_subdomain = pod
                .spec
                .as_ref()
                .and_then(|s| s.subdomain.as_ref())
                .map(|s| s.as_str());

            if pod_hostname == Some(hostname) && pod_subdomain == Some(subdomain) {
                let name = pod.metadata.name.unwrap_or_default();
                let ip = pod
                    .status
                    .as_ref()
                    .and_then(|s| s.pod_ip.clone())
                    .ok_or_else(|| {
                        anyhow!(
                            "Pod with hostname {}.{} in {} has no IP",
                            hostname,
                            subdomain,
                            namespace
                        )
                    })?;

                debug!(
                    "Found pod {} with hostname {}.{} in namespace {}",
                    name, hostname, subdomain, namespace
                );

                return Ok(PodEndpoint {
                    name,
                    namespace: namespace.to_string(),
                    ip,
                });
            }
        }

        // If not found by hostname/subdomain, try by name (StatefulSet pods often have
        // hostname matching their name)
        self.get_pod_by_name(hostname, namespace).await
    }

    /// Watches for service changes in the given namespaces.
    pub async fn watch_services<F>(&self, namespaces: Vec<String>, on_change: F) -> Result<()>
    where
        F: Fn(ServiceEvent) + Send + Sync + Clone + 'static,
    {
        use kube::runtime::watcher;

        for namespace in namespaces {
            let api: Api<Service> = Api::namespaced(self.client.clone(), &namespace);
            let watcher = watcher(api, watcher::Config::default());

            let namespace_clone = namespace.clone();
            let on_change_clone = on_change.clone();
            tokio::spawn(async move {
                let mut stream = watcher.boxed();
                while let Some(event) = stream.next().await {
                    match event {
                        Ok(watcher::Event::Apply(svc)) => {
                            if let Some(name) = svc.metadata.name {
                                on_change_clone(ServiceEvent::Added {
                                    name,
                                    namespace: namespace_clone.clone(),
                                });
                            }
                        }
                        Ok(watcher::Event::Delete(svc)) => {
                            if let Some(name) = svc.metadata.name {
                                on_change_clone(ServiceEvent::Deleted {
                                    name,
                                    namespace: namespace_clone.clone(),
                                });
                            }
                        }
                        Ok(watcher::Event::Init) => {
                            debug!("Service watcher initialized for {}", namespace_clone);
                        }
                        Ok(watcher::Event::InitApply(svc)) => {
                            if let Some(name) = svc.metadata.name {
                                on_change_clone(ServiceEvent::Added {
                                    name,
                                    namespace: namespace_clone.clone(),
                                });
                            }
                        }
                        Ok(watcher::Event::InitDone) => {
                            debug!("Service watcher init done for {}", namespace_clone);
                        }
                        Err(e) => {
                            warn!("Service watcher error: {}", e);
                        }
                    }
                }
            });
        }

        Ok(())
    }
}

/// Information about a discovered Kubernetes service.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub namespace: String,
    pub ports: Vec<u16>,
}

/// Events from the service watcher.
#[derive(Debug, Clone)]
pub enum ServiceEvent {
    Added { name: String, namespace: String },
    Deleted { name: String, namespace: String },
}

/// Watches all Kubernetes namespaces and maintains an up-to-date set of namespace names.
pub struct NamespaceWatcher {
    client: Client,
    namespaces: NamespaceSet,
}

impl NamespaceWatcher {
    /// Creates a new namespace watcher.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            namespaces: new_namespace_set(),
        }
    }

    /// Returns a clone of the shared namespace set that can be used elsewhere.
    pub fn namespace_set(&self) -> NamespaceSet {
        Arc::clone(&self.namespaces)
    }

    /// Starts watching namespaces in the background.
    /// Returns immediately after spawning the watch task.
    pub fn start(&self) {
        use kube::runtime::watcher;

        let api: Api<Namespace> = Api::all(self.client.clone());
        let watcher_stream = watcher(api, watcher::Config::default());

        let namespaces = Arc::clone(&self.namespaces);

        tokio::spawn(async move {
            let mut stream = watcher_stream.boxed();
            while let Some(event) = stream.next().await {
                match event {
                    Ok(watcher::Event::Apply(ns)) => {
                        if let Some(name) = ns.metadata.name {
                            // Clone current set, add new namespace, swap atomically
                            let current = namespaces.load();
                            if !current.contains(&name) {
                                let mut new_set = (**current).clone();
                                new_set.insert(name.clone());
                                namespaces.store(Arc::new(new_set));
                                debug!("Namespace added: {}", name);
                            }
                        }
                    }
                    Ok(watcher::Event::Delete(ns)) => {
                        if let Some(name) = ns.metadata.name {
                            // Clone current set, remove namespace, swap atomically
                            let current = namespaces.load();
                            if current.contains(&name) {
                                let mut new_set = (**current).clone();
                                new_set.remove(&name);
                                namespaces.store(Arc::new(new_set));
                                debug!("Namespace deleted: {}", name);
                            }
                        }
                    }
                    Ok(watcher::Event::Init) => {
                        debug!("Namespace watcher initialized");
                    }
                    Ok(watcher::Event::InitApply(ns)) => {
                        if let Some(name) = ns.metadata.name {
                            // Clone current set, add namespace, swap atomically
                            let current = namespaces.load();
                            let mut new_set = (**current).clone();
                            new_set.insert(name);
                            namespaces.store(Arc::new(new_set));
                        }
                    }
                    Ok(watcher::Event::InitDone) => {
                        let set = namespaces.load();
                        info!("Namespace watcher ready: {} namespaces found", set.len());
                    }
                    Err(e) => {
                        warn!("Namespace watcher error: {}", e);
                    }
                }
            }
        });
    }
}

impl K8sClient {
    /// Creates a namespace watcher using this client's connection.
    pub fn namespace_watcher(&self) -> NamespaceWatcher {
        NamespaceWatcher::new(self.client.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_key() {
        let key1 = ServiceKey {
            name: "backend".to_string(),
            namespace: "default".to_string(),
        };
        let key2 = ServiceKey {
            name: "backend".to_string(),
            namespace: "default".to_string(),
        };
        assert_eq!(key1, key2);
    }
}
