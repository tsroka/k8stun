//! DNS packet parsing and response building.
//!
//! This module handles intercepting DNS queries for Kubernetes services and pods
//! and returning virtual IP addresses as responses.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use std::net::Ipv4Addr;
use tracing::debug;

use crate::k8s::NamespaceSet;

/// Represents a parsed DNS question (simplified view for our purposes).
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: RecordType,
}

/// Represents a parsed DNS query.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// The parsed hickory Message.
    message: Message,
}

impl DnsQuery {
    /// Parses a DNS query from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let message =
            Message::from_vec(data).map_err(|e| anyhow!("Failed to parse DNS message: {}", e))?;

        // Check if this is a query (not a response)
        if message.message_type() != MessageType::Query {
            return Err(anyhow!("Not a DNS query (message type is response)"));
        }

        Ok(DnsQuery { message })
    }

    /// Returns all questions in this query.
    pub fn questions(&self) -> Vec<DnsQuestion> {
        self.message
            .queries()
            .iter()
            .map(|q| DnsQuestion {
                name: q.name().to_string().trim_end_matches('.').to_string(),
                qtype: q.query_type(),
            })
            .collect()
    }

    /// Builds a DNS response with the given IP address.
    pub fn build_response(&self, ip: Ipv4Addr) -> Bytes {
        let mut response = Message::new();

        // Set up the response header
        let mut header = Header::response_from_request(self.message.header());
        header.set_authoritative(true);
        header.set_recursion_available(true);
        header.set_response_code(ResponseCode::NoError);
        response.set_header(header);

        // Copy the queries from the original message
        for query in self.message.queries() {
            response.add_query(query.clone());
        }

        // Add the answer record for the first A record question
        if let Some(query) = self
            .message
            .queries()
            .iter()
            .find(|q| q.query_type() == RecordType::A)
        {
            let mut record = Record::from_rdata(query.name().clone(), 60, RData::A(A(ip)));
            record.set_dns_class(DNSClass::IN);
            response.add_answer(record);
        }

        let response_bytes = response.to_vec().expect("Failed to serialize DNS response");

        debug!(
            "Built DNS response for {} -> {}",
            self.questions()
                .first()
                .map(|q| q.name.as_str())
                .unwrap_or("?"),
            ip
        );

        Bytes::from(response_bytes)
    }
}

/// Checks if a DNS name looks like a Kubernetes service name.
pub fn is_k8s_service_name(name: &str) -> bool {
    let name = name.trim_end_matches('.');

    // Match patterns like:
    // - service.namespace
    // - service.namespace.svc
    // - service.namespace.svc.cluster.local

    if name.ends_with(".svc.cluster.local") {
        return true;
    }

    if name.ends_with(".svc") {
        return true;
    }

    false
}

/// Checks if a DNS name looks like a Kubernetes pod name.
pub fn is_k8s_pod_name(name: &str) -> bool {
    let name = name.trim_end_matches('.');

    // Match pod patterns:
    // - pod-ip-with-dashes.namespace.pod.cluster.local
    // - pod-ip-with-dashes.namespace.pod
    if name.ends_with(".pod.cluster.local") || name.ends_with(".pod") {
        return true;
    }

    false
}

/// Information extracted from a pod DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodDnsInfo {
    /// Pod accessed by IP address (dashed format).
    /// Pattern: pod-ip-with-dashes.namespace.pod.cluster.local
    Ip {
        /// The pod IP address (converted from dashed format).
        ip: Ipv4Addr,
        /// The namespace.
        namespace: String,
    },
    /// Pod accessed via StatefulSet headless service.
    /// Pattern: pod-name.service-name.namespace.svc.cluster.local
    StatefulSet {
        /// The pod name (e.g., "mysql-0").
        pod_name: String,
        /// The headless service name (e.g., "mysql").
        service: String,
        /// The namespace.
        namespace: String,
    },
    /// Pod accessed by hostname and subdomain.
    /// Pattern: hostname.subdomain.namespace.svc.cluster.local
    /// Note: Currently treated the same as ByStatefulSet since the DNS pattern is identical.
    #[allow(dead_code)]
    Hostname {
        /// The pod hostname.
        hostname: String,
        /// The subdomain (usually a headless service name).
        subdomain: String,
        /// The namespace.
        namespace: String,
    },
}

/// Parses a dashed IP address (e.g., "172-17-0-3") to an Ipv4Addr.
fn parse_dashed_ip(dashed: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = dashed.split('-').collect();
    if parts.len() != 4 {
        return None;
    }

    let octets: Result<Vec<u8>, _> = parts.iter().map(|p| p.parse::<u8>()).collect();
    let octets = octets.ok()?;

    Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

/// DNS handler that processes queries and generates responses.
pub struct DnsHandler {
    /// Dynamically updated set of Kubernetes namespaces.
    namespaces: NamespaceSet,
}

impl DnsHandler {
    /// Creates a new DNS handler with a shared namespace set.
    pub fn new(namespaces: NamespaceSet) -> Self {
        Self { namespaces }
    }

    /// Determines if we should intercept this DNS query.
    /// Lock-free read via ArcSwap - just loads the current snapshot.
    pub fn should_intercept(&self, query: &DnsQuery) -> bool {
        let namespaces = self.namespaces.load();

        for question in query.questions() {
            if question.qtype != RecordType::A {
                continue;
            }

            // Always intercept .svc.cluster.local queries
            if is_k8s_service_name(&question.name) {
                return true;
            }

            // Always intercept .pod.cluster.local queries
            if is_k8s_pod_name(&question.name) {
                return true;
            }

            let parts: Vec<&str> = question.name.split('.').collect();
            if parts.len() != 2 {
                continue;
            }
            let tld = parts[1].to_lowercase();
            // Check if it matches any known Kubernetes namespace
            for ns in namespaces.iter() {
                // Match patterns like "service.namespace" or "service.namespace.svc"
                if tld.eq(ns) {
                    return true;
                }
            }
        }

        false
    }

    /// Checks if this is a pod DNS query (vs a service query).
    pub fn is_pod_query(&self, query: &DnsQuery) -> bool {
        for question in query.questions() {
            if question.qtype != RecordType::A {
                continue;
            }

            // Check for .pod or .pod.cluster.local suffix
            if is_k8s_pod_name(&question.name) {
                return true;
            }

            // Check for StatefulSet pattern: pod-name.service.namespace.svc.cluster.local
            // This has 3 parts before .svc.cluster.local (vs 2 for services)
            let name = question.name.trim_end_matches('.');
            if let Some(stripped) = name
                .strip_suffix(".svc.cluster.local")
                .or_else(|| name.strip_suffix(".svc"))
            {
                let parts: Vec<&str> = stripped.split('.').collect();
                // 3 parts = pod.service.namespace (StatefulSet/hostname pattern)
                // 2 parts = service.namespace (regular service)
                if parts.len() == 3 {
                    return true;
                }
            }
        }

        false
    }

    /// Extracts pod information from a DNS query.
    /// Returns None if this is not a pod DNS query.
    pub fn extract_pod_info(&self, query: &DnsQuery) -> Option<PodDnsInfo> {
        for question in query.questions() {
            if question.qtype != RecordType::A {
                continue;
            }

            let name = question.name.trim_end_matches('.');

            // Try to parse as IP-based pod DNS: pod-ip.namespace.pod.cluster.local
            if let Some(stripped) = name
                .strip_suffix(".pod.cluster.local")
                .or_else(|| name.strip_suffix(".pod"))
            {
                let parts: Vec<&str> = stripped.splitn(2, '.').collect();
                if parts.len() == 2 {
                    if let Some(ip) = parse_dashed_ip(parts[0]) {
                        return Some(PodDnsInfo::Ip {
                            ip,
                            namespace: parts[1].to_string(),
                        });
                    }
                }
            }

            // Try to parse as StatefulSet pod DNS: pod-name.service.namespace.svc.cluster.local
            if let Some(stripped) = name
                .strip_suffix(".svc.cluster.local")
                .or_else(|| name.strip_suffix(".svc"))
            {
                let parts: Vec<&str> = stripped.split('.').collect();
                if parts.len() == 3 {
                    // This could be either StatefulSet or hostname pattern
                    // We treat them the same way for now
                    return Some(PodDnsInfo::StatefulSet {
                        pod_name: parts[0].to_string(),
                        service: parts[1].to_string(),
                        namespace: parts[2].to_string(),
                    });
                }
            }
        }

        None
    }

    /// Extracts the service name and namespace from a DNS query.
    /// Lock-free read via ArcSwap - just loads the current snapshot.
    pub fn extract_service_info(&self, query: &DnsQuery) -> Option<(String, String)> {
        let namespaces = self.namespaces.load();

        for question in query.questions() {
            if question.qtype != RecordType::A {
                continue;
            }

            let name = question.name.trim_end_matches('.');

            // Skip pod DNS patterns
            if is_k8s_pod_name(name) {
                continue;
            }

            // Try to parse as service.namespace.svc.cluster.local
            if let Some(stripped) = name.strip_suffix(".svc.cluster.local") {
                let parts: Vec<&str> = stripped.split('.').collect();
                // Only 2 parts = service.namespace (not StatefulSet pattern with 3 parts)
                if parts.len() == 2 {
                    return Some((parts[0].to_string(), parts[1].to_string()));
                }
            }

            // Try to parse as service.namespace.svc
            if let Some(stripped) = name.strip_suffix(".svc") {
                let parts: Vec<&str> = stripped.split('.').collect();
                if parts.len() == 2 {
                    return Some((parts[0].to_string(), parts[1].to_string()));
                }
            }

            // Try to parse as service.namespace
            let parts: Vec<&str> = name.splitn(2, '.').collect();
            if parts.len() == 2 {
                // Check if namespace matches any known Kubernetes namespace
                if namespaces.contains(parts[1]) {
                    return Some((parts[0].to_string(), parts[1].to_string()));
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn make_namespace_set(namespaces: Vec<&str>) -> NamespaceSet {
        Arc::new(ArcSwap::from_pointee(
            namespaces
                .into_iter()
                .map(String::from)
                .collect::<HashSet<_>>(),
        ))
    }

    #[test]
    fn test_dns_handler_should_intercept() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default", "production"]));

        // Create a mock DNS query packet for backend.default
        let query_packet = build_test_query("backend.default");
        let query = DnsQuery::parse(&query_packet).unwrap();

        assert!(handler.should_intercept(&query));

        // Create a query for google.com - should not intercept
        let query_packet2 = build_test_query("google.com");
        let query2 = DnsQuery::parse(&query_packet2).unwrap();

        assert!(!handler.should_intercept(&query2));
    }

    #[test]
    fn test_dns_handler_should_intercept_pods() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // Pod IP-based DNS
        let query =
            DnsQuery::parse(&build_test_query("172-17-0-3.default.pod.cluster.local")).unwrap();
        assert!(handler.should_intercept(&query));

        // StatefulSet pod DNS
        let query =
            DnsQuery::parse(&build_test_query("mysql-0.mysql.default.svc.cluster.local")).unwrap();
        assert!(handler.should_intercept(&query));
    }

    #[test]
    fn test_dns_query_parse_and_response() {
        // Create a test DNS query
        let query_packet = build_test_query("backend.default.svc.cluster.local");
        let query = DnsQuery::parse(&query_packet).unwrap();

        let questions = query.questions();
        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].name, "backend.default.svc.cluster.local");
        assert_eq!(questions[0].qtype, RecordType::A);

        // Build a response
        let ip = Ipv4Addr::new(198, 18, 0, 1);
        let response = query.build_response(ip);

        // Parse the response to verify it's valid
        let response_msg = Message::from_vec(&response).unwrap();
        assert_eq!(response_msg.message_type(), MessageType::Response);
        assert_eq!(response_msg.answers().len(), 1);

        match response_msg.answers()[0].data() {
            RData::A(a) => assert_eq!(a.0, ip),
            _ => panic!("Expected A record in response"),
        }
    }

    #[test]
    fn test_extract_service_info() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // Test service.namespace.svc.cluster.local
        let query =
            DnsQuery::parse(&build_test_query("backend.default.svc.cluster.local")).unwrap();
        let info = handler.extract_service_info(&query);
        assert_eq!(info, Some(("backend".to_string(), "default".to_string())));

        // Test service.namespace.svc
        let query = DnsQuery::parse(&build_test_query("api.production.svc")).unwrap();
        let handler2 = DnsHandler::new(make_namespace_set(vec!["production"]));
        let info = handler2.extract_service_info(&query);
        assert_eq!(info, Some(("api".to_string(), "production".to_string())));

        // Test service.namespace (with matching namespace)
        let query = DnsQuery::parse(&build_test_query("web.default")).unwrap();
        let info = handler.extract_service_info(&query);
        assert_eq!(info, Some(("web".to_string(), "default".to_string())));

        // StatefulSet pattern should NOT be extracted as service info
        let query =
            DnsQuery::parse(&build_test_query("mysql-0.mysql.default.svc.cluster.local")).unwrap();
        let info = handler.extract_service_info(&query);
        assert_eq!(info, None);
    }

    #[test]
    fn test_is_k8s_pod_name() {
        assert!(is_k8s_pod_name("172-17-0-3.default.pod.cluster.local"));
        assert!(is_k8s_pod_name("172-17-0-3.default.pod"));
        assert!(!is_k8s_pod_name("backend.default.svc.cluster.local"));
        assert!(!is_k8s_pod_name("google.com"));
    }

    #[test]
    fn test_parse_dashed_ip() {
        assert_eq!(
            parse_dashed_ip("172-17-0-3"),
            Some(Ipv4Addr::new(172, 17, 0, 3))
        );
        assert_eq!(
            parse_dashed_ip("10-0-0-1"),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(parse_dashed_ip("invalid"), None);
        assert_eq!(parse_dashed_ip("172-17-0"), None);
        assert_eq!(parse_dashed_ip("172-17-0-3-4"), None);
        assert_eq!(parse_dashed_ip("256-0-0-1"), None); // Invalid octet
    }

    #[test]
    fn test_is_pod_query() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // Pod IP-based DNS
        let query =
            DnsQuery::parse(&build_test_query("172-17-0-3.default.pod.cluster.local")).unwrap();
        assert!(handler.is_pod_query(&query));

        // StatefulSet pod DNS (3 parts before .svc.cluster.local)
        let query =
            DnsQuery::parse(&build_test_query("mysql-0.mysql.default.svc.cluster.local")).unwrap();
        assert!(handler.is_pod_query(&query));

        // Regular service DNS (2 parts before .svc.cluster.local)
        let query =
            DnsQuery::parse(&build_test_query("backend.default.svc.cluster.local")).unwrap();
        assert!(!handler.is_pod_query(&query));

        // Short service name
        let query = DnsQuery::parse(&build_test_query("backend.default")).unwrap();
        assert!(!handler.is_pod_query(&query));
    }

    #[test]
    fn test_extract_pod_info_by_ip() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // Full pod DNS name
        let query =
            DnsQuery::parse(&build_test_query("172-17-0-3.default.pod.cluster.local")).unwrap();
        let info = handler.extract_pod_info(&query);
        assert_eq!(
            info,
            Some(PodDnsInfo::Ip {
                ip: Ipv4Addr::new(172, 17, 0, 3),
                namespace: "default".to_string(),
            })
        );

        // Short pod DNS name
        let query = DnsQuery::parse(&build_test_query("10-0-0-1.production.pod")).unwrap();
        let info = handler.extract_pod_info(&query);
        assert_eq!(
            info,
            Some(PodDnsInfo::Ip {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                namespace: "production".to_string(),
            })
        );
    }

    #[test]
    fn test_extract_pod_info_statefulset() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // StatefulSet pod DNS
        let query =
            DnsQuery::parse(&build_test_query("mysql-0.mysql.default.svc.cluster.local")).unwrap();
        let info = handler.extract_pod_info(&query);
        assert_eq!(
            info,
            Some(PodDnsInfo::StatefulSet {
                pod_name: "mysql-0".to_string(),
                service: "mysql".to_string(),
                namespace: "default".to_string(),
            })
        );

        // Short StatefulSet pod DNS
        let query = DnsQuery::parse(&build_test_query("redis-1.redis.cache.svc")).unwrap();
        let info = handler.extract_pod_info(&query);
        assert_eq!(
            info,
            Some(PodDnsInfo::StatefulSet {
                pod_name: "redis-1".to_string(),
                service: "redis".to_string(),
                namespace: "cache".to_string(),
            })
        );
    }

    #[test]
    fn test_extract_pod_info_not_pod() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // Regular service DNS should return None
        let query =
            DnsQuery::parse(&build_test_query("backend.default.svc.cluster.local")).unwrap();
        let info = handler.extract_pod_info(&query);
        assert_eq!(info, None);
    }

    /// Helper to build a test DNS query packet.
    fn build_test_query(domain: &str) -> Vec<u8> {
        use hickory_proto::op::{OpCode, Query};
        use hickory_proto::rr::Name;
        use std::str::FromStr;

        let name = Name::from_str(&format!("{}.", domain)).unwrap();
        let query = Query::query(name, RecordType::A);

        let mut message = Message::new();
        message.set_id(1234);
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(query);

        message.to_vec().unwrap()
    }
}
