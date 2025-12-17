//! DNS packet parsing and response building.
//!
//! This module handles intercepting DNS queries for Kubernetes services and pods
//! and returning virtual IP addresses as responses.

use anyhow::{anyhow, Result};
use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use std::net::{IpAddr, Ipv4Addr};
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

    /// Builds a DNS response with the given IP address (for K8s VIP responses).
    pub fn build_response(&self, ip: Ipv4Addr) -> Message {
        self.build_response_with_ips(std::iter::once(IpAddr::V4(ip)))
    }

    /// Builds a DNS response with all given IP addresses.
    pub fn build_response_with_ips(&self, ips: impl Iterator<Item = IpAddr>) -> Message {
        let mut response = Message::new();

        // Set up the response header
        let mut header = Header::response_from_request(self.message.header());
        header.set_authoritative(false); // Not authoritative for forwarded responses
        header.set_recursion_available(true);
        header.set_response_code(ResponseCode::NoError);
        response.set_header(header);

        // Copy the queries from the original message
        for query in self.message.queries() {
            response.add_query(query.clone());
        }

        // Find the query name for the answer records
        let query_name = self
            .message
            .queries()
            .iter()
            .find(|q| q.query_type() == RecordType::A || q.query_type() == RecordType::AAAA)
            .map(|q| q.name().clone());

        if let Some(name) = query_name {
            let mut count = 0;
            for ip in ips {
                let rdata = match ip {
                    IpAddr::V4(v4) => RData::A(A(v4)),
                    IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
                };
                let mut record = Record::from_rdata(name.clone(), 60, rdata);
                record.set_dns_class(DNSClass::IN);
                response.add_answer(record);
                count += 1;
            }

            debug!(
                "Built DNS response for {} with {} address(es)",
                self.questions()
                    .first()
                    .map(|q| q.name.as_str())
                    .unwrap_or("?"),
                count
            );
        }

        response
    }

    /// Builds a DNS response with the given records (for forwarded responses).
    pub fn build_response_with_records(&self, records: &[Record]) -> Message {
        let mut response = Message::new();

        // Set up the response header
        let mut header = Header::response_from_request(self.message.header());
        header.set_authoritative(false); // Not authoritative for forwarded responses
        header.set_recursion_available(true);
        header.set_response_code(ResponseCode::NoError);
        response.set_header(header);

        // Copy the queries from the original message
        for query in self.message.queries() {
            response.add_query(query.clone());
        }

        // Add all answer records
        for record in records {
            response.add_answer(record.clone());
        }

        debug!(
            "Built DNS response for {} with {} record(s)",
            self.questions()
                .first()
                .map(|q| q.name.as_str())
                .unwrap_or("?"),
            records.len()
        );

        response
    }

    /// Builds a DNS error response with the given response code.
    pub fn build_error_response(&self, rcode: ResponseCode) -> Message {
        let mut response = Message::new();

        // Set up the response header with the error code
        let mut header = Header::response_from_request(self.message.header());
        header.set_authoritative(false);
        header.set_recursion_available(true);
        header.set_response_code(rcode);
        response.set_header(header);

        // Copy the queries from the original message
        for query in self.message.queries() {
            response.add_query(query.clone());
        }

        debug!(
            "Built DNS error response ({:?}) for {}",
            rcode,
            self.questions()
                .first()
                .map(|q| q.name.as_str())
                .unwrap_or("?"),
        );

        response
    }

    /// Builds an empty DNS response (NOERROR with no answers).
    /// Used when the name exists but has no A records (e.g., IPv6-only).
    pub fn build_empty_response(&self) -> Message {
        let mut response = Message::new();

        // Set up the response header - NOERROR but with no answers
        let mut header = Header::response_from_request(self.message.header());
        header.set_authoritative(false);
        header.set_recursion_available(true);
        header.set_response_code(ResponseCode::NoError);
        response.set_header(header);

        // Copy the queries from the original message
        for query in self.message.queries() {
            response.add_query(query.clone());
        }

        debug!(
            "Built empty DNS response for {}",
            self.questions()
                .first()
                .map(|q| q.name.as_str())
                .unwrap_or("?"),
        );

        response
    }
}

/// Builds a FORMERR (format error) response from raw DNS data.
/// Extracts the transaction ID from the raw bytes to build a minimal error response.
/// If the data is too short, uses transaction ID 0 as fallback (per standard practice
/// of always responding rather than silently dropping).
pub fn build_formerr_response(dns_data: &[u8]) -> Message {
    // Extract transaction ID from first 2 bytes, or use 0 as fallback
    let id = if dns_data.len() >= 2 {
        u16::from_be_bytes([dns_data[0], dns_data[1]])
    } else {
        0 // Fallback for truncated/empty queries
    };

    let mut response = Message::new();

    // Set up a minimal response header with FORMERR
    let mut header = Header::new();
    header.set_id(id);
    header.set_message_type(MessageType::Response);
    header.set_authoritative(false);
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::FormErr);
    response.set_header(header);

    debug!(
        "Built FORMERR response for unparseable query (id={}, data_len={})",
        id,
        dns_data.len()
    );

    response
}

/// Builds a SERVFAIL (server failure) response from raw DNS data.
/// Used when DNS resolution encounters an internal error.
/// Extracts the transaction ID from the raw bytes to build a minimal error response.
pub fn build_servfail_response(dns_data: &[u8]) -> Message {
    // Extract transaction ID from first 2 bytes, or use 0 as fallback
    let id = if dns_data.len() >= 2 {
        u16::from_be_bytes([dns_data[0], dns_data[1]])
    } else {
        0 // Fallback for truncated/empty queries
    };

    let mut response = Message::new();

    // Set up a minimal response header with SERVFAIL
    let mut header = Header::new();
    header.set_id(id);
    header.set_message_type(MessageType::Response);
    header.set_authoritative(false);
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::ServFail);
    response.set_header(header);

    debug!(
        "Built SERVFAIL response for failed query (id={}, data_len={})",
        id,
        dns_data.len()
    );

    response
}

/// Result of parsing a DNS query to determine if it's a K8s resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum K8sQueryType {
    /// Query is for a Kubernetes service.
    Service {
        /// The service name.
        name: String,
        /// The namespace.
        namespace: String,
    },
    /// Query is for a Kubernetes pod.
    Pod(PodDnsInfo),
    /// Query is not for a Kubernetes resource (should be forwarded upstream).
    NotK8s,
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

    /// Parses a DNS query and determines if it's for a K8s service, pod, or neither.
    ///
    /// This method combines the logic of `should_intercept`, `is_pod_query`, and
    /// extraction methods into a single unified parsing pass.
    ///
    /// Returns:
    /// - `K8sQueryType::Service` if the query is for a K8s service
    /// - `K8sQueryType::Pod` if the query is for a K8s pod
    /// - `K8sQueryType::NotK8s` if the query should be forwarded upstream
    pub fn parse_k8s_query(&self, query: &DnsQuery) -> K8sQueryType {
        let namespaces = self.namespaces.load();

        for question in query.questions() {
            // Only handle A record queries
            if question.qtype != RecordType::A {
                continue;
            }

            let name = question.name.trim_end_matches('.');

            // Check for IP-based pod DNS: pod-ip.namespace.pod.cluster.local
            if let Some(stripped) = name
                .strip_suffix(".pod.cluster.local")
                .or_else(|| name.strip_suffix(".pod"))
            {
                let parts: Vec<&str> = stripped.splitn(2, '.').collect();
                if parts.len() == 2 {
                    if let Some(ip) = parse_dashed_ip(parts[0]) {
                        return K8sQueryType::Pod(PodDnsInfo::Ip {
                            ip,
                            namespace: parts[1].to_string(),
                        });
                    }
                }
            }

            // Check for .svc.cluster.local or .svc suffix patterns
            if let Some(stripped) = name
                .strip_suffix(".svc.cluster.local")
                .or_else(|| name.strip_suffix(".svc"))
            {
                let parts: Vec<&str> = stripped.split('.').collect();
                match parts.len() {
                    // 2 parts = service.namespace (regular service)
                    2 => {
                        return K8sQueryType::Service {
                            name: parts[0].to_string(),
                            namespace: parts[1].to_string(),
                        };
                    }
                    // 3 parts = pod.service.namespace (StatefulSet pod)
                    3 => {
                        return K8sQueryType::Pod(PodDnsInfo::StatefulSet {
                            pod_name: parts[0].to_string(),
                            service: parts[1].to_string(),
                            namespace: parts[2].to_string(),
                        });
                    }
                    _ => continue,
                }
            }

            // Check for short names (service.namespace or pod.service.namespace)
            let parts: Vec<&str> = name.split('.').collect();
            match parts.len() {
                // 2 parts = service.namespace (if namespace is known)
                2 => {
                    let namespace = parts[1].to_lowercase();
                    if namespaces.contains(&*namespace) {
                        return K8sQueryType::Service {
                            name: parts[0].to_string(),
                            namespace: parts[1].to_string(),
                        };
                    }
                }
                // 3 parts = pod.service.namespace (if namespace is known)
                3 => {
                    let namespace = parts[2].to_lowercase();
                    if namespaces.contains(&*namespace) {
                        return K8sQueryType::Pod(PodDnsInfo::StatefulSet {
                            pod_name: parts[0].to_string(),
                            service: parts[1].to_string(),
                            namespace: parts[2].to_string(),
                        });
                    }
                }
                _ => continue,
            }
        }

        K8sQueryType::NotK8s
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
    fn test_parse_k8s_query_service() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default", "production"]));

        // Create a mock DNS query packet for backend.default
        let query_packet = build_test_query("backend.default");
        let query = DnsQuery::parse(&query_packet).unwrap();

        assert!(matches!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Service { .. }
        ));

        // Create a query for google.com - should not intercept
        let query_packet2 = build_test_query("google.com");
        let query2 = DnsQuery::parse(&query_packet2).unwrap();

        assert!(matches!(
            handler.parse_k8s_query(&query2),
            K8sQueryType::NotK8s
        ));
    }

    #[test]
    fn test_parse_k8s_query_pods() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // Pod IP-based DNS
        let query =
            DnsQuery::parse(&build_test_query("172-17-0-3.default.pod.cluster.local")).unwrap();
        assert!(matches!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Pod(_)
        ));

        // StatefulSet pod DNS
        let query =
            DnsQuery::parse(&build_test_query("mysql-0.mysql.default.svc.cluster.local")).unwrap();
        assert!(matches!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Pod(_)
        ));
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

        // Verify the response is valid
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.answers().len(), 1);

        match response.answers()[0].data() {
            RData::A(a) => assert_eq!(a.0, ip),
            _ => panic!("Expected A record in response"),
        }
    }

    #[test]
    fn test_parse_k8s_query_service_info() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // Test service.namespace.svc.cluster.local
        let query =
            DnsQuery::parse(&build_test_query("backend.default.svc.cluster.local")).unwrap();
        assert_eq!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Service {
                name: "backend".to_string(),
                namespace: "default".to_string()
            }
        );

        // Test service.namespace.svc
        let query = DnsQuery::parse(&build_test_query("api.production.svc")).unwrap();
        let handler2 = DnsHandler::new(make_namespace_set(vec!["production"]));
        assert_eq!(
            handler2.parse_k8s_query(&query),
            K8sQueryType::Service {
                name: "api".to_string(),
                namespace: "production".to_string()
            }
        );

        // Test service.namespace (with matching namespace)
        let query = DnsQuery::parse(&build_test_query("web.default")).unwrap();
        assert_eq!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Service {
                name: "web".to_string(),
                namespace: "default".to_string()
            }
        );

        // StatefulSet pattern should be recognized as Pod, not Service
        let query =
            DnsQuery::parse(&build_test_query("mysql-0.mysql.default.svc.cluster.local")).unwrap();
        assert!(matches!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Pod(_)
        ));
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
    fn test_parse_k8s_query_pod_types() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // Pod IP-based DNS
        let query =
            DnsQuery::parse(&build_test_query("172-17-0-3.default.pod.cluster.local")).unwrap();
        assert!(matches!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Pod(_)
        ));

        // StatefulSet pod DNS (3 parts before .svc.cluster.local)
        let query =
            DnsQuery::parse(&build_test_query("mysql-0.mysql.default.svc.cluster.local")).unwrap();
        assert!(matches!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Pod(_)
        ));

        // Regular service DNS (2 parts before .svc.cluster.local)
        let query =
            DnsQuery::parse(&build_test_query("backend.default.svc.cluster.local")).unwrap();
        assert!(matches!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Service { .. }
        ));

        // Short service name
        let query = DnsQuery::parse(&build_test_query("backend.default")).unwrap();
        assert!(matches!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Service { .. }
        ));
    }

    #[test]
    fn test_parse_k8s_query_pod_by_ip() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // Full pod DNS name
        let query =
            DnsQuery::parse(&build_test_query("172-17-0-3.default.pod.cluster.local")).unwrap();
        assert_eq!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Pod(PodDnsInfo::Ip {
                ip: Ipv4Addr::new(172, 17, 0, 3),
                namespace: "default".to_string(),
            })
        );

        // Short pod DNS name
        let query = DnsQuery::parse(&build_test_query("10-0-0-1.production.pod")).unwrap();
        assert_eq!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Pod(PodDnsInfo::Ip {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                namespace: "production".to_string(),
            })
        );
    }

    #[test]
    fn test_parse_k8s_query_pod_statefulset() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default", "cache"]));

        // StatefulSet pod DNS (full form)
        let query =
            DnsQuery::parse(&build_test_query("mysql-0.mysql.default.svc.cluster.local")).unwrap();
        assert_eq!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Pod(PodDnsInfo::StatefulSet {
                pod_name: "mysql-0".to_string(),
                service: "mysql".to_string(),
                namespace: "default".to_string(),
            })
        );

        // StatefulSet pod DNS with .svc suffix
        let query = DnsQuery::parse(&build_test_query("redis-1.redis.cache.svc")).unwrap();
        assert_eq!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Pod(PodDnsInfo::StatefulSet {
                pod_name: "redis-1".to_string(),
                service: "redis".to_string(),
                namespace: "cache".to_string(),
            })
        );

        // StatefulSet pod DNS - SHORT FORM without .svc suffix (e.g., curl http://mysql-0.mysql.default:3306/)
        let query = DnsQuery::parse(&build_test_query("mysql-0.mysql.default")).unwrap();
        assert_eq!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Pod(PodDnsInfo::StatefulSet {
                pod_name: "mysql-0".to_string(),
                service: "mysql".to_string(),
                namespace: "default".to_string(),
            })
        );
    }

    #[test]
    fn test_parse_k8s_query_service_not_pod() {
        let handler = DnsHandler::new(make_namespace_set(vec!["default"]));

        // Regular service DNS should be recognized as Service, not Pod
        let query =
            DnsQuery::parse(&build_test_query("backend.default.svc.cluster.local")).unwrap();
        assert_eq!(
            handler.parse_k8s_query(&query),
            K8sQueryType::Service {
                name: "backend".to_string(),
                namespace: "default".to_string()
            }
        );
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
