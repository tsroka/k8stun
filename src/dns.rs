//! DNS packet parsing and response building.
//!
//! This module handles intercepting DNS queries for Kubernetes services
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

            let parts: Vec<&str> = question.name.split('.').collect();
            if parts.len() != 2 {
                return false;
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

    /// Extracts the service name and namespace from a DNS query.
    /// Lock-free read via ArcSwap - just loads the current snapshot.
    pub fn extract_service_info(&self, query: &DnsQuery) -> Option<(String, String)> {
        let namespaces = self.namespaces.load();

        for question in query.questions() {
            if question.qtype != RecordType::A {
                continue;
            }

            let name = question.name.trim_end_matches('.');

            // Try to parse as service.namespace.svc.cluster.local
            if let Some(stripped) = name.strip_suffix(".svc.cluster.local") {
                let parts: Vec<&str> = stripped.splitn(2, '.').collect();
                if parts.len() == 2 {
                    return Some((parts[0].to_string(), parts[1].to_string()));
                }
            }

            // Try to parse as service.namespace.svc
            if let Some(stripped) = name.strip_suffix(".svc") {
                let parts: Vec<&str> = stripped.splitn(2, '.').collect();
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
