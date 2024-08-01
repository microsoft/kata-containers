// Parse the network policy
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs};

#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(rename="apiVersion")]
    #[serde(default)]
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: Option<PolicyRule>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Metadata {
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    labels: HashMap<String, String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct PolicyRule {
    #[serde(default)]
    ingress: Option<Vec<IngressRule>>,
    #[serde(default)]
    egress: Option<Vec<EgressRule>>,
    #[serde(rename="podSelector")]
    #[serde(default)]
    pod_selector: LabelSelector,
    #[serde(rename="policyTypes")]

    #[serde(default)]
    policy_types: Option<Vec<String>>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct LabelSelector {
    #[serde(rename="matchLabels")]
    #[serde(default)]
    match_labels: HashMap<String, String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct IngressRule {
    #[serde(default)]
    from: Option<Vec<NetworkPolicyPeers>>,
    #[serde(default)]
    ports: Option<Vec<Port>>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct EgressRule {
    #[serde(default)]
    to: Option<Vec<NetworkPolicyPeers>>,
    #[serde(default)]
    ports: Option<Vec<Port>>,
}

// TO-DO: Does not implement named port
//        Does not support end_port range
#[derive(Clone, Default, Serialize, Deserialize)]
struct Port {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    port: Option<u32>,
}

// TO-DO: DOes not handle IP blocks (CIDR)
#[derive(Clone, Default, Serialize, Deserialize)]
struct NetworkPolicyPeers {
    #[serde(rename="namespaceSelector")]
    #[serde(default)]
    namespace_selector: Option<LabelSelector>,
    #[serde(rename="podSelector")]
    #[serde(default)]
    pod_selector: Option<LabelSelector>,
}

pub const NETWORK_POLICY_FILE : &str = "/tmp/eztnetworkpolicy.txt";
pub const API_VERSION: &str = "networking.k8s.io/v1";
pub const KIND: &str = "NetworkPolicy";
//pub const DEF_NAMESPACE: &str = "default";

// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger()
}

impl NetworkPolicy {
    pub fn validate_policy(&self) -> bool {
        if !self.api_version.contains(API_VERSION) || !self.kind.contains(KIND) {
            warn!(sl(), "EZT: validate_policy: Missing apiVersion or Kind string");
            return false;
        }

        if self.spec.is_none() {
            warn!(sl(), "EZT: validate_policy: missing spec");
            return false;
        }

        if self.metadata.labels.is_empty() || self.metadata.labels.len() != 1 {
            warn!(sl(), "EZT: validate_policy: missing self labels or has more than desired entry");
            return false;
        }

        true
    }

    pub fn get_self_label(&self) -> (String, String) {
        let mut label_key = String::new();
        let mut label_val: String = String::new(); 
        for (key, val) in self.metadata.labels.iter() {
            label_key = key.to_string();
            label_val = val.to_string();
        }

        warn!(sl(), "EZT: get_self_label: key:{} value:{}", label_key, label_val);
        (label_key, label_val)
    }

    // The network policy metadata contains pods own labels.
    // Determine if this label is part of podSelector list.
    pub fn is_in_pod_selector(&self, label: (&str, &str)) -> bool {
        warn!(sl(), "EZT: network_policy: is_in_pod_selector");
        
        // Option::None is handled in validate_policy
        let spec = self.spec.as_ref().unwrap();

        // TO-DO: Add pods namespace handling, for now assuming all are in the
        // same namespace
        if spec.pod_selector.match_labels.is_empty() {
            warn!(sl(), "EZT: is_in_pod_selector: Pod selector is empty, selecting this pod to apply policy");
            return true;
        } else {
            match spec.pod_selector.match_labels.get_key_value(label.0) {
                Some((_, &ref v)) => {
                    if v.eq(&label.1) {
                        warn!(sl(), "EZT: is_in_pod_selector: The label is in pod selector");
                        return true;
                    }
                }
                None => warn!(sl(), "EZT: is_in_pod_selector: The label is not in pod selector"),
            }
        }
        false
    }

    pub fn is_peer_allowed(&self, label: (&str, &str)) -> bool {
        warn!(sl(), "EZT: network_policy: is_peer_allowed");

        let mut matches = false;

        // This label can either be part of ingress/egress block
        let spec = self.spec.as_ref().unwrap();
        match &spec.policy_types {
            Some(pt) => {
                for type_str in pt.iter() {
                    if type_str.eq("ingress") {
                        matches = self.is_in_ingress(label);
                    } else {
                        matches = self.is_in_egress(label);
                    }
                }
            }
            None => {
                warn!(sl(), "EZT: is_peer_allowed: policy type is missing, taking ingress as default");
                // Check against ingress blocks
                matches = self.is_in_ingress(label);
            }
        }

        matches
    }

    fn is_in_ingress(&self, label: (&str, &str)) -> bool {
        warn!(sl(), "EZT: network_policy: is_in_ingress");
        let spec = self.spec.as_ref().unwrap();
        if spec.ingress.is_none() {
            warn!(sl(), "EZT: is_in_ingress: ingress block is not present, this means a default deny rule");
        } else {
            let ingress_block = spec.ingress.as_ref().unwrap();
            if ingress_block.len() == 0 {
                warn!(sl(), "EZT: is_in_ingress: ingress block is empty, default allow all");
                return true;
            }
            for peer_from in ingress_block.iter() {
                match &peer_from.from {
                    Some(peers) => {
                        if peers.len() == 0 {
                            warn!(sl(), "EZT: is_in_ingress: peer len is zero");
                            return true;
                        }

                        for pods_list in peers.iter() {
                            match &pods_list.pod_selector {
                                Some(match_list) => {
                                    if match_list.match_labels.is_empty() {
                                        warn!(sl(), "EZT: is_in_ingress`: pod_selector match labels list is empty");
                                        return true;
                                    }
                                    match match_list.match_labels.get_key_value(label.0) {
                                        Some((_, &ref v)) => {
                                            if v.eq(&label.1) {
                                                return true;
                                            }
                                        }
                                        None => warn!(sl(), "EZT: is_in_ingress: The label is not in pod selector"),
                                    }
                                }
                                None => {
                                    warn!(sl(), "EZT: is_in_ingress: pod_selector list is empty");
                                    return true;
                                }
                            }
                        }
                    }
                    None => {
                        warn!(sl(), "EZT: is_in_ingress: peer from block is not present");
                        return true;
                    }
                }
            }
        }

        false
    }

    fn is_in_egress(&self, label: (&str, &str)) -> bool {
        warn!(sl(), "EZT: network_policy: is_in_egress");
        let spec = self.spec.as_ref().unwrap();
        if spec.egress.is_none() {
            warn!(sl(), "EZT: is_in_egress: egress block is not present, this means a default deny rule");
        } else {
            let egress_block = spec.egress.as_ref().unwrap();
            if egress_block.len() == 0 {
                warn!(sl(), "EZT: is_in_egress: egress block is empty, default allow all");
                return true;
            }
            for peer_to in egress_block.iter() {
                match &peer_to.to {
                    Some(peers) => {
                        if peers.len() == 0 {
                            warn!(sl(), "EZT: is_in_egress: peer len is zero");
                            return true;
                        }

                        for pods_list in peers.iter() {
                            match &pods_list.pod_selector {
                                Some(match_list) => {
                                    if match_list.match_labels.is_empty() {
                                        warn!(sl(), "EZT: is_in_egress: pod_selector match labels list is empty");
                                        return true;
                                    }
                                    match match_list.match_labels.get_key_value(label.0) {
                                        Some((_, &ref v)) => {
                                            if v.eq(&label.1) {
                                                return true;
                                            }
                                        }
                                        None => warn!(sl(), "EZT: is_in_egress: The label is not in pod selector"),
                                    }
                                }
                                None => {
                                    warn!(sl(), "EZT: is_in_egress: pod_selector list is empty");
                                    return true;
                                }
                            }
                        }
                    }
                    None => {
                        warn!(sl(), "EZT: is_in_egress: peer to block is not present");
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn get_ingress_ports(&mut self) -> HashMap<String, Vec<u32>>{
        warn!(sl(), "EZT: get_ingress_ports");
        let mut ingress_ports: HashMap<String, Vec<u32>> = HashMap::new();
        let spec = self.spec.as_mut().unwrap();
        if spec.ingress.is_some() {
            let rules = spec.ingress.as_mut().unwrap();
            for rule in rules.iter_mut() {
                if rule.from.is_some() && rule.from.as_ref().unwrap().len() != 0 {
                    if rule.ports.is_some() && rule.ports.as_ref().unwrap().len() > 0 {
                        warn!(sl(), "EZT: get_ingress_ports: port information is present, parsing it");
                        let ports = rule.ports.as_mut().unwrap();
                        for entry in ports.iter_mut() {
                            if entry.port.is_some() {
                                let port_val = entry.port.take().unwrap();
                                warn!(sl(), "EZT: get_ingress_ports: entry port is present for protocol: {} port:{}", entry.protocol, port_val);
                                if ingress_ports.contains_key(&entry.protocol) {
                                    ingress_ports.get_mut(&entry.protocol).as_mut().unwrap().push(port_val);
                                } else {
                                    ingress_ports.insert(entry.protocol.clone(), vec![port_val]);
                                }
                            }
                        }
                    }
                }
            }
        }
        ingress_ports
    }

    pub fn get_egress_ports(&mut self) -> HashMap<String, Vec<u32>>{
        warn!(sl(), "EZT: get_egress_ports");
        let mut egress_ports: HashMap<String, Vec<u32>> = HashMap::new();
        let spec = self.spec.as_mut().unwrap();
        if spec.egress.is_some() {
            let rules = spec.egress.as_mut().unwrap();
            for rule in rules.iter_mut() {
                if rule.to.is_some() && rule.to.as_ref().unwrap().len() != 0 {
                    if rule.ports.is_some() && rule.ports.as_ref().unwrap().len() > 0 {
                        warn!(sl(), "EZT: get_egress_ports: port information is present, parsing it");
                        let ports = rule.ports.as_mut().unwrap();
                        for entry in ports.iter_mut() {
                            if entry.port.is_some() {
                                let port_val = entry.port.take().unwrap();
                                warn!(sl(), "EZT: get_egress_ports: entry port is present for protocol: {} port:{}", entry.protocol, port_val);
                                if egress_ports.contains_key(&entry.protocol) {
                                    egress_ports.get_mut(&entry.protocol).as_mut().unwrap().push(port_val);
                                } else {
                                    egress_ports.insert(entry.protocol.clone(), vec![port_val]);
                                }
                            }
                        }
                    }
                }
            }
        }
        egress_ports
    }
}

pub fn parse_network_policy() -> Result<NetworkPolicy>{
    let yaml_policy_data = fs::read_to_string(NETWORK_POLICY_FILE)?;
    let policy = serde_yaml::from_str::<NetworkPolicy>(&yaml_policy_data).map_err(|e| anyhow!("EZT: Failed to parse network policy file {}", e))?;
    Ok(policy)
}
