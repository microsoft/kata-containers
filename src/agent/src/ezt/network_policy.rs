// Parse the network policy
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs};

#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(rename="apiVersion")]
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: Option<PolicyRule>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Metadata {
    name: String,  
    namespace: String,
    labels: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PolicyRule {
    ingress: Option<Vec<IngressRule>>,
    egress: Option<Vec<EgressRule>>,
    #[serde(rename="podSelector")]
    pod_selector: LabelSelector,
    #[serde(rename="policyTypes")]
    policy_types: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct LabelSelector {
    #[serde(rename="matchLabels")]
    match_labels: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct IngressRule {
    from: Option<Vec<NetworkPolicyPeers>>,
    ports: Option<Vec<Port>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct EgressRule {
    to: Option<Vec<NetworkPolicyPeers>>,
    ports: Option<Vec<Port>>,
}

// TO-DO: Does not implement named port
//        Does not support end_port range
#[derive(Clone, Serialize, Deserialize)]
struct Port {
    protocol: String,
    port: Option<u32>,
}

// TO-DO: DOes not handle IP blocks (CIDR)
#[derive(Clone, Serialize, Deserialize)]
struct NetworkPolicyPeers {
    #[serde(rename="namespaceSelector")]
    namespace_selector: Option<LabelSelector>,
    #[serde(rename="podSelector")]
    pod_selector: Option<LabelSelector>,
}

#[derive(Clone, Default, Debug)]
struct FromPorts {

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
            return false;
        }

        if self.spec.is_none() {
            warn!(sl(), "EZT: network_policy: missing spec");
            return false;
        }

        if self.metadata.labels.is_empty() || self.metadata.labels.len() != 1 {
            warn!(sl(), "EZT: network_policy: missing self labels or has more than desired entry");
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
            warn!(sl(), "EZT: network_policy: Pod selector is empty, selecting this pod to apply policy");
            return true;
        } else {
            match spec.pod_selector.match_labels.get_key_value(label.0) {
                Some((_, &ref v)) => {
                    if v.eq(&label.1) {
                        return true;
                    }
                }
                None => warn!(sl(), "EZT: network_policy: The label is not in pod selector"),
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
                warn!(sl(), "EZT: network_policy: policy type is missing, taking ingress as default");
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
            warn!(sl(), "EZT: network_policy: ingress block is not present, this means a default deny rule");
        } else {
            let ingress_block = spec.ingress.as_ref().unwrap();
            if ingress_block.len() == 0 {
                warn!(sl(), "EZT: network_policy: ingress block is empty, default allow all");
                return true;
            }
            for peer_from in ingress_block.iter() {
                match &peer_from.from {
                    Some(peers) => {
                        if peers.len() == 0 {
                            warn!(sl(), "EZT: network_policy: peer len is zero");
                            return true;
                        }

                        for pods_list in peers.iter() {
                            match &pods_list.pod_selector {
                                Some(match_list) => {
                                    if match_list.match_labels.is_empty() {
                                        warn!(sl(), "EZT: network_policy: pod_selector match labels list is empty");
                                        return true;
                                    }
                                    match match_list.match_labels.get_key_value(label.0) {
                                        Some((_, &ref v)) => {
                                            if v.eq(&label.1) {
                                                return true;
                                            }
                                        }
                                        None => warn!(sl(), "EZT: network_policy: The label is not in pod selector"),
                                    }
                                }
                                None => {
                                    warn!(sl(), "EZT: network_policy: pod_selector list is empty");
                                    return true;
                                }
                            }
                        }
                    }
                    None => {
                        warn!(sl(), "EZT: network_policy: peer from block is not present");
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
            warn!(sl(), "EZT: network_policy: egress block is not present, this means a default deny rule");
        } else {
            let egress_block = spec.egress.as_ref().unwrap();
            if egress_block.len() == 0 {
                warn!(sl(), "EZT: network_policy: egress block is empty, default allow all");
                return true;
            }
            for peer_to in egress_block.iter() {
                match &peer_to.to {
                    Some(peers) => {
                        if peers.len() == 0 {
                            warn!(sl(), "EZT: network_policy: peer len is zero");
                            return true;
                        }

                        for pods_list in peers.iter() {
                            match &pods_list.pod_selector {
                                Some(match_list) => {
                                    if match_list.match_labels.is_empty() {
                                        warn!(sl(), "EZT: network_policy: pod_selector match labels list is empty");
                                        return true;
                                    }
                                    match match_list.match_labels.get_key_value(label.0) {
                                        Some((_, &ref v)) => {
                                            if v.eq(&label.1) {
                                                return true;
                                            }
                                        }
                                        None => warn!(sl(), "EZT: network_policy: The label is not in pod selector"),
                                    }
                                }
                                None => {
                                    warn!(sl(), "EZT: network_policy: pod_selector list is empty");
                                    return true;
                                }
                            }
                        }
                    }
                    None => {
                        warn!(sl(), "EZT: network_policy: peer to block is not present");
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn get_ingress_ports(&self) -> HashMap<String, Vec<u32>>{
        warn!(sl(), "EZT: get_ingress_ports");
        let mut ingress_ports: HashMap<String, Vec<u32>> = HashMap::new();
        let spec = self.spec.as_ref().unwrap();
        if spec.ingress.is_some() {
            let rules = spec.ingress.as_ref().unwrap();
            for rule in rules.iter() {
                if rule.from.is_some() && rule.from.as_ref().unwrap().len() != 0 {
                    warn!(sl(), "EZT: network_policy: Some valid value present, see if we have port information as well");
                    if rule.ports.is_some() && rule.ports.as_ref().unwrap().len() > 0 {
                        // determined
                        let ports = rule.ports.as_ref().unwrap();
                        for entry in ports.iter() {
                            if entry.port.is_some() {
                                if ingress_ports.contains_key(&entry.protocol) {
                                    ingress_ports.get_mut(&entry.protocol).as_mut().unwrap().push(*entry.port.as_ref().unwrap());
                                } else {
                                    ingress_ports.insert(entry.protocol.clone(), vec![*entry.port.as_ref().unwrap()]);
                                }
                            }
                        }
                    }
                }
            }
        }
        ingress_ports
    }

    pub fn get_egress_ports(&self) -> HashMap<String, Vec<u32>>{
        warn!(sl(), "EZT: get_egress_ports");
        let mut egress_ports: HashMap<String, Vec<u32>> = HashMap::new();
        let spec = self.spec.as_ref().unwrap();
        if spec.egress.is_some() {
            let rules = spec.egress.as_ref().unwrap();
            for rule in rules.iter() {
                if rule.to.is_some() && rule.to.as_ref().unwrap().len() != 0 {
                    warn!(sl(), "EZT: network_policy: Some valid value present, see if we have port information as well");
                    if rule.ports.is_some() && rule.ports.as_ref().unwrap().len() > 0 {
                        // determined
                        let ports = rule.ports.as_ref().unwrap();
                        for entry in ports.iter() {
                            if entry.port.is_some() {
				let value = *entry.port.as_ref().unwrap();
                                if egress_ports.contains_key(&entry.protocol) {
                                    egress_ports.get_mut(&entry.protocol).as_mut().unwrap().push(value);
                                } else {
                                    egress_ports.insert(entry.protocol.clone(), vec![value]);
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
