extern crate socket2;
extern crate nix;

use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::task::{self, JoinHandle};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time::{sleep, Duration};
use std::fs::File;
use std::process::Command;
use serde::{Deserialize, Serialize};
use std::fs;
use std::collections::HashMap;
use std::path::Path;
use nix::sched::{setns, CloneFlags};
use std::os::unix::io::AsRawFd;
use self::network_policy::{NetworkPolicy, parse_network_policy};

mod network_policy;

#[derive(Debug, Default, Serialize, Deserialize)]
struct InterfaceSettings {
    eth_ip: String,
    veth_defns_end_ip: String,
    veth_eztns_end_ip: String,
    wg_ip: String,
    wg_port: String,
    wg_pub_key:String,
}

impl InterfaceSettings {
    pub fn is_valid(&self) -> bool {
        if self.eth_ip.is_empty() ||
            self.veth_defns_end_ip.is_empty() ||
            self.veth_eztns_end_ip.is_empty() ||
            self.wg_ip.is_empty() ||
            self.wg_port.is_empty() ||
            self.wg_pub_key.is_empty() {
            return false;
        }

        true
    }
}

pub const NETWORK_POLICY_FILE : &str = "/tmp/eztnetworkpolicy.txt";
// Choosing a random port
pub const PORT: u16 = 51850;
lazy_static! {
    // Using a broadcast address from link-local address
    pub static ref IPV4: IpAddr = Ipv4Addr::new(224, 0, 0, 123).into();
}

#[derive(Debug, Default)]
pub struct EztHandler {
    handle: Vec<JoinHandle<()>>,
}

impl EztHandler {
    pub fn new() -> EztHandler {
        warn!(sl(), "EZT: EztHandler::new");
        EztHandler {
            handle: vec![],
        }
    }

    // In order to setup ezt wireguard peers, we need ip addresses.
    // Idea is to setup a UdpSocket to multicast such intent with
    // the required payload.
    // When such message is received, the listener will parse it and
    // add peers to configure wireguard.
    // The sender will periodically multicast its own data.
    // Since we do not know the order in which the pods will be created, trying
    // this in to setup the wireguard interfaces.
    // TO-DO: This is a POC only implementation.
    pub fn start_ezt_handler(&mut self, sndbx_id: String) ->Result<()> {
        warn!(sl(), "EZT: EztHandler: Get the Network Policy File");

        // Check if the network policy file path exists.
        // If not, don't setup EZT.
        if Path::new(NETWORK_POLICY_FILE).exists() {
            let mut policy_data = parse_network_policy()?;
            if !policy_data.validate_policy() {
                return Err(anyhow!("EZT: Invalid network policy format"));
            }

            // Self Pod label
            let podlabel = policy_data.get_self_label();
            // determine if this pod is selected by the policy.
            let pod_selected = policy_data.is_in_pod_selector((&podlabel.0, &podlabel.1));
            // if not, is this pod in the ingress/egress block
            let mut pod_selected_as_peer = false;
            if !pod_selected {
                pod_selected_as_peer = policy_data.is_peer_allowed((&podlabel.0, &podlabel.1));
            }
            // TO-DO: Adding peers is needed for configuring wireguard.
            // network policy works as 'from/to' AND 'port'.
            // So, if any valid entry is present, we look at all port rules.
            let from_ports = policy_data.get_ingress_ports();
            let to_ports = policy_data.get_egress_ports();

            warn!(sl(), "EZT: EztHandler: run EZT Namespace Isolation Script");
            copy_ezt_scripts()?;
            let ezt_interfaces = run_ezt_script()?;

            // Need to run the multicast sender/listener in the eztns.
            let original_ns = File::open("/proc/self/ns/net").map_err(|e| anyhow!("Failed to open default net ns: {}", e))?;
            let ns_file = File::open("/var/run/netns/eztns").map_err(|e| anyhow!("Failed to open eztns net ns: {}", e))?;
            setns(ns_file.as_raw_fd(), CloneFlags::CLONE_NEWNET).map_err(|e| anyhow!("Failed to clone new network namespace: {}", e))?;
    
            warn!(sl(), "EZT: EztHandler: setup listener");
            let multi_addr = SocketAddr::new(*IPV4, PORT);
            let listener_sock = setup_listener(multi_addr)?;
            let async_listener_sock = TokioUdpSocket::from_std(listener_sock)?;
            self.handle.push(task::spawn(listen_task(async_listener_sock, sndbx_id.clone(),policy_data, pod_selected, pod_selected_as_peer)));
    
            warn!(sl(), "EZT: EztHandler: setup sender");
            let sender_sock = setup_sender(multi_addr)?;
            let async_sender_sock = TokioUdpSocket::from_std(sender_sock)?;
            self.handle.push(task::spawn(send_task(async_sender_sock, multi_addr, sndbx_id, ezt_interfaces, podlabel)));
    
            setns(original_ns.as_raw_fd(), CloneFlags::CLONE_NEWNET).map_err(|e| anyhow!("Failed to set back original net namespace: {}", e))?;
            if pod_selected {
                handle_port(from_ports, to_ports)?;
            }
            warn!(sl(), "EZT: EztHandler: ezt handlers are setup");
        } else {
            warn!(sl(), "EZT: EztHandler: Network Policy File does not exist, not setting ezt");
        }

        Ok(())
    }

    pub fn stop_ezt_handler(&self) {
        warn!(sl(), "EZT: EztHandler: stop_ezt_handler");
        for handle in self.handle.iter() {
            handle.abort();
        }
    }
}

// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger()
}

// Store EZT Scripts in /tmp/ and make them executable
fn copy_ezt_scripts() -> Result<()> {
    let files = ["/usr/lib/eztsetup.sh"];
    let destination_folder = "/tmp/";

    for file in files.iter() {
        // TO-DO: THIS will panic
        let destination = format!("{}{}", destination_folder, file.split('/').last().unwrap());
        fs::copy(file, &destination)?;

        Command::new("chmod")
            .arg("+x")
            .arg(&destination)
            .output()?;
    }
    Ok(())
}

fn handle_port(ingress_ports: HashMap<String, Vec<u32>>, egress_ports: HashMap<String, Vec<u32>>) -> Result<()> {
    warn!(sl(), "EZT: handle_port");

    let mut ingress_ports_tcp = String::new();
    let mut egress_ports_tcp = String::new();
    let mut ingress_ports_udp = String::new();
    let mut egress_ports_udp = String::new();

    for (protocol, ports) in ingress_ports.iter() {
        for port in ports.iter() {
            let port_str = format!("{}", port);
                if protocol.eq("TCP") {
                    if !ingress_ports_tcp.is_empty() {
                        ingress_ports_tcp.push_str(",")
                    }
                    ingress_ports_tcp.push_str(port_str.as_str());
                } else if protocol.eq("UDP") {
                    if !ingress_ports_udp.is_empty() {
                        ingress_ports_udp.push_str(",")
                    }
                    ingress_ports_udp.push_str(port_str.as_str());
                }
        }
    }

    for (protocol, ports) in egress_ports.iter() {
        for port in ports.iter() {
            let port_str = format!("{}", port);
                if protocol.eq("TCP") {
                    if !egress_ports_tcp.is_empty() {
                        egress_ports_tcp.push_str(",")
                    }
                    egress_ports_tcp.push_str(port_str.as_str());
                } else if protocol.eq("UDP") {
                    if !egress_ports_udp.is_empty() {
                        egress_ports_udp.push_str(",")
                    }
                    egress_ports_udp.push_str(port_str.as_str());
                }
        }
    }

    if !ingress_ports_tcp.is_empty() {
        let ingress_tcp_cmd = format!("iptables -A INPUT -i eztif0 -p tcp --match multiport ! --dport {} -j REJECT", ingress_ports_tcp);
        warn!(sl(), "EZT: handle port: ingress_tcp_cmd: {}", ingress_tcp_cmd);
        let _ = Command::new("sh").arg("-c").arg(&ingress_tcp_cmd).output().map_err(|e| anyhow!("EZT: handle_port Failed to set ingress tcp ports rules {}", e))?;
    }

    if !ingress_ports_udp.is_empty() {
        let ingress_udp_cmd = format!("iptables -A INPUT -i eztif0 -p udp --match multiport ! --dport {} -j REJECT", ingress_ports_udp);
        warn!(sl(), "EZT: handle port: ingress_udp_cmd: {}", ingress_udp_cmd);
        let _ = Command::new("sh").arg("-c").arg(&ingress_udp_cmd).output().map_err(|e| anyhow!("EZT: handle_port Failed to set ingress tcp ports rules {}", e))?;
    }

    if !egress_ports_tcp.is_empty() {
        let egress_tcp_cmd = format!("iptables -A OUTPUT -o eztif0 -p tcp --match multiport ! --dport {} -j REJECT", ingress_ports_tcp);
        warn!(sl(), "EZT: handle port: egress_tcp_cmd: {}", egress_tcp_cmd);
        let _ = Command::new("sh").arg("-c").arg(&egress_tcp_cmd).output().map_err(|e| anyhow!("EZT: handle_port Failed to set ingress tcp ports rules {}", e))?;
    }

    if !egress_ports_tcp.is_empty() {
        let egress_udp_cmd = format!("iptables -A OUTPUT -o eztif0 -p udp --match multiport ! --dport {} -j REJECT", ingress_ports_tcp);
        warn!(sl(), "EZT: handle port: egress_udp_cmd: {}", egress_udp_cmd);
        let _ = Command::new("sh").arg("-c").arg(&egress_udp_cmd).output().map_err(|e| anyhow!("EZT: handle_port Failed to set ingress tcp ports rules {}", e))?;
    }

    Ok(())
}

fn run_ezt_script() -> Result<InterfaceSettings>{
    let script_path = "/tmp/eztsetup.sh";
    let output = Command::new("sh")
                        .arg(&script_path)
                        .output()
                        .map_err(|e| anyhow!("failed to run command: {}", e))?;

    if !output.status.success() {
        warn!(sl(), "EZT: Failed to run ezt setup script {}", String::from_utf8(output.stdout)?);
        warn!(sl(), "EZT: Failed to run ezt setup script {}", String::from_utf8(output.stderr)?);
        return Err(anyhow!("EZT: Failed to setup ezt"));
    }

    let output_str = String::from_utf8(output.stdout)?;

    let mut ezt_interfaces = InterfaceSettings::default();

    for line in output_str.lines().into_iter() {
        let v: Vec<&str> = line.split(' ').collect();

        if v.len() != 2 {
            continue;
        }

        match v[0] {
            "eth0_ip" =>  ezt_interfaces.eth_ip = v[1].to_string(),
            "eztif0_ip" => ezt_interfaces.veth_defns_end_ip = v[1].to_string(),
            "eztif1_ip" => ezt_interfaces.veth_eztns_end_ip = v[1].to_string(),
            "wg_ip" => ezt_interfaces.wg_ip = v[1].to_string(),
            "wgport" => ezt_interfaces.wg_port = v[1].to_string(),
            "wgpublickey" => ezt_interfaces.wg_pub_key = v[1].to_string(),
            _ => (),
            
        }
    }

    if !ezt_interfaces.is_valid() {
        warn!(sl(), "EZT: Interface struct is not valid");
        return Err(anyhow!("EZT: Failed to populate interfaces struct"));
    }

    warn!(sl(), "EZT: ezt interface setup complete");
    Ok(ezt_interfaces)
}

// Helper function to construct a socket instance.
fn new_socket(addr: &SocketAddr) -> Result<Socket> {
    warn!(sl(), "EZT: new_socket");
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        error!(sl(), "EZT: new_socket: Only Ipv4 domain is supported");
        return Err(anyhow!("EZT: Invalid ip domain"));
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                        .map_err(|e| anyhow!("EZT: new_socket: Unable to create a socket instance with err: {}", e))?;

    socket.set_reuse_address(true).map_err(|e| anyhow!("EZT: Failed to set reuse address: {}", e))?;
    socket.set_nonblocking(true)?;

    warn!(sl(), "EZT: new_socket success!!");
    Ok(socket)
}

fn setup_listener(addr: SocketAddr) -> Result<UdpSocket> {
    warn!(sl(), "EZT: setup_listener");
    let ipaddr = addr.ip();

    let socket = new_socket(&addr)?;
    match ipaddr {
        IpAddr::V4(ref multi_addr) => {
            socket.join_multicast_v4(
                multi_addr, &Ipv4Addr::UNSPECIFIED
                ).map_err(|e| anyhow!("EZT: Failed to join multicast: {}",e))?;
        }
        IpAddr::V6(_) => {
            return Err(anyhow!("EZT: setup_listener: Ipv6 is not supported"));
        }
    };

    socket.bind(
        &SockAddr::from(addr))
        .map_err(|e| anyhow!("EZT: setup_listener: Failed to bind socket: {}", e))?;

    warn!(sl(), "EZT: setup_listener success!");
    Ok(socket.into())
}

fn setup_sender(addr: SocketAddr) -> Result<UdpSocket> {
    warn!(sl(), "EZT: setup_sender");
    let ipaddr = addr.ip();

    let socket = new_socket(&addr)?;
    match ipaddr {
        IpAddr::V4(_) => {
            socket.set_multicast_if_v4(
                &Ipv4Addr::UNSPECIFIED)
                .map_err(|e| anyhow!("EZT: setup_sender: Failed to join multicast: {}",e))?;
        }
        IpAddr::V6(_) => {
            return Err(anyhow!("EZT: setup_sender: Ipv6 is not supported"));
        }
    };

    socket.bind(&SockAddr::from(SocketAddr::new(
                Ipv4Addr::UNSPECIFIED.into(),
                0,))).map_err(|e| anyhow!("EZT: setup_sender: Failed to bind socket: {}", e))?;

    warn!(sl(), "EZT: setup_sender success!");
    Ok(socket.into())
}

async fn listen_task(sock: TokioUdpSocket, sndbx_id: String, policy: NetworkPolicy, pod_selected: bool, pod_selected_as_peer: bool) {
    warn!(sl(), "EZT: listen_task");

    let mut buf = vec![0u8; 1024];
    loop {
        // This is one messy match pattern, but not trying to return errors here.
        match sock.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                warn!(sl(), "EZT: listen_task: Received len:{:?} from addr:{:?}", len, addr);
                let data = &buf[..len];
                match String::from_utf8(data.to_vec()) {
                    Ok(payload) => {
                        let v: Vec<&str> = payload.split(':').collect();
                        if v.len() != 8 {
                            warn!(sl(), "EZT: listen_task: Payload not in expected format");
                        } else {
                            warn!(sl(), "EZT: listen_task sandbox {:?}: Payload: endpointip: {:?} endpointport: {:?} allowedip: {:?} publickey: {:?} podlabel: {:?}  sndbx_id:{:?}", sndbx_id, v[1], v[2], v[3], v[4], v[5], v[0]);
                            let label_k = v[5].to_string();
                            let label_v = v[6].to_string();

                            if (pod_selected && policy.is_peer_allowed((&label_k, &label_v))) ||
                                (pod_selected_as_peer && policy.is_in_pod_selector((&label_k, &label_v))) {
                                    warn!(sl(), "Setting label {}:{} as peer", label_k, label_v);
                                    let peerscript = format!("ip netns exec eztns wg set wg0 peer {} allowed-ips {} endpoint {}:{}", v[4],v[3],v[1],v[2]);
                                    let _ = Command::new("sh").arg("-c").arg(&peerscript).output().expect("EZT: Failed to Configure Wireguard");
                            }
                        }
                    }
                    Err(_) => {
                        info!(sl(), "EZT: listen_task: Failed to convert data to string");
                    }
                }
            }
            Err(e) => warn!(sl(), "EZT: listen_task: Failed to receive data on socket: {:?}", e)
        }
    }
}

async fn send_task(sock: TokioUdpSocket, addr: SocketAddr, mut sndbx_id: String, ezt_if: InterfaceSettings, podlabel: (String, String)) {
    warn!(sl(), "EZT: send_task");
    let allowed_ip = format!("{}/32,{}/32,{}/32", ezt_if.eth_ip ,ezt_if.veth_defns_end_ip ,ezt_if.wg_ip);
    let label = format!("{}:{}", podlabel.0, podlabel.1);
    let label_data = format!(":{}:{}:{}:{}:{}:{}", ezt_if.eth_ip, ezt_if.wg_port, allowed_ip, ezt_if.wg_pub_key, label,ezt_if.veth_defns_end_ip);
    sndbx_id.push_str(&label_data);
    let mut buf = sndbx_id.as_bytes();
    loop {
        warn!(sl(), "EZT: send_task loop");
        match sock.send_to(&mut buf, &addr).await {
            Ok(len) => warn!(sl(), "EZT: send_task: Successfully sent size {:?}", len),
            Err(e) => warn!(sl(), "EZT: send_task: Error sending data on socket: {:?}", e),
        };
        sleep(Duration::from_millis(10000)).await;
    }
}
