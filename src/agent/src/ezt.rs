extern crate socket2;

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::task::{self, JoinHandle};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time::{sleep, Duration};

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

    pub fn start_ezt_handler(&mut self, sndbx_id: String) ->Result<()> {
        // In order to setup ezt wireguard peers, we need ip addresses.
        // Idea is to setup a UdpSocket to multicast such intent with
        // public-key:label:eth0_ip as the payload.
        // When such message is received, the listener will parse it and
        // for now temporarily add it to a known list of peers.
        // The sender will periodically multicast its own data.
        // Since we do not know the order in which the pods will be created, trying
        // this in to setup the wireguard interfaces.
        // TO-DO: This is a POC only implementation.
        warn!(sl(), "EZT: EztHandler: setup listener");
        let multi_addr = SocketAddr::new(*IPV4, PORT);
        let listener_sock = setup_listener(multi_addr)?;
        let async_listener_sock = TokioUdpSocket::from_std(listener_sock)?;
        self.handle.push(task::spawn(listen_task(async_listener_sock, sndbx_id.clone())));

        warn!(sl(), "EZT: EztHandler: setup sender");
        let sender_sock = setup_sender(multi_addr)?;
        let async_sender_sock = TokioUdpSocket::from_std(sender_sock)?;
        self.handle.push(task::spawn(send_task(async_sender_sock, multi_addr, sndbx_id)));

        warn!(sl(), "EZT: EztHandler: ezt handlers are setup");

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
                multi_addr, &Ipv4Addr::new(0, 0, 0, 0)
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
                &Ipv4Addr::new(0, 0, 0, 0))
                .map_err(|e| anyhow!("EZT: setup_sender: Failed to join multicast: {}",e))?;
        }
        IpAddr::V6(_) => {
            return Err(anyhow!("EZT: setup_sender: Ipv6 is not supported"));
        }
    };

    socket.bind(&SockAddr::from(SocketAddr::new(
                Ipv4Addr::new(0, 0, 0, 0).into(),
                0,))).map_err(|e| anyhow!("EZT: setup_sender: Failed to bind socket: {}", e))?;

    warn!(sl(), "EZT: setup_sender success!");
    Ok(socket.into())
}

async fn listen_task(sock: TokioUdpSocket, sndbx_id: String) {
    warn!(sl(), "EZT: listen_task");
    // TO-DO: For now, we only see if the data being sent is already cached by us.
    // If not, add it.
    let mut peer_data = HashMap::new();

    let mut buf = vec![0u8; 1024];

    loop {
        // This is one messy match pattern, but not trying to return errors here.
        match sock.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                warn!(sl(), "EZT: listen_task: Received len:{:?} from addr:{:?}", len, addr);
                let data = &buf[..len];
                match String::from_utf8(data.to_vec()) {
                    Ok(payload) => {
                        // TO-DO: Format of payload=> sandbox-id:pubkey:label
                        let v: Vec<&str> = payload.split(':').collect();
                        if v.len() != 3 {
                            warn!(sl(), "EZT: listen_task: Payload not in expected format");
                        } else {
                            warn!(sl(), "EZT: listen_task sandbox {:?}: Payload: pubkey: {:?}  label: {:?}  sndbx_id:{:?}", sndbx_id, v[1], v[2], v[0]);
                            if !peer_data.contains_key(v[0]) {
                                peer_data.insert(v[0].to_string(), v[1].to_string());
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

async fn send_task(sock: TokioUdpSocket, addr: SocketAddr, mut sndbx_id: String) {
    warn!(sl(), "EZT: send_task");
    // TO-DO: Change it later to pod specific values
    let label_data = ":PubKeyPod:test=Multicast";
    sndbx_id.push_str(label_data);
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
