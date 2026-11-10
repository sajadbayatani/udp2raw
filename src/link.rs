//! Link-layer transmit on Linux. SOCK_DGRAM adds the Ethernet header for us.
use std::str::FromStr;

// The portable CLI validates the same syntax before reporting that L2 is Linux-only.
#[cfg_attr(
    any(not(target_os = "linux"), feature = "pcap-client"),
    allow(dead_code)
)]
#[derive(Clone, Debug)]
pub enum LinkMode {
    Auto,
    Manual { interface: String, mac: [u8; 6] },
}

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut octets = text.split(':');
    let mut result = [0; 6];
    for byte in &mut result {
        let hex = octets.next()?;
        if hex.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(hex, 16).ok()?;
    }
    octets.next().is_none().then_some(result)
}

impl FromStr for LinkMode {
    type Err = String;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == "auto" {
            return Ok(Self::Auto);
        }
        let (interface, address) = text.split_once('#').ok_or("use auto or INTERFACE#MAC")?;
        if interface.is_empty() || interface.len() >= 16 || interface.contains(['/', '\0']) {
            return Err("invalid interface name".into());
        }
        Ok(Self::Manual {
            interface: interface.into(),
            mac: parse_mac(address).ok_or("expected six hexadecimal MAC octets")?,
        })
    }
}

#[cfg(all(target_os = "linux", not(feature = "pcap-client")))]
pub use linux::Sender;

#[cfg(all(target_os = "linux", not(feature = "pcap-client")))]
mod linux {
    use super::{parse_mac, LinkMode};
    use std::{
        collections::HashMap,
        ffi::CString,
        io,
        net::{IpAddr, SocketAddr},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        process::Command,
        sync::Mutex,
        time::{Duration, Instant},
    };
    use tokio::io::unix::AsyncFd;

    #[derive(Clone, Copy)]
    struct Hop {
        index: i32,
        mac: [u8; 6],
    }

    impl Hop {
        fn new(interface: &str, mac: [u8; 6]) -> io::Result<Self> {
            let name = CString::new(interface)?;
            // if_nametoindex reads the NUL-terminated string during this call.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                index: index as i32,
                mac,
            })
        }
    }

    fn ip(args: &[&str]) -> io::Result<String> {
        let output = Command::new("ip").args(args).output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "ip {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn value_after<'a>(text: &'a str, key: &str) -> Option<&'a str> {
        let mut words = text.split_whitespace();
        words.find(|word| *word == key)?;
        words.next()
    }

    fn discover(source: IpAddr, destination: IpAddr) -> io::Result<Hop> {
        let family = if destination.is_ipv4() { "-4" } else { "-6" };
        let (dest, src) = (destination.to_string(), source.to_string());
        let route = ip(&[family, "route", "get", &dest, "from", &src])?;
        let interface = value_after(&route, "dev")
            .ok_or(io::Error::other("no output interface on link route"))?;
        let flags = std::fs::read_to_string(format!("/sys/class/net/{interface}/flags"))?;
        let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
            .map_err(|_| io::Error::other("invalid interface flags"))?;
        if flags & (libc::IFF_NOARP | libc::IFF_LOOPBACK) as u32 != 0 {
            return Hop::new(interface, [0; 6]);
        }
        let next = value_after(&route, "via").unwrap_or(&dest);
        let neighbor = || -> io::Result<Option<[u8; 6]>> {
            let record = ip(&[family, "neigh", "show", "to", next, "dev", interface])?;
            Ok(value_after(&record, "lladdr").and_then(parse_mac))
        };
        let mac = match neighbor()? {
            Some(mac) => mac,
            None => {
                // Initiate ARP/ND on a cold cache. Only the neighbor entry matters,
                // so gateways that discard the echo request still work.
                let _ = Command::new("ping")
                    .args([family, "-n", "-c", "1", "-W", "1", "-I", interface, next])
                    .output();
                neighbor()?.ok_or_else(|| {
                    io::Error::other(format!(
                        "no link address for {next} on {interface}; supply INTERFACE#MAC"
                    ))
                })?
            }
        };
        Hop::new(interface, mac)
    }

    type CachedRoutes = HashMap<(IpAddr, IpAddr), (Instant, Hop)>;
    pub struct Sender {
        socket: AsyncFd<OwnedFd>,
        manual: Option<Hop>,
        routes: Mutex<CachedRoutes>,
    }

    impl Sender {
        pub fn new(mode: &LinkMode) -> io::Result<Self> {
            let manual = match mode {
                LinkMode::Auto => None,
                LinkMode::Manual { interface, mac } => Some(Hop::new(interface, *mac)?),
            };
            // Protocol zero makes this a send-only descriptor.
            let fd = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // This nonblocking descriptor is exclusively owned and remains registered
            // with this AsyncFd until it is dropped.
            let socket =
                unsafe { AsyncFd::register(OwnedFd::from_raw_fd(fd)) }.map_err(io::Error::from)?;
            Ok(Self {
                socket,
                manual,
                routes: Mutex::new(HashMap::new()),
            })
        }

        async fn next_hop(&self, source: IpAddr, dest: IpAddr) -> io::Result<Hop> {
            if let Some(hop) = self.manual {
                return Ok(hop);
            }
            let key = (source, dest);
            if let Some((time, hop)) = self.routes.lock().unwrap().get(&key).copied() {
                if time.elapsed() < Duration::from_secs(30) {
                    return Ok(hop);
                }
            }
            let hop = tokio::task::spawn_blocking(move || discover(source, dest)).await??;
            let mut routes = self.routes.lock().unwrap();
            if routes.len() >= 1024 {
                routes.clear();
            }
            routes.insert(key, (Instant::now(), hop));
            Ok(hop)
        }

        pub async fn send(
            &self,
            packet: &[u8],
            source: IpAddr,
            peer: SocketAddr,
        ) -> io::Result<()> {
            let hop = self.next_hop(source, peer.ip()).await?;
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            addr.sll_family = libc::AF_PACKET as _;
            addr.sll_protocol = (if peer.is_ipv4() {
                libc::ETH_P_IP
            } else {
                libc::ETH_P_IPV6
            } as u16)
                .to_be();
            addr.sll_ifindex = hop.index;
            addr.sll_halen = 6;
            addr.sll_addr[..6].copy_from_slice(&hop.mac);
            loop {
                let mut ready = self.socket.writable().await?;
                let result = ready.try_io(|fd| {
                    // Both buffers live through sendto. sockaddr_ll carries the validated interface and next hop.
                    let n = unsafe {
                        libc::sendto(
                            fd.get_ref().as_raw_fd(),
                            packet.as_ptr().cast(),
                            packet.len(),
                            0,
                            (&addr as *const libc::sockaddr_ll).cast(),
                            std::mem::size_of_val(&addr) as _,
                        )
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else if n as usize != packet.len() {
                        Err(io::Error::other("short packet socket write"))
                    } else {
                        Ok(())
                    }
                });
                if let Ok(sent) = result {
                    return sent;
                }
            }
        }
    }
}
