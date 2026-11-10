use crate::{
    legacy::{Auth, Cipher},
    link::LinkMode,
};
use std::{
    collections::{HashSet, VecDeque},
    env, fmt, fs,
    io::IsTerminal,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Mode {
    FakeTcp = 0,
    Udp = 1,
    Icmp = 2,
    EasyFakeTcp = 3,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FakeTcp => "faketcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::EasyFakeTcp => "easy-faketcp",
        })
    }
}

impl FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "faketcp" => Ok(Self::FakeTcp),
            "udp" => Ok(Self::Udp),
            "icmp" => Ok(Self::Icmp),
            "easy-faketcp" | "easy_faketcp" | "easyfaketcp" => Ok(Self::EasyFakeTcp),
            _ => Err(format!("unknown carrier {s:?}")),
        }
    }
}

pub const HELP: &str = "udp2raw — multithreaded Rust UDP tunnel
  udp2raw -s -l 0.0.0.0:4096 -r 127.0.0.1:7777
  udp2raw -c -l 127.0.0.1:3333 -r 192.0.2.1:4096

  -s | -c                        Run as server or client
  -l, --local IP:PORT            Local listener (IPv6: [address]:port)
  -r, --remote IP:PORT           Tunnel peer or server-side UDP destination
  -k, --key KEY                  Shared secret; alternatively set UDP2RAW_KEY
  --conf-file PATH               Read one option and optional value per line
  --threads N                    Worker threads per process (1..256, default 4)
  --dns-resolve                  Resolve hostnames in endpoint arguments
  --protocols LIST               Client priority or server listener list
                                 Default: faketcp,udp,icmp
  --raw-mode MODE                faketcp, easy-faketcp, udp or icmp
  --easy-tcp                     Use kernel handshakes for the FakeTCP carrier
  --wire modern|legacy           Rust v1 or original udp2raw wire format
  --cipher-mode MODE             Legacy aes128cbc, aes128cfb, aes128cfb_0, xor, none
  --auth-mode MODE               Legacy md5, hmac_sha1, crc32, simple, none
  --disable-anti-replay          Disable receive sequence window checks
  --fix-gro                      Length-frame payloads to recover coalesced packets
  --heartbeat-ms N               Probe interval (default 1000)
  --timeout-ms N                 Path timeout (default 5000, >= 2 intervals)
  --hb-mode 0|1                  0: count all traffic; 1: count only heartbeats
  --hb-len N                     Heartbeat payload size (0..1500)
  --fifo PATH                    Read reconnect commands from a named pipe
  --retry-on-error               Retry startup when the network is unavailable
  --pcap-send / --no-pcap-mutex  Packet capture client options
  --source-ip IP                 Bind client carrier to this source address
  --source-port N                Bind client carrier to a fixed source port
  --dev IFACE                    Bind carrier socket to interface
  --lower-level auto|IFACE#MAC   Send frames at layer 2
  --sock-buf KiB                 Socket buffer size (10..10240)
  --force-sock-buf               Override system socket buffer caps
  --disable-bpf                  Disable kernel receive filtering
  --seq-mode N                   FakeTCP sequence policy (0..4)
  --set-ttl N                    IP TTL or IPv6 hop limit
  --random-drop N                Drop N of 10000 outgoing packets on average
  --max-rst-to-show N            Limit reset messages (-1: unlimited)
  --max-rst-allowed N            Reject a path after N resets (-1: unlimited)
  --mtu N                        Max UDP application payload in either direction (1..60000)
  --fragment-size N              Split modern data into chunks of N payload bytes (512..4096)
  --mtu-warn N                   Warn at N UDP payload bytes (default 1375)
  -a, --auto-rule                Install tunnel firewall rules until normal exit
  -g, --gen-rule                 Print firewall rules and exit
  --gen-add                      Install persistent rules and exit
  --clear                        Remove udp2raw-managed rules and exit
  --keep-rule                    Monitor and restore rules (implies -a)
  --wait-lock                    Wait for the xtables lock
  --simple-rule                  Generate direct DROP rules
  --log-level 0..6               Silent, fatal, error, warn, info, debug, trace
  --log-position                 Include source locations
  --enable-color|--disable-color Control log colors
  --debug                        Enable debug diagnostics
  --unit-test                    Run a config and legacy packet self-test
  -V, --version                  Print version
  -h, --help                     Print help";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    None,
    Auto,
    Keep,
    Print,
    Add,
    Clear,
}

pub struct Config {
    pub server: bool,
    pub threads: usize,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub key: String,
    pub modes: Vec<Mode>,
    pub beat: Duration,
    pub timeout: Duration,
    pub legacy: bool,
    pub cipher_mode: Cipher,
    pub auth_mode: Auth,
    pub hb_mode: u8,
    pub hb_len: usize,
    pub mtu: usize,
    pub fragment_size: Option<usize>,
    pub mtu_warn: usize,
    pub fix_gro: bool,
    pub disable_anti_replay: bool,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub ttl: u8,
    pub sock_buf: usize,
    pub force_sock_buf: bool,
    pub dev: Option<String>,
    pub seq_mode: u8,
    pub disable_bpf: bool,
    pub random_drop: u16,
    pub max_rst_to_show: i32,
    pub max_rst_allowed: i32,
    pub lower_level: Option<LinkMode>,
    pub pcap_send: bool,
    pub no_pcap_mutex: bool,
    pub fifo: Option<PathBuf>,
    pub retry_on_error: bool,
    pub firewall: FirewallAction,
    pub simple_rule: bool,
    pub wait_lock: bool,
    pub debug: bool,
    pub log_level: u8,
    pub log_color: bool,
    pub log_position: bool,
}

fn range<T>(arg: &str, name: &str, min: T, max: T) -> Result<T, String>
where
    T: FromStr + PartialOrd + fmt::Display,
{
    arg.parse::<T>()
        .ok()
        .filter(|v| min <= *v && *v <= max)
        .ok_or_else(|| format!("{name} must be between {min} and {max}"))
}

fn endpoint(value: &str, dns: bool) -> Result<SocketAddr, String> {
    if let Ok(addr) = value.parse() {
        return Ok(addr);
    }
    if dns {
        return value
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {value:?}: {e}"))?
            .next()
            .ok_or_else(|| format!("no addresses found for {value:?}"));
    }
    Err(format!(
        "invalid endpoint {value:?}; use IP:port, [IPv6]:port or --dns-resolve"
    ))
}

fn file_args(path: &str) -> Result<Vec<String>, String> {
    let contents = fs::read_to_string(path).map_err(|e| format!("configuration {path:?}: {e}"))?;
    let mut result = Vec::new();
    for (i, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (opt, value) = line.split_once([' ', '\t']).unwrap_or((line, ""));
        if !opt.starts_with('-') || opt.split('=').next() == Some("--conf-file") {
            return Err(format!("{path}:{}: expected a non-nested option", i + 1));
        }
        result.push(opt.to_owned());
        let value = value.trim_start();
        if !value.is_empty() {
            result.push(value.to_owned());
        }
    }
    Ok(result)
}

impl Config {
    pub fn bind_application_udp(&self, addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};

        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        crate::transport::buffers(&socket, self)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        tokio::net::UdpSocket::from_std(socket.into())
    }

    pub fn parse() -> Result<Self, String> {
        Self::from_args(env::args().skip(1).collect(), env::var("UDP2RAW_KEY").ok())
    }

    fn from_args(mut args: VecDeque<String>, key: Option<String>) -> Result<Self, String> {
        let unset = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let mut c = Self {
            server: false,
            threads: 4,
            local: unset,
            remote: unset,
            key: key.unwrap_or_default(),
            modes: vec![Mode::FakeTcp, Mode::Udp, Mode::Icmp],
            beat: Duration::from_secs(1),
            timeout: Duration::from_secs(5),
            legacy: false,
            cipher_mode: Cipher::default(),
            auth_mode: Auth::default(),
            hb_mode: 1,
            hb_len: 0,
            mtu: crate::wire::MAX_DATA,
            mtu_warn: 1375,
            fragment_size: None,
            fix_gro: false,
            disable_anti_replay: false,
            source_ip: None,
            source_port: None,
            ttl: 64,
            sock_buf: 1024 * 1024,
            force_sock_buf: false,
            dev: None,
            seq_mode: 3,
            disable_bpf: false,
            random_drop: 0,
            max_rst_to_show: 15,
            max_rst_allowed: -1,
            lower_level: None,
            pcap_send: false,
            no_pcap_mutex: false,
            fifo: None,
            retry_on_error: false,
            firewall: FirewallAction::None,
            simple_rule: false,
            wait_lock: false,
            debug: false,
            log_level: 4,
            log_color: std::io::stderr().is_terminal(),
            log_position: false,
        };
        let (mut role, mut local, mut remote) = (None, None, None);
        let mut seen = HashSet::new();
        while let Some(arg) = args.pop_front() {
            let (opt, inline) = if arg.starts_with("--") {
                arg.split_once('=')
                    .map_or((arg.as_str(), None), |(a, b)| (a, Some(b)))
            } else if arg.len() > 2 && ["-l", "-r", "-k"].iter().any(|p| arg.starts_with(p)) {
                (&arg[..2], Some(&arg[2..]))
            } else {
                (arg.as_str(), None)
            };
            let opt = match opt {
                "-l" => "--local",
                "-r" => "--remote",
                "-k" => "--key",
                "-a" => "--auto-rule",
                "-g" => "--gen-rule",
                other => other,
            };
            if !seen.insert(opt.to_owned()) {
                return Err(format!("duplicate option {opt}"));
            }
            let mut value_used = false;
            let mut value = || {
                value_used = true;
                inline
                    .map(str::to_owned)
                    .or_else(|| args.pop_front())
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| format!("missing value for {opt}"))
            };
            match opt {
                "-h" | "--help" => {
                    println!("{HELP}");
                    std::process::exit(0);
                }
                "-V" | "--version" => {
                    println!("udp2raw {}", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                "-s" | "-c" => {
                    if role.replace(opt == "-s").is_some() {
                        return Err("choose one role".into());
                    }
                }
                "--local" => local = Some(value()?),
                "--remote" => remote = Some(value()?),
                "--key" => c.key = value()?,
                "--threads" => c.threads = range(&value()?, opt, 1, 256)?,
                "--protocols" | "--raw-mode" => {
                    c.modes.clear();
                    for item in value()?.split(',') {
                        let mode = item.parse()?;
                        if c.modes.contains(&mode) {
                            return Err(format!("duplicate carrier {item}"));
                        }
                        c.modes.push(mode);
                    }
                    if opt == "--raw-mode" && c.modes.len() != 1 {
                        return Err("--raw-mode takes one carrier".into());
                    }
                }
                "--conf-file" => {
                    let path = value()?;
                    args.extend(file_args(&path)?);
                }
                "--wire" => {
                    c.legacy = match value()?.as_str() {
                        "modern" => false,
                        "legacy" => true,
                        _ => return Err("--wire expects modern or legacy".into()),
                    }
                }
                "--auth-mode" => c.auth_mode = value()?.parse()?,
                "--cipher-mode" => c.cipher_mode = value()?.parse()?,
                "--disable-anti-replay" => c.disable_anti_replay = true,
                "--fix-gro" => c.fix_gro = true,
                "--heartbeat-ms" => {
                    c.beat = Duration::from_millis(range(&value()?, opt, 10, 150000)?)
                }
                "--timeout-ms" => {
                    c.timeout = Duration::from_millis(range(&value()?, opt, 20, 300000)?)
                }
                "--hb-mode" => c.hb_mode = range(&value()?, opt, 0, 1)?,
                "--hb-len" => c.hb_len = range(&value()?, opt, 0, 1500)?,
                "--mtu" => c.mtu = range(&value()?, opt, 1, crate::wire::MAX_DATA)?,
                "--fragment-size" => {
                    c.fragment_size = Some(range(
                        &value()?,
                        opt,
                        crate::fragment::MIN_CHUNK,
                        crate::fragment::MAX_CHUNK,
                    )?)
                }
                "--mtu-warn" => c.mtu_warn = range(&value()?, opt, 1, usize::MAX)?,
                "--source-ip" => {
                    c.source_ip = Some(value()?.parse().map_err(|_| "invalid --source-ip")?)
                }
                "--source-port" => c.source_port = Some(range(&value()?, opt, 1, u16::MAX)?),
                "--dev" => c.dev = Some(value()?),
                "--lower-level" => c.lower_level = Some(value()?.parse()?),
                "--seq-mode" => c.seq_mode = range(&value()?, opt, 0, 4)?,
                "--set-ttl" => c.ttl = range(&value()?, opt, 0, 255)?,
                "--sock-buf" => c.sock_buf = range::<usize>(&value()?, opt, 10, 10240)? * 1024,
                "--force-sock-buf" => c.force_sock_buf = true,
                "--disable-bpf" => c.disable_bpf = true,
                "--random-drop" => c.random_drop = range(&value()?, opt, 0, 10000)?,
                "--max-rst-to-show" => c.max_rst_to_show = range(&value()?, opt, -1, i32::MAX)?,
                "--max-rst-allowed" => c.max_rst_allowed = range(&value()?, opt, -1, i32::MAX)?,
                "--retry-on-error" => c.retry_on_error = true,
                "--pcap-send" => c.pcap_send = true,
                "--no-pcap-mutex" => c.no_pcap_mutex = true,
                "--fifo" => c.fifo = Some(PathBuf::from(value()?)),
                "--wait-lock" => c.wait_lock = true,
                "--simple-rule" => c.simple_rule = true,
                "--log-level" => c.log_level = range(&value()?, opt, 0, 6)?,
                "--enable-color" => c.log_color = true,
                "--disable-color" => c.log_color = false,
                "--log-position" => c.log_position = true,
                "--unit-test" | "--debug" | "--easy-tcp" | "--dns-resolve" | "--gen-add"
                | "--gen-rule" | "--clear" | "--keep-rule" | "--auto-rule" => {}
                _ => return Err(format!("unknown option {opt}")),
            }
            if !value_used && inline.is_some() {
                return Err(format!("{opt} takes no value"));
            }
        }
        if seen.contains("--unit-test") {
            let mut sample = Self::from_args(
                [
                    "-c",
                    "-l127.0.0.1:1",
                    "-r[::1]:2",
                    "-kself-test",
                    "--auth-mode",
                    "hmac_sha1",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
                None,
            )?;
            let client = crate::legacy::Interop::new(&sample);
            let packet = client.handshake(10, 20, 30);
            sample.server = true;
            let server = crate::legacy::Interop::new(&sample);
            if !matches!(
                server.read(&packet).as_slice(),
                [crate::legacy::Packet::Handshake {
                    sender: 10,
                    receiver: 20,
                    identity: 30
                }]
            ) {
                return Err("legacy encrypted handshake self-test failed".into());
            }
            println!("Configuration and encrypted handshake self-test passed");
            std::process::exit(0);
        }
        c.firewall = if seen.contains("--clear") {
            FirewallAction::Clear
        } else if seen.contains("--gen-add") {
            FirewallAction::Add
        } else if seen.contains("--gen-rule") {
            FirewallAction::Print
        } else if seen.contains("--keep-rule") {
            FirewallAction::Keep
        } else if seen.contains("--auto-rule") {
            FirewallAction::Auto
        } else {
            FirewallAction::None
        };
        if c.firewall == FirewallAction::Clear {
            if !cfg!(target_os = "linux") {
                return Err("--clear requires Linux".into());
            }
            return Ok(c);
        }
        c.server = role.ok_or("specify -s or -c")?;
        let dns = seen.contains("--dns-resolve");
        c.local = endpoint(&local.ok_or("missing -l")?, dns)?;
        c.remote = endpoint(&remote.ok_or("missing -r")?, dns)?;
        if c.local.port() == 0 || c.remote.port() == 0 || c.remote.ip().is_unspecified() {
            return Err("specify nonzero ports and a concrete remote address".into());
        }
        if c.source_ip
            .is_some_and(|ip| ip.is_ipv4() != c.remote.is_ipv4())
            || c.server && (c.source_ip.is_some() || c.source_port.is_some())
        {
            return Err("source binding requires a client and the tunnel address family".into());
        }
        if c.timeout < c.beat * 2 {
            return Err("timeout must be at least two heartbeat intervals".into());
        }
        if seen.contains("--raw-mode") && seen.contains("--protocols") {
            return Err("choose --protocols or --raw-mode".into());
        }
        if seen.contains("--easy-tcp") {
            let mode = c
                .modes
                .iter_mut()
                .find(|m| **m == Mode::FakeTcp || **m == Mode::EasyFakeTcp)
                .ok_or("--easy-tcp requires a TCP carrier")?;
            *mode = Mode::EasyFakeTcp;
        }
        if c.server && c.modes.contains(&Mode::EasyFakeTcp) && c.modes.contains(&Mode::FakeTcp) {
            return Err("choose one TCP listener implementation on a shared port".into());
        }
        #[cfg(any(not(target_os = "linux"), feature = "pcap-client"))]
        if c.server || c.lower_level.is_some() || c.force_sock_buf {
            return Err(
                "server, lower-level and forced buffers require the native Linux backend".into(),
            );
        }
        #[cfg(not(target_os = "linux"))]
        if !matches!(c.firewall, FirewallAction::None | FirewallAction::Print) {
            return Err("firewall mutation requires Linux".into());
        }
        if (c.pcap_send || c.no_pcap_mutex)
            && !cfg!(any(not(target_os = "linux"), feature = "pcap-client"))
        {
            return Err("pcap switches require the pcap-client build".into());
        }
        if seen.contains("--cipher-mode") || seen.contains("--auth-mode") {
            if seen.contains("--wire") && !c.legacy {
                return Err("legacy cipher/auth options require --wire legacy".into());
            }
            c.legacy = true;
        }
        if c.legacy && c.fragment_size.is_some() {
            return Err("--fragment-size requires modern wire format".into());
        }
        c.debug = seen.contains("--debug");
        if c.debug && !seen.contains("--log-level") {
            c.log_level = 5;
        }
        if c.legacy && !seen.contains("--hb-len") {
            c.hb_len = 1200;
        }
        if c.legacy && seen.contains("--key") {
            // The historical -k parser read one %s, including when the option
            // came from a file. Implicit "secret key" included the space.
            c.key = c.key.split_ascii_whitespace().next().unwrap_or("").into();
        }
        if c.legacy && c.key.is_empty() {
            c.key = "secret key".into();
        }
        if c.key.is_empty() && !matches!(c.firewall, FirewallAction::Add | FirewallAction::Print) {
            return Err("set UDP2RAW_KEY or supply -k".into());
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(words: &[&str]) -> Result<Config, String> {
        Config::from_args(words.iter().map(|s| s.to_string()).collect(), None)
    }
    #[test]
    fn parses_both_wire_formats_and_mixed_address_families() {
        let flags = [
            "-c",
            "-l127.0.0.1:1000",
            "-r",
            "[::1]:1001",
            "--cipher-mode",
            "aes128cfb",
            "--auth-mode",
            "hmac_sha1",
            "--source-ip",
            "::1",
        ];
        let c = parse(&flags).unwrap();
        assert!(c.legacy && c.remote.is_ipv6() && c.local.is_ipv4());
        assert_eq!(c.key, "secret key");
        assert_eq!(c.hb_len, 1200);
        let mut bad = flags.to_vec();
        bad.extend(["--wire", "modern"]);
        assert!(parse(&bad).is_err());
        let m = parse(&["-c", "-l[::]:1000", "-r127.0.0.1:1002", "-ksecret"]).unwrap();
        assert!(!m.legacy);
        assert_eq!(m.hb_len, 0);
    }
    #[test]
    fn legacy_config_treats_entire_value_as_literal_and_rejects_duplicates() {
        let path = std::env::temp_dir().join(format!(
            "udp2raw-test-{:016x}",
            u64::from_be_bytes(crate::wire::random())
        ));
        let file = path.to_str().unwrap();
        fs::write(
            &path,
            "# client\n  -c\n-l 127.0.0.1:9998\n-r 127.0.0.1:9999\n--threads 8\n\n-k  \"a key\" # literal \t\n",
        )
        .unwrap();
        let c = parse(&["--conf-file", file]).unwrap();
        assert_eq!(c.key, "\"a key\" # literal");
        assert_eq!(c.threads, 8);
        assert!(parse(&["--key", "extra", "--conf-file", file]).is_err());
        fs::write(&path, format!("--conf-file {file}\n")).unwrap();
        assert!(parse(&["--conf-file", file]).is_err());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn firewall_commands_do_not_require_secrets() {
        assert_eq!(parse(&["--clear"]).is_ok(), cfg!(target_os = "linux"));
        assert!(parse(&["-g", "-c", "-l127.0.0.1:9998", "-r127.0.0.1:9999"]).is_ok());
        assert!(parse(&["-c", "-l127.0.0.1:9998", "-r127.0.0.1:9999"]).is_err());
    }
}
