use std::{env, fmt, net::SocketAddrV4, str::FromStr, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    FakeTcp,
    Udp,
    Icmp,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FakeTcp => "faketcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
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
            _ => Err(format!(
                "unknown protocol {s:?} (expected faketcp, udp or icmp)"
            )),
        }
    }
}

pub const HELP: &str = "udp2raw — Rust UDP tunnel for Linux IPv4
  udp2raw -s -l 0.0.0.0:4096 -r 127.0.0.1:7777
  udp2raw -c -l 127.0.0.1:3333 -r 192.0.2.1:4096

  -s | -c                       Run as server or client
  -l, --local IP:PORT           Listen address
  -r, --remote IP:PORT          Target service (server) or tunnel endpoint (client)
  -k, --key KEY                 Shared secret (or set UDP2RAW_KEY)
  --protocols LIST              Ordered client paths or server listeners
                                Default: faketcp,udp,icmp
  --heartbeat-ms N              Client probe interval (default 1000)
  --timeout-ms N                Client path timeout (default 5000, >= 2 intervals)
  --raw-mode MODE               Select a single protocol
  -h, --help                    Print help
  -V, --version                 Print version

FakeTCP and ICMP require CAP_NET_RAW. See README for the FakeTCP RST firewall rule.";

pub struct Config {
    pub server: bool,
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub key: String,
    pub modes: Vec<Mode>,
    pub beat: Duration,
    pub timeout: Duration,
}

impl Config {
    pub fn parse() -> Result<Self, String> {
        let mut args = env::args().skip(1);
        let (mut role, mut local, mut remote) = (None, None, None);
        let mut key = env::var("UDP2RAW_KEY").ok();
        let mut modes = vec![Mode::FakeTcp, Mode::Udp, Mode::Icmp];
        let (mut beat, mut timeout) = (1000u64, 5000u64);
        while let Some(arg) = args.next() {
            let (opt, inline) =
                if arg.starts_with("-l") || arg.starts_with("-r") || arg.starts_with("-k") {
                    arg.split_at(2)
                } else {
                    (arg.as_str(), "")
                };
            let mut value = || {
                if inline.is_empty() {
                    args.next()
                        .ok_or_else(|| format!("missing value for {opt}"))
                } else {
                    Ok(inline.to_owned())
                }
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
                "-l" | "--local" => {
                    local = Some(
                        value()?
                            .parse::<SocketAddrV4>()
                            .map_err(|e| e.to_string())?,
                    )
                }
                "-r" | "--remote" => {
                    remote = Some(
                        value()?
                            .parse::<SocketAddrV4>()
                            .map_err(|e| e.to_string())?,
                    )
                }
                "-k" | "--key" => key = Some(value()?),
                "--protocols" | "--raw-mode" => {
                    modes.clear();
                    for name in value()?.split(',') {
                        let mode = name.parse()?;
                        if modes.contains(&mode) {
                            return Err(format!("duplicate protocol {name}"));
                        }
                        modes.push(mode);
                    }
                    if opt == "--raw-mode" && modes.len() != 1 {
                        return Err("--raw-mode takes one protocol".into());
                    }
                }
                "--heartbeat-ms" => beat = value()?.parse().map_err(|_| "invalid heartbeat")?,
                "--timeout-ms" => timeout = value()?.parse().map_err(|_| "invalid timeout")?,
                _ => return Err(format!("unknown option {arg}")),
            }
        }
        let local = local.ok_or("missing -l")?;
        let remote = remote.ok_or("missing -r")?;
        if local.port() == 0 || remote.port() == 0 || remote.ip().is_unspecified() {
            return Err("specify nonzero ports and a concrete remote IP".into());
        }
        if beat < 10 || timeout > 300_000 || timeout < beat.saturating_mul(2) {
            return Err(
                "require 10 <= heartbeat-ms, 2 * heartbeat-ms <= timeout-ms <= 300000".into(),
            );
        }
        Ok(Self {
            server: role.ok_or("specify -s or -c")?,
            local,
            remote,
            key: key
                .filter(|k| !k.is_empty())
                .ok_or("set UDP2RAW_KEY or supply -k")?,
            modes,
            beat: Duration::from_millis(beat),
            timeout: Duration::from_millis(timeout),
        })
    }
}
