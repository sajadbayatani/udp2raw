//! Manage per-process rules so stopping one tunnel cannot remove another's rule.
use crate::config::{Config, FirewallAction, Mode};
use std::{
    io,
    process::{Command, Output},
    sync::mpsc,
    thread,
    time::Duration,
};

/// Distinguish userspace ICMP responses from automatic kernel echo replies.
#[cfg(target_os = "linux")]
pub const ICMP_MARK: u32 = 0x75327231;

#[derive(Clone)]
struct Table {
    program: &'static str,
    wait: bool,
}
impl Table {
    fn output(&self, args: &[String]) -> io::Result<Output> {
        let mut cmd = Command::new(self.program);
        if self.wait {
            cmd.arg("-w");
        }
        cmd.args(args)
            .output()
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", self.program)))
    }
    fn run(&self, args: &[String]) -> io::Result<String> {
        let out = self.output(args)?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "{} {}: {}",
                self.program,
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
    fn exists(&self, args: &[String]) -> io::Result<bool> {
        let out = self.output(args)?;
        if out.status.success() {
            return Ok(true);
        }
        if out.status.code() == Some(1) {
            return Ok(false);
        }
        Err(io::Error::other(format!(
            "{}: {}",
            self.program,
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|s| (*s).into()).collect()
}

#[derive(Clone)]
struct Rule {
    table: Table,
    selector: Vec<String>,
    tag: String,
    simple: bool,
}

impl Rule {
    fn for_config(c: &Config) -> Vec<Self> {
        let peer = if c.server { c.local } else { c.remote };
        let program = if peer.is_ipv4() {
            "iptables"
        } else {
            "ip6tables"
        };
        let mut addr = Vec::new();
        if !peer.ip().is_unspecified() {
            addr.push(if c.server { "-s" } else { "-d" }.into());
            addr.push(peer.ip().to_string());
        }
        let mut result = Vec::new();
        if c.modes.contains(&Mode::FakeTcp) {
            let mut selector = args(&["-p", "tcp"]);
            selector.extend_from_slice(&addr);
            selector.push(if c.server { "--sport" } else { "--dport" }.into());
            selector.push(peer.port().to_string());
            selector.extend(args(&["--tcp-flags", "RST", "RST"]));
            result.push(Self::new(program, c, selector));
        }
        #[cfg(target_os = "linux")]
        if c.server && c.modes.contains(&Mode::Icmp) {
            let (proto, kind, ip_len) = if peer.is_ipv4() {
                ("icmp", "--icmp-type", 20)
            } else {
                ("ipv6-icmp", "--icmpv6-type", 40)
            };
            let mut selector = args(&["-p", proto, kind, "echo-reply"]);
            selector.extend(addr);
            // Short, ordinary pings remain unaffected when their payload cannot
            // possibly contain a tunnel frame. Encrypted payloads have no magic.
            let min = ip_len + 8 + if c.legacy { 18 } else { 97 };
            selector.extend(args(&[
                "-m",
                "length",
                "--length",
                &format!("{min}:65535"),
                "-m",
                "mark",
                "!",
                "--mark",
                &format!("{ICMP_MARK:#x}"),
            ]));
            result.push(Self::new(program, c, selector));
        }
        result
    }
    fn new(program: &'static str, c: &Config, selector: Vec<String>) -> Self {
        // Managed permanent identities are deterministic per rule. Temporary tags
        // are random so two matching processes can stop in either order.
        let tag = if c.firewall == FirewallAction::Add {
            let hash = selector.join(" ").bytes().fold(2166136261u32, |a, b| {
                (a ^ u32::from(b)).wrapping_mul(16777619)
            });
            format!("u2r_p{hash:08x}")
        } else {
            format!("u2r_t{:016x}", u64::from_ne_bytes(crate::wire::random()))
        };
        Self {
            table: Table {
                program,
                wait: c.wait_lock,
            },
            selector,
            tag,
            simple: c.simple_rule,
        }
    }
    fn jump(&self, action: &str) -> Vec<String> {
        let mut cmd = args(&[action, "OUTPUT"]);
        cmd.extend_from_slice(&self.selector);
        if self.simple {
            cmd.extend(args(&[
                "-m",
                "comment",
                "--comment",
                &self.tag,
                "-j",
                "DROP",
            ]));
        } else {
            cmd.extend(args(&["-j", &self.tag]));
        }
        cmd
    }
    fn change(
        &self,
        apply: Vec<String>,
        undo: Vec<String>,
        journal: &mut Vec<(Table, Vec<String>)>,
    ) -> io::Result<()> {
        self.table.run(&apply)?;
        journal.push((self.table.clone(), undo));
        Ok(())
    }
    fn ensure(&self, journal: &mut Vec<(Table, Vec<String>)>) -> io::Result<()> {
        if !self.simple {
            if !self.table.exists(&args(&["-S", &self.tag]))? {
                self.change(args(&["-N", &self.tag]), args(&["-X", &self.tag]), journal)?;
            }
            if !self.table.exists(&args(&["-C", &self.tag, "-j", "DROP"]))? {
                self.change(
                    args(&["-A", &self.tag, "-j", "DROP"]),
                    args(&["-D", &self.tag, "-j", "DROP"]),
                    journal,
                )?;
            }
        }
        if !self.table.exists(&self.jump("-C"))? {
            self.change(self.jump("-I"), self.jump("-D"), journal)?;
        }
        Ok(())
    }
    fn remove(&self) -> io::Result<()> {
        while self.table.exists(&self.jump("-C"))? {
            self.table.run(&self.jump("-D"))?;
        }
        if !self.simple && self.table.exists(&args(&["-S", &self.tag]))? {
            self.table.run(&args(&["-F", &self.tag]))?;
            self.table.run(&args(&["-X", &self.tag]))?;
        }
        Ok(())
    }
    #[cfg(all(target_os = "linux", not(feature = "pcap-client")))]
    fn print(&self) {
        println!(
            "{}{} -I OUTPUT {} -j DROP",
            self.table.program,
            if self.table.wait { " -w" } else { "" },
            self.selector.join(" ")
        );
    }
}

// iptables locks each individual invocation. Serialize this program's multi-step
// changes within a netns, including --clear, without leaving a lock file behind.
fn serialized<T>(f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    #[cfg(target_os = "linux")]
    let _lock = {
        use std::os::fd::AsRawFd;
        let netns = std::fs::File::open("/proc/self/ns/net")?;
        loop {
            // SAFETY: flock receives the valid borrowed namespace descriptor.
            if unsafe { libc::flock(netns.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        netns
    };
    f()
}

fn install(rules: &[Rule]) -> io::Result<()> {
    serialized(|| {
        let mut journal = Vec::new();
        for rule in rules {
            if let Err(e) = rule.ensure(&mut journal) {
                for (table, undo) in journal.into_iter().rev() {
                    if let Err(cleanup) = table.run(&undo) {
                        crate::log!(2, "rolling back firewall change: {cleanup}");
                    }
                }
                return Err(e);
            }
        }
        Ok(())
    })
}

fn owned(s: &str) -> bool {
    let s = s.trim_matches('"');
    if let Some(id) = s.strip_prefix("u2r_t") {
        return id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if let Some(id) = s.strip_prefix("u2r_p") {
        return id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if s == "udp2rawDwrW_C" {
        return true;
    }
    if let Some(s) = s.strip_prefix("udp2rawDwrW_") {
        return s.rsplit_once("_C").is_some_and(|(id, index)| {
            matches!(index, "0" | "1")
                && !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_hexdigit())
        });
    }
    false
}

fn clear(table: &Table) -> io::Result<()> {
    let snapshot = table.run(&args(&["-S"]))?;
    let mut chains = Vec::new();
    for line in snapshot.lines() {
        let mut words: Vec<String> = line
            .split_ascii_whitespace()
            .map(|w| w.trim_matches('"').to_string())
            .collect();
        match words.first().map(String::as_str) {
            Some("-N") if words.len() == 2 && owned(&words[1]) => chains.push(words[1].clone()),
            Some("-A")
                if words.len() > 2
                    && !owned(&words[1])
                    && words
                        .windows(2)
                        .any(|w| matches!(w[0].as_str(), "-j" | "--comment") && owned(&w[1])) =>
            {
                words[0] = "-D".into();
                table.run(&words)?;
            }
            _ => {}
        }
    }
    for chain in &chains {
        table.run(&args(&["-F", chain]))?;
    }
    for chain in &chains {
        table.run(&args(&["-X", chain]))?;
    }
    Ok(())
}

pub struct Firewall {
    rules: Vec<Rule>,
    owner: u32,
    worker: Option<(mpsc::Sender<()>, thread::JoinHandle<()>)>,
}
impl Drop for Firewall {
    fn drop(&mut self) {
        if self.owner != std::process::id() {
            return;
        }
        if let Some((stop, worker)) = self.worker.take() {
            let _ = stop.send(());
            let _ = worker.join();
        }
        let result = serialized(|| {
            for rule in self.rules.iter().rev() {
                rule.remove()?;
            }
            Ok(())
        });
        if let Err(e) = result {
            crate::log!(2, "firewall cleanup: {e}");
        }
    }
}

pub enum Activation {
    Run(Option<Firewall>),
    Exit,
}

/// Packet capture sees inbound frames before the host's IP stack. For pcap
/// clients the original INPUT rules can suppress redundant kernel responses.
#[cfg(any(not(target_os = "linux"), feature = "pcap-client"))]
fn print_capture_rules(c: &Config) {
    let ip = c.remote.ip();
    let port = c.remote.port();
    let table = if ip.is_ipv4() {
        "iptables"
    } else {
        "ip6tables"
    };
    let pf_family = if ip.is_ipv4() { "inet" } else { "inet6" };
    let wait = if c.wait_lock { " -w" } else { "" };
    for mode in &c.modes {
        let (proto, xt_match, pf_match, netsh_proto, netsh_port) = match mode {
            Mode::EasyFakeTcp => continue,
            Mode::FakeTcp | Mode::Udp => {
                let name = if *mode == Mode::FakeTcp { "tcp" } else { "udp" };
                (
                    name,
                    format!("--sport {port}"),
                    format!(" port {port}"),
                    name,
                    format!(" remoteport={port}"),
                )
            }
            Mode::Icmp if ip.is_ipv4() => (
                "icmp",
                "--icmp-type echo-reply".into(),
                String::new(),
                "icmpv4:0,any",
                String::new(),
            ),
            Mode::Icmp => (
                "icmp6",
                "--icmpv6-type echo-reply".into(),
                String::new(),
                "icmpv6:129,any",
                String::new(),
            ),
        };
        let xt_proto = if proto == "icmp6" { "ipv6-icmp" } else { proto };
        println!("# Linux\n{table}{wait} -I INPUT -s {ip} -p {xt_proto} {xt_match} -j DROP");
        println!("# PF (macOS / BSD)\nblock drop in {pf_family} proto {proto} from {ip}{pf_match} to any");
        println!("# Windows\nnetsh advfirewall firewall add rule name=udp2raw dir=in protocol={netsh_proto} remoteip={ip}{netsh_port} action=block");
    }
}
pub fn activate(c: &Config) -> io::Result<Activation> {
    use FirewallAction::*;
    if c.firewall == Clear {
        let mut found = false;
        for program in ["iptables", "ip6tables"] {
            match serialized(|| {
                clear(&Table {
                    program,
                    wait: c.wait_lock,
                })
            }) {
                Ok(()) => found = true,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if !found {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "cannot find iptables or ip6tables",
            ));
        }
        return Ok(Activation::Exit);
    }
    if c.firewall == None {
        return Ok(Activation::Run(Option::None));
    }
    #[cfg(any(not(target_os = "linux"), feature = "pcap-client"))]
    if c.firewall == Print {
        print_capture_rules(c);
        return Ok(Activation::Exit);
    }
    let rules = Rule::for_config(c);
    if rules.is_empty() {
        crate::log!(4, "configured carriers need no kernel firewall rules");
        return Ok(if matches!(c.firewall, Print | Add) {
            Activation::Exit
        } else {
            Activation::Run(Option::None)
        });
    }
    #[cfg(all(target_os = "linux", not(feature = "pcap-client")))]
    if c.firewall == Print {
        for rule in &rules {
            rule.print();
        }
        return Ok(Activation::Exit);
    }
    install(&rules)?;
    if c.firewall == Add {
        return Ok(Activation::Exit);
    }
    let mut guard = Firewall {
        rules,
        owner: std::process::id(),
        worker: Option::None,
    };
    if c.firewall == Keep {
        let (stop, receiver) = mpsc::channel();
        let rules = guard.rules.clone();
        let worker = thread::Builder::new()
            .name("firewall".into())
            .spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) =
                    receiver.recv_timeout(Duration::from_secs(2))
                {
                    if let Err(e) = install(&rules) {
                        crate::log!(2, "restoring firewall rules: {e}");
                    }
                }
            })?;
        guard.worker = Some((stop, worker));
    }
    Ok(Activation::Run(Some(guard)))
}
