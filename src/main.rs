mod client;
mod config;
mod firewall;
mod legacy;
mod link;
mod logging;
mod ops;
mod packet;
mod path;
mod server;
#[cfg(all(target_os = "linux", not(feature = "pcap-client")))]
mod transport;
#[cfg(any(not(target_os = "linux"), feature = "pcap-client"))]
#[path = "portable.rs"]
mod transport;
mod wire;

use std::{io, process::ExitCode, time::Duration};

async fn run(c: &config::Config) -> io::Result<()> {
    let Some(_services) = ops::start(c).await? else {
        return Ok(());
    };
    loop {
        let codec = wire::Codec::new(c);
        let result = if c.server {
            server::run(c, codec).await
        } else {
            client::run(c, codec).await
        };
        match result {
            Err(e) if c.retry_on_error => {
                crate::log!(3, "network unavailable: {e}; retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            result => return result,
        }
    }
}

fn start(c: config::Config) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(c.threads)
        .thread_name("udp2raw-io")
        .enable_all()
        .build()?;
    crate::log!(5, "started runtime with {} worker threads", c.threads);
    let tunnel = runtime.spawn(async move {
        tokio::select! {
            biased;
            _ = ops::shutdown() => Ok(()),
            result = run(&c) => result,
        }
    });
    runtime.block_on(tunnel)?
}

fn main() -> ExitCode {
    let c = match config::Config::parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}\n{}", config::HELP);
            return ExitCode::from(2);
        }
    };
    logging::init(&c);
    match start(c) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            crate::log!(1, "udp2raw: {e}");
            ExitCode::FAILURE
        }
    }
}
