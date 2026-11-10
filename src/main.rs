mod client;
mod config;
mod path;
mod server;
mod transport;
mod wire;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> std::process::ExitCode {
    let c = match config::Config::parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}\n{}", config::HELP);
            return std::process::ExitCode::from(2);
        }
    };
    let codec = wire::Codec::new(&c.key, c.server);
    let result = if c.server {
        server::run(&c, codec).await
    } else {
        client::run(&c, codec).await
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("udp2raw: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
