// https://tools.ietf.org/rfc/rfc5128.txt
// https://blog.csdn.net/bytxl/article/details/44344855

use flexi_logger::*;
use hbb_common::{bail, config::RENDEZVOUS_PORT, log, ResultType};
use hbbs::api;
use hbbs::config::{AppConfig, ConfigTarget};
use hbbs::{common::*, *};

const RMEM: usize = 0;

fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let args = format!(
        "-c --config=[FILE] +takes_value 'Sets a custom config file'
        -p, --port=[NUMBER(default={RENDEZVOUS_PORT})] 'Sets the listening port'
        -s, --serial=[NUMBER(default=0)] 'Sets configure update serial number'
        -R, --rendezvous-servers=[HOSTS] 'Sets rendezvous servers, separated by comma'
        -u, --software-url=[URL] 'Sets download url of RustDesk software of newest version'
        -r, --relay-servers=[HOST] 'Sets the default relay servers, separated by comma'
        -M, --rmem=[NUMBER(default={RMEM})] 'Sets UDP recv buffer size, set system rmem_max first, e.g., sudo sysctl -w net.core.rmem_max=52428800. vi /etc/sysctl.conf, net.core.rmem_max=52428800, sudo sysctl –p'
        , --mask=[MASK] 'Determine if the connection comes from LAN, e.g. 192.168.0.0/16'
        -k, --key=[KEY] 'Only allow the client with the same key'",
    );
    let matches = init_args(&args, "hbbs", "RustDesk ID/Rendezvous Server");
    let config =
        AppConfig::load_with_cli_args(&matches, ConfigTarget::Hbbs).unwrap_or_else(|err| {
            eprintln!("{}", err);
            std::process::exit(1);
        });
    config.sync_to_legacy_env();
    log::info!("loaded config:\n{}", config);
    let port = config.id_server_port();
    if port < 3 {
        bail!("Invalid port");
    }
    let api_addr = config.api_server_addr().unwrap_or_else(|err| {
        eprintln!("Failed to parse api_server address: {}", err);
        std::process::exit(1);
    });
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let _api_thread = std::thread::spawn(move || {
        api::api_server_forever(api_addr, ready_tx);
    });
    match ready_rx.recv() {
        Ok(Ok(())) => {
            log::info!("API server bind confirmed, starting RendezvousServer");
        }
        Ok(Err(err)) => {
            eprintln!("Fatal: API server failed to start: {}", err);
            std::process::exit(1);
        }
        Err(err) => {
            eprintln!("Fatal: API server failed to start: {}", err);
            std::process::exit(1);
        }
    }
    let rmem = config.relay.rmem;
    let serial = config.rendezvous.serial;
    crate::common::check_software_update();
    RendezvousServer::start(port, serial, &config.server.key, rmem)?;
    Ok(())
}
