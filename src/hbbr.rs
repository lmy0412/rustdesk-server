mod common;
mod config;
mod relay_server;
use config::{AppConfig, ConfigTarget};
use flexi_logger::*;
use hbb_common::{config::RELAY_PORT, log, ResultType};
use relay_server::*;
mod version;

fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let args = format!(
        "-c --config=[FILE] +takes_value 'Sets a custom config file'
        -p, --port=[NUMBER(default={RELAY_PORT})] 'Sets the listening port'
        -k, --key=[KEY] 'Only allow the client with the same key'
        ",
    );
    let matches = common::init_args(&args, "hbbr", "RustDesk Relay Server");
    let config =
        AppConfig::load_with_cli_args(&matches, ConfigTarget::Hbbr).unwrap_or_else(|err| {
            eprintln!("{}", err);
            std::process::exit(1);
        });
    config.sync_to_legacy_env();
    log::info!("loaded config:\n{}", config);
    start(&config.relay_server_port().to_string(), &config.server.key)?;
    Ok(())
}
