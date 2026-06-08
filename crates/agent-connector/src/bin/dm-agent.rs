use std::path::PathBuf;
use std::process::ExitCode;

use agent_connector::{AgentConnectorConfig, ConnectorError, default_socket_path, serve_socket};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "dm-agent",
    about = "Marmot local agent connector for Hermes and OpenClaw gateways"
)]
struct Args {
    #[arg(long, value_name = "PATH", help = "Use this Darkmatter data directory")]
    home: PathBuf,
    #[arg(long, value_name = "PATH", help = "Listen on this Unix socket")]
    socket: Option<PathBuf>,
    #[arg(
        long,
        value_name = "URL",
        value_delimiter = ',',
        help = "Default relay URLs for hosted app runtime state"
    )]
    relay: Vec<String>,
    #[arg(
        long,
        help = "Accept all welcome invites without consulting the allowlist"
    )]
    allow_any: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "Require this local control-plane bearer token file for every request"
    )]
    auth_token_file: Option<PathBuf>,
    #[arg(
        long,
        value_name = "OCTAL",
        default_value = "0700",
        help = "Mode for the parent directory of the Unix control socket"
    )]
    socket_dir_mode: String,
    #[arg(
        long,
        value_name = "OCTAL",
        default_value = "0600",
        help = "Mode for the Unix control socket"
    )]
    socket_mode: String,
    #[arg(long, hide = true, help = "Enable debug-only local control requests")]
    debug_controls: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let socket = args
        .socket
        .unwrap_or_else(|| default_socket_path(&args.home));
    let socket_dir_mode = match parse_octal_mode(&args.socket_dir_mode) {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("dm-agent: startup failed code=invalid_socket_mode detail={message}");
            return ExitCode::FAILURE;
        }
    };
    let socket_mode = match parse_octal_mode(&args.socket_mode) {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("dm-agent: startup failed code=invalid_socket_mode detail={message}");
            return ExitCode::FAILURE;
        }
    };
    let auth_token = match read_auth_token(args.auth_token_file.as_ref()) {
        Ok(token) => token,
        Err(message) => {
            eprintln!("dm-agent: startup failed code=auth_token_file detail={message}");
            return ExitCode::FAILURE;
        }
    };
    let config = AgentConnectorConfig {
        home: args.home,
        socket,
        socket_dir_mode,
        socket_mode,
        relays: args.relay,
        allow_any: args.allow_any,
        debug_controls: args.debug_controls,
        auth_token,
    };
    match serve_socket(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("dm-agent: {}", safe_error_message(&err));
            ExitCode::FAILURE
        }
    }
}

fn safe_error_message(err: &ConnectorError) -> String {
    format!("startup failed code={}", err.privacy_safe_code())
}

fn parse_octal_mode(value: &str) -> Result<u32, String> {
    let value = value.trim();
    let value = value.strip_prefix("0o").unwrap_or(value);
    let value = value.strip_prefix('0').unwrap_or(value);
    if value.is_empty() || value.len() > 3 || !value.chars().all(|ch| ('0'..='7').contains(&ch)) {
        return Err(format!("expected three octal digits, got {value:?}"));
    }
    u32::from_str_radix(value, 8).map_err(|err| err.to_string())
}

fn read_auth_token(path: Option<&PathBuf>) -> Result<Option<String>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let token = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(Some(token))
}
