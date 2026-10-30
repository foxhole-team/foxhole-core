mod args;
#[cfg(target_os = "linux")]
mod bootstrap;
#[cfg(any(target_os = "linux", test))]
mod bootstrap_budget;
#[cfg(target_os = "linux")]
mod bridge;
mod config;
mod import;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod probe;
mod protocols;
#[cfg(target_os = "linux")]
mod run;
mod status;

#[tokio::main(worker_threads = 2)]
async fn main() {
    let result = match args::parse(std::env::args().skip(1)) {
        Ok(command) => dispatch(command).await,
        Err(code) => Err(code),
    };
    if let Err(code) = result {
        eprintln!("{code}");
        std::process::exit(2);
    }
}

async fn dispatch(command: args::Command) -> Result<(), &'static str> {
    match command {
        args::Command::Help => println!(
            "foxcore-cli capabilities | import --profile FILE --out FILE | check --config FILE | run --config FILE --state FILE [--interface foxhole0] | status --state FILE | owner --state FILE [--interface foxhole0] | probe --state FILE [--interface foxhole0] | bridge --state FILE --auth FILE [--interface foxhole0]"
        ),
        args::Command::Capabilities => println!(
            "{}",
            serde_json::json!({"schema_version":1,"router_contract_version":1,"core_version":foxcore_api::CORE_VERSION,"platform":std::env::consts::OS,"protocols":protocols::compiled(),"tun_mark":args::TUNNEL_MARK,"upstream_mark":args::UPSTREAM_MARK,"proof_mark":args::PROOF_MARK})
        ),
        args::Command::Check(path) => {
            let value = config::read(&path)?;
            println!(
                "{}",
                serde_json::json!({"valid":true,"protocol":protocols::name(&value.outbound)})
            );
        }
        args::Command::Import { profile, output } => {
            let protocol = import::import(&profile, &output)?;
            println!(
                "{}",
                serde_json::json!({"imported":true,"protocol":protocol})
            );
        }
        args::Command::Status(path) => println!(
            "{}",
            serde_json::to_string(&status::read(&path)?).map_err(|_| "STATUS_INVALID")?
        ),
        #[cfg(target_os = "linux")]
        args::Command::Run {
            config,
            state,
            interface,
        } => run::run(&config, &state, &interface).await?,
        #[cfg(target_os = "linux")]
        args::Command::Probe { interface, state } => probe::probe(&state, &interface).await?,
        #[cfg(target_os = "linux")]
        args::Command::Bridge {
            interface,
            state,
            auth,
        } => bridge::serve(&state, &auth, &interface).await?,
        #[cfg(target_os = "linux")]
        args::Command::Owner { interface, state } => {
            let owner = status::read_recent(&state)?;
            status::require_owner(&owner, &interface)?;
            println!(
                "{}",
                serde_json::json!({"owned":true,"generation_key":format!("{:016x}",owner.generation)})
            );
        }
        #[cfg(not(target_os = "linux"))]
        args::Command::Run { .. }
        | args::Command::Probe { .. }
        | args::Command::Bridge { .. }
        | args::Command::Owner { .. } => {
            return Err("PLATFORM_UNSUPPORTED");
        }
    }
    Ok(())
}
