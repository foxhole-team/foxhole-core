use std::error::Error;

use foxcore_api::EngineConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let config_path = arguments
        .next()
        .ok_or("usage: foxcore-tun <engine-config.json> <tun-name>")?;
    let tun_name = arguments
        .next()
        .ok_or("usage: foxcore-tun <engine-config.json> <tun-name>")?;
    if arguments.next().is_some() {
        return Err("usage: foxcore-tun <engine-config.json> <tun-name>".into());
    }
    let json = std::fs::read_to_string(config_path)?;
    let config = EngineConfig::parse(&json)?;
    foxcore_testkit::run_named_tun(config, &tun_name).await?;
    Ok(())
}
