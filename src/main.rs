use std::any::Any;
mod ping;
use ping::PingMachina;

fn main() -> Result<(), Box<dyn Any + Send>> {
    
    log4rs::init_file("./log_config.yml", Default::default()).unwrap();

    let pinger = PingMachina::new();
    pinger.run();


    Ok(())
}
