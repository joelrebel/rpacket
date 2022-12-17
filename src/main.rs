use std::process::ExitCode;

use clap::Parser;
use rpacket::capturer::Capturer;

#[derive(Debug, Parser, Clone)]
struct Cli {
    // interface to listen on
    #[arg(short, long)]
    interface: String,
}

fn main() -> ExitCode {
    //   let interface: &str = "lo0";
    let mut c = Capturer::new(&Cli::parse().interface);

    c.capture();

    return ExitCode::SUCCESS;
}
