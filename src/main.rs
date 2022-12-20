use clap::Parser;
use rpacket::capturer::{Capturer, PacketData};

use std::io::stdin;
use std::{process::ExitCode, sync::mpsc, sync::mpsc::Receiver, sync::mpsc::Sender, thread};

use crossterm::event::{Event, KeyCode, KeyEvent};

#[derive(Debug, Parser, Clone)]
struct Cli {
    // interface to listen on
    #[arg(short, long)]
    interface: String,
}

fn main() -> ExitCode {
    let (tx, rx): (Sender<PacketData>, Receiver<PacketData>) = mpsc::channel();
    let mut children = Vec::new();

    // spawn capture thread
    let capture_thr = thread::spawn(move || {
        Capturer::open(&Cli::parse().interface, tx).capture();
    });

    children.push(capture_thr);

    // spawn collect thread
    let collect_thr = thread::spawn(move || {
        for data in rx {
            println!("recv: {:?}", data)
        }
    });

    children.push(collect_thr);

    loop {
        let mut keyevent = crossterm::event::read();

        let Event::Key(KeyEvent { code, .. }) = keyevent 

        match event::code {
            KeyCode::Char(q) => {
                break;
            }
            _ => {}
        }
    }

    println!("joining on child threads");

    for child in children {
        match child.join() {
            Ok(_) => {}
            Err(e) => println!("error in child join: {:?}", e),
        }
    }

    return ExitCode::SUCCESS;
}
