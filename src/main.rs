use clap::Parser;
use rpacket::capturer::{self, Capturer};

use crossbeam_channel::{bounded, select, Sender};
use crossterm::event::{self, read, Event, KeyCode, KeyEvent};
use std::{process::ExitCode, thread};

#[derive(Debug, Parser, Clone)]
struct Cli {
    // interface to listen on
    #[arg(short, long)]
    interface: String,
}

fn main() -> ExitCode {
    // tx1, rx1 recieve packet data
    let (tx1, rx1) = bounded(0);

    // tx2, rx2 recieve events from the key listener
    let (tx2, rx2) = bounded(0);

    let mut capturer = match Capturer::open(&Cli::parse().interface, tx1) {
        Ok(capturer) => capturer,
        Err(e) => {
            println!("{}", e.to_string());
            return ExitCode::FAILURE;
        }
    };

    thread::spawn(move || capturer.capture());
    thread::spawn(move || listen_keyevents(tx2));
    //match listen_keyevents() {
    //     Ok(k) => match k {
    //         'q' => break,
    //         _ => {}
    //     },
    //     Err(e) => println!("error in keyevent: {:?}", e),
    // };

    select! {
        recv(rx1) -> packets =>  for packet in packets { println!("recv: {:?}", packet)} ,
        recv(rx2) -> keyevent => println!("key event: {:?}", keyevent),
    }

    return ExitCode::SUCCESS;
}

fn listen_keyevents(keyevent_channel: Sender<char>) {
    loop {
        let event = match read() {
            Ok(event) => event,
            Err(err) => {
                print!("error in key event: {}", err.to_string());
                continue;
            }
        };

        if event == Event::Key(KeyCode::Char('q').into()) {
            match keyevent_channel.send('c') {
                Ok(_) => continue,
                Err(err) => print!("error sending key event on channel: {}", err.to_string()),
            }
        }
    }
}
