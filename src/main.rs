use clap::Parser;
use rpacket::capturer::{self, Capturer};

use crossbeam_channel::{bounded, select, Sender};
use crossterm::{
    event::{self, read, Event, KeyCode, KeyEvent},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::{process::ExitCode, thread};

#[derive(Debug, Parser, Clone)]
struct Cli {
    // interface to listen on
    #[arg(short, long)]
    interface: String,
}

fn main() -> ExitCode {
    // tx0, rx0 are channels to notify threads to stop and return
    let (tx0, rx0) = bounded(0);

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

    thread::spawn(move || capturer.capture(rx0));
    thread::spawn(move || listen_keyevents(tx2));

    loop {
        select! {
            recv(rx1) -> packets =>  for packet in packets { println!("recv: {:?}\r", packet)} ,
            recv(rx2) -> keyevent =>  for key in keyevent { if key == 'q' {  return ExitCode::SUCCESS  } },
        }
    }

    // notify threads to return
    //tx0.try_send(true);

    return ExitCode::SUCCESS;
}

fn listen_keyevents(keyevent_channel: Sender<char>) {
    enable_raw_mode();

    loop {
        let event = match read() {
            Ok(event) => event,
            Err(err) => {
                print!("error in key event: {}\r", err.to_string());
                continue;
            }
        };

        // if event == Event::Key(KeyCode::Char('q').into()) {
        //     match keyevent_channel.send('c') {
        //         Ok(_) => continue,
        //         Err(err) => println!("error sending key event on channel: {}\r", err.to_string()),
        //     }
        // }

        if event == Event::Key(KeyCode::Esc.into()) {
            break;
        }
    }

    disable_raw_mode();

    match keyevent_channel.send('q') {
        Ok(_) => (),
        Err(err) => print!("error sending : {}", err.to_string()),
    }
}
