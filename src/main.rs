use std::process::ExitCode;

use tokio::sync::mpsc;

#[derive(Debug)]
struct PacketData {
    header: pcap::PacketHeader,
    data: Vec<u8>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut capturer = rpacket::new_capturer();

    let interface_name: &str = "en7";

    match capturer.new(interface_name) {
        Ok(pcap_device) => {
            println!("listening on {}", interface_name);

            let (tx, mut rx) = mpsc::channel(100);

            match capturer.open(&pcap_device) {
                Ok(device) => {
                    // capture packets
                    tokio::spawn(async move { capture(device, tx.clone()) });
                }
                Err(e) => {
                    print!("{}", e);
                    return ExitCode::FAILURE;
                }
            }

            // collect packets
            while let Some(packet) = rx.recv().await {
                println!("{:?}", packet)
            }
        }
        Err(e) => {
            println!("{}", e.cause);

            return ExitCode::FAILURE;
        }
    }
    return ExitCode::SUCCESS;
}

async fn capture(mut device: pcap::Capture<pcap::Active>, channel: mpsc::Sender<PacketData>) {
    while let Ok(packet) = device.next_packet() {
        let mut count = 0;
        let max_count = 10;

        print!("got packet!");
        // https://users.rust-lang.org/t/how-to-put-pcap-packets-into-a-vec-packet/41105

        let data = PacketData {
            header: packet.header.clone(),
            data: Vec::from(packet.data), // [u8] converted to vector to store in a struct
        };

        match channel.send(data).await {
            Ok(_s) => (),
            Err(e) => print!("error sending packet {}", e),
        }

        count += 1;
        if count >= max_count {
            break;
        }
    }
}
