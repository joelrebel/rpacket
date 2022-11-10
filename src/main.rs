use std::process::ExitCode;

use pcap::{Active, Capture, Inactive};

fn main() -> ExitCode {
    let devices = pcap::Device::list();

    // initialize mutable variable encapsulated in Option
    // so its value can be None or Some.
    let mut listen_device: Option<&pcap::Device> = None;

    for device in devices.iter() {
        for interface in device.iter() {
            if interface.name == "en7" {
                listen_device = Some(interface);
            }
        }
    }

    match listen_device {
        Some(listen_device) => {
            println!(
                "listening on {}, {:?}",
                listen_device.name.as_str(),
                listen_device.addresses,
            );

            return capture(listen_device);
        }
        None => {
            println!("no matching capture device interface found");
            return ExitCode::FAILURE;
        }
    }
}

// creates a capture for a device interface
fn capture(device: &pcap::Device) -> ExitCode {
    let _ = match pcap::Capture::from_device(device.name.as_str()) {
        Ok(capture) => activate_capture(capture),
        Err(e) => {
            println!("error in capture from_device {}", e.to_string());
            return ExitCode::FAILURE;
        }
    };

    return ExitCode::SUCCESS;
}

// opens the the capture
fn activate_capture(capture: Capture<Inactive>) -> ExitCode {
    let _ = match capture.immediate_mode(true).promisc(true).open() {
        Ok(capture) => read_packets(capture),
        Err(e) => {
            println!("error in activate_capture {}", e.to_string());
            return ExitCode::FAILURE;
        }
    };

    return ExitCode::SUCCESS;
}

// reads packets
fn read_packets(mut capture: Capture<Active>) {
    let mut count = 0;
    let max_count = 10;

    while let Ok(packet) = capture.next_packet() {
        println!("{:?}", packet);

        count += 1;
        if count >= max_count {
            break;
        }
    }
}
