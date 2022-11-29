use pcap::{Active, Capture};
use std::fmt;

pub struct CapturerError {
    pub cause: String,
}

impl CapturerError {
    fn new(cause: &str) -> CapturerError {
        return CapturerError {
            cause: cause.to_string(),
        };
    }
}

impl fmt::Display for CapturerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error in packet capture: {}", self.cause)
    }
}

pub struct Capturer {}

pub fn new_capturer() -> Capturer {
    return Capturer {};
}

impl Capturer {
    pub fn new(self: &mut Self, interface_name: &str) -> Result<pcap::Device, CapturerError> {
        let devices = pcap::Device::list();

        // initialize mutable variable encapsulated in Option
        // so its value can be None or Some.
        let mut listen_device: Option<&pcap::Device> = None;

        for device in devices.iter() {
            for interface in device.iter() {
                if interface.name == *interface_name {
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

                Ok(listen_device.clone())
            }
            None => Err(CapturerError::new(
                "Error: no matching capture device interface found",
            )),
        }
    }

    // creates a capture for a device interface
    pub fn open(self: &Self, device: &pcap::Device) -> Result<Capture<Active>, CapturerError> {
        let active = match pcap::Capture::from_device(device.name.as_str()) {
            Ok(capture) => capture
                .immediate_mode(true)
                .promisc(true)
                .open()
                .or_else(|error| Err(CapturerError::new(&error.to_string()))),
            Err(e) => Err(CapturerError::new(&e.to_string())),
        };

        active
    }
}
