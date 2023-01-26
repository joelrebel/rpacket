#### collection
 - packet filtering requires changes to the pnet_datalink library to accept a BPF program
    - https://github.com/libpnet/libpnet/blob/master/pnet_datalink/src/pcap.rs#L59
    - https://github.com/rust-pcap/pcap/blob/main/src/lib.rs#L1294
 - consider switching to read packets from /dev/bpf (tradeoffs?)
    - https://github.com/libpnet/libpnet/blob/master/pnet_datalink/src/bpf.rs#L74
 - reload based on filter


#### tui

- key modifiers
 - q should stop collection and exit
 - p should pause collection
 - f should pop up filter dialog
