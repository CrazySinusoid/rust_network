use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: u64,
    pub peer_addr: SocketAddr,
    pub send_seq: u64,
    pub recv_highest_seq: u64,
    pub last_seen: Instant,
    pub selected_mtu: u16,
}

impl Session {
    pub fn next_sequence_number(&mut self) -> u64 {
        self.send_seq += 1;
        self.send_seq
    }

    pub fn accept_sequence_number(&mut self, sequence_number: u64) -> bool {
        if sequence_number == 0 || sequence_number <= self.recv_highest_seq {
            return false;
        }

        self.recv_highest_seq = sequence_number;
        true
    }
}
