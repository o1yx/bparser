// Парс сообщений типа:
// prefix | payload

const BUFFER_SIZE: usize = 256;

enum State {
    Prefix,
    Payload,
}

struct Protocol {
    prefix: &[u8],
    prefix_size: u8,
    payload_size: u8,
}

pub struct Parser {
    buffer: [u8; BUFFER_SIZE],
    state: State,
    protocol: &Protocol,
    bytes_read: u8,
    bytes_need_read: u8,
    buffer_position: usize,
}

impl Protocol {
    pub fn init(&self, prefix: &[u8], prefix_size: u8, payload_size: u8) {
        self.prefix = prefix;
        self.prefix_size = prefix_size;
        self.payload_size = payload_size;
    }
}

impl Parser {
    pub fn init(&self, protocol: &Protocol) {
        self.state = State::Prefix;
        self.protocol = protocol;
    }
}