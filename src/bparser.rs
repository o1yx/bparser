// Парс сообщений типа:
// prefix | payload

const BUFFER_SIZE: usize = 256;

enum State {
    Prefix,
    Payload,
}

struct Protocol<'a> {
    prefix: &'a [u8],
    prefix_size: u8,
    payload_size: u8,
}

struct Parser<'a> {
    buffer: [u8; BUFFER_SIZE],
    state: State,
    protocol: &'a Protocol<'a>,
    bytes_read: u8,
    bytes_need_read: u8,
    buffer_position: usize,
}

impl<'a> Protocol<'a> {
    pub fn init(&mut self, prefix: &'a [u8], prefix_size: u8, payload_size: u8) {
        self.prefix = prefix;
        self.prefix_size = prefix_size;
        self.payload_size = payload_size;
    }
}

impl<'a> Parser<'a> {
    pub fn init(&mut self, protocol: &'a Protocol) {
        self.state = State::Prefix;
        self.protocol = protocol;
    }
}