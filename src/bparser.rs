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
    data_size: u8,
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

    fn reset(&mut self) {
        self.state = State::Prefix;
        self.data_size = 0;
        self.bytes_read = 0;
        self.bytes_need_read = 0;
        self.buffer_position = 0;
    }

    fn add_to_buffer(&mut self, data_byte: &'a u8) {
        if self.buffer_position < BUFFER_SIZE {
            self.buffer[self.buffer_position] = *data_byte;
            self.data_size += 1;
            self.bytes_read += 1;
            self.bytes_need_read -= 1;
            self.buffer_position += 1;
        } else {
            panic!("Buffer overflow")  // Добавить обработку ошибки переполнения буфера
        }
    }

    fn change_state(&mut self, new_state: State) {
        self.bytes_read = 0;
        self.state = new_state;
    }

    fn task(&mut self, data_byte: &'a u8) -> Option<u8> {
        match self.state {
            State::Prefix => {
                self.bytes_need_read = self.protocol.prefix_size;
                self.add_to_buffer(data_byte);

                if self.protocol.prefix[..self.buffer_position] != &self.buffer[..self.buffer_position] {
                    self.reset();
                    return None;
                } else if self.bytes_read == self.protocol.prefix_size {
                    self.change_state(State::Payload);
                    self.bytes_need_read = self.protocol.payload_size;
                    return None;
                }

                return None;
            },

            State::Payload => {
                self.add_to_buffer(data_byte);
                if self.bytes_need_read == 0 {
                    self.change_state(State::Prefix);
                    self.bytes_need_read = self.protocol.prefix_size;
                    return Some(self.data_size);
                }

                return None;
            }
        };
    }
}