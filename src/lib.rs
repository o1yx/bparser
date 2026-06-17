//! # bparser
//! 
//! 'bparser' - is a binary protocol parser designed for parsing messages like: prefix | length (optional) | payload

use std::mem;

const BUFFER_SIZE: usize = 256;

/// Enumeration of states of the parser state machine
enum State {
    SearchingPrefix,
    ValidatingPrefix(usize),
    ReadingLength(usize),
    ReadingPayload(usize),
}

/// Enumeration of parsing errors 
#[derive(Debug, PartialEq)]
pub enum ParseError {
    InvalidPrefix,
    BufferOverflow
}

/// Protocol structure
/// # payload_size = 0
/// if the payload_size is 0 then the parser will take the payload length from the message
pub struct Protocol<'a> {
    prefix: &'a [u8],
    prefix_size: usize,
    payload_size: usize,
}

impl<'a> Protocol<'a> {
    pub fn new(prefix: &'a [u8], prefix_size: usize, payload_size: usize) -> Self {
        Self {
            prefix,
            prefix_size,
            payload_size
        }
    }
}

/// Parser structure
pub struct Parser<'a> {
    buffer: [u8; BUFFER_SIZE],
    state: State,
    protocols: Vec<Protocol<'a>>,
    num_of_protocols: usize,
    // protocol_lock: isize,
    data_size: usize,
    bytes_read: usize,
    bytes_need_read: usize,
    buffer_position: usize,
}

impl<'a> Parser<'a> {
    pub fn new() -> Self {
        Self {
            buffer: [0; BUFFER_SIZE],
            state: State::SearchingPrefix,
            protocols: Vec::new(),
            num_of_protocols: 0,
            // protocol_lock: -1,
            data_size: 0,
            bytes_read: 0,
            bytes_need_read: 1,
            buffer_position: 0
        }
    }

    pub fn add_protocol(&mut self, prefix: &'a [u8], prefix_size: usize, payload_size: usize) {
        let protocol = Protocol::new(prefix, prefix_size, payload_size);
        self.protocols.push(protocol);
        self.num_of_protocols += 1;
    }

    fn reset(&mut self) {
        self.state = State::SearchingPrefix;
        // self.protocol_lock = -1;
        self.bytes_read = 0;
        self.bytes_need_read = 1;
        self.buffer_position = 0;
    }

    fn add_to_buffer(&mut self, data_byte: u8) -> Result<(), ParseError> {
        if self.buffer_position < BUFFER_SIZE {
            self.buffer[self.buffer_position] = data_byte;
            self.bytes_read += 1;
            self.bytes_need_read -= 1;
            self.buffer_position += 1;
            Ok(())
        } else {
            Err(ParseError::BufferOverflow)
        }
    }

    fn change_state(&mut self, new_state: State) {
        self.bytes_read = 0;
        self.state = new_state;
    }

    /// The main function of the parser
    pub fn task(&mut self, data_byte: u8) -> Result<&[u8], ParseError> {
        if let Err(error) = self.add_to_buffer(data_byte) {
            self.reset();
            return Err(error);
        }

        match self.state {
            State::SearchingPrefix => {
                for (protocol_index, protocol) in self.protocols.iter().enumerate() {
                    if self.buffer[0] == protocol.prefix[0] {
                        self.bytes_need_read = protocol.prefix_size - 1;
                        self.change_state(State::ValidatingPrefix(protocol_index));
                        self.bytes_read = 1;
                        return Ok(&[]);
                    }
                }

                self.reset();
                return Ok(&[]);
            },

            State::ValidatingPrefix(protocol_index) => {
                if self.buffer[..self.buffer_position] != self.protocols[protocol_index].prefix[..self.buffer_position] {
                    for (index, protocol) in self.protocols.iter().enumerate() {
                        if self.buffer[1..self.buffer_position] == protocol.prefix[..self.buffer_position - 1] {
                            self.buffer[self.buffer_position - 1] = self.buffer[self.buffer_position];
                            self.buffer_position -= 1;
                            self.change_state(State::ValidatingPrefix(index));
                            self.bytes_need_read = self.protocols[index].prefix_size - 1;
                            self.bytes_read = 1;
                            return Ok(&[]);
                        }

                        self.reset();
                        return Err(ParseError::InvalidPrefix);
                    }
                } else if self.bytes_read == self.protocols[protocol_index].prefix_size {
                    if self.protocols[protocol_index].payload_size == 0 {
                        self.change_state(State::ReadingLength(protocol_index));
                        self.bytes_need_read = mem::size_of::<u8>();
                    } else {
                        self.change_state(State::ReadingPayload(protocol_index));
                        self.bytes_need_read = self.protocols[protocol_index].payload_size;
                    }

                    return Ok(&[]);
                }

                return Ok(&[]);
            },

            State::ReadingLength(protocol_index) => {
                if self.bytes_need_read == 0 {
                    self.change_state(State::ReadingPayload(protocol_index));
                    self.bytes_need_read = data_byte as usize;
                }

                return Ok(&[]);
            },

            State::ReadingPayload(protocol_index) => {
                if self.bytes_need_read == 0 {
                    self.data_size = self.buffer_position;
                    let mut offset: usize = 0;
                    self.reset();

                    if self.protocols[protocol_index].payload_size == 0
                    {
                        offset = 1;
                    }

                    return Ok(&self.buffer[self.protocols[protocol_index].prefix_size + offset..self.data_size]);
                }

                Ok(&[])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_message() {
        let mut  parser = Parser::new();
        parser.add_protocol(&[0xAA, 0xBB], 2, 4);

        let data: [u8; 6] = [0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04];

        for elem in data {
            if let Ok(payload) = parser.task(elem) {
                if !payload.is_empty() {
                    assert_eq!(payload, [0x01, 0x02, 0x03, 0x04]);
                }
            }
        }
    }

    #[test]
    fn some_messages() {
        let mut  parser = Parser::new();
        parser.add_protocol(&[0xAA, 0xBB], 2, 4);

        let data: [u8; 18] = [
            0xDD, 0xAA,
            0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04,
            0x44, 0x45,
            0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04,
            0x33, 0x33
        ];

        let mut messages_received = 0;

        for elem in data {
            if let Ok(payload) = parser.task(elem) {
                if !payload.is_empty() {
                    assert_eq!(payload, [0x01, 0x02, 0x03, 0x04]);
                    messages_received += 1;
                }
            }
        }

        assert_eq!(messages_received, 2);
    }

    #[test]
    fn invalid_prefix() {
        let mut  parser = Parser::new();
        parser.add_protocol(&[0xAA, 0xBB], 2, 4);

        let data: [u8; 6] = [0xAA, 0xCC, 0x01, 0x02, 0x03, 0x04];

        for elem in data {
            if let Err(error) = parser.task(elem) {
                assert_eq!(error, ParseError::InvalidPrefix);
            }
        }
    }

    #[test]
    fn buffer_overflow() {
        let mut  parser = Parser::new();
        parser.add_protocol(&[0xAA, 0xBB], 2, 300);

        let mut data = [0u8; 0xDD];
        data[0] = 0xAA;
        data[1] = 0xBB;
        
        for elem in data {
            if let Err(error) = parser.task(elem) {
                assert_eq!(error, ParseError::BufferOverflow);
            }
        }
    }

    #[test]
    fn variable_length() {
        let mut parser = Parser::new();
        parser.add_protocol(&[0xAA, 0xBB], 2, 0);

        let data: [u8; 20] = [
            0xDD, 0xAA,
            0xAA, 0xBB, 0x04, 0x01, 0x02, 0x03, 0x04,
            0x44, 0x45,
            0xAA, 0xBB, 0x04, 0x01, 0x02, 0x03, 0x04,
            0x33, 0x33
        ];

        let mut messages_received = 0;

        for elem in data {
            if let Ok(payload) = parser.task(elem) {
                if !payload.is_empty() {
                    assert_eq!(payload, [0x01, 0x02, 0x03, 0x04]);
                    messages_received += 1;
                }
            }
        }

        assert_eq!(messages_received, 2);
    }

    #[test]
    fn multiple_protocols() {
        let mut parser = Parser::new();
        parser.add_protocol(&[0xAA, 0xBB], 2, 4);
        parser.add_protocol(&[0xCC, 0xDD, 0xFF], 3, 4);

        let data: [u8; 19] = [
            0xBB, 0xAA,
            0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04,
            0x44, 0x45,
            0xCC, 0xDD, 0xFF, 0x11, 0x22, 0x33, 0x44,
            0x33, 0x33
        ];

        let mut messages_received = 0;

        for elem in data {
            if let Ok(payload) = parser.task(elem) {
                if !payload.is_empty() {
                    messages_received += 1;
                }
            }
        }

        assert_eq!(messages_received, 2);
    }
}