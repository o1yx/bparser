//! # bparser
//! 
//! 'bparser' - is a binary protocol parser designed for parsing messages like: prefix | length (optional) | payload

use std::mem;

const BUFFER_SIZE: usize = 256;

/// Enumeration of states of the parser state machine
enum State {
    Prefix,
    Length,
    Payload,
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

/// Parser structure
pub struct Parser<'a> {
    buffer: [u8; BUFFER_SIZE],
    state: State,
    protocol: &'a Protocol<'a>,
    data_size: usize,
    bytes_read: usize,
    bytes_need_read: usize,
    buffer_position: usize,
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

impl<'a> Parser<'a> {
    pub fn new(protocol: &'a Protocol) -> Self {
        Self {
            buffer: [0; BUFFER_SIZE],
            state: State::Prefix,
            protocol: protocol,
            data_size: 0,
            bytes_read: 0,
            bytes_need_read: 0,
            buffer_position: 0
        }
    }

    fn reset(&mut self) {
        self.state = State::Prefix;
        self.bytes_read = 0;
        self.bytes_need_read = self.protocol.prefix_size;
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
        match self.state {
            State::Prefix => {
                self.bytes_need_read = self.protocol.prefix_size;
                if let Err(error) = self.add_to_buffer(data_byte) {
                    return Err(error);
                }

                if &self.buffer[..self.buffer_position] != &self.protocol.prefix[..self.buffer_position] {
                    if &self.buffer[1..self.buffer_position] == &self.protocol.prefix[..self.buffer_position - 1] {
                        self.buffer[self.buffer_position - 1] = self.buffer[self.buffer_position];
                        self.bytes_read -= 1;
                        self.bytes_need_read += 1;
                        self.buffer_position -= 1;
                    } else {
                        self.reset();
                        return Err(ParseError::InvalidPrefix);
                    }
                } else if self.bytes_read == self.protocol.prefix_size {
                    if self.protocol.payload_size == 0 {
                        self.change_state(State::Length);
                        self.bytes_need_read = mem::size_of::<u8>();
                        return Ok(&[]);
                    } else {
                        self.change_state(State::Payload);
                        self.bytes_need_read = self.protocol.payload_size;
                        return Ok(&[]);
                    }
                }

                Ok(&[])
            },

            State::Length => {
                if let Err(error) = self.add_to_buffer(data_byte) {
                    return Err(error);
                }

                if self.bytes_need_read == 0 {
                    self.change_state(State::Payload);
                    self.bytes_need_read = data_byte as usize;
                    return Ok(&[]);
                }

                return Ok(&[]);
            },

            State::Payload => {
                if let Err(error) = self.add_to_buffer(data_byte) {
                    return Err(error);
                }
                if self.bytes_need_read == 0 {
                    self.data_size = self.buffer_position;
                    self.reset();
                    let mut offset: usize = 0;
                    if self.protocol.payload_size == 0 {
                        offset = 1;
                    }
                    return Ok(&self.buffer[self.protocol.prefix_size + offset..self.data_size]);
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
        let protocol = Protocol::new(&[0xAA, 0xBB], 2, 4);
        let mut  parser = Parser::new(&protocol);

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
        let protocol = Protocol::new(&[0xAA, 0xBB], 2, 4);
        let mut  parser = Parser::new(&protocol);

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
        let protocol = Protocol::new(&[0xAA, 0xBB], 2, 4);
        let mut  parser = Parser::new(&protocol);

        let data: [u8; 6] = [0xAA, 0xCC, 0x01, 0x02, 0x03, 0x04];

        for elem in data {
            if let Err(error) = parser.task(elem) {
                assert_eq!(error, ParseError::InvalidPrefix);
            }
        }
    }

    #[test]
    fn buffer_overflow() {
        let protocol = Protocol::new(&[0xAA, 0xBB], 2, 300);
        let mut  parser = Parser::new(&protocol);

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
        let protocol = Protocol::new(&[0xAA, 0xBB], 2, 0);
        let mut parser = Parser::new(&protocol);

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
}