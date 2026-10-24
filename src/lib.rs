//! # bparser
//! 
//! 'bparser' - is a binary protocol parser designed for parsing messages like: prefix | length (optional) | payload

const BUFFER_SIZE: usize = 256;

/// Enumeration of states of the parser state machine
#[derive(Debug)]
enum State {
    SearchingPrefix,
    ValidatingPrefix,
    ReadingLength,
    ReadingPayload,
}

/// Enumeration of parsing errors 
#[derive(Debug, PartialEq)]
pub enum ParseError {
    BufferOverflow,
}

/// Protocol structure
/// # payload_size = 0
/// if the payload_size is 0 then the parser will take the payload length from the message
pub struct Protocol<'a> {
    prefix: &'a [u8],
    payload_size: usize,
}

impl<'a> Protocol<'a> {
    pub fn new(prefix: &'a [u8], payload_size: usize) -> Self {
        Self {
            prefix,
            payload_size
        }
    }
}

/// Parser structure
pub struct Parser<'a> {
    buffer: [u8; BUFFER_SIZE],
    buffer_position: usize,
    state: State,
    protocols: Vec<Protocol<'a>>,
    active_protocol_idx: Option<usize>,
    expected_len: usize,
}

impl<'a> Default for Parser<'a> {
    fn default() -> Self {
        Self {
            buffer: [0; BUFFER_SIZE],
            buffer_position: 0,
            state: State::SearchingPrefix,
            protocols: Vec::new(),
            active_protocol_idx: None,
            expected_len: 0,
        }
    }
}

impl<'a> Parser<'a> {
    pub fn add_protocol(&mut self, prefix: &'a [u8], payload_size: usize) {
        if !prefix.is_empty() {
            self.protocols.push(Protocol::new(prefix, payload_size));
        }
    }

    fn reset(&mut self) {
        self.buffer_position = 0;
        self.state = State::SearchingPrefix;
        self.active_protocol_idx = None;
        self.expected_len = 0;
    }

    /// The main function of the parser
    pub fn task(&mut self, data_byte: u8) -> Result<&[u8], ParseError> {
        if self.buffer_position >= BUFFER_SIZE {
            self.reset();
            return Err(ParseError::BufferOverflow);
        }

        self.buffer[self.buffer_position] = data_byte;
        self.buffer_position += 1;

        match self.state {
            State::SearchingPrefix => {
                if let Some(protocol_idx) = self.protocols.iter().position(|pr| self.buffer[0] == pr.prefix[0]) {
                    self.active_protocol_idx = Some(protocol_idx);
                    self.state = State::ValidatingPrefix;
                    return Ok(&[]);
                }

                self.reset();
                Ok(&[])
            },

            State::ValidatingPrefix => {
                let protocol_idx = self.active_protocol_idx.unwrap();
                let protocol = &self.protocols[protocol_idx];

                if self.buffer[..self.buffer_position] == protocol.prefix[..self.buffer_position] {
                    if self.buffer_position == protocol.prefix.len() {
                        if protocol.payload_size == 0 {
                            self.state = State::ReadingLength;
                        } else {
                            self.expected_len = protocol.prefix.len() + protocol.payload_size;
                            self.state = State::ReadingPayload;
                        }
                    }
                    return Ok(&[]);
                }

                for len in (1..self.buffer_position).rev() {
                    if let Some(protocol_idx) = self.protocols.iter().position(|pr| len <= pr.prefix.len() && self.buffer[self.buffer_position - len .. self.buffer_position] == pr.prefix[..len]) {
                        self.buffer.copy_within(self.buffer_position - len .. self.buffer_position, 0);
                        self.buffer_position = len;
                        self.active_protocol_idx = Some(protocol_idx);
                        self.state = State::ValidatingPrefix;
                        return Ok(&[]);
                    }
                }

                self.buffer[0] = data_byte;
                self.buffer_position = 1;
                self.state = State::SearchingPrefix;

                if let Some(protocol_idx) = self.protocols.iter().position(|pr| self.buffer[0] == pr.prefix[0]) {
                    self.active_protocol_idx = Some(protocol_idx);
                    self.state = State::ValidatingPrefix;
                    return Ok(&[]);
                }

                self.reset();
                Ok(&[])
            },

            State::ReadingLength => {
                let idx = self.active_protocol_idx.unwrap();
                let protocol = &self.protocols[idx];

                self.expected_len = protocol.prefix.len() + 1 + data_byte as usize;

                if self.expected_len > BUFFER_SIZE {
                    self.reset();
                    return Err(ParseError::BufferOverflow);
                }

                self.state = State::ReadingPayload;
                Ok(&[])
            },

            State::ReadingPayload => {
                if self.buffer_position == self.expected_len {
                    let full_msg_len = self.buffer_position;
                    self.reset();
                    let full_msg = &self.buffer[..full_msg_len];
                    return Ok(full_msg);
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
        let mut  parser = Parser::default();
        parser.add_protocol(&[0xAA, 0xBB], 4);

        let data: [u8; 6] = [0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04];

        for elem in data {
            if let Ok(msg) = parser.task(elem) && !msg.is_empty() {
                assert_eq!(msg, [0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04]);
            }
        }
    }

    #[test]
    fn some_messages() {
        let mut  parser = Parser::default();
        parser.add_protocol(&[0xAA, 0xBB], 4);

        let data: [u8; 18] = [
            0xDD, 0xAA,
            0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04,
            0x44, 0x45,
            0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04,
            0x33, 0x33
        ];

        let mut messages_received = 0;

        for elem in data {
            if let Ok(msg) = parser.task(elem) && !msg.is_empty() {
                assert_eq!(msg, [0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04]);
                messages_received += 1;
            }
        }

        assert_eq!(messages_received, 2);
    }

    #[test]
    fn buffer_overflow() {
        let mut  parser = Parser::default();
        parser.add_protocol(&[0xAA, 0xBB], BUFFER_SIZE + 6);

        let mut data = [0u8; BUFFER_SIZE + 6];
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
        let mut parser = Parser::default();
        parser.add_protocol(&[0xAA, 0xBB], 0);

        let data: [u8; 20] = [
            0xDD, 0xAA,
            0xAA, 0xBB, 0x04, 0x01, 0x02, 0x03, 0x04,
            0x44, 0x45,
            0xAA, 0xBB, 0x04, 0x01, 0x02, 0x03, 0x04,
            0x33, 0x33
        ];

        let mut messages_received = 0;

        for elem in data {
            if let Ok(msg) = parser.task(elem) && !msg.is_empty() {
                assert_eq!(msg, [0xAA, 0xBB, 0x04, 0x01, 0x02, 0x03, 0x04]);
                messages_received += 1;
            }
        }

        assert_eq!(messages_received, 2);
    }

    #[test]
    fn multiple_protocols() {
        let mut parser = Parser::default();
        parser.add_protocol(&[0xAA, 0xBB], 4);
        parser.add_protocol(&[0xCC, 0xDD, 0xFF], 4);

        let data: [u8; 19] = [
            0xBB, 0xAA,
            0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04,
            0x44, 0x45,
            0xCC, 0xDD, 0xFF, 0x11, 0x22, 0x33, 0x44,
            0x33, 0x33
        ];

        let mut messages_received = 0;

        for elem in data {
            if let Ok(msg) = parser.task(elem) && !msg.is_empty() {
                messages_received += 1;
            }
        }

        assert_eq!(messages_received, 2);
    }

    #[test]
    fn overlap_with_long_prefix() {
        let mut parser = Parser::default();
        parser.add_protocol(&[0xAA, 0xBB, 0xCC], 2);

        let data = [0xAA, 0xBB, 0xAA, 0xBB, 0xCC, 0x01, 0x02];

        let mut messages_received = 0;
        for elem in data {
            if let Ok(msg) = parser.task(elem) && !msg.is_empty() {
                assert_eq!(msg, [0xAA, 0xBB, 0xCC, 0x01, 0x02]);
                messages_received += 1;
            }
        }

        assert_eq!(messages_received, 1);
    }
}