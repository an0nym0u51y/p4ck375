/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                                                                            │ *
 * │ This Source Code Form is subject to the terms of the Mozilla Public                        │ *
 * │ License, v. 2.0. If a copy of the MPL was not distributed with this                        │ *
 * │ file, You can obtain one at http://mozilla.org/MPL/2.0/.                                   │ *
 * │                                                                                            │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                          Imports                                           │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

mod heartbeat;
mod hello;
mod message;

pub use self::heartbeat::Heartbeat;
pub use self::hello::Hello;
pub use self::message::Message;

use format::{Decode, Encode};
use std::io::{self, Read, Write};

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                      enum Packet{,Id}                                      │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

#[derive(Debug)]
pub enum Packet {
    Heartbeat(Heartbeat),
    Hello(Box<Hello>),
    Message(Message),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum PacketId {
    Heartbeat = 0,
    Hello = 1,
    Message = 2,
}

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                        impl Packet                                         │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

impl Packet {
/*     ┌────────────────────────────────────────────────────────────────────────────────────┐     *\
 *     │                                      fn id()                                       │     *
\*     └────────────────────────────────────────────────────────────────────────────────────┘     */

    pub fn id(&self) -> PacketId {
        match self {
            Packet::Heartbeat(_) => PacketId::Heartbeat,
            Packet::Hello(_) => PacketId::Hello,
            Packet::Message(_) => PacketId::Message,
        }
    }

/*     ┌────────────────────────────────────────────────────────────────────────────────────┐     *\
 *     │                         fn is_{heartbeat,hello,message}()                          │     *
\*     └────────────────────────────────────────────────────────────────────────────────────┘     */

    pub fn is_heartbeat(&self) -> bool {
        matches!(self, Packet::Heartbeat(_))
    }

    pub fn is_hello(&self) -> bool {
        matches!(self, Packet::Hello(_))
    }

    pub fn is_message(&self) -> bool {
        matches!(self, Packet::Message(_))
    }

/*     ┌────────────────────────────────────────────────────────────────────────────────────┐     *\
 *     │                         fn as_{heartbeat,hello,message}()                          │     *
\*     └────────────────────────────────────────────────────────────────────────────────────┘     */

    pub fn as_heartbeat(&self) -> Option<&Heartbeat> {
        if let Packet::Heartbeat(heartbeat) = self {
            Some(heartbeat)
        } else {
            None
        }
    }

    pub fn as_hello(&self) -> Option<&Hello> {
        if let Packet::Hello(hello) = self {
            Some(hello)
        } else {
            None
        }
    }

    pub fn as_message(&self) -> Option<&Message> {
        if let Packet::Message(message) = self {
            Some(message)
        } else {
            None
        }
    }

/*     ┌────────────────────────────────────────────────────────────────────────────────────┐     *\
 *     │                        fn into_{heartbeat,hello,message}()                         │     *
\*     └────────────────────────────────────────────────────────────────────────────────────┘     */

    pub fn into_heartbeat(self) -> Option<Heartbeat> {
        if let Packet::Heartbeat(heartbeat) = self {
            Some(heartbeat)
        } else {
            None
        }
    }

    pub fn into_hello(self) -> Option<Hello> {
        if let Packet::Hello(hello) = self {
            Some(*hello)
        } else {
            None
        }
    }

    pub fn into_message(self) -> Option<Message> {
        if let Packet::Message(message) = self {
            Some(message)
        } else {
            None
        }
    }
}

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                impl {En,De}code for Packet                                 │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

impl Encode for Packet {
    type Error = io::Error;

    fn fast_size(&self) -> usize {
        match self {
            Packet::Heartbeat(packet) => PacketId::Heartbeat.fast_size() + packet.fast_size(),
            Packet::Hello(packet) => PacketId::Hello.fast_size() + packet.fast_size(),
            Packet::Message(packet) => PacketId::Message.fast_size() + packet.fast_size(),
        }
    }

    fn encode_into<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        match self {
            Packet::Heartbeat(packet) => {
                PacketId::Heartbeat.encode_into(&mut writer)?;
                packet.encode_into(writer)
            }
            Packet::Hello(packet) => {
                PacketId::Hello.encode_into(&mut writer)?;
                packet.encode_into(writer)
            }
            Packet::Message(packet) => {
                PacketId::Message.encode_into(&mut writer)?;
                packet.encode_into(writer)
            }
        }
    }
}

impl Decode for Packet {
    fn decode_with_read_from<R: Read>(mut reader: R) -> Result<(Self, usize), Self::Error> {
        let (id, read1) = PacketId::decode_with_read_from(&mut reader)?;
        match id {
            PacketId::Heartbeat => {
                let (packet, read2) = Heartbeat::decode_with_read_from(reader)?;
                Ok((Packet::Heartbeat(packet), read1 + read2))
            }
            PacketId::Hello => {
                let (packet, read2) = Box::<Hello>::decode_with_read_from(reader)?;
                Ok((Packet::Hello(packet), read1 + read2))
            }
            PacketId::Message => {
                let (packet, read2) = Message::decode_with_read_from(reader)?;
                Ok((Packet::Message(packet), read1 + read2))
            }
        }
    }
}

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                               impl {En,De}code for PacketId                                │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

impl Encode for PacketId {
    type Error = io::Error;

    fn fast_size(&self) -> usize {
        (*self as u8).fast_size()
    }

    fn encode_into<W: Write>(&self, writer: W) -> Result<(), Self::Error> {
        (*self as u8).encode_into(writer)
    }
}

impl Decode for PacketId {
    fn decode_with_read_from<R: Read>(reader: R) -> Result<(Self, usize), Self::Error> {
        match u8::decode_with_read_from(reader)? {
            (0, read) => Ok((PacketId::Heartbeat, read)),
            (1, read) => Ok((PacketId::Hello, read)),
            (2, read) => Ok((PacketId::Message, read)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid packet id"))
        }
    }
}
