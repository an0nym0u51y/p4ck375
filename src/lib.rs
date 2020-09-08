/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

pub use chrono::{self, DateTime, Utc};
pub use ed25519::{self, PublicKey, Signature};
pub use sparse::{self, Hash};

use core::convert::TryFrom;
use ed25519::Verifier;
use format::{Decode, Encode};
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[cfg(feature = "thiserror")]
use thiserror::Error;

// ========================================== Constants ========================================= \\

pub const RAW_OVERHEAD: usize = 2;
pub const NOISE_OVERHEAD: usize = 16;
pub const MSG_OVERHEAD: usize = RAW_OVERHEAD + NOISE_OVERHEAD;

pub const RAW_MAX_LEN: usize = NOISE_MAX_LEN - RAW_OVERHEAD;
pub const NOISE_MAX_LEN: usize = 65535;
pub const MSG_MAX_LEN: usize = NOISE_MAX_LEN - MSG_OVERHEAD;

// ============================================ Types =========================================== \\

pub enum Packet {
    Heartbeat(Heartbeat),
    Hello(Box<Hello>),
}

#[repr(u16)]
#[derive(Eq, PartialEq, IntoPrimitive, TryFromPrimitive, Copy, Clone, Debug)]
pub enum PacketId {
    Heartbeat = 0,
    Hello = 1,
}

#[derive(Debug)]
/// ## Encoding
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// +         Packet ID (0)         |                               |   4
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct Heartbeat;

#[derive(Debug)]
/// ## Encoding
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// +         Packet ID (1)         |                               |   4
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |   8
/// +                                                               +
/// |                                                               |  12
/// +                                                               +
/// |                                                               |  16
/// +                                                               +
/// |                                                               |  20
/// +                            Node ID                            +
/// |                                                               |  24
/// +                                                               +
/// |                                                               |  28
/// +                                                               +
/// |                                                               |  32
/// +                                                               +
/// |                                                               |  36
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |  40
/// +                                                               +
///
///                               {Root}
///
/// +                                                               +
/// |                                                               | 130
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct Hello {
    id: NodeId,
    root: Root,
}

#[derive(Debug)]
/// ## Encoding
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |   4
/// +                           Timestamp                           +
/// |                                                               |   8
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |  12
/// +                                                               +
/// |                                                               |  16
/// +                                                               +
/// |                                                               |  20
/// +                                                               +
/// |                                                               |  24
/// +                           Root Hash                           +
/// |                                                               |  28
/// +                                                               +
/// |                                                               |  32
/// +                                                               +
/// |                                                               |  36
/// +                                                               +
/// |                                                               |  40
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |  44
/// +                                                               +
/// |                                                               |  48
/// +                                                               +
/// |                                                               |  52
/// +                                                               +
/// |                                                               |  56
/// +                                                               +
/// |                                                               |  60
/// +                                                               +
/// |                                                               |  64
/// +                                                               +
/// |                                                               |  68
/// +                                                               +
/// |                                                               |  72
/// +                           Signature                           +
/// |                                                               |  76
/// +                                                               +
/// |                                                               |  80
/// +                                                               +
/// |                                                               |  84
/// +                                                               +
/// |                                                               |  88
/// +                                                               +
/// |                                                               |  92
/// +                                                               +
/// |                                                               |  96
/// +                                                               +
/// |                                                               | 100
/// +                                                               +
/// |                                                               | 104
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct Root {
    time: DateTime<Utc>,
    hash: Hash,
    sig: Signature,
}

#[derive(Debug)]
/// ## Encoding
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Length            |                               |   4
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
///
///                              {Proof}
///
/// +                                                               +
/// |                                                               | ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct Routes {
    proof: sparse::Proof,
}

pub type NodeId = PublicKey;
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(Error))]
pub enum Error {
    #[cfg_attr(feature = "thiserror", error("ed25519-related error ({0})"))]
    Ed25519(ed25519::SignatureError),
    #[cfg_attr(feature = "thiserror", error("f0rm47-related error ({0})"))]
    F0rm47(format::Error),
    #[cfg_attr(feature = "thiserror", error("invalid packet id ({0})"))]
    InvalidPacketId(u16),
    #[cfg_attr(feature = "thiserror", error("wrong packet id ({0:?})"))]
    WrongPacketId(PacketId),
}

// ========================================= impl Packet ======================================== \\

impl Packet {
    // ==================================== Constructors ==================================== \\

    #[inline]
    pub const fn heartbeat() -> Self {
        Packet::Heartbeat(Heartbeat::new())
    }

    #[inline]
    pub fn hello(id: NodeId, root: Root) -> Self {
        Hello::new(id, root).into()
    }
}

// ======================================= impl Heartbeat ======================================= \\

impl Heartbeat {
    // ==================================== Constructors ==================================== \\

    pub const fn new() -> Self {
        Heartbeat
    }
}

// ========================================= impl Hello ========================================= \\

impl Hello {
    // ==================================== Constructors ==================================== \\

    pub const fn new(id: NodeId, root: Root) -> Self {
        Hello { id, root }
    }

    // ======================================== Read ======================================== \\

    #[inline]
    pub fn id(&self) -> &NodeId {
        &self.id
    }

    #[inline]
    pub fn root(&self) -> &Root {
        &self.root
    }

    pub fn verify(&self) -> Result<()> {
        self.root.verify_for(&self.id)
    }
}

// ========================================== impl Root ========================================= \\

impl Root {
    // ==================================== Constructors ==================================== \\

    pub const fn new(time: DateTime<Utc>, hash: Hash, sig: Signature) -> Self {
        Root { time, hash, sig }
    }

    // ======================================= Helpers ====================================== \\

    pub fn prepare(time: &DateTime<Utc>, hash: &Hash) -> Result<[u8; 40]> {
        let mut msg = [0; 40];
        let (_, rest) = time.encode(&mut msg)?;
        hash.encode(rest)?;

        Ok(msg)
    }

    // ======================================== Read ======================================== \\

    #[inline]
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    #[inline]
    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    pub fn verify_for(&self, id: &NodeId) -> Result<()> {
        let msg = Self::prepare(&self.time, &self.hash)?;

        Ok(id.verify(&msg, &self.sig)?)
    }
}

// ======================================== macro_rules! ======================================== \\

macro_rules! group {
    ($group:ident {
        $({PacketId::$id:ident})?
        $({[u8; $offset:literal]})?

        $(
            $field:ident: $ty:ty
        ),* $(,)?
    }) => {
        impl Encode for $group {
            type Error = Error;

            fn encode<'buf>(&self, buf: &'buf mut [u8]) -> Result<(usize, &'buf mut [u8])> {
                let mut bytes = 0;
                $(
                    let (octets, buf) = PacketId::$id.encode(buf)?;
                    bytes += octets;
                )?

                $(
                    let (octets, buf) = [0u8; $offset].encode(buf)?;
                    bytes += octets;
                )?

                $(
                    let (octets, buf) = self.$field.encode(buf)?;
                    bytes += octets;
                )*

                Ok((bytes, buf))
            }
        }

        impl<'buf> Decode<'buf> for $group {
            type Error = Error;

            fn decode(buf: &'buf [u8]) -> Result<(Self, &'buf [u8])> {
                $(
                    let (id, buf) = PacketId::decode(buf)?;
                    if id != PacketId::$id {
                        return Err(Error::WrongPacketId(id));
                    }
                )?

                $(
                    let (_, buf) = <[u8; $offset]>::decode(buf)?;
                )?

                $(
                    let ($field, buf) = <$ty>::decode(buf)?;
                )*

                Ok(($group { $($field),* }, buf))
            }
        }
    };
}

// =========================================== group! =========================================== \\

group! {
    Heartbeat {
        {PacketId::Heartbeat}
        {[u8; 2]}
    }
}

group! {
    Hello {
        {PacketId::Hello}
        {[u8; 2]}
        id: NodeId,
        root: Root,
    }
}

group! {
    Root {
        time: DateTime<Utc>,
        hash: Hash,
        sig: Signature,
    }
}

group! {
    Routes {
        proof: sparse::Proof,
    }
}

// ========================================= impl Encode ======================================== \\

impl Encode for Packet {
    type Error = Error;

    fn encode<'buf>(&self, buf: &'buf mut [u8]) -> Result<(usize, &'buf mut [u8])> {
        match self {
            Packet::Heartbeat(packet) => packet.encode(buf),
            Packet::Hello(packet) => packet.encode(buf),
        }
    }
}

impl Encode for PacketId {
    type Error = Error;

    fn encode<'buf>(&self, buf: &'buf mut [u8]) -> Result<(usize, &'buf mut [u8])> {
        Ok((*self as u16).encode(buf)?)
    }
}

// ========================================= impl Decode ======================================== \\

impl<'buf> Decode<'buf> for Packet {
    type Error = Error;

    fn decode(buf: &'buf [u8]) -> Result<(Self, &'buf [u8])> {
        let (id, _) = PacketId::decode(buf)?;

        match id {
            PacketId::Heartbeat => {
                let (packet, rest) = Heartbeat::decode(buf)?;
                Ok((Packet::Heartbeat(packet), rest))
            },
            PacketId::Hello => {
                let (packet, rest) = Box::<Hello>::decode(buf)?;
                Ok((Packet::Hello(packet), rest))
            },
        }
    }
}

impl<'buf> Decode<'buf> for PacketId {
    type Error = Error;

    fn decode(buf: &'buf [u8]) -> Result<(Self, &'buf [u8])> {
        let (id, rest) = u16::decode(buf)?;

        Ok((PacketId::try_from(id)?, rest))
    }
}

// ========================================== impl From ========================================= \\

impl From<Heartbeat> for Packet {
    #[inline]
    fn from(packet: Heartbeat) -> Self {
        Packet::Heartbeat(packet)
    }
}

impl From<Hello> for Packet {
    #[inline]
    fn from(packet: Hello) -> Self {
        Packet::Hello(packet.into())
    }
}

impl From<ed25519::SignatureError> for Error {
    #[inline]
    fn from(error: ed25519::SignatureError) -> Self {
        Error::Ed25519(error)
    }
}

impl From<format::Error> for Error {
    #[inline]
    fn from(error: format::Error) -> Self {
        Error::F0rm47(error)
    }
}

impl From<num_enum::TryFromPrimitiveError<PacketId>> for Error {
    #[inline]
    fn from(error: num_enum::TryFromPrimitiveError<PacketId>) -> Self {
        Error::InvalidPacketId(error.number)
    }
}
