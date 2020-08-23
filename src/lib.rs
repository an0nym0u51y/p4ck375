/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use chrono::{NaiveDateTime, Utc};
use core::convert::TryFrom;
use ed25519::{PublicKey, Signature, Verifier};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use sparse::Hash;

#[cfg(feature = "thiserror")]
use thiserror::Error;

// ============================================ Types =========================================== \\

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct NodeId(PublicKey);

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
    time: DateTime,
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
/// |                                                               |   4
/// +                                                               +
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

pub type DateTime = chrono::DateTime<Utc>;
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(Error))]
pub enum Error {
    #[cfg_attr(feature = "thiserror", error("ed25519-related error ({0})"))]
    Ed25519(ed25519::SignatureError),
    #[cfg_attr(feature = "thiserror", error("maximum size exceeded (max: {max}, actual: {actual})"))]
    MaxSize {
        max: usize,
        actual: usize,
    },
    #[cfg_attr(feature = "thiserror", error("mininum size not reached (min: {min}, actual: {actual})"))]
    MinSize {
        min: usize,
        actual: usize,
    },
    #[cfg_attr(feature = "thiserror", error("sp4r53-related error ({0})"))]
    Sparse(sparse::Error),
    #[cfg_attr(feature = "thiserror", error("invalid packet id ({0})"))]
    InvalidPacketId(u16),
    #[cfg_attr(feature = "thiserror", error("wrong packet id ({0:?})"))]
    WrongPacketId(PacketId),
}

// ========================================= Interfaces ========================================= \\

pub trait Packet: Encode + Decode {
    const PACKET_ID: PacketId;
}

pub trait Encode {
    fn encode(&self, buf: &mut [u8]) -> Result<usize>;
}

pub trait Decode: Sized {
    fn decode(buf: &[u8]) -> Result<(Self, usize)>;
}

// ========================================== Constants ========================================= \\

pub const RAW_OVERHEAD: usize = 2;
pub const NOISE_OVERHEAD: usize = 16;

pub const RAW_MAX_LEN: usize = NOISE_MAX_LEN - RAW_OVERHEAD;
pub const NOISE_MAX_LEN: usize = 65535;
pub const MSG_MAX_LEN: usize = RAW_MAX_LEN - NOISE_OVERHEAD;

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

    pub const fn new(time: DateTime, hash: Hash, sig: Signature) -> Self {
        Root { time, hash, sig }
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
        let mut msg = [0; 40];
        msg[0..8].copy_from_slice(&(self.time.timestamp().to_le_bytes()));
        msg[8..40].copy_from_slice(self.hash.as_bytes());

        Ok(id.0.verify(&msg, &self.sig)?)
    }
}

// ======================================== macro_rules! ======================================== \\

macro_rules! group {
    ($name:ident {
        $({PacketId::$id:ident})?
        $({[u8; $offset:literal]})?

        $(
            $fname:ident: $fty:ty
            $({[u8; $foffset:literal]})?
        ),* $(,)?

    }) => {
        $(impl Packet for $name {
            const PACKET_ID: PacketId = PacketId::$id;
        })?

        impl Encode for $name {
            fn encode(&self, buf: &mut [u8]) -> Result<usize> {
                let mut offset = 0;
                $(offset += PacketId::$id.encode(&mut buf[offset..])?;)?
                $(offset += [0; $offset].encode(&mut buf[offset..])?;)?

                $(
                    $(offset += [0; $foffset].encode(&mut buf[offset..])?;)?
                    offset += self.$fname.encode(&mut buf[offset..])?;
                )*

                Ok(offset)
            }
        }

        impl Decode for $name {
            fn decode(buf: &[u8]) -> Result<(Self, usize)> {
                let mut offset = 0;

                $(
                    let (packet, bytes) = PacketId::decode(&buf[offset..])?;
                    if packet != PacketId::$id {
                        return Err(Error::WrongPacketId(packet));
                    }

                    offset += bytes;
                )?

                $(
                    let (_, bytes) = <[u8; $offset]>::decode(&buf[offset..])?;
                    offset += bytes;
                )?

                $(
                    $(
                        let (_, bytes) = <[u8; $foffset]>::decode(&buf[offset..])?;
                        offset += bytes;
                    )?

                    let ($fname, bytes) = <$fty>::decode(&buf[offset..])?;
                    offset += bytes;
                )*

                Ok(($name { $($fname),* }, offset))
            }
        }
    };
}

macro_rules! assert_min_size {
    ($buf:ident, $min:expr) => {
        if $buf.len() < $min {
            return Err(Error::MinSize {
                min: $min,
                actual: $buf.len(),
            });
        }
    };
}

macro_rules! assert_max_size {
    ($buf:ident, $max:expr) => {
        if $buf.len() > $max {
            return Err(Error::MaxSize {
                max: $max,
                actual: $buf.len(),
            });
        }
    }
}

macro_rules! encode_from_slice {
    (($this:ident: $ty:ty): 0..$b:literal <- $bytes:expr) => {
        impl Encode for $ty {
            fn encode(&self, buf: &mut [u8]) -> Result<usize> {
                assert_min_size!(buf, $b);

                let $this = self;
                buf[0..$b].copy_from_slice($bytes);

                Ok($b)
            }
        }
    };
}

macro_rules! decode_bytes {
    ([u8; $n:literal]) => {
        impl Decode for [u8; $n] {
            fn decode(buf: &[u8]) -> Result<(Self, usize)> {
                assert_min_size!(buf, $n);

                let mut arr = [0; $n];
                arr[..].copy_from_slice(&buf[..$n]);

                Ok((arr, $n))
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
        time: DateTime,
        hash: Hash,
        sig: Signature,
    }
}

// =========================================== Encode =========================================== \\

impl Encode for PacketId {
    fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        assert_min_size!(buf, 2);

        buf[0..2].copy_from_slice(&(*self as u16).to_le_bytes());

        Ok(2)
    }
}

encode_from_slice!((this: DateTime): 0..8 <- &(this.timestamp().to_le_bytes()));
encode_from_slice!((this: Hash): 0..32 <- this.as_bytes());
encode_from_slice!((this: NodeId): 0..32 <- this.0.as_bytes());
encode_from_slice!((this: Signature): 0..64 <- &this.to_bytes());

impl Encode for sparse::Proof {
    fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        assert_min_size!(buf, 2);

        let bytes = self.as_bytes();
        assert_max_size!(buf, MSG_MAX_LEN - 2);
        assert_min_size!(buf, 2 + bytes.len());

        buf[0..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        buf[2..(2 + bytes.len())].copy_from_slice(&bytes);

        Ok(2 + bytes.len())
    }
}

impl Encode for [u8] {
    fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        assert_min_size!(buf, self.len());

        buf[0..self.len()].copy_from_slice(self);

        Ok(self.len())
    }
}

// ========================================= impl Decode ======================================== \\

impl Decode for PacketId {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        assert_min_size!(buf, 2);

        Ok((PacketId::try_from(u16::from_le_bytes([buf[0], buf[1]]))?, 2))
    }
}

impl Decode for DateTime {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        assert_min_size!(buf, 8);

        let bytes = <[u8; 8]>::try_from(&buf[0..8]).unwrap();
        let time = NaiveDateTime::from_timestamp(i64::from_le_bytes(bytes), 0);

        Ok((DateTime::from_utc(time, Utc), 8))
    }
}

impl Decode for Hash {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        assert_min_size!(buf, 32);

        Ok((Hash::from(<[u8; 32]>::try_from(&buf[0..32]).unwrap()), 32))
    }
}

impl Decode for sparse::Proof {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        assert_min_size!(buf, 2);

        let len = u16::from_le_bytes([buf[0], buf[1]]) as usize + 2;
        assert_min_size!(buf, len);

        Ok((Self::from_bytes(&buf[2..len])?, len))
    }
}

impl Decode for NodeId {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        assert_min_size!(buf, 32);

        Ok((NodeId(PublicKey::from_bytes(&buf[0..32])?), 32))
    }
}

impl Decode for Signature {
    fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        assert_min_size!(buf, 64);

        Ok((Signature::try_from(&buf[0..64])?, 64))
    }
}

decode_bytes!([u8; 1]);
decode_bytes!([u8; 2]);
decode_bytes!([u8; 3]);
decode_bytes!([u8; 4]);

// ========================================== impl From ========================================= \\

impl From<ed25519::SignatureError> for Error {
    #[inline]
    fn from(error: ed25519::SignatureError) -> Self {
        Error::Ed25519(error)
    }
}

impl From<num_enum::TryFromPrimitiveError<PacketId>> for Error {
    #[inline]
    fn from(error: num_enum::TryFromPrimitiveError<PacketId>) -> Self {
        Error::InvalidPacketId(error.number)
    }
}

impl From<sparse::Error> for Error {
    #[inline]
    fn from(error: sparse::Error) -> Self {
        Error::Sparse(error)
    }
}
