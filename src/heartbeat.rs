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

use core::ops::{Deref, DerefMut};
use format::{Decode, Encode};
use std::io::{self, Read, Write};

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                      struct Heartbeat                                      │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct Heartbeat(u32);

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                       impl Heartbeat                                       │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

impl Heartbeat {
/*     ┌────────────────────────────────────────────────────────────────────────────────────┐     *\
 *     │                                    Constructors                                    │     *
\*     └────────────────────────────────────────────────────────────────────────────────────┘     */

    pub fn new(nonce: u32) -> Self {
        Heartbeat(nonce)
    }
}

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                               impl {En,De}code for Heartbeat                               │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

impl Encode for Heartbeat {
    type Error = io::Error;

    fn fast_size(&self) -> usize {
        self.0.fast_size()
    }

    fn encode_into<W: Write>(&self, writer: W) -> Result<(), Self::Error> {
        self.0.encode_into(writer)
    }
}

impl Decode for Heartbeat {
    fn decode_with_read_from<R: Read>(reader: R) -> Result<(Self, usize), Self::Error> {
        let (nonce, read) = u32::decode_with_read_from(reader)?;
        Ok((Heartbeat(nonce), read))
    }
}

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                               impl Deref{,Mut} for Heartbeat                               │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

impl Deref for Heartbeat {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Heartbeat {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                             impl PartialEq<u32> for Heartbeat                              │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

impl PartialEq<u32> for Heartbeat {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}
