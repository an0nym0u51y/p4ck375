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

use format::{Decode, Encode};
use std::io::{self, Read, Write};

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                       struct Message                                       │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

#[derive(Debug)]
pub struct Message {
    buf: Vec<u8>,
}

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                impl {En,De}code for Message                                │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

impl Encode for Message {
    type Error = io::Error;

    fn fast_size(&self) -> usize {
        self.buf.fast_size()
    }

    fn encode_into<W: Write>(&self, writer: W) -> Result<(), Self::Error> {
        self.buf.encode_into(writer)
    }
}

impl Decode for Message {
    fn decode_with_read_from<R: Read>(reader: R) -> Result<(Self, usize), Self::Error> {
        let (buf, read) = Vec::<u8>::decode_with_read_from(reader)?;
        Ok((Message { buf }, read))
    }
}
