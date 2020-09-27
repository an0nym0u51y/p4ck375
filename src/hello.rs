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

use ed25519::{PublicKey, Signature, SignatureError, Verifier};
use format::{Decode, Encode};
use std::io::{self, Read, Write};

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                        struct Hello                                        │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

#[derive(Debug, Clone)]
pub struct Hello {
    group: PublicKey,
    hash: [u8; 32],
    sig: Signature,
}

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                                         impl Hello                                         │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

impl Hello {
/*     ┌────────────────────────────────────────────────────────────────────────────────────┐     *\
 *     │                                        Read                                        │     *
\*     └────────────────────────────────────────────────────────────────────────────────────┘     */

    #[inline]
    pub fn group(&self) -> &PublicKey {
        &self.group
    }

    #[inline]
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        self.group.verify(&self.hash[..], &self.sig)
    }
}

/* ┌────────────────────────────────────────────────────────────────────────────────────────────┐ *\
 * │                               impl {En,De}code for PublicKey                               │ *
\* └────────────────────────────────────────────────────────────────────────────────────────────┘ */

impl Encode for Hello {
    type Error = io::Error;

    fn fast_size(&self) -> usize {
        let Hello {
            group,
            hash,
            sig,
        } = self;

        group.fast_size() + hash.fast_size() + sig.fast_size()
    }

    fn encode_into<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        let Hello {
            group,
            hash,
            sig,
        } = self;

        group.encode_into(&mut writer)?;
        hash.encode_into(&mut writer)?;
        sig.encode_into(writer)
    }
}

impl Decode for Hello {
    fn decode_with_read_from<R: Read>(mut reader: R) -> Result<(Self, usize), Self::Error> {
        let (group, read1) = PublicKey::decode_with_read_from(&mut reader)?;
        let (hash, read2) = <[u8; 32]>::decode_with_read_from(&mut reader)?;
        let (sig, read3) = Signature::decode_with_read_from(reader)?;

        Ok((Hello { group, hash, sig }, read1 + read2 + read3))
    }
}
