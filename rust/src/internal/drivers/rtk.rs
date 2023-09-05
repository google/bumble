// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Drivers for Realtek controllers

use nom::{bytes, combinator, error, multi, number, sequence};

/// Realtek firmware file contents
pub struct Firmware {
    version: u32,
    project_id: u8,
    patches: Vec<Patch>,
}

impl Firmware {
    /// Parse a `*_fw.bin` file
    pub fn parse(input: &[u8]) -> Result<Self, nom::Err<error::Error<&[u8]>>> {
        let extension_sig = [0x51, 0x04, 0xFD, 0x77];

        let (_rem, (_tag, fw_version, patch_count, payload)) =
            combinator::all_consuming(combinator::map_parser(
                // ignore the sig suffix
                sequence::terminated(
                    bytes::complete::take(
                        // underflow will show up as parse failure
                        input.len().saturating_sub(extension_sig.len()),
                    ),
                    bytes::complete::tag(extension_sig.as_slice()),
                ),
                sequence::tuple((
                    bytes::complete::tag(b"Realtech"),
                    // version
                    number::complete::le_u32,
                    // patch count
                    combinator::map(number::complete::le_u16, |c| c as usize),
                    // everything else except suffix
                    combinator::rest,
                )),
            ))(input)?;

        // ignore remaining input, since patch offsets are relative to the complete input
        let (_rem, (chip_ids, patch_lengths, patch_offsets)) = sequence::tuple((
            // chip id
            multi::many_m_n(patch_count, patch_count, number::complete::le_u16),
            // patch length
            multi::many_m_n(patch_count, patch_count, number::complete::le_u16),
            // patch offset
            multi::many_m_n(patch_count, patch_count, number::complete::le_u32),
        ))(payload)?;

        let patches = chip_ids
            .into_iter()
            .zip(patch_lengths.into_iter())
            .zip(patch_offsets.into_iter())
            .map(|((chip_id, patch_length), patch_offset)| {
                combinator::map(
                    sequence::preceded(
                        bytes::complete::take(patch_offset),
                        // ignore trailing 4-byte suffix
                        sequence::terminated(
                            // patch including svn version, but not suffix
                            combinator::consumed(sequence::preceded(
                                // patch before svn version or version suffix
                                // prefix length underflow will show up as parse failure
                                bytes::complete::take(patch_length.saturating_sub(8)),
                                // svn version
                                number::complete::le_u32,
                            )),
                            // dummy suffix, overwritten with firmware version
                            bytes::complete::take(4_usize),
                        ),
                    ),
                    |(patch_contents_before_version, svn_version): (&[u8], u32)| {
                        let mut contents = patch_contents_before_version.to_vec();
                        // replace what would have been the trailing dummy suffix with fw version
                        contents.extend_from_slice(&fw_version.to_le_bytes());

                        Patch {
                            contents,
                            svn_version,
                            chip_id,
                        }
                    },
                )(input)
                .map(|(_rem, output)| output)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // look for project id from the end
        let mut offset = payload.len();
        let mut project_id: Option<u8> = None;
        while offset >= 2 {
            // Won't panic, since offset >= 2
            let chunk = &payload[offset - 2..offset];
            let length: usize = chunk[0].into();
            let opcode = chunk[1];
            offset -= 2;

            if opcode == 0xFF {
                break;
            }
            if length == 0 {
                // report what nom likely would have done, if nom was good at parsing backwards
                return Err(nom::Err::Error(error::Error::new(
                    chunk,
                    error::ErrorKind::Verify,
                )));
            }
            if opcode == 0 && length == 1 {
                project_id = offset
                    .checked_sub(1)
                    .and_then(|index| payload.get(index))
                    .copied();
                break;
            }

            offset -= length;
        }

        match project_id {
            Some(project_id) => Ok(Firmware {
                project_id,
                version: fw_version,
                patches,
            }),
            None => {
                // we ran out of file without finding a project id
                Err(nom::Err::Error(error::Error::new(
                    payload,
                    error::ErrorKind::Eof,
                )))
            }
        }
    }

    /// Patch version
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Project id
    pub fn project_id(&self) -> u8 {
        self.project_id
    }

    /// Patches
    pub fn patches(&self) -> &[Patch] {
        &self.patches
    }
}

/// Patch in a [Firmware}
pub struct Patch {
    chip_id: u16,
    contents: Vec<u8>,
    svn_version: u32,
}

impl Patch {
    /// Chip id
    pub fn chip_id(&self) -> u16 {
        self.chip_id
    }
    /// Contents of the patch, including the 4-byte firmware version suffix
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
    /// SVN version
    pub fn svn_version(&self) -> u32 {
        self.svn_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::{fs, io, path};

    #[test]
    fn parse_firmware_rtl8723b() -> anyhow::Result<()> {
        let fw = Firmware::parse(&firmware_contents("rtl8723b_fw_structure.bin")?)
            .map_err(|e| anyhow!("{:?}", e))?;

        let fw_version = 0x0E2F9F73;
        assert_eq!(fw_version, fw.version());
        assert_eq!(0x0001, fw.project_id());
        assert_eq!(
            vec![(0x0001, 0x00002BBF, 22368,), (0x0002, 0x00002BBF, 22496,),],
            patch_summaries(fw, fw_version)
        );

        Ok(())
    }

    #[test]
    fn parse_firmware_rtl8761bu() -> anyhow::Result<()> {
        let fw = Firmware::parse(&firmware_contents("rtl8761bu_fw_structure.bin")?)
            .map_err(|e| anyhow!("{:?}", e))?;

        let fw_version = 0xDFC6D922;
        assert_eq!(fw_version, fw.version());
        assert_eq!(0x000E, fw.project_id());
        assert_eq!(
            vec![(0x0001, 0x00005060, 14048,), (0x0002, 0xD6D525A4, 30204,),],
            patch_summaries(fw, fw_version)
        );

        Ok(())
    }

    fn firmware_contents(filename: &str) -> io::Result<Vec<u8>> {
        fs::read(
            path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources/test/firmware/realtek")
                .join(filename),
        )
    }

    /// Return a tuple of (chip id, svn version, contents len, contents sha256)
    fn patch_summaries(fw: Firmware, fw_version: u32) -> Vec<(u16, u32, usize)> {
        fw.patches()
            .iter()
            .map(|p| {
                let contents = p.contents();
                let mut dummy_contents = dummy_contents(contents.len());
                dummy_contents.extend_from_slice(&p.svn_version().to_le_bytes());
                dummy_contents.extend_from_slice(&fw_version.to_le_bytes());
                assert_eq!(&dummy_contents, contents);
                (p.chip_id(), p.svn_version(), contents.len())
            })
            .collect::<Vec<_>>()
    }

    fn dummy_contents(len: usize) -> Vec<u8> {
        let mut vec = (len as u32).to_le_bytes().as_slice().repeat(len / 4 + 1);
        assert!(vec.len() >= len);
        // leave room for svn version and firmware version
        vec.truncate(len - 8);
        vec
    }
}
