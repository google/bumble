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

use crate::internal::hci::{
    packets::{Event, EventBuilder, EventCode, Sco},
    parse_with_expected_packet_type, prepend_packet_type, Error, Packet, PacketType,
    PacketTypeParseError, WithPacketType,
};
use bytes::Bytes;

#[test]
fn prepends_packet_type() {
    let packet_type = PacketType::Event;
    let actual = prepend_packet_type(packet_type, FakePacket { bytes: vec![0xFF] });
    assert_eq!(vec![0x04, 0xFF], actual);
}

#[test]
fn parse_empty_slice_should_error() {
    let actual = parse_with_expected_packet_type(FakePacket::parse, PacketType::Event, &[]);
    assert_eq!(Err(PacketTypeParseError::EmptySlice), actual);
}

#[test]
fn parse_invalid_packet_type_should_error() {
    let actual = parse_with_expected_packet_type(FakePacket::parse, PacketType::Event, &[0xFF]);
    assert_eq!(
        Err(PacketTypeParseError::InvalidPacketType { value: 0xFF }),
        actual
    );
}

#[test]
fn parse_mismatched_packet_type_should_error() {
    let actual = parse_with_expected_packet_type(FakePacket::parse, PacketType::Acl, &[0x01]);
    assert_eq!(
        Err(PacketTypeParseError::PacketTypeMismatch {
            expected: PacketType::Acl,
            actual: PacketType::Command
        }),
        actual
    );
}

#[test]
fn parse_invalid_packet_should_error() {
    let actual = parse_with_expected_packet_type(Sco::parse, PacketType::Sco, &[0x03]);
    assert!(actual.is_err());
}

#[test]
fn test_packet_roundtrip_with_type() {
    let event_packet = EventBuilder {
        event_code: EventCode::InquiryComplete,
        payload: None,
    }
    .build();
    let event_packet_bytes = event_packet.clone().to_vec_with_packet_type();
    let actual =
        parse_with_expected_packet_type(Event::parse, PacketType::Event, &event_packet_bytes)
            .unwrap();
    assert_eq!(event_packet, actual);
}

#[derive(Debug, PartialEq)]
struct FakePacket {
    bytes: Vec<u8>,
}

impl FakePacket {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

impl Packet for FakePacket {
    fn to_bytes(self) -> Bytes {
        Bytes::new()
    }

    fn to_vec(self) -> Vec<u8> {
        self.bytes
    }
}
