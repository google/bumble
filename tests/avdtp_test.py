# Copyright 2021-2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from bumble.a2dp import A2DP_SBC_CODEC_TYPE
from bumble.avdtp import (
    AVDTP_AUDIO_MEDIA_TYPE,
    AVDTP_DELAY_REPORTING_SERVICE_CATEGORY,
    AVDTP_GET_CAPABILITIES,
    AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY,
    AVDTP_SET_CONFIGURATION,
    Message,
    MediaPacket,
    Get_Capabilities_Response,
    Set_Configuration_Command,
    Set_Configuration_Response,
    ServiceCapabilities,
    MediaCodecCapabilities,
)


# -----------------------------------------------------------------------------
def test_messages():
    capabilities = [
        ServiceCapabilities(AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY),
        MediaCodecCapabilities(
            media_type=AVDTP_AUDIO_MEDIA_TYPE,
            media_codec_type=A2DP_SBC_CODEC_TYPE,
            media_codec_information=bytes.fromhex('211502fa'),
        ),
        ServiceCapabilities(AVDTP_DELAY_REPORTING_SERVICE_CATEGORY),
    ]
    message = Get_Capabilities_Response(capabilities)
    parsed = Message.create(
        AVDTP_GET_CAPABILITIES, Message.MessageType.RESPONSE_ACCEPT, message.payload
    )
    assert message.payload == parsed.payload

    message = Set_Configuration_Command(3, 4, capabilities)
    parsed = Message.create(
        AVDTP_SET_CONFIGURATION, Message.MessageType.COMMAND, message.payload
    )
    assert message.payload == parsed.payload


# -----------------------------------------------------------------------------
def test_rtp():
    packet = bytes.fromhex(
        '8060000103141c6a000000000a9cbd2adbfe75443333542210037eeeed5f76dfbbbb57ddb890eed5f76e2ad3958613d3d04a5f596fc2b54d613a6a95570b4b49c2d0955ac710ca6abb293bb4580d5896b106cd6a7c4b557d8bb73aac56b8e633aa161447caa86585ae4cbc9576cc9cbd2a54fe7443322064221000b44a5cd51929bc96328916b1694e1f3611d6b6928dbf554b01e96d23a6ad879834d99326a649b94ca6adbeab1311e372a3aa3468e9582d2d9c857da28e5b76a2d363089367432930a0160af22d48911bc46cea549cbd2a03fe754332206532210054cf1d3d9260d3bc9895566f124b22c4b3cb6bc66648cf9b21e1613a48b3592466e90cee3424cc6cc56d2f569b12145234c6bd73560c95ad9c584c9d6c26552cea9905da55b3eab182c40e2dae64b46c328ba64d9cbd2a3cde74433220643211001e8d1ad6210d5c26b296d40d298a29b073b46bb4542ceb1aea011612c6df64c731068d49b56bb48afb2456ea9b5903222bb63b8b1a60c52896325a22aad781486cdb36269d9dc6dd38d9acf5b0e9328e0b23542c9cbd2adffe744323206432200095731b2a62604accea58da8ee6aba6d6fc9169ab66a824527412a66ac6c5c41d12c85295673c3263848c88ae934f62619c46ed2adccaaeb3eac70c396bb28cb8cecaf22423c548cd4adca92d30d1370ba34a772d9cbd2a3efe6442221064322100cc932cd12222dcd854d6da8d09330d2708b392a3997ec8a2f30b9312b8c562d9353513eda7733c4b835176eeca695909cc10d08614574d36cac669c583e68d9778daca9b92d6e4bb5cd008ef3562aa52332bc54a9cbd2a1efe6443332064322100a6e91a6ddc58a3a4b966a3452cb6d0b9c5334d2b695929128dcd6123b8b366d491122fd545f9b96cf769d530d2e2646b15c6a43695b12d33aa214e622e45b1ac132309a39eddc82caad35115b3d2350c5c6dcd749cbd2a9c7e654332207433110086ed5b68531a54c6e7bb052d15add1b204bd62568d8922d3379418b9c4e202482909ab712a744d81f392fa94193d62293ac6dfa7278f79b451c70c3b4b2b64d70f0b3463323c46f598ecd70d35e5a743282307099cbd2ae9fe654332106432110082acdb4aca734b843b6699f491ad3a511aab6db2344eeed386d0aa34c49c4b0a4b2aa59ec98bba6419b06310d2f9626c42a7466728f0ca0f1db579b46c0a701264e59153535228dc6497492dac722596138bd74a9cbd2a0b7e655432107432110056a8d22a62d643b428e513b52ea4a66c7a41991719370c8d9664ce2bca685dd2690b1c368c5dce36d26b38d10e0c672343ca8c25c58d0d5c568de433b7561c61268aaf83260b4b868dca8ee6dc6ba573abcb5093'
    )
    media_packet = MediaPacket.from_bytes(packet)
    print(media_packet)


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_messages()
    test_rtp()
