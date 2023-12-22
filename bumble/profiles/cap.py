# Copyright 2021-2023 Google LLC
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
from __future__ import annotations

from bumble import gatt
from bumble import gatt_client
from bumble.profiles import csip


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class CommonAudioServiceService(gatt.TemplateService):
    UUID = gatt.GATT_COMMON_AUDIO_SERVICE

    def __init__(
        self,
        coordinated_set_identification_service: csip.CoordinatedSetIdentificationService,
    ) -> None:
        self.coordinated_set_identification_service = (
            coordinated_set_identification_service
        )
        super().__init__(
            characteristics=[],
            included_services=[coordinated_set_identification_service],
        )


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class CommonAudioServiceServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = CommonAudioServiceService

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        self.service_proxy = service_proxy
