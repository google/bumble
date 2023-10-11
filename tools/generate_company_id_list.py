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
# This script generates a python-syntax list of dictionary entries for the
# company IDs listed at:
# https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/company_identifiers/company_identifiers.yaml
# The input to this script is the YAML file that can be obtained at that URL
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import sys
import yaml

# -----------------------------------------------------------------------------
with open(sys.argv[1], "r") as yaml_file:
    root = yaml.safe_load(yaml_file)
    companies = {}
    for company in root["company_identifiers"]:
        companies[company["value"]] = company["name"]

    for company_id in sorted(companies.keys()):
        company_name = companies[company_id]
        escaped_company_name = company_name.replace('"', '\\"')
        print(f'    0x{company_id:04X}: "{escaped_company_name}",')
