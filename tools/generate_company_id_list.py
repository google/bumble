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
# company IDs listed at: https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/
# The input to this script is the CSV file that can be obtained at that URL
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import sys
import csv

# -----------------------------------------------------------------------------
with open(sys.argv[1], newline='') as csvfile:
    reader = csv.reader(csvfile, delimiter=',', quotechar='"')
    lines = []
    for row in reader:
        if len(row) == 3 and row[1].startswith('0x'):
            company_id = row[1]
            company_name = row[2]
            escaped_company_name = company_name.replace('"', '\\"')
            lines.append(f'    {company_id}: "{escaped_company_name}"')

    print(',\n'.join(reversed(lines)))
