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

//! Assigned service IDs

use crate::wrapper::core::Uuid16;
use lazy_static::lazy_static;
use std::collections;

lazy_static! {
    /// Assigned service IDs
    pub static ref SERVICE_IDS: collections::HashMap<Uuid16, &'static str> = [
        (0x1800_u16, "Generic Access"),
        (0x1801, "Generic Attribute"),
        (0x1802, "Immediate Alert"),
        (0x1803, "Link Loss"),
        (0x1804, "TX Power"),
        (0x1805, "Current Time"),
        (0x1806, "Reference Time Update"),
        (0x1807, "Next DST Change"),
        (0x1808, "Glucose"),
        (0x1809, "Health Thermometer"),
        (0x180A, "Device Information"),
        (0x180D, "Heart Rate"),
        (0x180E, "Phone Alert Status"),
        (0x180F, "Battery"),
        (0x1810, "Blood Pressure"),
        (0x1811, "Alert Notification"),
        (0x1812, "Human Interface Device"),
        (0x1813, "Scan Parameters"),
        (0x1814, "Running Speed and Cadence"),
        (0x1815, "Automation IO"),
        (0x1816, "Cycling Speed and Cadence"),
        (0x1818, "Cycling Power"),
        (0x1819, "Location and Navigation"),
        (0x181A, "Environmental Sensing"),
        (0x181B, "Body Composition"),
        (0x181C, "User Data"),
        (0x181D, "Weight Scale"),
        (0x181E, "Bond Management"),
        (0x181F, "Continuous Glucose Monitoring"),
        (0x1820, "Internet Protocol Support"),
        (0x1821, "Indoor Positioning"),
        (0x1822, "Pulse Oximeter"),
        (0x1823, "HTTP Proxy"),
        (0x1824, "Transport Discovery"),
        (0x1825, "Object Transfer"),
        (0x1826, "Fitness Machine"),
        (0x1827, "Mesh Provisioning"),
        (0x1828, "Mesh Proxy"),
        (0x1829, "Reconnection Configuration"),
        (0x183A, "Insulin Delivery"),
        (0x183B, "Binary Sensor"),
        (0x183C, "Emergency Configuration"),
        (0x183E, "Physical Activity Monitor"),
        (0x1843, "Audio Input Control"),
        (0x1844, "Volume Control"),
        (0x1845, "Volume Offset Control"),
        (0x1846, "Coordinated Set Identification Service"),
        (0x1847, "Device Time"),
        (0x1848, "Media Control Service"),
        (0x1849, "Generic Media Control Service"),
        (0x184A, "Constant Tone Extension"),
        (0x184B, "Telephone Bearer Service"),
        (0x184C, "Generic Telephone Bearer Service"),
        (0x184D, "Microphone Control"),
    ]
    .into_iter()
    .map(|(num, name)| (Uuid16::from_le_bytes(num.to_le_bytes()), name))
    .collect();
}
