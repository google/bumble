// Copyright 2024 Google LLC
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

#![allow(missing_docs)]

use crate::wrapper::core::Uuid16;
use lazy_static::lazy_static;
use std::collections;

lazy_static! {
    /// Assigned service IDs
    pub static ref SERVICE_IDS: collections::HashMap<Uuid16, NamedUuid> = [
        GENERIC_ACCESS,
        GENERIC_ATTRIBUTE,
        IMMEDIATE_ALERT,
        LINK_LOSS,
        TX_POWER,
        CURRENT_TIME,
        REFERENCE_TIME_UPDATE,
        NEXT_DST_CHANGE,
        GLUCOSE,
        HEALTH_THERMOMETER,
        DEVICE_INFORMATION,
        HEART_RATE,
        PHONE_ALERT_STATUS,
        BATTERY,
        BLOOD_PRESSURE,
        ALERT_NOTIFICATION,
        HUMAN_INTERFACE_DEVICE,
        SCAN_PARAMETERS,
        RUNNING_SPEED_AND_CADENCE,
        AUTOMATION_IO,
        CYCLING_SPEED_AND_CADENCE,
        CYCLING_POWER,
        LOCATION_AND_NAVIGATION,
        ENVIRONMENTAL_SENSING,
        BODY_COMPOSITION,
        USER_DATA,
        WEIGHT_SCALE,
        BOND_MANAGEMENT,
        CONTINUOUS_GLUCOSE_MONITORING,
        INTERNET_PROTOCOL_SUPPORT,
        INDOOR_POSITIONING,
        PULSE_OXIMETER,
        HTTP_PROXY,
        TRANSPORT_DISCOVERY,
        OBJECT_TRANSFER,
        FITNESS_MACHINE,
        MESH_PROVISIONING,
        MESH_PROXY,
        RECONNECTION_CONFIGURATION,
        INSULIN_DELIVERY,
        BINARY_SENSOR,
        EMERGENCY_CONFIGURATION,
        PHYSICAL_ACTIVITY_MONITOR,
        AUDIO_INPUT_CONTROL,
        VOLUME_CONTROL,
        VOLUME_OFFSET_CONTROL,
        COORDINATED_SET_IDENTIFICATION,
        DEVICE_TIME,
        MEDIA_CONTROL,
        GENERIC_MEDIA_CONTROL,
        CONSTANT_TONE_EXTENSION,
        TELEPHONE_BEARER,
        GENERIC_TELEPHONE_BEARER,
        MICROPHONE_CONTROL,
    ]
    .into_iter()
    .map(|n| (n.uuid, n))
    .collect();
}

pub const GENERIC_ACCESS: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1800_u16.to_be_bytes()),
    "Generic Access",
);
pub const GENERIC_ATTRIBUTE: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1801_u16.to_be_bytes()),
    "Generic Attribute",
);
pub const IMMEDIATE_ALERT: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1802_u16.to_be_bytes()),
    "Immediate Alert",
);
pub const LINK_LOSS: NamedUuid =
    NamedUuid::new(Uuid16::from_be_bytes(0x1803_u16.to_be_bytes()), "Link Loss");
pub const TX_POWER: NamedUuid =
    NamedUuid::new(Uuid16::from_be_bytes(0x1804_u16.to_be_bytes()), "TX Power");
pub const CURRENT_TIME: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1805_u16.to_be_bytes()),
    "Current Time",
);
pub const REFERENCE_TIME_UPDATE: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1806_u16.to_be_bytes()),
    "Reference Time Update",
);
pub const NEXT_DST_CHANGE: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1807_u16.to_be_bytes()),
    "Next DST Change",
);
pub const GLUCOSE: NamedUuid =
    NamedUuid::new(Uuid16::from_be_bytes(0x1808_u16.to_be_bytes()), "Glucose");
pub const HEALTH_THERMOMETER: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1809_u16.to_be_bytes()),
    "Health Thermometer",
);
pub const DEVICE_INFORMATION: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x180A_u16.to_be_bytes()),
    "Device Information",
);
pub const HEART_RATE: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x180D_u16.to_be_bytes()),
    "Heart Rate",
);
pub const PHONE_ALERT_STATUS: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x180E_u16.to_be_bytes()),
    "Phone Alert Status",
);
pub const BATTERY: NamedUuid =
    NamedUuid::new(Uuid16::from_be_bytes(0x180F_u16.to_be_bytes()), "Battery");
pub const BLOOD_PRESSURE: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1810_u16.to_be_bytes()),
    "Blood Pressure",
);
pub const ALERT_NOTIFICATION: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1811_u16.to_be_bytes()),
    "Alert Notification",
);
pub const HUMAN_INTERFACE_DEVICE: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1812_u16.to_be_bytes()),
    "Human Interface Device",
);
pub const SCAN_PARAMETERS: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1813_u16.to_be_bytes()),
    "Scan Parameters",
);
pub const RUNNING_SPEED_AND_CADENCE: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1814_u16.to_be_bytes()),
    "Running Speed and Cadence",
);
pub const AUTOMATION_IO: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1815_u16.to_be_bytes()),
    "Automation IO",
);
pub const CYCLING_SPEED_AND_CADENCE: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1816_u16.to_be_bytes()),
    "Cycling Speed and Cadence",
);
pub const CYCLING_POWER: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1818_u16.to_be_bytes()),
    "Cycling Power",
);
pub const LOCATION_AND_NAVIGATION: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1819_u16.to_be_bytes()),
    "Location and Navigation",
);
pub const ENVIRONMENTAL_SENSING: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x181A_u16.to_be_bytes()),
    "Environmental Sensing",
);
pub const BODY_COMPOSITION: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x181B_u16.to_be_bytes()),
    "Body Composition",
);
pub const USER_DATA: NamedUuid =
    NamedUuid::new(Uuid16::from_be_bytes(0x181C_u16.to_be_bytes()), "User Data");
pub const WEIGHT_SCALE: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x181D_u16.to_be_bytes()),
    "Weight Scale",
);
pub const BOND_MANAGEMENT: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x181E_u16.to_be_bytes()),
    "Bond Management",
);
pub const CONTINUOUS_GLUCOSE_MONITORING: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x181F_u16.to_be_bytes()),
    "Continuous Glucose Monitoring",
);
pub const INTERNET_PROTOCOL_SUPPORT: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1820_u16.to_be_bytes()),
    "Internet Protocol Support",
);
pub const INDOOR_POSITIONING: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1821_u16.to_be_bytes()),
    "Indoor Positioning",
);
pub const PULSE_OXIMETER: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1822_u16.to_be_bytes()),
    "Pulse Oximeter",
);
pub const HTTP_PROXY: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1823_u16.to_be_bytes()),
    "HTTP_Proxy",
);
pub const TRANSPORT_DISCOVERY: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1824_u16.to_be_bytes()),
    "Transport Discovery",
);
pub const OBJECT_TRANSFER: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1825_u16.to_be_bytes()),
    "Object Transfer",
);
pub const FITNESS_MACHINE: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1826_u16.to_be_bytes()),
    "Fitness Machine",
);
pub const MESH_PROVISIONING: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1827_u16.to_be_bytes()),
    "Mesh Provisioning",
);
pub const MESH_PROXY: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1828_u16.to_be_bytes()),
    "Mesh Proxy",
);
pub const RECONNECTION_CONFIGURATION: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1829_u16.to_be_bytes()),
    "Reconnection Configuration",
);
pub const INSULIN_DELIVERY: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x183A_u16.to_be_bytes()),
    "Insulin Delivery",
);
pub const BINARY_SENSOR: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x183B_u16.to_be_bytes()),
    "Binary Sensor",
);
pub const EMERGENCY_CONFIGURATION: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x183C_u16.to_be_bytes()),
    "Emergency Configuration",
);
pub const PHYSICAL_ACTIVITY_MONITOR: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x183E_u16.to_be_bytes()),
    "Physical Activity Monitor",
);
pub const AUDIO_INPUT_CONTROL: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1843_u16.to_be_bytes()),
    "Audio Input Control",
);
pub const VOLUME_CONTROL: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1844_u16.to_be_bytes()),
    "Volume Control",
);
pub const VOLUME_OFFSET_CONTROL: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1845_u16.to_be_bytes()),
    "Volume Offset Control",
);
pub const COORDINATED_SET_IDENTIFICATION: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1846_u16.to_be_bytes()),
    "Coordinated Set Identification Service",
);
pub const DEVICE_TIME: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1847_u16.to_be_bytes()),
    "Device Time",
);
pub const MEDIA_CONTROL: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1848_u16.to_be_bytes()),
    "Media Control Service",
);
pub const GENERIC_MEDIA_CONTROL: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x1849_u16.to_be_bytes()),
    "Generic Media Control Service",
);
pub const CONSTANT_TONE_EXTENSION: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x184A_u16.to_be_bytes()),
    "Constant Tone Extension",
);
pub const TELEPHONE_BEARER: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x184B_u16.to_be_bytes()),
    "Telephone Bearer Service",
);
pub const GENERIC_TELEPHONE_BEARER: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x184C_u16.to_be_bytes()),
    "Generic Telephone Bearer Service",
);
pub const MICROPHONE_CONTROL: NamedUuid = NamedUuid::new(
    Uuid16::from_be_bytes(0x184D_u16.to_be_bytes()),
    "Microphone Control",
);

/// Basic info about a service defined in the BT spec.
#[derive(Debug, Clone)]
pub struct NamedUuid {
    uuid: Uuid16,
    name: &'static str,
}

impl NamedUuid {
    const fn new(uuid: Uuid16, name: &'static str) -> Self {
        Self { uuid, name }
    }

    pub fn uuid(&self) -> Uuid16 {
        self.uuid
    }
    pub fn name(&self) -> &'static str {
        self.name
    }
}
