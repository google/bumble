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

//! Rust version of the Python `usb_probe.py`.
//!
//! This tool lists all the USB devices, with details about each device.
//! For each device, the different possible Bumble transport strings that can
//! refer to it are listed. If the device is known to be a Bluetooth HCI device,
//! its identifier is printed in reverse colors, and the transport names in cyan color.
//! For other devices, regardless of their type, the transport names are printed
//! in red. Whether that device is actually a Bluetooth device or not depends on
//! whether it is a Bluetooth device that uses a non-standard Class, or some other
//! type of device (there's no way to tell).

use itertools::Itertools as _;
use owo_colors::{OwoColorize, Style};
use rusb::{Device, DeviceDescriptor, Direction, TransferType, UsbContext};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
const USB_DEVICE_CLASS_DEVICE: u8 = 0x00;
const USB_DEVICE_CLASS_WIRELESS_CONTROLLER: u8 = 0xE0;
const USB_DEVICE_SUBCLASS_RF_CONTROLLER: u8 = 0x01;
const USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER: u8 = 0x01;

pub(crate) fn probe(verbose: bool) -> anyhow::Result<()> {
    let mut bt_dev_count = 0;
    let mut device_serials_by_id: HashMap<(u16, u16), HashSet<String>> = HashMap::new();
    for device in rusb::devices()?.iter() {
        let device_desc = device.device_descriptor().unwrap();

        let class_info = ClassInfo::from(&device_desc);
        let handle = device.open()?;
        let timeout = Duration::from_secs(1);
        // some devices don't have languages
        let lang = handle
            .read_languages(timeout)
            .ok()
            .and_then(|langs| langs.into_iter().next());
        let serial = lang.and_then(|l| {
            handle
                .read_serial_number_string(l, &device_desc, timeout)
                .ok()
        });
        let mfg = lang.and_then(|l| {
            handle
                .read_manufacturer_string(l, &device_desc, timeout)
                .ok()
        });
        let product = lang.and_then(|l| handle.read_product_string(l, &device_desc, timeout).ok());

        let is_hci = is_bluetooth_hci(&device, &device_desc)?;
        let addr_style = if is_hci {
            bt_dev_count += 1;
            Style::new().black().on_yellow()
        } else {
            Style::new().yellow().on_black()
        };

        let mut transport_names = Vec::new();
        let basic_transport_name = format!(
            "usb:{:04X}:{:04X}",
            device_desc.vendor_id(),
            device_desc.product_id()
        );

        if is_hci {
            transport_names.push(format!("usb:{}", bt_dev_count - 1));
        }

        let device_id = (device_desc.vendor_id(), device_desc.product_id());
        if !device_serials_by_id.contains_key(&device_id) {
            transport_names.push(basic_transport_name.clone());
        } else {
            transport_names.push(format!(
                "{}#{}",
                basic_transport_name,
                device_serials_by_id
                    .get(&device_id)
                    .map(|serials| serials.len())
                    .unwrap_or(0)
            ))
        }

        if let Some(s) = &serial {
            if !device_serials_by_id
                .get(&device_id)
                .map(|serials| serials.contains(s))
                .unwrap_or(false)
            {
                transport_names.push(format!("{}/{}", basic_transport_name, s))
            }
        }

        println!(
            "{}",
            format!(
                "ID {:04X}:{:04X}",
                device_desc.vendor_id(),
                device_desc.product_id()
            )
            .style(addr_style)
        );
        if !transport_names.is_empty() {
            let style = if is_hci {
                Style::new().cyan()
            } else {
                Style::new().red()
            };
            println!(
                "{:26}{}",
                "  Bumble Transport Names:".blue(),
                transport_names.iter().map(|n| n.style(style)).join(" or ")
            )
        }
        println!(
            "{:26}{:03}/{:03}",
            "  Bus/Device:".green(),
            device.bus_number(),
            device.address()
        );
        println!(
            "{:26}{}",
            "  Class:".green(),
            class_info.formatted_class_name()
        );
        println!(
            "{:26}{}",
            "  Subclass/Protocol:".green(),
            class_info.formatted_subclass_protocol()
        );
        if let Some(s) = serial {
            println!("{:26}{}", "  Serial:".green(), s);
            device_serials_by_id.entry(device_id).or_default().insert(s);
        }
        if let Some(m) = mfg {
            println!("{:26}{}", "  Manufacturer:".green(), m);
        }
        if let Some(p) = product {
            println!("{:26}{}", "  Product:".green(), p);
        }

        if verbose {
            print_device_details(&device, &device_desc)?;
        }

        println!();
    }

    Ok(())
}

fn is_bluetooth_hci<T: UsbContext>(
    device: &Device<T>,
    device_desc: &DeviceDescriptor,
) -> rusb::Result<bool> {
    if device_desc.class_code() == USB_DEVICE_CLASS_WIRELESS_CONTROLLER
        && device_desc.sub_class_code() == USB_DEVICE_SUBCLASS_RF_CONTROLLER
        && device_desc.protocol_code() == USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER
    {
        Ok(true)
    } else if device_desc.class_code() == USB_DEVICE_CLASS_DEVICE {
        for i in 0..device_desc.num_configurations() {
            for interface in device.config_descriptor(i)?.interfaces() {
                for d in interface.descriptors() {
                    if d.class_code() == USB_DEVICE_CLASS_WIRELESS_CONTROLLER
                        && d.sub_class_code() == USB_DEVICE_SUBCLASS_RF_CONTROLLER
                        && d.protocol_code() == USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER
                    {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    } else {
        Ok(false)
    }
}

fn print_device_details<T: UsbContext>(
    device: &Device<T>,
    device_desc: &DeviceDescriptor,
) -> anyhow::Result<()> {
    for i in 0..device_desc.num_configurations() {
        println!("  Configuration {}", i + 1);
        for interface in device.config_descriptor(i)?.interfaces() {
            let interface_descriptors: Vec<_> = interface.descriptors().collect();
            for d in &interface_descriptors {
                let class_info =
                    ClassInfo::new(d.class_code(), d.sub_class_code(), d.protocol_code());

                println!(
                    "      Interface: {}{} ({}, {})",
                    interface.number(),
                    if interface_descriptors.len() > 1 {
                        format!("/{}", d.setting_number())
                    } else {
                        String::new()
                    },
                    class_info.formatted_class_name(),
                    class_info.formatted_subclass_protocol()
                );

                for e in d.endpoint_descriptors() {
                    println!(
                        "        Endpoint {:#04X}: {} {}",
                        e.address(),
                        match e.transfer_type() {
                            TransferType::Control => "CONTROL",
                            TransferType::Isochronous => "ISOCHRONOUS",
                            TransferType::Bulk => "BULK",
                            TransferType::Interrupt => "INTERRUPT",
                        },
                        match e.direction() {
                            Direction::In => "IN",
                            Direction::Out => "OUT",
                        }
                    )
                }
            }
        }
    }

    Ok(())
}

struct ClassInfo {
    class: u8,
    sub_class: u8,
    protocol: u8,
}

impl ClassInfo {
    fn new(class: u8, sub_class: u8, protocol: u8) -> Self {
        Self {
            class,
            sub_class,
            protocol,
        }
    }

    fn class_name(&self) -> Option<&str> {
        match self.class {
            0x00 => Some("Device"),
            0x01 => Some("Audio"),
            0x02 => Some("Communications and CDC Control"),
            0x03 => Some("Human Interface Device"),
            0x05 => Some("Physical"),
            0x06 => Some("Still Imaging"),
            0x07 => Some("Printer"),
            0x08 => Some("Mass Storage"),
            0x09 => Some("Hub"),
            0x0A => Some("CDC Data"),
            0x0B => Some("Smart Card"),
            0x0D => Some("Content Security"),
            0x0E => Some("Video"),
            0x0F => Some("Personal Healthcare"),
            0x10 => Some("Audio/Video"),
            0x11 => Some("Billboard"),
            0x12 => Some("USB Type-C Bridge"),
            0x3C => Some("I3C"),
            0xDC => Some("Diagnostic"),
            USB_DEVICE_CLASS_WIRELESS_CONTROLLER => Some("Wireless Controller"),
            0xEF => Some("Miscellaneous"),
            0xFE => Some("Application Specific"),
            0xFF => Some("Vendor Specific"),
            _ => None,
        }
    }

    fn protocol_name(&self) -> Option<&str> {
        match self.class {
            USB_DEVICE_CLASS_WIRELESS_CONTROLLER => match self.sub_class {
                0x01 => match self.protocol {
                    0x01 => Some("Bluetooth"),
                    0x02 => Some("UWB"),
                    0x03 => Some("Remote NDIS"),
                    0x04 => Some("Bluetooth AMP"),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }

    fn formatted_class_name(&self) -> String {
        self.class_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{:#04X}", self.class))
    }

    fn formatted_subclass_protocol(&self) -> String {
        format!(
            "{}/{}{}",
            self.sub_class,
            self.protocol,
            self.protocol_name()
                .map(|s| format!(" [{}]", s))
                .unwrap_or_default()
        )
    }
}

impl From<&DeviceDescriptor> for ClassInfo {
    fn from(value: &DeviceDescriptor) -> Self {
        Self::new(
            value.class_code(),
            value.sub_class_code(),
            value.protocol_code(),
        )
    }
}
