// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use log::{info, warn};
use vm_memory::{Bytes, GuestAddress};

use crate::GuestMemoryMmap;

// This address belongs to the CloudHv EDK II reset-vector scratch area, not the PVH ABI.
const EDK2_SAVED_START_INFO: GuestAddress = GuestAddress(0x80f000);
const MAX_ACPI_TABLE_SIZE: usize = 64 * 1024;

pub(crate) fn enabled() -> bool {
    enabled_for_setting(std::env::var_os("CHV_PVH_DEBUG").as_deref())
}

fn enabled_for_setting(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| value == "1")
}

pub(crate) struct RebootTrace {
    context: Option<(u64, Instant)>,
}

impl RebootTrace {
    pub(crate) fn new() -> Self {
        static NEXT_REBOOT: AtomicU64 = AtomicU64::new(1);
        Self {
            context: enabled()
                .then(|| (NEXT_REBOOT.fetch_add(1, Ordering::Relaxed), Instant::now())),
        }
    }

    pub(crate) fn stage(&self, stage: &str) {
        if let Some((reboot, start)) = &self.context {
            warn!(
                "PVH_DEBUG reboot={reboot} stage={stage} elapsed_us={}",
                start.elapsed().as_micros()
            );
        }
    }
}

fn read<const N: usize>(
    mem: &GuestMemoryMmap,
    stage: &str,
    label: &str,
    address: GuestAddress,
) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    match mem.read_slice(&mut bytes, address) {
        Ok(()) => {
            info!(
                "PVH_DEBUG stage={stage} {label} gpa={:#x} bytes={bytes:02x?}",
                address.0
            );
            Some(bytes)
        }
        Err(e) => {
            warn!(
                "PVH_DEBUG stage={stage} cannot read {label} gpa={:#x} size={N}: {e}",
                address.0
            );
            None
        }
    }
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

fn start_info(mem: &GuestMemoryMmap, stage: &str, label: &str, address: GuestAddress) {
    let Some(bytes) = read::<56>(mem, stage, label, address) else {
        return;
    };
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let rsdp = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    warn!("PVH_DEBUG stage={stage} {label} magic={magic:#x} version={version} rsdp={rsdp:#x}");
    if magic != 0x336ec578 {
        warn!("PVH_DEBUG stage={stage} {label} invalid PVH magic");
        return;
    }
    rsdp_info(mem, stage, GuestAddress(rsdp));
}

fn rsdp_info(mem: &GuestMemoryMmap, stage: &str, address: GuestAddress) {
    let Some(bytes) = read::<36>(mem, stage, "rsdp", address) else {
        return;
    };
    let signature_valid = &bytes[..8] == b"RSD PTR ";
    let legacy_checksum = checksum(&bytes[..20]);
    let revision = bytes[15];
    let length = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let extended_checksum = checksum(&bytes);
    let xsdt = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    info!(
        "PVH_DEBUG stage={stage} rsdp signature_valid={signature_valid} \
         revision={revision} length={length} checksum={legacy_checksum:#x} \
         checksum36={extended_checksum:#x} xsdt={xsdt:#x}"
    );
    if !signature_valid
        || legacy_checksum != 0
        || revision < 2
        || length != 36
        || extended_checksum != 0
    {
        warn!("PVH_DEBUG stage={stage} invalid or unsupported ACPI 2.0 RSDP");
        return;
    }
    let address = GuestAddress(xsdt);
    let Some(header) = read::<36>(mem, stage, "xsdt_header", address) else {
        return;
    };
    let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
    if &header[..4] != b"XSDT"
        || !(36..=MAX_ACPI_TABLE_SIZE).contains(&length)
        || !(length - 36).is_multiple_of(8)
    {
        warn!("PVH_DEBUG stage={stage} invalid or oversized XSDT length={length}");
        return;
    }
    let mut table = vec![0; length];
    match mem.read_slice(&mut table, address) {
        Ok(()) => {
            let sum = checksum(&table);
            warn!("PVH_DEBUG stage={stage} xsdt length={length} checksum={sum:#x}");
            if sum != 0 {
                warn!("PVH_DEBUG stage={stage} invalid XSDT checksum");
            }
        }
        Err(e) => warn!("PVH_DEBUG stage={stage} cannot read full XSDT: {e}"),
    }
}

pub(crate) fn log_memory(mem: &GuestMemoryMmap, stage: &str) {
    start_info(
        mem,
        stage,
        "expected_start_info",
        arch::layout::PVH_INFO_START,
    );
    let Some(bytes) = read::<4>(mem, stage, "edk2_saved_start_info", EDK2_SAVED_START_INFO) else {
        return;
    };
    let saved = GuestAddress(u32::from_le_bytes(bytes) as u64);
    info!(
        "PVH_DEBUG stage={stage} edk2_saved_start_info pointer={:#x}",
        saved.0
    );
    if saved.0 != 0 && saved != arch::layout::PVH_INFO_START {
        start_info(mem, stage, "saved_start_info", saved);
    }
    rsdp_info(mem, stage, arch::layout::RSDP_POINTER);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enabled_setting() {
        use std::ffi::OsStr;

        assert!(!enabled_for_setting(None));
        assert!(enabled_for_setting(Some(OsStr::new("1"))));
        assert!(!enabled_for_setting(Some(OsStr::new("0"))));
        assert!(!enabled_for_setting(Some(OsStr::new(""))));
        assert!(!enabled_for_setting(Some(OsStr::new("invalid"))));
    }

    #[test]
    fn test_checksum() {
        assert_eq!(checksum(&[]), 0);
        assert_eq!(checksum(&[0xff, 1]), 0);
        assert_eq!(checksum(&[1, 2]), 3);
    }

    #[test]
    fn test_read_and_log_invalid_handoff() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x900000)]).unwrap();
        let address = arch::layout::PVH_INFO_START;
        mem.write_slice(&0x336ec578u32.to_le_bytes(), address)
            .unwrap();
        mem.write_slice(
            &0x0086000000000086u64.to_le_bytes(),
            GuestAddress(address.0 + 0x20),
        )
        .unwrap();
        mem.write_slice(&(address.0 as u32).to_le_bytes(), EDK2_SAVED_START_INFO)
            .unwrap();
        assert!(read::<36>(&mem, "test", "bad_rsdp", GuestAddress(0x0086000000000086)).is_none());
        assert_eq!(
            read::<4>(&mem, "test", "magic", address).unwrap(),
            0x336ec578u32.to_le_bytes()
        );
        log_memory(&mem, "test");
    }

    #[test]
    fn test_log_unmapped_handoff() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        log_memory(&mem, "test");
    }

    #[test]
    fn test_log_acpi_tables() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x900000)]).unwrap();
        let rsdp_address = arch::layout::RSDP_POINTER;
        let xsdt_address = GuestAddress(rsdp_address.0 + 0x100);
        let mut xsdt = [0u8; 36];
        xsdt[..4].copy_from_slice(b"XSDT");
        xsdt[4..8].copy_from_slice(&36u32.to_le_bytes());
        xsdt[8] = 1;
        xsdt[9] = 0u8.wrapping_sub(checksum(&xsdt));
        mem.write_slice(&xsdt, xsdt_address).unwrap();

        let mut rsdp = [0u8; 36];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
        rsdp[24..32].copy_from_slice(&xsdt_address.0.to_le_bytes());
        rsdp[8] = 0u8.wrapping_sub(checksum(&rsdp[..20]));
        rsdp[32] = 0u8.wrapping_sub(checksum(&rsdp));
        mem.write_slice(&rsdp, rsdp_address).unwrap();
        assert_eq!(checksum(&rsdp[..20]), 0);
        assert_eq!(checksum(&rsdp), 0);
        assert_eq!(checksum(&xsdt), 0);
        rsdp_info(&mem, "test_valid", rsdp_address);

        // Reject guest-controlled lengths before allocating an XSDT-sized buffer.
        mem.write_slice(&u32::MAX.to_le_bytes(), GuestAddress(xsdt_address.0 + 4))
            .unwrap();
        rsdp_info(&mem, "test_oversized", rsdp_address);
        mem.write_slice(&0u32.to_le_bytes(), GuestAddress(xsdt_address.0 + 4))
            .unwrap();
        rsdp_info(&mem, "test_undersized", rsdp_address);
    }
}
