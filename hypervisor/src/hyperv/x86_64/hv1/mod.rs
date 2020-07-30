// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
use hyperv_bindings::*;
pub fn process_cpuid(rax: u32) -> (u32, u32, u32, u32) {
    match rax {
        HV_CPUID_FUNCTION_HV_VENDOR_AND_MAX_FUNCTION => (
            HV_CPUID_FUNCTION_MS_HV_IMPLEMENTATION_LIMITS,
            u32::from_le_bytes(*b"Micr"),
            u32::from_le_bytes(*b"osof"),
            u32::from_le_bytes(*b"t Hv"),
        ),
        HV_CPUID_FUNCTION_HV_INTERFACE => (u32::from_le_bytes(*b"Hv#1"), 0, 0, 0),
        HV_CPUID_FUNCTION_MS_HV_FEATURES => {
            let privileges = HV_PARTITION_PRIVILEGE_PARTITION_REFERENCE_COUNTER
                | HV_PARTITION_PRIVILEGE_ACCESS_HYPERCALL_MSRS
                | HV_PARTITION_PRIVILEGE_ACCESS_VP_INDEX;
            (privileges as u32, (privileges >> 32) as u32, 0, 0)
        }
        HV_CPUID_FUNCTION_MS_HV_ENLIGHTENMENT_INFORMATION => (
            HV_ENLIGHTENMENT_DEPRECATE_AUTO_EOI,
            0xffffffff, // no spin wait notifications
            0,
            0,
        ),
        HV_CPUID_FUNCTION_MS_HV_IMPLEMENTATION_LIMITS => (0, 0, 0, 0),
        _ => (0, 0, 0, 0),
    }
}
