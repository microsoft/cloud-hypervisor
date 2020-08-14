// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
use hyperv_bindings::*;
pub const X86X_IA32_MSR_PLATFORM_ID: u32 = 0x17;

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
            let privileges = HV_PARTITION_PRIVILEGE_ACCESS_HYPERCALL_MSRS
                | HV_PARTITION_PRIVILEGE_ACCESS_VP_INDEX
                | HV_PARTITION_PRIVILEGE_ACCESS_FREQUENCY_MSRS
                /*| HV_PARTITION_PRIVILEGE_PARTITION_REFERENCE_COUNTER*/;
            let features = HV_FEATURE_FREQUENCY_REGS_AVAILABLE;
            (
                privileges as u32,
                (privileges >> 32) as u32,
                0,
                features
            )
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

pub fn process_msr_read(vp_index: u32, n: u32) -> Option<u64> {
    Some(match n {
        HV_X64_MSR_GUEST_OS_ID => 0,            // GUEST ID, meaning full ID
        HV_X64_MSR_HYPERCALL => 0,              // TODO
        HV_X64_MSR_VP_INDEX => vp_index as u64, // VP index
        /*
         * vcpu register for this is only available on ARM
         * TODO better way to get this - e.g. cat /proc/cpuinfo
         */
        HV_X64_MSR_TSC_FREQUENCY => {
            1000000000
        },
        /*
         * vcpu register for this isn't available in 19h1
         * TODO better way to get this
         */
        HV_X64_MSR_APIC_FREQUENCY => {
            200000000
        },
        _ => {
            debug!("Unhandled MSR read: {:x}", n);
            return None;
        }
    })
}

pub fn process_msr_write(vp_index: u32, n: u32, v: u64) -> Option<()> {
    Some(match n {
        HV_X64_MSR_GUEST_OS_ID => (),            // TODO
        HV_X64_MSR_HYPERCALL => (),              // TODO
        HV_X64_MSR_VP_ASSIST_PAGE => (),         // bug in linux
        _ => {
            debug!("Unhandled MSR write: {:x}", n);
            return None;
        }
    })
}
