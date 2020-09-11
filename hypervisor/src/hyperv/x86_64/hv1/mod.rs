// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
use crate::hyperv::{raise_general_page_fault, HvState, PAGE_SHIFT};
use hyperv_bindings::*;
use std::sync::{Arc, Mutex, RwLock};
pub const X86X_IA32_MSR_PLATFORM_ID: u32 = 0x17;
use crate::cpu::VcpuRun;
use hyperv_ioctls::VcpuFd;

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
            (privileges as u32, (privileges >> 32) as u32, 0, features)
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

pub fn process_msr_read(vp_index: u32, n: u32, hv_state: Arc<RwLock<HvState>>) -> Option<u64> {
    Some(match n {
        HV_X64_MSR_GUEST_OS_ID => 0,            // GUEST ID, meaning full ID
        HV_X64_MSR_VP_INDEX => vp_index as u64, // VP index
        /*
         * vcpu register for this is only available on ARM
         * TODO better way to get this - e.g. cat /proc/cpuinfo
         */
        HV_X64_MSR_TSC_FREQUENCY => 1000000000,
        /*
         * vcpu register for this isn't available in 19h1
         * TODO better way to get this
         */
        HV_X64_MSR_APIC_FREQUENCY => 200000000,
        HV_X64_MSR_HYPERCALL => {
            debug!(
                "Returning {} gpf as hypercall page",
                hv_state.read().unwrap().hypercall_page
            );
            hv_state.read().unwrap().hypercall_page
        }
        _ => {
            debug!("Unhandled MSR read: {:X}", n);
            return None;
        }
    })
}

pub fn process_msr_write(
    vp_index: u32,
    n: u32,
    input: u64,
    hv_state: Arc<RwLock<HvState>>,
    vr: &dyn VcpuRun,
    fd_ref: &VcpuFd,
) -> Option<()> {
    Some(match n {
        HV_X64_MSR_GUEST_OS_ID => (), // TODO
        HV_X64_MSR_HYPERCALL => {
            let curr_hcp = hv_state.read().unwrap().hypercall_page;
            let guest_pfn = input >> 12;
            let guest_gpa = guest_pfn << PAGE_SHIFT;
            debug!("Setting {} as Hypercall Page\n", guest_pfn);
            if curr_hcp & MSR_HYPERCALL_LOCKED == 0 {
                if input & MSR_HYPERCALL_ACTIVE != 0 {
                    //Vmcall Opcode
                    let vmcall = [0xf, 0x1, 0xc1, 0xc3];
                    let nr_bytes = vr.write_to_guest_mem(&vmcall, guest_gpa).unwrap();
                    if nr_bytes != 4 {
                        raise_general_page_fault(fd_ref);
                        panic!("Failed while writing vmcall Page to Guest VM\n");
                    }
                }
                //Store input
                hv_state.write().unwrap().hypercall_page = input;
            }
        }
        HV_X64_MSR_VP_ASSIST_PAGE => (), // bug in linux
        _ => {
            debug!("Unhandled MSR write: {:X}", n);
            return None;
        }
    })
}
