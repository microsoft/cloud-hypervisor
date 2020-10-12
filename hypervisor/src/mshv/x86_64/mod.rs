// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

use crate::arch::x86::{msr_index, MTRR_ENABLE, MTRR_MEM_TYPE_WB};
/// X86_64 specfic definitions for hyperv
///
use serde_derive::{Deserialize, Serialize};
///
/// Export generically-named wrappers of mshv_bindings for Unix-based platforms
///
pub use {
    mshv_bindings::mshv_user_mem_region as MemoryRegion, mshv_bindings::msr_entry as MsrEntry,
    mshv_bindings::CpuId, mshv_bindings::DebugRegisters,
    mshv_bindings::FloatingPointUnit as FpuState, mshv_bindings::LapicState,
    mshv_bindings::MsrList, mshv_bindings::Msrs as MsrEntries, mshv_bindings::Msrs,
    mshv_bindings::SegmentRegister, mshv_bindings::SpecialRegisters,
    mshv_bindings::StandardRegisters, mshv_bindings::VcpuEvents, mshv_bindings::XSave as Xsave,
    mshv_bindings::Xcrs as ExtendedControlRegisters,
};
#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuHypervState {
    pub msrs: MsrEntries,
    pub vcpu_events: VcpuEvents,
    pub regs: StandardRegisters,
    pub sregs: SpecialRegisters,
    pub fpu: FpuState,
    pub xcrs: ExtendedControlRegisters,
    pub lapic: LapicState,
    pub dbg: DebugRegisters,
    pub xsave: Xsave,
}

pub struct CreateDevice {}
pub struct DeviceAttr {}
pub struct IrqRouting {}
pub enum VcpuExit {}
pub struct MpState {}

#[derive(Eq, PartialEq, Hash, Clone, Debug, Copy)]
pub enum IoEventAddress {
    /// Representation of an programmable I/O address.
    Pio(u64),
    /// Representation of an memory mapped I/O address.
    Mmio(u64),
}
macro_rules! msr {
    ($msr:expr) => {
        MsrEntry {
            index: $msr,
            data: 0x0,
            ..Default::default()
        }
    };
}
macro_rules! msr_data {
    ($msr:expr, $data:expr) => {
        MsrEntry {
            index: $msr,
            data: $data,
            ..Default::default()
        }
    };
}

pub fn boot_msr_entries() -> MsrEntries {
    MsrEntries::from_entries(&[
        msr!(msr_index::MSR_IA32_SYSENTER_CS),
        msr!(msr_index::MSR_IA32_SYSENTER_ESP),
        msr!(msr_index::MSR_IA32_SYSENTER_EIP),
        msr!(msr_index::MSR_STAR),
        msr!(msr_index::MSR_CSTAR),
        msr!(msr_index::MSR_LSTAR),
        msr!(msr_index::MSR_KERNEL_GS_BASE),
        msr!(msr_index::MSR_SYSCALL_MASK),
        msr!(msr_index::MSR_IA32_TSC),
        // TODO: feature guard kvm and move this out of kvm
        /*
        msr_data!(
            msr_index::MSR_IA32_MISC_ENABLE,
            msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64
        ),
        msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB), */
    ])
}

pub mod emulator;
pub mod hv1;
