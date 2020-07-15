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
/// Export generically-named wrappers of hyperv-bindings for Unix-based platforms
///
pub use {
    hyperv_bindings::hv_userspace_memory_region as MemoryRegion,
    hyperv_bindings::msr_entry as MsrEntry, hyperv_bindings::CpuId,
    hyperv_bindings::FloatingPointUnit as FpuState, hyperv_bindings::LapicState,
    hyperv_bindings::Msrs as MsrEntries, hyperv_bindings::Msrs, hyperv_bindings::SegmentRegister,
    hyperv_bindings::SpecialRegisters, hyperv_bindings::StandardRegisters,
    hyperv_bindings::VcpuEvents, hyperv_bindings::Xcrs as ExtendedControlRegisters,
};
#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuHypervState {
    //pub msrs: MsrEntries,
    pub vcpu_events: VcpuEvents,
    pub regs: StandardRegisters,
    pub sregs: SpecialRegisters,
    pub fpu: FpuState,
    pub xcrs: ExtendedControlRegisters,
}

pub struct CreateDevice {}
pub struct DeviceAttr {}
pub struct IrqRouting {}
pub enum VcpuExit {}
pub struct MpState {}
pub struct Xsave {}

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
        msr_data!(
            msr_index::MSR_IA32_MISC_ENABLE,
            msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64
        ),
        msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
    ])
}
