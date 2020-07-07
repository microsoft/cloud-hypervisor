// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

/// X86_64 specfic definitions for hyperv
///
use serde_derive::{Deserialize, Serialize};
///
/// Export generically-named wrappers of hyperv-bindings for Unix-based platforms
///
pub use {
    hyperv_bindings::hv_userspace_memory_region as MemoryRegion,
    hyperv_bindings::FloatingPointUnit as FpuState, hyperv_bindings::Msrs as MsrEntries,
    hyperv_bindings::SegmentRegister, hyperv_bindings::SpecialRegisters,
    hyperv_bindings::StandardRegisters, hyperv_bindings::VcpuEvents,
    hyperv_bindings::Xcrs as ExtendedControlRegisters,
};
#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuHypervState {
    pub msrs: MsrEntries,
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

pub enum IoEventAddress {
    /// Representation of an programmable I/O address.
    Pio(u64),
    /// Representation of an memory mapped I/O address.
    Mmio(u64),
}
