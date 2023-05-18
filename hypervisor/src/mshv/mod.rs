// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//

use crate::arch::emulator::{PlatformEmulator, PlatformError};

#[cfg(target_arch = "x86_64")]
use crate::arch::x86::emulator::{Emulator, EmulatorCpuState};
use crate::cpu;
use crate::cpu::Vcpu;
use crate::hypervisor;
use crate::vec_with_array_field;
use crate::vm::{self, InterruptSourceConfig, VmOps};
use crate::HypervisorType;
use byteorder::BigEndian;
use igvm_parser::importer::HV_PAGE_SIZE;
pub use mshv_bindings::*;
use mshv_ioctls::{set_registers_64, Mshv, NoDatamatch, VcpuFd, VmFd};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use vfio_ioctls::VfioDeviceFd;
use vm::DataMatch;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::GuestAddress;
use vm_memory::GuestAddressSpace;
use vm_memory::GuestMemory;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
// x86_64 dependencies
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
use crate::{
    ClockData, CpuState, IoEventAddress, IrqRoutingEntry, MpState, UserMemoryRegion,
    USER_MEMORY_REGION_ADJUST_PERMISSION, USER_MEMORY_REGION_EXECUTE, USER_MEMORY_REGION_READ,
    USER_MEMORY_REGION_WRITE,
};
use vmm_sys_util::eventfd::EventFd;
#[cfg(target_arch = "x86_64")]
pub use x86_64::VcpuMshvState;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "x86_64")]
use std::fs::File;
use std::os::unix::io::AsRawFd;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86::{
    CpuIdEntry, FpuState, LapicState, MsrEntry, SpecialRegisters, StandardRegisters,
};

#[cfg(feature = "snp")]
use igvm_parser::igvm::IgvmVhsSnpIdBlock;

const DIRTY_BITMAP_CLEAR_DIRTY: u64 = 0x4;
const DIRTY_BITMAP_SET_DIRTY: u64 = 0x8;

///
/// Export generically-named wrappers of mshv-bindings for Unix-based platforms
///
pub use {
    mshv_bindings::mshv_create_device as CreateDevice,
    mshv_bindings::mshv_device_attr as DeviceAttr, mshv_ioctls::DeviceFd,
};

pub const PAGE_SHIFT: usize = 12;

impl From<mshv_user_mem_region> for UserMemoryRegion {
    fn from(region: mshv_user_mem_region) -> Self {
        let mut flags: u32 = 0;
        if region.flags & HV_MAP_GPA_READABLE != 0 {
            flags |= USER_MEMORY_REGION_READ;
        }
        if region.flags & HV_MAP_GPA_WRITABLE != 0 {
            flags |= USER_MEMORY_REGION_WRITE;
        }
        if region.flags & HV_MAP_GPA_EXECUTABLE != 0 {
            flags |= USER_MEMORY_REGION_EXECUTE;
        }
        if region.flags & HV_MAP_GPA_ADJUSTABLE != 0 {
            flags |= USER_MEMORY_REGION_ADJUST_PERMISSION;
        }

        UserMemoryRegion {
            guest_phys_addr: (region.guest_pfn << PAGE_SHIFT as u64)
                + (region.userspace_addr & ((1 << PAGE_SHIFT) - 1)),
            memory_size: region.size,
            userspace_addr: region.userspace_addr,
            flags,
            ..Default::default()
        }
    }
}

impl From<UserMemoryRegion> for mshv_user_mem_region {
    fn from(region: UserMemoryRegion) -> Self {
        let mut flags: u32 = 0;
        if region.flags & USER_MEMORY_REGION_READ != 0 {
            flags |= HV_MAP_GPA_READABLE;
        }
        if region.flags & USER_MEMORY_REGION_WRITE != 0 {
            flags |= HV_MAP_GPA_WRITABLE;
        }
        if region.flags & USER_MEMORY_REGION_EXECUTE != 0 {
            flags |= HV_MAP_GPA_EXECUTABLE;
        }
        if region.flags & USER_MEMORY_REGION_ADJUST_PERMISSION != 0 {
            flags |= HV_MAP_GPA_ADJUSTABLE;
        }

        mshv_user_mem_region {
            guest_pfn: region.guest_phys_addr >> PAGE_SHIFT,
            size: region.memory_size,
            userspace_addr: region.userspace_addr,
            flags,
        }
    }
}

impl From<mshv_ioctls::IoEventAddress> for IoEventAddress {
    fn from(a: mshv_ioctls::IoEventAddress) -> Self {
        match a {
            mshv_ioctls::IoEventAddress::Pio(x) => Self::Pio(x),
            mshv_ioctls::IoEventAddress::Mmio(x) => Self::Mmio(x),
        }
    }
}

impl From<IoEventAddress> for mshv_ioctls::IoEventAddress {
    fn from(a: IoEventAddress) -> Self {
        match a {
            IoEventAddress::Pio(x) => Self::Pio(x),
            IoEventAddress::Mmio(x) => Self::Mmio(x),
        }
    }
}

impl From<VcpuMshvState> for CpuState {
    fn from(s: VcpuMshvState) -> Self {
        CpuState::Mshv(s)
    }
}

impl From<CpuState> for VcpuMshvState {
    fn from(s: CpuState) -> Self {
        match s {
            CpuState::Mshv(s) => s,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("CpuState is not valid"),
        }
    }
}

impl From<mshv_msi_routing_entry> for IrqRoutingEntry {
    fn from(s: mshv_msi_routing_entry) -> Self {
        IrqRoutingEntry::Mshv(s)
    }
}

impl From<IrqRoutingEntry> for mshv_msi_routing_entry {
    fn from(e: IrqRoutingEntry) -> Self {
        match e {
            IrqRoutingEntry::Mshv(e) => e,
            /* Needed in case other hypervisors are enabled */
            #[allow(unreachable_patterns)]
            _ => panic!("IrqRoutingEntry is not valid"),
        }
    }
}

struct MshvDirtyLogSlot {
    guest_pfn: u64,
    memory_size: u64,
}

/// Wrapper over mshv system ioctls.
pub struct MshvHypervisor {
    mshv: Mshv,
}

impl MshvHypervisor {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Retrieve the list of MSRs supported by MSHV.
    ///
    fn get_msr_list(&self) -> hypervisor::Result<MsrList> {
        self.mshv
            .get_msr_index_list()
            .map_err(|e| hypervisor::HypervisorError::GetMsrList(e.into()))
    }
}

impl MshvHypervisor {
    /// Create a hypervisor based on Mshv
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> hypervisor::Result<Arc<dyn hypervisor::Hypervisor>> {
        let mshv_obj =
            Mshv::new().map_err(|e| hypervisor::HypervisorError::HypervisorCreate(e.into()))?;
        Ok(Arc::new(MshvHypervisor { mshv: mshv_obj }))
    }
    /// Check if the hypervisor is available
    pub fn is_available() -> hypervisor::Result<bool> {
        match std::fs::metadata("/dev/mshv") {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(hypervisor::HypervisorError::HypervisorAvailableCheck(
                err.into(),
            )),
        }
    }
}
/// Implementation of Hypervisor trait for Mshv
///
/// # Examples
///
/// ```
/// # use hypervisor::mshv::MshvHypervisor;
/// # use std::sync::Arc;
/// let mshv = MshvHypervisor::new().unwrap();
/// let hypervisor = Arc::new(mshv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// ```
impl hypervisor::Hypervisor for MshvHypervisor {
    ///
    /// Returns the type of the hypervisor
    ///
    fn hypervisor_type(&self) -> HypervisorType {
        HypervisorType::Mshv
    }

    fn create_vm_with_type(&self, vm_type: u64) -> hypervisor::Result<Arc<dyn crate::Vm>> {
        let fd: VmFd;
        loop {
            match self.mshv.create_vm_with_type(vm_type) {
                Ok(res) => fd = res,
                Err(e) => {
                    if e.errno() == libc::EINTR {
                        // If the error returned is EINTR, which means the
                        // ioctl has been interrupted, we have to retry as
                        // this can't be considered as a regular error.
                        continue;
                    } else {
                        return Err(hypervisor::HypervisorError::VmCreate(e.into()));
                    }
                }
            }
            break;
        }

        // Default Microsoft Hypervisor behavior for unimplemented MSR is to
        // send a fault to the guest if it tries to access it. It is possible
        // to override this behavior with a more suitable option i.e., ignore
        // writes from the guest and return zero in attempt to read unimplemented
        // MSR.
        fd.set_partition_property(
            hv_partition_property_code_HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION,
            hv_unimplemented_msr_action_HV_UNIMPLEMENTED_MSR_ACTION_IGNORE_WRITE_READ_ZERO as u64,
        )
        .map_err(|e| hypervisor::HypervisorError::SetPartitionProperty(e.into()))?;

        match vm_type {
            1 /* SEV-SNP VM */ => {
                let snp_policy = snp::get_default_snp_guest_policy();
                unsafe {
                    debug!("Setting the partition isolation policy as: 0x{:x}", snp_policy.as_uint64);
                    fd.set_partition_property(
                        hv_partition_property_code_HV_PARTITION_PROPERTY_ISOLATION_POLICY,
                        snp_policy.as_uint64,
                    )
                    .map_err(|e| hypervisor::HypervisorError::SetPartitionProperty(e.into()))?;
                }
            },
            _ => { /* Do not need to do anything special for other VM types. */ },
        }

        let msr_list = self.get_msr_list()?;
        let num_msrs = msr_list.as_fam_struct_ref().nmsrs as usize;
        let mut msrs: Vec<MsrEntry> = vec![
            MsrEntry {
                ..Default::default()
            };
            num_msrs
        ];
        let indices = msr_list.as_slice();
        for (pos, index) in indices.iter().enumerate() {
            msrs[pos].index = *index;
        }
        let vm_fd = Arc::new(fd);

        Ok(Arc::new(MshvVm {
            fd: vm_fd,
            msrs,
            dirty_log_slots: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    /// Create a mshv vm object and return the object as Vm trait object
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate hypervisor;
    /// # use hypervisor::mshv::MshvHypervisor;
    /// use hypervisor::mshv::MshvVm;
    /// let hypervisor = MshvHypervisor::new().unwrap();
    /// let vm = hypervisor.create_vm().unwrap();
    /// ```
    fn create_vm(&self) -> hypervisor::Result<Arc<dyn vm::Vm>> {
        let vm_type = 0;
        self.create_vm_with_type(vm_type)
    }
    ///
    /// Get the supported CpuID
    ///
    fn get_supported_cpuid(&self) -> hypervisor::Result<Vec<CpuIdEntry>> {
        Ok(Vec::new())
    }

    /// Get maximum number of vCPUs
    fn get_max_vcpus(&self) -> u32 {
        // TODO: Using HV_MAXIMUM_PROCESSORS would be better
        // but the ioctl API is limited to u8
        256
    }
}

/// Vcpu struct for Microsoft Hypervisor
pub struct MshvVcpu {
    fd: VcpuFd,
    vp_index: u8,
    cpuid: Vec<CpuIdEntry>,
    msrs: Vec<MsrEntry>,
    vm_ops: Option<Arc<dyn vm::VmOps>>,
    vm_fd: Arc<VmFd>,
}

/// Implementation of Vcpu trait for Microsoft Hypervisor
///
/// # Examples
///
/// ```
/// # use hypervisor::mshv::MshvHypervisor;
/// # use std::sync::Arc;
/// let mshv = MshvHypervisor::new().unwrap();
/// let hypervisor = Arc::new(mshv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// let vcpu = vm.create_vcpu(0, None).unwrap();
/// ```
impl cpu::Vcpu for MshvVcpu {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU general purpose registers.
    ///
    fn get_regs(&self) -> cpu::Result<StandardRegisters> {
        Ok(self
            .fd
            .get_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetStandardRegs(e.into()))?
            .into())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU general purpose registers.
    ///
    fn set_regs(&self, regs: &StandardRegisters) -> cpu::Result<()> {
        let regs = (*regs).into();
        self.fd
            .set_regs(&regs)
            .map_err(|e| cpu::HypervisorCpuError::SetStandardRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU special registers.
    ///
    fn get_sregs(&self) -> cpu::Result<SpecialRegisters> {
        Ok(self
            .fd
            .get_sregs()
            .map_err(|e| cpu::HypervisorCpuError::GetSpecialRegs(e.into()))?
            .into())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU special registers.
    ///
    fn set_sregs(&self, sregs: &SpecialRegisters) -> cpu::Result<()> {
        let sregs = (*sregs).into();
        self.fd
            .set_sregs(&sregs)
            .map_err(|e| cpu::HypervisorCpuError::SetSpecialRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the floating point state (FPU) from the vCPU.
    ///
    fn get_fpu(&self) -> cpu::Result<FpuState> {
        Ok(self
            .fd
            .get_fpu()
            .map_err(|e| cpu::HypervisorCpuError::GetFloatingPointRegs(e.into()))?
            .into())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Set the floating point state (FPU) of a vCPU.
    ///
    fn set_fpu(&self, fpu: &FpuState) -> cpu::Result<()> {
        let fpu: mshv_bindings::FloatingPointUnit = (*fpu).clone().into();
        self.fd
            .set_fpu(&fpu)
            .map_err(|e| cpu::HypervisorCpuError::SetFloatingPointRegs(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    fn get_msrs(&self, msrs: &mut Vec<MsrEntry>) -> cpu::Result<usize> {
        let mshv_msrs: Vec<msr_entry> = msrs.iter().map(|e| (*e).into()).collect();
        let mut mshv_msrs = MsrEntries::from_entries(&mshv_msrs).unwrap();
        let succ = self
            .fd
            .get_msrs(&mut mshv_msrs)
            .map_err(|e| cpu::HypervisorCpuError::GetMsrEntries(e.into()))?;

        msrs[..succ].copy_from_slice(
            &mshv_msrs.as_slice()[..succ]
                .iter()
                .map(|e| (*e).into())
                .collect::<Vec<MsrEntry>>(),
        );

        Ok(succ)
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    ///
    fn set_msrs(&self, msrs: &[MsrEntry]) -> cpu::Result<usize> {
        let mshv_msrs: Vec<msr_entry> = msrs.iter().map(|e| (*e).into()).collect();
        let mshv_msrs = MsrEntries::from_entries(&mshv_msrs).unwrap();
        self.fd
            .set_msrs(&mshv_msrs)
            .map_err(|e| cpu::HypervisorCpuError::SetMsrEntries(e.into()))
    }

    fn get_cpuid_values(&self, function: u32, index: u32, xfem: u64, xss: u64) -> cpu::Result<[u32; 4]> {
        self.fd.get_cpuid_values(function, index, xfem, xss).map_err(|e| cpu::HypervisorCpuError::GetCpuidVales(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to enable HyperV SynIC
    ///
    fn enable_hyperv_synic(&self) -> cpu::Result<()> {
        /* We always have SynIC enabled on MSHV */
        Ok(())
    }
    #[allow(non_upper_case_globals)]
    fn run(
        &self,
        guest_memory: &GuestMemoryAtomic<vm_memory::GuestMemoryMmap<AtomicBitmap>>,
    ) -> std::result::Result<cpu::VmExit, cpu::HypervisorCpuError> {
        let hv_message: hv_message = hv_message::default();
        match self.fd.run(hv_message) {
            Ok(x) => match x.header.message_type {
                hv_message_type_HVMSG_X64_HALT => {
                    debug!("HALT");
                    Ok(cpu::VmExit::Reset)
                }
                hv_message_type_HVMSG_UNRECOVERABLE_EXCEPTION => {
                    warn!("TRIPLE FAULT");
                    Ok(cpu::VmExit::Shutdown)
                }
                hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT => {
                    let info = x.to_ioport_info().unwrap();
                    let access_info = info.access_info;
                    // SAFETY: access_info is valid, otherwise we won't be here
                    let len = unsafe { access_info.__bindgen_anon_1.access_size() } as usize;
                    let is_write = info.header.intercept_access_type == 1;
                    let port = info.port_number;
                    let mut data: [u8; 4] = [0; 4];
                    let mut ret_rax = info.rax;

                    /*
                     * XXX: Ignore QEMU fw_cfg (0x5xx) and debug console (0x402) ports.
                     *
                     * Cloud Hypervisor doesn't support fw_cfg at the moment. It does support 0x402
                     * under the "fwdebug" feature flag. But that feature is not enabled by default
                     * and is considered legacy.
                     *
                     * OVMF unconditionally pokes these IO ports with string IO.
                     *
                     * Instead of trying to implement string IO support now which does not do much
                     * now, skip those ports explicitly to avoid panicking.
                     *
                     * Proper string IO support can be added once we gain the ability to translate
                     * guest virtual addresses to guest physical addresses on MSHV.
                     */
                    match port {
                        0x402 | 0x510 | 0x511 | 0x514 => {
                            let insn_len = info.header.instruction_length() as u64;

                            /* Advance RIP and update RAX */
                            let arr_reg_name_value = [
                                (
                                    hv_register_name_HV_X64_REGISTER_RIP,
                                    info.header.rip + insn_len,
                                ),
                                (hv_register_name_HV_X64_REGISTER_RAX, ret_rax),
                            ];
                            set_registers_64!(self.fd, arr_reg_name_value)
                                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                            return Ok(cpu::VmExit::Ignore);
                        }
                        _ => {
                            println!("VMEXIT Ddddddddddddddddddddddddddd: port {:0x}", { port });
                        }
                    }

                    assert!(
                        // SAFETY: access_info is valid, otherwise we won't be here
                        (unsafe { access_info.__bindgen_anon_1.string_op() } != 1),
                        "String IN/OUT not supported"
                    );
                    assert!(
                        // SAFETY: access_info is valid, otherwise we won't be here
                        (unsafe { access_info.__bindgen_anon_1.rep_prefix() } != 1),
                        "Rep IN/OUT not supported"
                    );

                    if is_write {
                        let data = (info.rax as u32).to_le_bytes();
                        if let Some(vm_ops) = &self.vm_ops {
                            vm_ops
                                .pio_write(port.into(), &data[0..len])
                                .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
                        }
                    } else {
                        if let Some(vm_ops) = &self.vm_ops {
                            vm_ops
                                .pio_read(port.into(), &mut data[0..len])
                                .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;
                        }

                        let v = u32::from_le_bytes(data);
                        /* Preserve high bits in EAX but clear out high bits in RAX */
                        let mask = 0xffffffff >> (32 - len * 8);
                        let eax = (info.rax as u32 & !mask) | (v & mask);
                        ret_rax = eax as u64;
                    }

                    let insn_len = info.header.instruction_length() as u64;

                    /* Advance RIP and update RAX */
                    let arr_reg_name_value = [
                        (
                            hv_register_name_HV_X64_REGISTER_RIP,
                            info.header.rip + insn_len,
                        ),
                        (hv_register_name_HV_X64_REGISTER_RAX, ret_rax),
                    ];
                    set_registers_64!(self.fd, arr_reg_name_value)
                        .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                    Ok(cpu::VmExit::Ignore)
                }
                hv_message_type_HVMSG_UNMAPPED_GPA => {
                    let info = x.to_memory_info().unwrap();
                    let insn_len = info.instruction_byte_count as usize;
                    assert!(insn_len > 0 && insn_len <= 16);

                    let mut context = MshvEmulatorContext {
                        vcpu: self,
                        map: (info.guest_virtual_address, info.guest_physical_address),
                    };

                    // Create a new emulator.
                    let mut emul = Emulator::new(&mut context);

                    // Emulate the trapped instruction, and only the first one.
                    let new_state = emul
                        .emulate_first_insn(self.vp_index as usize, &info.instruction_bytes)
                        .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

                    // Set CPU state back.
                    context
                        .set_cpu_state(self.vp_index as usize, new_state)
                        .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))?;

                    Ok(cpu::VmExit::Ignore)
                }
                hv_message_type_HVMSG_X64_CPUID_INTERCEPT => {
                    let info = x.to_cpuid_info().unwrap();
                    debug!("cpuid eax: {:x}", { info.rax });
                    Ok(cpu::VmExit::Ignore)
                }
                hv_message_type_HVMSG_X64_MSR_INTERCEPT => {
                    let info = x.to_msr_info().unwrap();
                    if info.header.intercept_access_type == 0 {
                        debug!("msr read: {:x}", { info.msr_number });
                    } else {
                        debug!("msr write: {:x}", { info.msr_number });
                    }
                    Ok(cpu::VmExit::Ignore)
                }
                hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT => {
                    //TODO: Handler for VMCALL here.
                    let info = x.to_exception_info().unwrap();
                    debug!("Exception Info {:?}", { info.exception_vector });
                    Ok(cpu::VmExit::Ignore)
                }
                hv_message_type_HVMSG_UNACCEPTED_GPA => {
                    let info = x.to_memory_info().unwrap();
                    let gva = info.guest_virtual_address;
                    let gpa = info.guest_physical_address;
                    let GB = gpa / (1024 * 1024 * 1024);
                    info!(
                        "Unaccepted GPA: GVA: {:x}, GPA: {:x} Gigabyte: {:?}",
                        gva, gpa, GB
                    );
                    Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                        "Unhandled VCPU exit: Unaccepted GPA"
                    )))
                }
                hv_message_type_HVMSG_GPA_ATTRIBUTE_INTERCEPT => {
                    let info = x.to_gpa_attribute_info().unwrap();
                    let vp_index = info.vp_index;
                    let host_vis = info.__bindgen_anon_1.host_visibility();
                    info!("vp_index: {:?}, host_vis: {:?}", vp_index, host_vis);
                    let ranges = info.ranges;
                    let (gpa_start, gpa_count) = snp::parse_gpa_range(ranges[0]).unwrap();
                    info!("gpa_start: {:?}, gpa_count: {:?}", gpa_start, gpa_count);
                    let mut gpa_list = Vec::new();
                    for i in 0..gpa_count {
                        let gpa = guest_memory
                            .clone()
                            .memory()
                            .get_host_address(GuestAddress(gpa_start + i * HV_PAGE_SIZE))
                            .unwrap() as u64;
                        // let gpa = gpa_start + i * HV_PAGE_SIZE;
                        gpa_list.push(gpa);
                    }
                    // if host_vis != 3 {
                    _modify_gpa_host_access(
                        self.vm_fd.clone(),
                        0,
                        0,
                        false as u8,
                        gpa_list.as_slice(),
                    )
                    .unwrap();
                    Ok(cpu::VmExit::Ignore)
                    // } else {
                    //     _modify_gpa_host_access(
                    //         self.vm_fd.clone(),
                    //         host_vis,
                    //         0,
                    //         true as u8,
                    //         gpa_list.as_slice(),
                    //     )
                    //     .unwrap();
                    //     Ok(cpu::VmExit::Ignore)
                    // }
                }
                hv_message_type_HVMSG_X64_SEV_VMG_EXIT_INTERCEPT => {
                    let info = x.to_vmg_intercept_info().unwrap();
                    //let ghcb_msr: u64 = info.ghcb_msr;
                    //let op = ghcb_msr & GHCB_INFO_MASK as u64;
                    let ghcb_data = (info.ghcb_msr >> GHCB_INFO_BIT_WIDTH) as u64;
                    let ghcb_msr = svm_ghcb_msr {
                        as_uint64: info.ghcb_msr,
                    };
                    let op = unsafe { ghcb_msr.__bindgen_anon_2.ghcb_info() as u64 };
                    //println!("VMG_EXIT: ");
                    // Don't understand the need for this check????
                    // assert!(info.__bindgen_anon_1.ghcb_page_valid() != 1);
                    assert!(info.header.intercept_access_type == HV_INTERCEPT_ACCESS_EXECUTE as u8);
                    if op == GHCB_INFO_REGISTER_REQUEST as u64 {
                        // // The VMM sets the HvX64RegisterSevGhcbGpa register as specified by the guest
                        // let mut ghcb_page_msr = hv_x64_register_sev_ghcb {
                        //     as_uint64: ghcb_msr,
                        // };
                        // unsafe {
                        //     // ghcb_page_msr.__bindgen_anon_1.set_enabled(0);
                        //     // ghcb_page_msr.__bindgen_anon_1.set_page_number((ghcb_msr >> GHCB_INFO_BIT_WIDTH) & GHCB_DATA_MASK);
                        //     let arr_reg_name_value = [(
                        //         hv_register_name_HV_X64_REGISTER_GHCB,
                        //         ghcb_page_msr.as_uint64,
                        //     )];
                        //     println!("GHCB_INFO_REGISTER_REQUEST: {:0x}", ghcb_page_msr.as_uint64);
                        //     set_registers_64!(self.fd, arr_reg_name_value)
                        //         .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                        // }
                        // // The VMM writes the result to the GHCB register
                        // let mut write_msr = ghcb_msr;
                        // // write_msr &= GHCB_DATA_MASK << GHCB_INFO_BIT_WIDTH; //clear GHCB info
                        // write_msr |= GHCB_INFO_REGISTER_RESPONSE as u64;
                        // let arr_reg_name_value =
                        //     [(hv_register_name_HV_X64_REGISTER_GHCB, write_msr)];
                        // println!("GHCB_INFO_REGISTER_REQUEST: {:0x}", write_msr);
                        // set_registers_64!(self.fd, arr_reg_name_value)
                        //     .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                        // println!("Done GHCB_INFO_REGISTER_REQUEST: {:0x}", write_msr);

                        let mut ghcb_gpa = hv_x64_register_sev_ghcb::default();
                        unsafe {
                            // println!("GHCB_INFO_REGISTER_REQUEST: {:0x}", ghcb_msr.__bindgen_anon_2.gpa_page_number());
                            ghcb_gpa.__bindgen_anon_1.set_enabled(1);
                            ghcb_gpa
                                .__bindgen_anon_1
                                .set_page_number(ghcb_msr.__bindgen_anon_2.gpa_page_number());

                            let reg_name_value = [(
                                hv_register_name_HV_X64_REGISTER_SEV_GHCB_GPA,
                                ghcb_gpa.as_uint64,
                            )];

                            set_registers_64!(self.fd, reg_name_value)
                                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                            println!(
                                "GHCB_INFO_REGISTER_REQUEST: {:0x} Done",
                                reg_name_value[0].1
                            );
                        }

                        let mut resp_ghcb_msr = svm_ghcb_msr::default();
                        unsafe {
                            resp_ghcb_msr
                                .__bindgen_anon_2
                                .set_ghcb_info(GHCB_INFO_REGISTER_RESPONSE as u64);
                            resp_ghcb_msr
                                .__bindgen_anon_2
                                .set_gpa_page_number(ghcb_msr.__bindgen_anon_2.gpa_page_number());

                            let reg_name_value = [(
                                hv_register_name_HV_X64_REGISTER_GHCB,
                                resp_ghcb_msr.as_uint64,
                            )];

                            set_registers_64!(self.fd, reg_name_value)
                                .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                        }
                    } else if op == GHCB_INFO_SEV_INFO_REQUEST as u64 {
                        // println!("GHCB_INFO_SEV_INFO_REQUEST");
                        let function = 0x8000_001F;
                        let cpu_leaf = self.fd.get_cpuid_values(function, 0, 0, 0).unwrap();
                        let ebx = cpu_leaf[1];
                        let pbit_encryption: u8 = (ebx & 0x3f) as u8;

                        let mut write_msr: u64 = GHCB_INFO_SEV_INFO_RESPONSE as u64;
                        write_msr |= (GHCB_PROTOCOL_VERSION_MAX as u64) << 48;
                        write_msr |= (GHCB_PROTOCOL_VERSION_MIN as u64) << 32;
                        write_msr |= (pbit_encryption as u64) << 24;
                        let arr_reg_name_value =
                            [(hv_register_name_HV_X64_REGISTER_GHCB, write_msr)];
                        set_registers_64!(self.fd, arr_reg_name_value)
                            .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                        println!(
                            "GHCB_INFO_SEV_INFO_REQUEST EBX: {:0x}, bit: {:0x} Done",
                            ebx, pbit_encryption
                        );
                    } else if op == GHCB_INFO_HYP_FEATURE_REQUEST as u64 {
                        // println!("GHCB_INFO_HYP_FEATURE_REQUEST: data: {:0x}", ghcb_data);
                        // GHCB data must be zero
                        assert!(ghcb_data == 0);

                        let mut write_msr: u64 = GHCB_INFO_HYP_FEATURE_RESPONSE as u64;
                        // Add support for AP creation
                        write_msr = write_msr | ((0x3 << GHCB_INFO_BIT_WIDTH) as u64);
                        println!("GHCB_INFO_HYP_FEATURE_REQUEST: write msr: {:0x}", write_msr);
                        let arr_reg_name_value =
                            [(hv_register_name_HV_X64_REGISTER_GHCB, write_msr)];
                        set_registers_64!(self.fd, arr_reg_name_value)
                            .map_err(|e| cpu::HypervisorCpuError::SetRegister(e.into()))?;
                        println!(
                            "GHCB_INFO_HYP_FEATURE_REQUEST: write msr: {:0x} done",
                            write_msr
                        );
                    } else if op == GHCB_INFO_SPECIAL_DBGPRINT as u64 {
                        let data = unsafe { ghcb_msr.as_uint64 } >> 16;
                        let bytes = data.to_le_bytes();
                        if let Ok(s) = std::str::from_utf8(bytes.as_slice()) {
                            print!("{}", s);
                        }
                    } else if op == GHCB_INFO_NORMAL as u64 {
                        // println!("GHCB_INFO_NORMAL");
                        // SAFETY: access_info is valid, otherwise we won't be here
                        let _exit_code =
                            unsafe { info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_code } as u64;
                        let exit_info1 =
                            info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info1 as u64;

                        let _exit_code_u32 =
                            unsafe { info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_code } as u32;
                        let exit_info1_u32 =
                            info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info1 as u32;
                        let exit_info2 = info.__bindgen_anon_2.__bindgen_anon_1.sw_exit_info2;
                        let sw_scratch = info.__bindgen_anon_2.__bindgen_anon_1.sw_scratch;
                        let pfn: u64 =
                            unsafe { ghcb_msr.__bindgen_anon_2.gpa_page_number() as u64 };
                        let gpa: u64 = pfn << GHCB_INFO_BIT_WIDTH;
                        // println!("Software exit code {:0x}", _exit_code);
                        // println!("Software exit exit_info1 {:0x}", exit_info1);
                        // println!("Software exit exit_info2 {:0x}", exit_info2);
                        // println!("Software exit sw_scratch {:0x}",sw_scratch);
                        // println!("Software exit pfn {:0x}", gpa);
                        match _exit_code_u32 {
                            SVM_EXITCODE_HV_DOORBELL_PAGE => match exit_info1_u32 {
                                SVM_NAE_HV_DOORBELL_PAGE_GET_PREFERRED => {
                                    let mut arg: mshv_read_write_gpa =
                                        mshv_read_write_gpa::default();
                                    let value: u64 = 0xFFFFFFFFFFFFFFFF;
                                    arg.base_gpa = gpa + 0x3a0;
                                    arg.byte_count = 8;
                                    arg.data.copy_from_slice(&value.to_le_bytes());
                                    self.fd.gpa_write(&mut arg).unwrap();
                                }
                                SVM_NAE_HV_DOORBELL_PAGE_SET => {
                                    let mut ghcb_doorbell_gpa =
                                        hv_x64_register_sev_hv_doorbell::default();
                                    unsafe {
                                        ghcb_doorbell_gpa.__bindgen_anon_1.set_enabled(1);
                                        ghcb_doorbell_gpa
                                            .__bindgen_anon_1
                                            .set_page_number(exit_info2 >> 12);
                                    }
                                    let write_msr = unsafe { ghcb_doorbell_gpa.as_uint64 };
                                    let arr_reg_name_value = [(
                                        hv_register_name_HV_X64_REGISTER_SEV_DOORBELL_GPA,
                                        write_msr,
                                    )];
                                    set_registers_64!(self.fd, arr_reg_name_value).map_err(
                                        |e| cpu::HypervisorCpuError::SetRegister(e.into()),
                                    )?;
                                    let mut arg: mshv_read_write_gpa =
                                        mshv_read_write_gpa::default();
                                    let value = exit_info2;
                                    arg.base_gpa = gpa + 0x3a0;
                                    arg.byte_count = 8;
                                    arg.data[0..8].copy_from_slice(&value.to_le_bytes());
                                    self.fd.gpa_write(&mut arg).unwrap();

                                    let value1 = 0_u64;
                                    arg.base_gpa = gpa + 0x398;
                                    arg.byte_count = 8;
                                    arg.data[0..8].copy_from_slice(&value1.to_le_bytes());
                                    self.fd.gpa_write(&mut arg).unwrap();
                                }
                                SVM_NAE_HV_DOORBELL_PAGE_QUERY => {
                                    let reg_names =
                                        [hv_register_name_HV_X64_REGISTER_SEV_DOORBELL_GPA];
                                    let mut reg_assocs: Vec<hv_register_assoc> = reg_names
                                        .iter()
                                        .map(|name| hv_register_assoc {
                                            name: *name,
                                            ..Default::default()
                                        })
                                        .collect();
                                    self.fd.get_reg(&mut reg_assocs).unwrap();
                                    let value = unsafe { reg_assocs[0].value.reg64 };
                                    let mut arg: mshv_read_write_gpa =
                                        mshv_read_write_gpa::default();
                                    arg.base_gpa = gpa + 0x3a0;
                                    arg.byte_count = 8;
                                    arg.data.copy_from_slice(&value.to_le_bytes());
                                    self.fd.gpa_write(&mut arg).unwrap();
                                }
                                SVM_NAE_HV_DOORBELL_PAGE_CLEAR => {
                                    let value: u64 = 0;
                                    let mut arg: mshv_read_write_gpa =
                                        mshv_read_write_gpa::default();
                                    arg.base_gpa = gpa + 0x3a0;
                                    arg.byte_count = 8;
                                    arg.data.copy_from_slice(&value.to_le_bytes());
                                    self.fd.gpa_write(&mut arg).unwrap();
                                }
                                _ => {
                                    panic!(
                                        "Unhandled exitinfo1 for doorbell page: {:0x}",
                                        exit_info1
                                    );
                                }
                            },
                            SVM_EXITCODE_SNP_GUEST_REQUEST => {
                                let req_gpa = exit_info1 as u64;
                                let rsp_gpa = exit_info2 as u64;

                                _psp_issue_guest_request(self.vm_fd.clone(), req_gpa, rsp_gpa).unwrap();

                                let mut arg_exit1: mshv_read_write_gpa =
                                    mshv_read_write_gpa::default();
                                let value1 = 0_u64;
                                arg_exit1.base_gpa = gpa + 0x3a0;
                                arg_exit1.byte_count = 8;
                                arg_exit1.data[0..8].copy_from_slice(&value1.to_le_bytes());
                                self.fd.gpa_write(&mut arg_exit1).unwrap();
                            }
                            SVM_EXITCODE_SNP_AP_CREATION => {
                                println!("VMSA GPA for CPU1 is {:0x}", exit_info2);
                                println!("APIC ID GPA for CPU1 is {:0x}", exit_info1);
                                _snp_start_vcpu(self.vm_fd.clone(), exit_info1 >> 32, exit_info2).unwrap();
                                let mut arg_exit1: mshv_read_write_gpa =
                                mshv_read_write_gpa::default();
                                let value1 = 0_u64;
                                arg_exit1.base_gpa = gpa + 0x398;
                                arg_exit1.byte_count = 8;
                                arg_exit1.data[0..8].copy_from_slice(&value1.to_le_bytes());
                                self.fd.gpa_write(&mut arg_exit1).unwrap();
                            }
                            0x7b => {
                                let addr = info.__bindgen_anon_2.__bindgen_anon_1.sw_scratch;
                                let port_into = hv_sev_vmgexit_port_info {
                                    as_uint32: (exit_info1 & 0xFFFFFFFF) as u32,
                                };
                                let port = unsafe { port_into.__bindgen_anon_1.intercepted_port() };
                                // println!("$$$$$$ Port we are trying to handle {0:0x}", port);
                                let mut len = 4;
                                unsafe {
                                    if port_into.__bindgen_anon_1.operand_size_16bit() == 1 {
                                        len = 2;
                                    } else if port_into.__bindgen_anon_1.operand_size_8bit() == 1 {
                                        len = 1;
                                    }
                                }
                                // println!("$$$$$$ Port we are trying to handle len {0:0x}", len);
                                let is_write =
                                    unsafe { port_into.__bindgen_anon_1.access_type() == 0 };
                                // println!("$$$$$$ Port we are trying to handle write {}", is_write);
                                // println!("$$$$$$ Port we are trying to handle gpa {0:0x}", gpa);
                                // println!("$$$$$$ Port we are trying to handle addr {0:0x}", addr);
                                let mut arg: mshv_read_write_gpa = mshv_read_write_gpa::default();
                                arg.base_gpa = gpa + 0x01F8;
                                arg.byte_count = 8;
                                self.fd.gpa_read(&mut arg).unwrap();
                                let mut bytes: [u8; 8] = [0u8; 8];
                                bytes.copy_from_slice(&arg.data[0..8]);
                                let rax: u64 = u64::from_le_bytes(bytes);
                                let data = (rax as u32).to_le_bytes();
                                if is_write {
                                    if let Some(vm_ops) = &self.vm_ops {
                                        //println!("gpamwrite bytes: {:02X?}", bytes);
                                        //println!("pio_write bytes: {:02X?}", &data[0..len]);
                                        vm_ops.pio_write(port.into(), &data[0..len]).map_err(
                                            |e| cpu::HypervisorCpuError::RunVcpu(e.into()),
                                        )?;
                                        //println!("######## Ports write: {:0x}, value {:0x} len {}", port, rax, len);
                                    }
                                } else {
                                    let mut data: [u8; 4] = [0; 4];
                                    //println!("######## Ports read: Port: {:0x} len: {}", port, len);
                                    if let Some(vm_ops) = &self.vm_ops {
                                        vm_ops.pio_read(port.into(), &mut data[0..len]).map_err(
                                            |e| cpu::HypervisorCpuError::RunVcpu(e.into()),
                                        )?;
                                    }

                                    let mut v = u32::from_le_bytes(data);
                                    //v =  ((v) & ((1u64 << ((len) * 8)) - 1) as u32);
                                    // /* Preserve high bits in EAX but clear out high bits in RAX */
                                    // let mask = 0xffffffff >> (32 - len * 8);
                                    // let eax = (rax as u32 & !mask) | (v & mask);
                                    let ret_rax = v as u64;
                                    arg.data[0..8].copy_from_slice(&ret_rax.to_le_bytes());
                                    self.fd.gpa_write(&mut arg).unwrap();
                                    //println!("######## Ports read done: value: {:0x} ", ret_rax);
                                }

                                let mut arg_exit1: mshv_read_write_gpa =
                                    mshv_read_write_gpa::default();
                                let value1 = 0_u64;
                                arg_exit1.base_gpa = gpa + 0x398;
                                arg_exit1.byte_count = 8;
                                arg_exit1.data[0..8].copy_from_slice(&value1.to_le_bytes());
                                self.fd.gpa_write(&mut arg_exit1).unwrap();
                                //println!("$$$$$$$: Port handle done is_write( {:?}): GPA: {:0x}, Port: {:0x}, ", is_write, gpa, port);
                            }
                            _ => {
                                panic!("Unhandled exit code: {:0x}", _exit_code);
                            }
                        }
                    } else {
                        panic!("--------------------------------------------VMGexit: Unhandled operations {:0x}", op);
                    }
                    Ok(cpu::VmExit::Ignore)
                }

                exit => Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "--------------------------- Unhandled VCPU exit {:?}",
                    exit
                ))),
            },

            Err(e) => match e.errno() {
                libc::EAGAIN | libc::EINTR => Ok(cpu::VmExit::Ignore),
                _ => Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                    "VCPU error {:?}",
                    e
                ))),
            },
        }
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to setup the CPUID registers.
    ///
    fn set_cpuid2(&self, cpuid: &[CpuIdEntry]) -> cpu::Result<()> {
        let cpuid: Vec<mshv_bindings::hv_cpuid_entry> = cpuid.iter().map(|e| (*e).into()).collect();
        let mshv_cpuid = <CpuId>::from_entries(&cpuid)
            .map_err(|_| cpu::HypervisorCpuError::SetCpuid(anyhow!("failed to create CpuId")))?;

        self.fd
            .register_intercept_result_cpuid(&mshv_cpuid)
            .map_err(|e| cpu::HypervisorCpuError::SetCpuid(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to retrieve the CPUID registers.
    ///
    fn get_cpuid2(&self, _num_entries: usize) -> cpu::Result<Vec<CpuIdEntry>> {
        Ok(self.cpuid.clone())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn get_lapic(&self) -> cpu::Result<LapicState> {
        Ok(self
            .fd
            .get_lapic()
            .map_err(|e| cpu::HypervisorCpuError::GetlapicState(e.into()))?
            .into())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn set_lapic(&self, lapic: &LapicState) -> cpu::Result<()> {
        let lapic: mshv_bindings::LapicState = (*lapic).clone().into();
        self.fd
            .set_lapic(&lapic)
            .map_err(|e| cpu::HypervisorCpuError::SetLapicState(e.into()))
    }
    ///
    /// Returns the vcpu's current "multiprocessing state".
    ///
    fn get_mp_state(&self) -> cpu::Result<MpState> {
        Ok(MpState::Mshv)
    }
    ///
    /// Sets the vcpu's current "multiprocessing state".
    ///
    fn set_mp_state(&self, _mp_state: MpState) -> cpu::Result<()> {
        Ok(())
    }
    ///
    /// Set CPU state
    ///
    fn set_state(&self, state: &CpuState) -> cpu::Result<()> {
        let state: VcpuMshvState = state.clone().into();
        self.set_msrs(&state.msrs)?;
        self.set_vcpu_events(&state.vcpu_events)?;
        self.set_regs(&state.regs.into())?;
        self.set_sregs(&state.sregs.into())?;
        self.set_fpu(&state.fpu)?;
        self.set_xcrs(&state.xcrs)?;
        self.set_lapic(&state.lapic)?;
        self.set_xsave(&state.xsave)?;
        // These registers are global and needed to be set only for first VCPU
        // as Microsoft Hypervisor allows setting this regsier for only one VCPU
        if self.vp_index == 0 {
            self.fd
                .set_misc_regs(&state.misc)
                .map_err(|e| cpu::HypervisorCpuError::SetMiscRegs(e.into()))?
        }
        self.fd
            .set_debug_regs(&state.dbg)
            .map_err(|e| cpu::HypervisorCpuError::SetDebugRegs(e.into()))?;
        Ok(())
    }
    ///
    /// Get CPU State
    ///
    fn state(&self) -> cpu::Result<CpuState> {
        let regs = self.get_regs()?;
        let sregs = self.get_sregs()?;
        let xcrs = self.get_xcrs()?;
        let fpu = self.get_fpu()?;
        let vcpu_events = self.get_vcpu_events()?;
        let mut msrs = self.msrs.clone();
        self.get_msrs(&mut msrs)?;
        let lapic = self.get_lapic()?;
        let xsave = self.get_xsave()?;
        let misc = self
            .fd
            .get_misc_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetMiscRegs(e.into()))?;
        let dbg = self
            .fd
            .get_debug_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetDebugRegs(e.into()))?;

        Ok(VcpuMshvState {
            msrs,
            vcpu_events,
            regs: regs.into(),
            sregs: sregs.into(),
            fpu,
            xcrs,
            lapic,
            dbg,
            xsave,
            misc,
        }
        .into())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Translate guest virtual address to guest physical address
    ///
    fn translate_gva(&self, gva: u64, flags: u64) -> cpu::Result<(u64, u32)> {
        let r = self
            .fd
            .translate_gva(gva, flags)
            .map_err(|e| cpu::HypervisorCpuError::TranslateVirtualAddress(e.into()))?;

        let gpa = r.0;
        // SAFETY: r is valid, otherwise this function will have returned
        let result_code = unsafe { r.1.__bindgen_anon_1.result_code };

        Ok((gpa, result_code))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Return the list of initial MSR entries for a VCPU
    ///
    fn boot_msr_entries(&self) -> Vec<MsrEntry> {
        use crate::arch::x86::{msr_index, MTRR_ENABLE, MTRR_MEM_TYPE_WB};

        [
            msr!(msr_index::MSR_IA32_SYSENTER_CS),
            msr!(msr_index::MSR_IA32_SYSENTER_ESP),
            msr!(msr_index::MSR_IA32_SYSENTER_EIP),
            msr!(msr_index::MSR_STAR),
            msr!(msr_index::MSR_CSTAR),
            msr!(msr_index::MSR_LSTAR),
            msr!(msr_index::MSR_KERNEL_GS_BASE),
            msr!(msr_index::MSR_SYSCALL_MASK),
            msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
        ]
        .to_vec()
    }
    #[cfg(feature = "snp")]
    fn set_sev_control_register(&self, vmsa_pfn: u64) -> cpu::Result<()> {
        let sev_control_reg = snp::get_sev_control_register(vmsa_pfn);

        self.fd
            .set_sev_control_register(sev_control_reg)
            .map_err(|e| cpu::HypervisorCpuError::SetSevControlRegister(e.into()))
    }
}

impl MshvVcpu {
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that returns the vcpu's current "xsave struct".
    ///
    fn get_xsave(&self) -> cpu::Result<Xsave> {
        self.fd
            .get_xsave()
            .map_err(|e| cpu::HypervisorCpuError::GetXsaveState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that sets the vcpu's current "xsave struct".
    ///
    fn set_xsave(&self, xsave: &Xsave) -> cpu::Result<()> {
        self.fd
            .set_xsave(xsave)
            .map_err(|e| cpu::HypervisorCpuError::SetXsaveState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that returns the vcpu's current "xcrs".
    ///
    fn get_xcrs(&self) -> cpu::Result<ExtendedControlRegisters> {
        self.fd
            .get_xcrs()
            .map_err(|e| cpu::HypervisorCpuError::GetXcsr(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that sets the vcpu's current "xcrs".
    ///
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> cpu::Result<()> {
        self.fd
            .set_xcrs(xcrs)
            .map_err(|e| cpu::HypervisorCpuError::SetXcsr(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns currently pending exceptions, interrupts, and NMIs as well as related
    /// states of the vcpu.
    ///
    fn get_vcpu_events(&self) -> cpu::Result<VcpuEvents> {
        self.fd
            .get_vcpu_events()
            .map_err(|e| cpu::HypervisorCpuError::GetVcpuEvents(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets pending exceptions, interrupts, and NMIs as well as related states
    /// of the vcpu.
    ///
    fn set_vcpu_events(&self, events: &VcpuEvents) -> cpu::Result<()> {
        self.fd
            .set_vcpu_events(events)
            .map_err(|e| cpu::HypervisorCpuError::SetVcpuEvents(e.into()))
    }
}

struct MshvEmulatorContext<'a> {
    vcpu: &'a MshvVcpu,
    map: (u64, u64), // Initial GVA to GPA mapping provided by the hypervisor
}

impl<'a> MshvEmulatorContext<'a> {
    // Do the actual gva -> gpa translation
    #[allow(non_upper_case_globals)]
    fn translate(&self, gva: u64) -> Result<u64, PlatformError> {
        if self.map.0 == gva {
            return Ok(self.map.1);
        }

        // TODO: More fine-grained control for the flags
        let flags = HV_TRANSLATE_GVA_VALIDATE_READ | HV_TRANSLATE_GVA_VALIDATE_WRITE;

        let (gpa, result_code) = self
            .vcpu
            .translate_gva(gva, flags.into())
            .map_err(|e| PlatformError::TranslateVirtualAddress(anyhow!(e)))?;

        match result_code {
            hv_translate_gva_result_code_HV_TRANSLATE_GVA_SUCCESS => Ok(gpa),
            _ => Err(PlatformError::TranslateVirtualAddress(anyhow!(result_code))),
        }
    }
}

/// Platform emulation for Hyper-V
impl<'a> PlatformEmulator for MshvEmulatorContext<'a> {
    type CpuState = EmulatorCpuState;

    fn read_memory(&self, gva: u64, data: &mut [u8]) -> Result<(), PlatformError> {
        let gpa = self.translate(gva)?;
        debug!(
            "mshv emulator: memory read {} bytes from [{:#x} -> {:#x}]",
            data.len(),
            gva,
            gpa
        );

        if let Some(vm_ops) = &self.vcpu.vm_ops {
            if vm_ops.guest_mem_read(gpa, data).is_err() {
                vm_ops
                    .mmio_read(gpa, data)
                    .map_err(|e| PlatformError::MemoryReadFailure(e.into()))?;
            }
        }

        Ok(())
    }

    fn write_memory(&mut self, gva: u64, data: &[u8]) -> Result<(), PlatformError> {
        let gpa = self.translate(gva)?;
        debug!(
            "mshv emulator: memory write {} bytes at [{:#x} -> {:#x}]",
            data.len(),
            gva,
            gpa
        );

        if let Some(vm_ops) = &self.vcpu.vm_ops {
            if vm_ops.guest_mem_write(gpa, data).is_err() {
                vm_ops
                    .mmio_write(gpa, data)
                    .map_err(|e| PlatformError::MemoryWriteFailure(e.into()))?;
            }
        }

        Ok(())
    }

    fn cpu_state(&self, cpu_id: usize) -> Result<Self::CpuState, PlatformError> {
        if cpu_id != self.vcpu.vp_index as usize {
            return Err(PlatformError::GetCpuStateFailure(anyhow!(
                "CPU id mismatch {:?} {:?}",
                cpu_id,
                self.vcpu.vp_index
            )));
        }

        let regs = self
            .vcpu
            .get_regs()
            .map_err(|e| PlatformError::GetCpuStateFailure(e.into()))?;
        let sregs = self
            .vcpu
            .get_sregs()
            .map_err(|e| PlatformError::GetCpuStateFailure(e.into()))?;

        debug!("mshv emulator: Getting new CPU state");
        debug!("mshv emulator: {:#x?}", regs);

        Ok(EmulatorCpuState { regs, sregs })
    }

    fn set_cpu_state(&self, cpu_id: usize, state: Self::CpuState) -> Result<(), PlatformError> {
        if cpu_id != self.vcpu.vp_index as usize {
            return Err(PlatformError::SetCpuStateFailure(anyhow!(
                "CPU id mismatch {:?} {:?}",
                cpu_id,
                self.vcpu.vp_index
            )));
        }

        debug!("mshv emulator: Setting new CPU state");
        debug!("mshv emulator: {:#x?}", state.regs);

        self.vcpu
            .set_regs(&state.regs)
            .map_err(|e| PlatformError::SetCpuStateFailure(e.into()))?;
        self.vcpu
            .set_sregs(&state.sregs)
            .map_err(|e| PlatformError::SetCpuStateFailure(e.into()))
    }

    fn gva_to_gpa(&self, gva: u64) -> Result<u64, PlatformError> {
        self.translate(gva)
    }

    fn fetch(&self, _ip: u64, _instruction_bytes: &mut [u8]) -> Result<(), PlatformError> {
        Err(PlatformError::MemoryReadFailure(anyhow!("unimplemented")))
    }
}

/// Wrapper over Mshv VM ioctls.
pub struct MshvVm {
    fd: Arc<VmFd>,
    msrs: Vec<MsrEntry>,
    dirty_log_slots: Arc<RwLock<HashMap<u64, MshvDirtyLogSlot>>>,
}

impl MshvVm {
    ///
    /// Creates an in-kernel device.
    ///
    /// See the documentation for `MSHV_CREATE_DEVICE`.
    fn create_device(&self, device: &mut CreateDevice) -> vm::Result<VfioDeviceFd> {
        let device_fd = self
            .fd
            .create_device(device)
            .map_err(|e| vm::HypervisorVmError::CreateDevice(e.into()))?;
        Ok(VfioDeviceFd::new_from_mshv(device_fd))
    }
}

///
/// Implementation of Vm trait for Mshv
///
/// # Examples
///
/// ```
/// # extern crate hypervisor;
/// # use hypervisor::mshv::MshvHypervisor;
/// # use std::sync::Arc;
/// let mshv = MshvHypervisor::new().unwrap();
/// let hypervisor = Arc::new(mshv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// ```
impl vm::Vm for MshvVm {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the address of the one-page region in the VM's address space.
    ///
    fn set_identity_map_address(&self, _address: u64) -> vm::Result<()> {
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the address of the three-page region in the VM's address space.
    ///
    fn set_tss_address(&self, _offset: usize) -> vm::Result<()> {
        Ok(())
    }
    ///
    /// Creates an in-kernel interrupt controller.
    ///
    fn create_irq_chip(&self) -> vm::Result<()> {
        Ok(())
    }
    ///
    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        debug!("register_irqfd fd {} gsi {}", fd.as_raw_fd(), gsi);

        self.fd
            .register_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::RegisterIrqFd(e.into()))?;

        Ok(())
    }
    ///
    /// Unregisters an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        debug!("unregister_irqfd fd {} gsi {}", fd.as_raw_fd(), gsi);

        self.fd
            .unregister_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::UnregisterIrqFd(e.into()))?;

        Ok(())
    }
    ///
    /// Creates a VcpuFd object from a vcpu RawFd.
    ///
    fn create_vcpu(
        &self,
        id: u8,
        vm_ops: Option<Arc<dyn VmOps>>,
    ) -> vm::Result<Arc<dyn cpu::Vcpu>> {
        let vcpu_fd = self
            .fd
            .create_vcpu(id)
            .map_err(|e| vm::HypervisorVmError::CreateVcpu(e.into()))?;
        let vcpu = MshvVcpu {
            fd: vcpu_fd,
            vp_index: id,
            cpuid: Vec::new(),
            msrs: self.msrs.clone(),
            vm_ops,
            vm_fd: self.fd.clone(),
        };
        Ok(Arc::new(vcpu))
    }
    #[cfg(target_arch = "x86_64")]
    fn enable_split_irq(&self) -> vm::Result<()> {
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    fn enable_sgx_attribute(&self, _file: File) -> vm::Result<()> {
        Ok(())
    }
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<DataMatch>,
    ) -> vm::Result<()> {
        #[cfg(not(feature = "snp"))]
        {
            let addr = &mshv_ioctls::IoEventAddress::from(*addr);
            debug!(
                "register_ioevent fd {} addr {:x?} datamatch {:?}",
                fd.as_raw_fd(),
                addr,
                datamatch
            );
            if let Some(dm) = datamatch {
                match dm {
                    vm::DataMatch::DataMatch32(mshv_dm32) => self
                        .fd
                        .register_ioevent(fd, addr, mshv_dm32)
                        .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into())),
                    vm::DataMatch::DataMatch64(mshv_dm64) => self
                        .fd
                        .register_ioevent(fd, addr, mshv_dm64)
                        .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into())),
                }
            } else {
                self.fd
                    .register_ioevent(fd, addr, NoDatamatch)
                    .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into()))
            }
        }
        #[cfg(feature = "snp")]
        Ok(())
    }
    /// Unregister an event from a certain address it has been previously registered to.
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> vm::Result<()> {
        #[cfg(not(feature = "snp"))]
        {
            let addr = &mshv_ioctls::IoEventAddress::from(*addr);
            debug!("unregister_ioevent fd {} addr {:x?}", fd.as_raw_fd(), addr);

            self.fd
                .unregister_ioevent(fd, addr, NoDatamatch)
                .map_err(|e| vm::HypervisorVmError::UnregisterIoEvent(e.into()))
        }
        #[cfg(feature = "snp")]
        Ok(())
    }

    /// Creates a guest physical memory region.
    fn create_user_memory_region(&self, user_memory_region: UserMemoryRegion) -> vm::Result<()> {
        let user_memory_region: mshv_user_mem_region = user_memory_region.into();
        // No matter read only or not we keep track the slots.
        // For readonly hypervisor can enable the dirty bits,
        // but a VM exit happens before setting the dirty bits
        self.dirty_log_slots.write().unwrap().insert(
            user_memory_region.guest_pfn,
            MshvDirtyLogSlot {
                guest_pfn: user_memory_region.guest_pfn,
                memory_size: user_memory_region.size,
            },
        );

        self.fd
            .map_user_memory(user_memory_region)
            .map_err(|e| vm::HypervisorVmError::CreateUserMemory(e.into()))?;
        Ok(())
    }

    /// Removes a guest physical memory region.
    fn remove_user_memory_region(&self, user_memory_region: UserMemoryRegion) -> vm::Result<()> {
        let user_memory_region: mshv_user_mem_region = user_memory_region.into();
        // Remove the corresponding entry from "self.dirty_log_slots" if needed
        self.dirty_log_slots
            .write()
            .unwrap()
            .remove(&user_memory_region.guest_pfn);

        self.fd
            .unmap_user_memory(user_memory_region)
            .map_err(|e| vm::HypervisorVmError::RemoveUserMemory(e.into()))?;
        Ok(())
    }

    fn make_user_memory_region(
        &self,
        _slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        readonly: bool,
        _log_dirty_pages: bool,
    ) -> UserMemoryRegion {
        let mut flags = HV_MAP_GPA_READABLE | HV_MAP_GPA_EXECUTABLE | HV_MAP_GPA_ADJUSTABLE;
        if !readonly {
            flags |= HV_MAP_GPA_WRITABLE;
            //flags |= HV_MAP_GPA_ADJUSTABLE;
        }

        mshv_user_mem_region {
            flags,
            guest_pfn: guest_phys_addr >> PAGE_SHIFT,
            size: memory_size,
            userspace_addr,
        }
        .into()
    }

    fn create_passthrough_device(&self) -> vm::Result<VfioDeviceFd> {
        let mut vfio_dev = mshv_create_device {
            type_: mshv_device_type_MSHV_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };

        self.create_device(&mut vfio_dev)
            .map_err(|e| vm::HypervisorVmError::CreatePassthroughDevice(e.into()))
    }

    ///
    /// Constructs a routing entry
    ///
    fn make_routing_entry(&self, gsi: u32, config: &InterruptSourceConfig) -> IrqRoutingEntry {
        match config {
            InterruptSourceConfig::MsiIrq(cfg) => mshv_msi_routing_entry {
                gsi,
                address_lo: cfg.low_addr,
                address_hi: cfg.high_addr,
                data: cfg.data,
            }
            .into(),
            _ => {
                unreachable!()
            }
        }
    }

    fn set_gsi_routing(&self, entries: &[IrqRoutingEntry]) -> vm::Result<()> {
        let mut msi_routing =
            vec_with_array_field::<mshv_msi_routing, mshv_msi_routing_entry>(entries.len());
        msi_routing[0].nr = entries.len() as u32;

        let entries: Vec<mshv_msi_routing_entry> = entries
            .iter()
            .map(|entry| match entry {
                IrqRoutingEntry::Mshv(e) => *e,
                #[allow(unreachable_patterns)]
                _ => panic!("IrqRoutingEntry type is wrong"),
            })
            .collect();

        // SAFETY: msi_routing initialized with entries.len() and now it is being turned into
        // entries_slice with entries.len() again. It is guaranteed to be large enough to hold
        // everything from entries.
        unsafe {
            let entries_slice: &mut [mshv_msi_routing_entry] =
                msi_routing[0].entries.as_mut_slice(entries.len());
            entries_slice.copy_from_slice(&entries);
        }

        self.fd
            .set_msi_routing(&msi_routing[0])
            .map_err(|e| vm::HypervisorVmError::SetGsiRouting(e.into()))
    }
    ///
    /// Start logging dirty pages
    ///
    fn start_dirty_log(&self) -> vm::Result<()> {
        self.fd
            .enable_dirty_page_tracking()
            .map_err(|e| vm::HypervisorVmError::StartDirtyLog(e.into()))
    }
    ///
    /// Stop logging dirty pages
    ///
    fn stop_dirty_log(&self) -> vm::Result<()> {
        let dirty_log_slots = self.dirty_log_slots.read().unwrap();
        // Before disabling the dirty page tracking we need
        // to set the dirty bits in the Hypervisor
        // This is a requirement from Microsoft Hypervisor
        for (_, s) in dirty_log_slots.iter() {
            self.fd
                .get_dirty_log(s.guest_pfn, s.memory_size as usize, DIRTY_BITMAP_SET_DIRTY)
                .map_err(|e| vm::HypervisorVmError::StartDirtyLog(e.into()))?;
        }
        self.fd
            .disable_dirty_page_tracking()
            .map_err(|e| vm::HypervisorVmError::StartDirtyLog(e.into()))?;
        Ok(())
    }
    ///
    /// Get dirty pages bitmap (one bit per page)
    ///
    fn get_dirty_log(&self, _slot: u32, base_gpa: u64, memory_size: u64) -> vm::Result<Vec<u64>> {
        self.fd
            .get_dirty_log(
                base_gpa >> PAGE_SHIFT,
                memory_size as usize,
                DIRTY_BITMAP_CLEAR_DIRTY,
            )
            .map_err(|e| vm::HypervisorVmError::GetDirtyLog(e.into()))
    }
    /// Retrieve guest clock.
    #[cfg(target_arch = "x86_64")]
    fn get_clock(&self) -> vm::Result<ClockData> {
        Ok(ClockData::Mshv)
    }
    /// Set guest clock.
    #[cfg(target_arch = "x86_64")]
    fn set_clock(&self, _data: &ClockData) -> vm::Result<()> {
        Ok(())
    }
    /// Downcast to the underlying MshvVm type
    fn as_any(&self) -> &dyn Any {
        self
    }
    #[cfg(feature = "snp")]
    /// Initialize the SEV-SNP
    fn snp_init(&self) -> vm::Result<()> {
        self.fd
            .set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_ISOLATION_STATE,
                hv_partition_isolation_state_HV_PARTITION_ISOLATION_SECURE as u64,
            )
            .map_err(|e| vm::HypervisorVmError::SnpInit(e.into()))
    }
    #[cfg(feature = "snp")]
    fn import_isolated_pages(
        &self,
        page_type: u32,
        page_size: u32,
        pages: &[u64],
    ) -> vm::Result<()> {
        if pages.len() == 0 {
            return Ok(());
        }
        let mut isolated_pages =
            vec_with_array_field::<mshv_import_isolated_pages, u64>(pages.len());
        isolated_pages[0].num_pages = pages.len() as u64;
        isolated_pages[0].page_type = page_type;
        isolated_pages[0].page_size = page_size;
        // SAFETY: isolated_pages initialized with pages.len() and now it is being turned into
        // pages_slice with pages.len() again. It is guaranteed to be large enough to hold
        // everything from pages.
        unsafe {
            let pages_slice: &mut [u64] = isolated_pages[0].page_number.as_mut_slice(pages.len());
            pages_slice.copy_from_slice(&pages);
        }
        self.fd
            .import_isolated_pages(&isolated_pages[0])
            .map_err(|e| vm::HypervisorVmError::ImportIsolatedPages(e.into()))
    }

    #[cfg(feature = "snp")]
    fn modify_gpa_host_access(
        &self,
        host_access: u32,
        flags: u32,
        acquire: u8,
        gpas: &[u64],
    ) -> vm::Result<()> {
        _modify_gpa_host_access(self.fd.clone(), host_access, flags, acquire, gpas)
    }

    #[cfg(feature = "snp")]
    fn complete_isolated_import(&self, snp_id_block: IgvmVhsSnpIdBlock, host_data: &[u8]) -> vm::Result<()> {
        let data = mshv_complete_isolated_import {
            import_data: hv_partition_complete_isolated_import_data {
                psp_parameters: hv_psp_launch_finish_data {
                    id_block: hv_snp_id_block {
                        ..Default::default()
                    },
                    id_auth_info: hv_snp_id_auth_info {
                        ..Default::default()
                    },
                    host_data: host_data[0..32].try_into().unwrap(),
                    id_block_enabled: false,
                    author_key_enabled: false,
                },
            },
        };
        self.fd
            .complete_isolated_import(&data)
            .map_err(|e| vm::HypervisorVmError::CompleteIsolatedImport(e.into()))
    }
}

#[cfg(feature = "snp")]
fn _modify_gpa_host_access(
    fd: Arc<VmFd>,
    host_access: u32,
    flags: u32,
    acquire: u8,
    gpas: &[u64],
) -> vm::Result<()> {
    let mut gpa_list = vec_with_array_field::<mshv_modify_gpa_host_access, u64>(gpas.len());
    gpa_list[0].gpa_list_size = gpas.len() as u64;
    gpa_list[0].host_access = host_access;
    gpa_list[0].acquire = acquire;
    gpa_list[0].flags = flags;
    // SAFETY: gpa_list initialized with gpas.len() and now it is being turned into
    // gpas_slice with gpas.len() again. It is guaranteed to be large enough to hold
    // everything from gpas.
    unsafe {
        let gpas_slice: &mut [u64] = gpa_list[0].gpa_list.as_mut_slice(gpas.len());
        gpas_slice.copy_from_slice(&gpas);
    }
    fd.modify_gpa_host_access(&gpa_list[0])
        .map_err(|e| vm::HypervisorVmError::ModifyGpaHostAccess(e.into()))
}

#[cfg(feature="snp")]
fn _psp_issue_guest_request(fd: Arc<VmFd>, req_gpa: u64, rsp_gpa: u64) -> vm::Result<()> {
    let req = mshv_issue_psp_guest_request {
        req_gpa,
        rsp_gpa,
    };

    fd.psp_issue_guest_request(&req).map_err(|e| vm::HypervisorVmError::PspIssueGuestRequest(e.into()))
}

#[cfg(feature="snp")]
fn _snp_start_vcpu(fd: Arc<VmFd>, apic_id: u64, vmsa_gpa: u64) -> vm::Result<()> {
    let req = mshv_snp_ap_create {
        apic_id,
        vmsa_gpa,
    };

    fd.snp_ap_create(&req).map_err(|e| vm::HypervisorVmError::PspIssueGuestRequest(e.into()))
}