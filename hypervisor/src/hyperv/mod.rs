// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use crate::cpu;
use crate::hypervisor;
use crate::vm;
pub use hyperv_bindings::*;
use hyperv_ioctls::{Hyperv, VcpuFd, VmFd};
use std::sync::Arc;
use vm::DataMatch;
// x86_64 dependencies
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

use std::convert::TryInto;

#[cfg(target_arch = "x86_64")]
use x86_64::emulator;

use vmm_sys_util::eventfd::EventFd;
#[cfg(target_arch = "x86_64")]
pub use x86_64::VcpuHypervState as CpuState;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

use crate::device;

// Wei: for emulating irqfd and ioeventfd
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Mutex, RwLock};
use std::thread;

pub const PAGE_SHIFT: usize = 12;

struct IrqfdCtrlEpollHandler {
    vm: Arc<dyn vm::Vm>, /* For issuing hypercall */
    irqfd: EventFd,      /* Registered by caller */
    kill: EventFd,       /* Created by us, signal thread exit */
    epoll_fd: RawFd,     /* epoll fd */
    gsi: u32,
    gsi_routes: Arc<RwLock<HashMap<u32, HypervIrqRoutingEntry>>>,
}

fn register_listener(
    epoll_fd: RawFd,
    fd: RawFd,
    ev_type: epoll::Events,
    data: u64,
) -> std::result::Result<(), io::Error> {
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        fd,
        epoll::Event::new(ev_type, data),
    )
}

const KILL_EVENT: u16 = 1;
const IRQFD_EVENT: u16 = 2;

impl IrqfdCtrlEpollHandler {
    fn run_ctrl(&mut self) {
        self.epoll_fd = epoll::create(true).unwrap();
        let epoll_file = unsafe { File::from_raw_fd(self.epoll_fd) };

        register_listener(
            epoll_file.as_raw_fd(),
            self.kill.as_raw_fd(),
            epoll::Events::EPOLLIN,
            u64::from(KILL_EVENT),
        )
        .unwrap();

        register_listener(
            epoll_file.as_raw_fd(),
            self.irqfd.as_raw_fd(),
            epoll::Events::EPOLLIN,
            u64::from(IRQFD_EVENT),
        )
        .unwrap();

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); 2];

        'epoll: loop {
            let num_events = match epoll::wait(epoll_file.as_raw_fd(), -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    panic!("irqfd epoll ???");
                }
            };

            for event in events.iter().take(num_events) {
                let ev_type = event.data as u16;

                match ev_type {
                    KILL_EVENT => {
                        break 'epoll;
                    }
                    IRQFD_EVENT => {
                        debug!("IRQFD_EVENT received, inject to guest");
                        let _ = self.irqfd.read().unwrap();
                        let gsi_routes = self.gsi_routes.read().unwrap();

                        if let Some(e) = gsi_routes.get(&self.gsi) {
                            assert_virtual_interrupt(&self.vm, &e);
                        } else {
                            debug!("No routing info found for GSI {}", self.gsi);
                        }
                    }
                    _ => {
                        error!("Unknown event");
                    }
                }
            }
        }
    }
}

// Translate from architectural defined delivery mode to Hyper-V type
// See Intel SDM vol3 10.11.2
fn get_interrupt_type(delivery_mode: u8) -> Option<HV_INTERRUPT_TYPE> {
    match delivery_mode {
        0 => Some(HV_INTERRUPT_TYPE_HvX64InterruptTypeFixed),
        1 => Some(HV_INTERRUPT_TYPE_HvX64InterruptTypeLowestPriority),
        2 => Some(HV_INTERRUPT_TYPE_HvX64InterruptTypeSmi),
        4 => Some(HV_INTERRUPT_TYPE_HvX64InterruptTypeNmi),
        5 => Some(HV_INTERRUPT_TYPE_HvX64InterruptTypeInit),
        7 => Some(HV_INTERRUPT_TYPE_HvX64InterruptTypeExtInt),
        _ => None,
    }
}

// See Intel SDM vol3 10.11.1
// We assume APIC ID and Hyper-V Vcpu ID are the same value
// This holds true for HvLite
fn get_destination(message_address: u32) -> u64 {
    ((message_address >> 12) & 0xff).into()
}

fn get_destination_mode(message_address: u32) -> bool {
    if (message_address >> 2) & 0x1 == 0x1 {
        return true;
    }

    false
}

fn get_redirection_hint(message_address: u32) -> bool {
    if (message_address >> 3) & 0x1 == 0x1 {
        return true;
    }

    false
}

fn get_vector(message_data: u32) -> u8 {
    (message_data & 0xff) as u8
}

// True means level triggered
fn get_trigger_mode(message_data: u32) -> bool {
    if (message_data >> 15) & 0x1 == 0x1 {
        return true;
    }

    false
}

fn get_delivery_mode(message_data: u32) -> u8 {
    ((message_data & 0x700) >> 8) as u8
}

// Only meaningful with level triggered interrupts
// True => High active
// False => Low active
fn get_level(message_data: u32) -> bool {
    if (message_data >> 14) & 0x1 == 0x1 {
        return true;
    }

    false
}

fn assert_virtual_interrupt(vm: &Arc<dyn vm::Vm>, e: &HypervIrqRoutingEntry) {
    // GSI routing contains MSI information.
    // We still need to translate that to APIC ID etc

    debug!("Inject {:x?}", e);

    let HypervIrqRouting::Msi(msi) = e.route;

    /* Make an assumption here ... */
    if msi.address_hi != 0 {
        panic!("MSI high address part is not zero");
    }

    let typ = get_interrupt_type(get_delivery_mode(msi.data)).unwrap();
    let apic_id = get_destination(msi.address_lo);
    let vector = get_vector(msi.data);
    let level_triggered = get_trigger_mode(msi.data);
    let logical_destination_mode = get_destination_mode(msi.address_lo);

    debug!(
        "{:x} {:x} {:x} {} {}",
        typ, apic_id, vector, level_triggered, logical_destination_mode
    );

    vm.request_virtual_interrupt(
        typ as u8,
        apic_id,
        vector.into(),
        level_triggered,
        logical_destination_mode,
        false,
    )
    .unwrap();
}

/// Wrapper over Hyperv system ioctls.
pub struct HypervHypervisor {
    hyperv: Hyperv,
}

impl HypervHypervisor {
    /// Create a hypervisor based on Hyperv
    pub fn new() -> hypervisor::Result<HypervHypervisor> {
        let hyperv_obj =
            Hyperv::new().map_err(|e| hypervisor::HypervisorError::HypervisorCreate(e.into()))?;
        Ok(HypervHypervisor { hyperv: hyperv_obj })
    }
}
/// Implementation of Hypervisor trait for Hyperv
/// Example:
/// #[cfg(feature = "hyperv")]
/// extern crate hypervisor
/// let hyperv = hypervisor::hyperv::HypervHypervisor::new().unwrap();
/// let hypervisor: Arc<dyn hypervisor::Hypervisor> = Arc::new(hyperv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
///
impl hypervisor::Hypervisor for HypervHypervisor {
    /// Create a hyperv vm object and return the object as Vm trait object
    /// Example
    /// # extern crate hypervisor;
    /// # use hypervisor::HypervHypervisor;
    /// use hypervisor::HypervVm;
    /// let hypervisor = HypervHypervisor::new().unwrap();
    /// let vm = hypervisor.create_vm().unwrap()
    ///
    fn create_vm(&self) -> hypervisor::Result<Arc<dyn vm::Vm>> {
        let fd: VmFd;
        loop {
            match self.hyperv.create_vm() {
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

        let msr_list = self.get_msr_list()?;
        let num_msrs = msr_list.as_fam_struct_ref().nmsrs as usize;
        let mut msrs = MsrEntries::new(num_msrs);
        let indices = msr_list.as_slice();
        let msr_entries = msrs.as_mut_slice();
        for (pos, index) in indices.iter().enumerate() {
            msr_entries[pos].index = *index;
        }
        let vm_fd = Arc::new(fd);

        let irqfds = Mutex::new(HashMap::new());
        let ioeventfds = Arc::new(RwLock::new(HashMap::new()));
        let gsi_routes = Arc::new(RwLock::new(HashMap::new()));

        Ok(Arc::new(HypervVm {
            fd: vm_fd,
            msrs,
            irqfds,
            ioeventfds,
            gsi_routes,
        }))
    }
    ///
    /// Get the supported CpuID
    ///
    fn get_cpuid(&self) -> hypervisor::Result<CpuId> {
        Ok(CpuId::new(1 as usize))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Retrieve the list of MSRs supported by KVM.
    ///
    fn get_msr_list(&self) -> hypervisor::Result<MsrList> {
        self.hyperv
            .get_msr_index_list()
            .map_err(|e| hypervisor::HypervisorError::GetMsrList(e.into()))
    }
}
/// Vcpu struct for Hyper-V
pub struct HypervVcpu {
    fd: VcpuFd,
    cpuid: CpuId,
    msrs: MsrEntries,
    ioeventfds: Arc<RwLock<HashMap<IoEventAddress, (Option<DataMatch>, EventFd)>>>,
    gsi_routes: Arc<RwLock<HashMap<u32, HypervIrqRoutingEntry>>>,
}
/// Implementation of Vcpu trait for Microsoft Hyper-V
/// Example:
/// #[cfg(feature = "hyperv")]
/// extern crate hypervisor
/// let hyperv = hypervisor::hyperv::HypervHypervisor::new().unwrap();
/// let hypervisor: Arc<dyn hypervisor::Hypervisor> = Arc::new(hyperv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// let vcpu = vm.create_vcpu(0).unwrap();
/// vcpu.get/set().unwrap()
///
impl cpu::Vcpu for HypervVcpu {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU general purpose registers.
    ///
    fn get_regs(&self) -> cpu::Result<StandardRegisters> {
        self.fd
            .get_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetStandardRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU general purpose registers.
    ///
    fn set_regs(&self, regs: &StandardRegisters) -> cpu::Result<()> {
        self.fd
            .set_regs(regs)
            .map_err(|e| cpu::HypervisorCpuError::SetStandardRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU special registers.
    ///
    fn get_sregs(&self) -> cpu::Result<SpecialRegisters> {
        self.fd
            .get_sregs()
            .map_err(|e| cpu::HypervisorCpuError::GetSpecialRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU special registers.
    ///
    fn set_sregs(&self, sregs: &SpecialRegisters) -> cpu::Result<()> {
        self.fd
            .set_sregs(sregs)
            .map_err(|e| cpu::HypervisorCpuError::SetSpecialRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the floating point state (FPU) from the vCPU.
    ///
    fn get_fpu(&self) -> cpu::Result<FpuState> {
        self.fd
            .get_fpu()
            .map_err(|e| cpu::HypervisorCpuError::GetFloatingPointRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Set the floating point state (FPU) of a vCPU.
    ///
    fn set_fpu(&self, fpu: &FpuState) -> cpu::Result<()> {
        self.fd
            .set_fpu(fpu)
            .map_err(|e| cpu::HypervisorCpuError::SetFloatingPointRegs(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    fn get_msrs(&self, msrs: &mut MsrEntries) -> cpu::Result<usize> {
        self.fd
            .get_msrs(msrs)
            .map_err(|e| cpu::HypervisorCpuError::GetMsrEntries(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    ///
    fn set_msrs(&self, msrs: &MsrEntries) -> cpu::Result<usize> {
        self.fd
            .set_msrs(msrs)
            .map_err(|e| cpu::HypervisorCpuError::SetMsrEntries(e.into()))
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
            .set_xcrs(&xcrs)
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
    fn run(
        &self,
        vr: &dyn cpu::VcpuRun,
    ) -> std::result::Result<cpu::VmExit, cpu::HypervisorCpuError> {
        // Safe because this is just only done during initialization.
        // TODO don't zero it everytime we enter this function.
        let hv_message: hv_message = unsafe { std::mem::zeroed() };
        match self.fd.run(hv_message) {
            Ok(x) => match x.header.message_type {
                hv_message_type_HVMSG_X64_HALT => {
                    debug!("HALT");
                    Ok(cpu::VmExit::Reset)
                }
                hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT => {
                    let info = x.to_ioport_info();
                    let access_info = info.access_info;
                    if unsafe { access_info.__bindgen_anon_1.string_op() } == 1 {
                        panic!("String IN/OUT not supported");
                    }
                    if unsafe { access_info.__bindgen_anon_1.rep_prefix() } == 1 {
                        panic!("Rep IN/OUT not supported");
                    }
                    let len = unsafe { access_info.__bindgen_anon_1.access_size() } as usize;
                    let is_write = info.header.intercept_access_type == 1;
                    let port = info.port_number;
                    let mut data: [u8; 4] = [0; 4];
                    let mut ret_rax = info.rax;
                    // debug!(
                    //     "port {:x?} insn byte count {:?} len {:?} write {:?}",
                    //     port, info.instruction_byte_count, len, is_write
                    // );

                    if is_write {
                        // debug!("data {:x?}", info.rax);
                        data[0] = info.rax as u8;
                        data[1] = (info.rax >> 8) as u8;
                        data[2] = (info.rax >> 16) as u8;
                        data[3] = (info.rax >> 24) as u8;
                        vr.pio_out(port.into(), &data[0..len]);
                    } else {
                        vr.pio_in(port.into(), &mut data[0..len]);
                        // debug!("data {:x?}", &data[0..len]);
                        let v = data[0] as u32
                            | (data[1] as u32) << 8
                            | (data[2] as u32) << 16
                            | (data[3] as u32) << 24;
                        /* Preserve high bits in EAX but clear out high bits in RAX */
                        let mask = 0xffffffff >> (32 - len * 8);
                        let eax = (info.rax as u32 & !mask) | (v & mask);
                        ret_rax = eax as u64;
                    }

                    let insn_len = info.header.instruction_length() as u64;

                    // debug!("RIP {:x?} len {}", info.header.rip, insn_len);
                    /* Advance RIP and update RAX */
                    let mut reg_vals: [hv_register_value; 2] = [
                        hv_register_value {
                            reg64: info.header.rip + insn_len,
                        },
                        hv_register_value { reg64: ret_rax },
                    ];
                    let mut reg_names: [hv_register_name; 2] = [
                        hv_register_name_hv_x64_register_rip,
                        hv_register_name_hv_x64_register_rax,
                    ];
                    let reg_arg = hv_vp_registers {
                        count: 2,
                        values: reg_vals.as_mut_ptr(),
                        names: reg_names.as_mut_ptr(),
                    };
                    self.fd.set_reg(reg_arg).unwrap();

                    Ok(cpu::VmExit::Ignore)
                }
                hv_message_type_HVMSG_UNMAPPED_GPA => {
                    let info = x.to_memory_info();
                    let insn_len = info.instruction_byte_count as usize;
                    assert!(insn_len > 0 && insn_len <= 16);
                    // debug!(
                    //     "RIP {:x?} gva {:x?} gpa {:x?} insn bytes {:x?} cnt {}",
                    //     info.header.rip,
                    //     info.guest_virtual_address,
                    //     info.guest_physical_address,
                    //     info.instruction_bytes,
                    //     insn_len,
                    // );

                    let mut emul = emulator::Emulator::new();
                    let mut emulator_input = emulator::Input::Start;

                    loop {
                        match emul.run(&emulator_input).unwrap() {
                            emulator::Output::GetInstructionStream => {
                                emulator_input = emulator::Input::Instructions(
                                    &info.instruction_bytes[0..insn_len],
                                );
                            }
                            emulator::Output::ReadRegister64(name) => {
                                let reg_name = emu_reg64_to_hv_reg64(name);
                                let mut reg_name: [hv_register_name; 1] = [reg_name];
                                let mut reg_val: [hv_register_value; 1] =
                                    [hv_register_value { reg64: 0 }];
                                let regs_arg = hv_vp_registers {
                                    count: 1,
                                    names: reg_name.as_mut_ptr(),
                                    values: reg_val.as_mut_ptr(),
                                };
                                self.fd.get_reg(regs_arg).unwrap();
                                let value = unsafe { reg_val[0].reg64 };
                                // debug!("emulator read {:?} {:x?}", name, value);
                                emulator_input = emulator::Input::Register64(name, value);
                            }
                            emulator::Output::WriteRegister64(name, value) => {
                                let reg_name = emu_reg64_to_hv_reg64(name);
                                let mut reg_name: [hv_register_name; 1] = [reg_name];
                                let mut reg_val: [hv_register_value; 1] =
                                    [hv_register_value { reg64: value }];
                                let regs_arg = hv_vp_registers {
                                    count: 1,
                                    names: reg_name.as_mut_ptr(),
                                    values: reg_val.as_mut_ptr(),
                                };
                                // debug!("emulator write {:?} {:x?}", name, value);
                                self.fd.set_reg(regs_arg).unwrap();
                                emulator_input = emulator::Input::Continue;
                            }
                            emulator::Output::ReadMemory(size) => {
                                assert!(size <= 4);
                                let mut data: [u8; 4] = [0; 4];
                                vr.mmio_read(
                                    info.guest_physical_address,
                                    &mut data[0..size as usize],
                                );
                                let reg_value = u32::from_ne_bytes(data.try_into().unwrap());
                                // debug!(
                                //     "emulator read mem {:x?} {:x?}",
                                //     info.guest_physical_address, reg_value
                                // );
                                emulator_input = emulator::Input::Memory(emulator::Value {
                                    length: 4,
                                    value: reg_value as u128,
                                });
                            }
                            emulator::Output::WriteMemory(value) => {
                                let reg_value = value.value.to_le_bytes();
                                // debug!(
                                //     "emulator write mem {:x?} {:x?}",
                                //     info.guest_physical_address, reg_value
                                // );

                                let addr = IoEventAddress::Mmio(info.guest_physical_address);

                                if let Some((datamatch, efd)) =
                                    self.ioeventfds.read().unwrap().get(&addr)
                                {
                                    // debug!(
                                    //     "Found {:x?} {:x?} {}",
                                    //     addr,
                                    //     datamatch,
                                    //     efd.as_raw_fd()
                                    // );
                                    /* TODO: use datamatch to provide the correct semantics */
                                    efd.write(1).unwrap();
                                }

                                vr.mmio_write(
                                    info.guest_physical_address,
                                    &reg_value[0..value.length as usize],
                                );

                                emulator_input = emulator::Input::Continue;
                            }
                            emulator::Output::Done => break,
                            x => {
                                panic!("Unhandled emulator output {:?}", x);
                            }
                        }
                    }

                    Ok(cpu::VmExit::Ignore)
                }
                exit => {
                    return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                        "Unhandled VCPU exit {:?}",
                        exit
                    )))
                }
            },

            Err(e) => match e.errno() {
                libc::EAGAIN | libc::EINTR => Ok(cpu::VmExit::Ignore),
                _ => {
                    return Err(cpu::HypervisorCpuError::RunVcpu(anyhow!(
                        "VCPU error {:?}",
                        e
                    )))
                }
            },
        }
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to setup the CPUID registers.
    ///
    fn set_cpuid2(&self, cpuid: &CpuId) -> cpu::Result<()> {
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to retrieve the CPUID registers.
    ///
    fn get_cpuid2(&self, num_entries: usize) -> cpu::Result<CpuId> {
        Ok(self.cpuid.clone())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn get_lapic(&self) -> cpu::Result<LapicState> {
        self.fd
            .get_lapic()
            .map_err(|e| cpu::HypervisorCpuError::GetlapicState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn set_lapic(&self, lapic: &LapicState) -> cpu::Result<()> {
        self.fd
            .set_lapic(lapic)
            .map_err(|e| cpu::HypervisorCpuError::SetLapicState(e.into()))
    }
    fn set_state(&self, state: &CpuState) -> cpu::Result<()> {
        self.set_msrs(&state.msrs)?;
        self.set_vcpu_events(&state.vcpu_events)?;
        self.set_regs(&state.regs)?;
        self.set_sregs(&state.sregs)?;
        self.set_fpu(&state.fpu)?;
        self.set_xcrs(&state.xcrs)?;
        self.set_lapic(&state.lapic)?;
        self.fd
            .set_dregs(&state.dbg)
            .map_err(|e| cpu::HypervisorCpuError::SetDebugRegs(e.into()));
        Ok(())
    }
    fn state(&self) -> cpu::Result<CpuState> {
        let regs = self.get_regs()?;
        let sregs = self.get_sregs()?;
        let xcrs = self.get_xcrs()?;
        let fpu = self.get_fpu()?;
        let vcpu_events = self.get_vcpu_events()?;
        let mut msrs = self.msrs.clone();
        self.get_msrs(&mut msrs)?;
        let lapic = self.get_lapic()?;
        let dbg = self
            .fd
            .get_dregs()
            .map_err(|e| cpu::HypervisorCpuError::GetDebugRegs(e.into()))?;
        Ok(CpuState {
            msrs,
            vcpu_events,
            regs,
            sregs,
            fpu,
            xcrs,
            lapic,
            dbg,
        })
    }
}

fn emu_reg64_to_hv_reg64(name: emulator::Register64) -> hv_register_name {
    match name {
        emulator::Register64::Rax => hv_register_name_hv_x64_register_rax,
        emulator::Register64::Rcx => hv_register_name_hv_x64_register_rcx,
        emulator::Register64::Rdx => hv_register_name_hv_x64_register_rdx,
        emulator::Register64::Rbx => hv_register_name_hv_x64_register_rbx,
        emulator::Register64::Rsp => hv_register_name_hv_x64_register_rsp,
        emulator::Register64::Rbp => hv_register_name_hv_x64_register_rbp,
        emulator::Register64::Rsi => hv_register_name_hv_x64_register_rsi,
        emulator::Register64::Rdi => hv_register_name_hv_x64_register_rdi,
        emulator::Register64::R8 => hv_register_name_hv_x64_register_r8,
        emulator::Register64::R9 => hv_register_name_hv_x64_register_r9,
        emulator::Register64::R10 => hv_register_name_hv_x64_register_r10,
        emulator::Register64::R11 => hv_register_name_hv_x64_register_r11,
        emulator::Register64::R12 => hv_register_name_hv_x64_register_r12,
        emulator::Register64::R13 => hv_register_name_hv_x64_register_r13,
        emulator::Register64::R14 => hv_register_name_hv_x64_register_r14,
        emulator::Register64::R15 => hv_register_name_hv_x64_register_r15,
        emulator::Register64::Rip => hv_register_name_hv_x64_register_rip,
        emulator::Register64::Cr0 => hv_register_name_hv_x64_register_cr0,
        emulator::Register64::Efer => hv_register_name_hv_x64_register_efer,
    }
}

/// Wrapper over Hyperv VM ioctls.
pub struct HypervVm {
    fd: Arc<VmFd>,
    msrs: MsrEntries,
    // Emulate irqfd
    irqfds: Mutex<HashMap<u32, (EventFd, EventFd)>>,
    // Emulate ioeventfd
    ioeventfds: Arc<RwLock<HashMap<IoEventAddress, (Option<DataMatch>, EventFd)>>>,
    // GSI routing information
    gsi_routes: Arc<RwLock<HashMap<u32, HypervIrqRoutingEntry>>>,
}

///
/// Implementation of Vm trait for Hyperv
/// Example:
/// #[cfg(feature = "hyperv")]
/// # extern crate hypervisor;
/// # use hypervisor::HypervHypervisor;
/// let hypervisor = HypervHypervisor::new().unwrap();
/// let hypervisor: Arc<dyn hypervisor::Hypervisor> = Arc::new(hyperv);
/// let vm = hypervisor.create_vm().expect("new VM fd creation failed");
/// vm.set/get().unwrap()
///
impl vm::Vm for HypervVm {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the address of the three-page region in the VM's address space.
    ///
    fn set_tss_address(&self, offset: usize) -> vm::Result<()> {
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
    fn register_irqfd(&self, fd: &EventFd, gsi: u32, vm: Arc<dyn vm::Vm>) -> vm::Result<()> {
        let dup_fd = fd.try_clone().unwrap();
        let kill_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();

        let mut ctrl_handler = IrqfdCtrlEpollHandler {
            vm,
            kill: kill_fd.try_clone().unwrap(),
            irqfd: fd.try_clone().unwrap(),
            epoll_fd: 0,
            gsi,
            gsi_routes: self.gsi_routes.clone(),
        };

        debug!("register_irqfd fd {} gsi {}", fd.as_raw_fd(), gsi);

        thread::Builder::new()
            .name(format!("irqfd_{}", gsi))
            .spawn(move || ctrl_handler.run_ctrl())
            .unwrap();

        self.irqfds.lock().unwrap().insert(gsi, (dup_fd, kill_fd));

        Ok(())
    }
    ///
    /// Unregisters an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn unregister_irqfd(&self, _fd: &EventFd, gsi: u32) -> vm::Result<()> {
        debug!("unregister_irqfd fd {} gsi {}", _fd.as_raw_fd(), gsi);
        let (_, kill_fd) = self.irqfds.lock().unwrap().remove(&gsi).unwrap();
        kill_fd.write(1).unwrap();
        Ok(())
    }
    ///
    /// Creates a VcpuFd object from a vcpu RawFd.
    ///
    fn create_vcpu(&self, id: u8) -> vm::Result<Arc<dyn cpu::Vcpu>> {
        let vc = self
            .fd
            .create_vcpu(id)
            .map_err(|e| vm::HypervisorVmError::CreateVcpu(e.into()))?;
        let vcpu = HypervVcpu {
            fd: vc,
            cpuid: CpuId::new(1 as usize),
            msrs: self.msrs.clone(),
            ioeventfds: self.ioeventfds.clone(),
            gsi_routes: self.gsi_routes.clone(),
        };
        Ok(Arc::new(vcpu))
    }
    #[cfg(target_arch = "x86_64")]
    fn enable_split_irq(&self) -> vm::Result<()> {
        Ok(())
    }
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<DataMatch>,
    ) -> vm::Result<()> {
        let dup_fd = fd.try_clone().unwrap();

        debug!(
            "register_ioevent fd {} addr {:x?} datamatch {:?}",
            fd.as_raw_fd(),
            addr,
            datamatch
        );

        self.ioeventfds
            .write()
            .unwrap()
            .insert(*addr, (datamatch, dup_fd));
        Ok(())
    }
    /// Unregister an event from a certain address it has been previously registered to.
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> vm::Result<()> {
        debug!("unregister_ioevent fd {} addr {:x?}", fd.as_raw_fd(), addr);
        self.ioeventfds.write().unwrap().remove(addr).unwrap();
        Ok(())
    }

    /// Creates/modifies a guest physical memory slot.
    fn set_user_memory_region(&self, user_memory_region: MemoryRegion) -> vm::Result<()> {
        self.fd
            .map_user_memory(user_memory_region)
            .map_err(|e| vm::HypervisorVmError::SetUserMemory(e.into()))?;
        Ok(())
    }

    fn make_user_memory_region(
        &self,
        _slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        readonly: bool,
    ) -> MemoryRegion {
        let mut flags = HV_MAP_GPA_READABLE | HV_MAP_GPA_EXECUTABLE;
        if !readonly {
            flags |= HV_MAP_GPA_WRITABLE;
        }

        hv_userspace_memory_region {
            flags,
            guest_pfn: guest_phys_addr >> PAGE_SHIFT,
            memory_size,
            userspace_addr: userspace_addr as u64,
        }
    }

    fn create_passthrough_device(&self) -> vm::Result<Arc<dyn device::Device>> {
        Err(vm::HypervisorVmError::CreatePassthroughDevice(anyhow!(
            "No passthrough support"
        )))
    }

    fn set_gsi_routing(&self, irq_routing: &[IrqRoutingEntry]) -> vm::Result<()> {
        let mut routes = self.gsi_routes.write().unwrap();

        routes.drain();

        for r in irq_routing {
            debug!("gsi routing {:x?}", r);
            routes.insert(r.gsi, *r);
        }

        Ok(())
    }

    fn request_virtual_interrupt(
        &self,
        interrupt_type: u8,
        apic_id: u64,
        vector: u32,
        level_triggered: bool,
        logical_destination_mode: bool,
        long_mode: bool,
    ) -> vm::Result<()> {
        self.fd
            .request_virtual_interrupt(
                interrupt_type.into(),
                apic_id,
                vector,
                level_triggered,
                logical_destination_mode,
                long_mode,
            )
            .map_err(|e| vm::HypervisorVmError::RequestVirtualInterrupt(e.into()))?;
        Ok(())
    }
}

pub use hv_cpuid_entry2 as CpuIdEntry;

#[derive(Copy, Clone, Debug)]
pub struct HypervIrqRoutingMsi {
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
}

#[derive(Copy, Clone, Debug)]
pub enum HypervIrqRouting {
    Msi(HypervIrqRoutingMsi),
}

#[derive(Copy, Clone, Debug)]
pub struct HypervIrqRoutingEntry {
    pub gsi: u32,
    pub route: HypervIrqRouting,
}

pub type IrqRoutingEntry = HypervIrqRoutingEntry;

pub const CPUID_FLAG_VALID_INDEX: u32 = 0;
