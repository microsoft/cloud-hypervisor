// Copyright (C) Microsoft Corporation. All rights reserved.

//! Loader implementation to load IGVM files.

use crate::cpu::{CpuManager, Error as CpuManagerError};
use crate::igvm::loader::ImageLoad;
use crate::igvm::loader::Loader;
use crate::igvm::IgvmLoadedInfo;
use crate::memory_manager::{Error as MemoryManagerError, MemoryManager};
use crate::ArchMemRegion;
use arch::RegionType;
use hypervisor::mshv::*;
use igvm_parser::hvdef::Vtl;
use igvm_parser::igvm::IgvmFile;
use igvm_parser::igvm::IgvmPageDataType;
use igvm_parser::igvm::IgvmPlatformHeader;
use igvm_parser::igvm::IgvmPlatformType;
use igvm_parser::igvm::IgvmRelocatableRegion;
use igvm_parser::igvm::IGVM_VHF_MEMORY_MAP_ENTRY_TYPE_MEMORY;
use igvm_parser::igvm::IGVM_VHF_MEMORY_MAP_ENTRY_TYPE_PLATFORM_RESERVED;
use igvm_parser::igvm::IGVM_VHF_MEMORY_MAP_ENTRY_TYPE_VTL2_PROTECTABLE;
use igvm_parser::igvm::IGVM_VHF_PAGE_DATA_FLAGS_UNMEASURED;
use igvm_parser::igvm::IGVM_VHF_REQUIRED_MEMORY_FLAGS_VTL2_PROTECTABLE;
use igvm_parser::igvm::IGVM_VHS_MEMORY_MAP_ENTRY;
use igvm_parser::igvm::IGVM_VHS_MEMORY_RANGE;
use igvm_parser::igvm::IGVM_VHS_MMIO_RANGES;
use igvm_parser::igvm::IGVM_VHS_PARAMETER;
use igvm_parser::igvm::IGVM_VHS_PARAMETER_INSERT;
use igvm_parser::importer::BootPageAcceptance;
use igvm_parser::importer::Register;
use igvm_parser::importer::StartupMemoryType;
use igvm_parser::importer::TableRegister;
use igvm_parser::importer::HV_PAGE_SIZE;
use igvm_parser::map_range::RangeMap;
use igvm_parser::memlayout::MemoryRange;
use igvm_parser::page_table::CpuPagingState;
use igvm_parser::snp::SEV_VMSA;
use std::collections::HashMap;
use std::ffi::CString;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::GuestMemoryAtomic;
use vm_memory::{GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryMmap};
use zerocopy::AsBytes;
pub use mshv_bindings::*;

#[derive(Debug, Error)]
pub enum Error {
    #[error("command line is not a valid C string")]
    InvalidCommandLine(#[source] std::ffi::NulError),
    #[error("failed to read igvm file")]
    Igvm(#[source] std::io::Error),
    #[error("invalid igvm file")]
    InvalidIgvmFile(#[source] igvm_parser::igvm::Error),
    #[error("loader error")]
    Loader(#[source] crate::igvm::loader::Error),
    #[error("parameter too large for parameter area")]
    ParameterTooLarge,
    #[error("relocation not supported in igvm file")]
    RelocationNotSupported,
    #[error("multiple igvm relocation headers specified in the file")]
    MultipleIgvmRelocationHeaders,
    #[error("relocated base address is not supported by relocation header {file_relocation:?}")]
    RelocationBaseInvalid {
        file_relocation: IgvmRelocatableRegion,
    },
    #[error("page table relocation header not specified")]
    NoPageTableRelocationHeader,
    #[error("vp index does not describe the BSP in relocation headers")]
    RelocationVpIndex,
    #[error("vtl does not target vtl2 in relocation headers")]
    RelocationVtl,
    #[error("page table builder")]
    PageTableBuilder(#[source] igvm_parser::page_table::Error),
    #[error("allocate address space")]
    MemoryManager(MemoryManagerError),
    #[error("Error modifying host access to isolated pages: {0}")]
    ModifyHostAccess(#[source] hypervisor::HypervisorVmError),
    #[error("Error importing isolated pages: {0}")]
    ImportIsolatedPages(#[source] hypervisor::HypervisorVmError),
    #[error("Error completing importing isolated pages: {0}")]
    CompleteIsolatedImport(#[source] hypervisor::HypervisorVmError),
}

fn from_memory_range(range: &MemoryRange) -> IGVM_VHS_MEMORY_RANGE {
    assert!(range.len() % HV_PAGE_SIZE == 0);
    IGVM_VHS_MEMORY_RANGE {
        starting_gpa_page_number: range.start() / HV_PAGE_SIZE,
        number_of_pages: range.len() / HV_PAGE_SIZE,
    }
}

fn memory_map_entry(range: &ArchMemRegion) -> IGVM_VHS_MEMORY_MAP_ENTRY {
    assert!(range.size as u64 % HV_PAGE_SIZE == 0);
    if range.r_type == RegionType::Ram {
        IGVM_VHS_MEMORY_MAP_ENTRY {
            starting_gpa_page_number: range.base / HV_PAGE_SIZE,
            number_of_pages: range.size as u64 / HV_PAGE_SIZE,
            entry_type: IGVM_VHF_MEMORY_MAP_ENTRY_TYPE_MEMORY,
            flags: 0,
            reserved: 0,
        }
    } else {
        IGVM_VHS_MEMORY_MAP_ENTRY {
            starting_gpa_page_number: range.base / HV_PAGE_SIZE,
            number_of_pages: range.size as u64 / HV_PAGE_SIZE,
            entry_type: IGVM_VHF_MEMORY_MAP_ENTRY_TYPE_PLATFORM_RESERVED,
            flags: 0,
            reserved: 0,
        }
    }
}

pub struct AcpiTables<'a> {
    pub madt: &'a [u8],
    pub srat: &'a [u8],
    pub slit: Option<&'a [u8]>,
    pub pptt: Option<&'a [u8]>,
}

struct GpaPages {
    pub gpa: u64,
    pub page_type: u32,
    pub page_size: u32,
}
/// Load the given IGVM file.
///
/// `vtl2_base_address` specifies the absolute guest physical address to relocate the VTL2 region to.
///
/// TODO: only supports underhill for now, with assumptions that the file always has VTL2 enabled.
pub fn load_igvm(
    mut file: &std::fs::File,
    memory_manager: Arc<Mutex<MemoryManager>>,
    cpu_manager: Arc<Mutex<CpuManager>>,
    mem_regions: Vec<ArchMemRegion>,
    proc_count: u32,
    cmdline: &str,
    #[cfg(feature = "snp")]
    mut host_data_file: &std::fs::File,
) -> Result<Box<IgvmLoadedInfo>, Error> {
    let mut loaded_info: Box<IgvmLoadedInfo> = Box::new(IgvmLoadedInfo::new());
    let command_line = CString::new(cmdline).map_err(Error::InvalidCommandLine)?;
    let mut first_gpa: u64 = 0;
    let mut gpa_found: bool = false;
    let mut file_contents = Vec::new();
    let memory = memory_manager.lock().as_ref().unwrap().guest_memory();
    let mut gpas: Vec<GpaPages> = Vec::new();

    file.seek(SeekFrom::Start(0)).map_err(Error::Igvm)?;
    file.read_to_end(&mut file_contents).map_err(Error::Igvm)?;

    let mut host_data_file_contents: Vec<u8> = Vec::new();
    #[cfg(feature = "snp")]
    {
        host_data_file.seek(SeekFrom::Start(0)).map_err(Error::Igvm)?;
        host_data_file.read_to_end(&mut host_data_file_contents).map_err(Error::Igvm)?;
        if host_data_file_contents.len() > 32 ||  host_data_file_contents.len() == 0 {
            panic!("Host data is not valid, invalid length {}", host_data_file_contents.len());
        }
    }

    let igvm_file = IgvmFile::new_from_binary(
        &file_contents,
        Some(igvm_parser::importer::IsolationType::Vbs),
    )
    .map_err(Error::InvalidIgvmFile)?;

    let (mask, max_vtl) = match &igvm_file.platforms()[0] {
        IgvmPlatformHeader::SupportedPlatform(info) => {
            debug_assert!(info.platform_type == IgvmPlatformType::SEV_SNP);
            (info.compatibility_mask, info.highest_vtl)
        }
    };
    let max_vtl = max_vtl
        .try_into()
        .expect("igvm file should be valid after new_from_binary");
    let mut loader = Loader::new(memory.clone(), max_vtl);

    #[derive(Debug)]
    enum ParameterAreaState {
        /// Parameter area has been declared via a ParameterArea header.
        Allocated { data: Vec<u8>, max_size: u64 },
        /// Parameter area inserted and invalid to use.
        Inserted,
    }
    let mut parameter_areas: HashMap<u32, ParameterAreaState> = HashMap::new();

    // Import a parameter to the given parameter area.
    let import_parameter = |parameter_areas: &mut HashMap<u32, ParameterAreaState>,
                            info: &IGVM_VHS_PARAMETER,
                            parameter: &[u8]|
     -> Result<(), Error> {
        let (parameter_area, max_size) = match parameter_areas
            .get_mut(&info.parameter_area_index)
            .expect("parameter area should be present")
        {
            ParameterAreaState::Allocated { data, max_size } => (data, max_size),
            ParameterAreaState::Inserted => panic!("igvmfile is not valid"),
        };
        let offset = info.byte_offset as usize;
        let end_of_parameter = offset as usize + parameter.len();

        if end_of_parameter > *max_size as usize {
            // TODO: tracing for which parameter was too big?
            return Err(Error::ParameterTooLarge);
        }

        if parameter_area.len() < end_of_parameter {
            parameter_area.resize(end_of_parameter, 0);
        }

        parameter_area[offset..end_of_parameter].copy_from_slice(parameter);
        Ok(())
    };

    let mut page_table_cpu_state: Option<CpuPagingState> = None;

    for header in igvm_file.directives() {
        debug_assert!(header.compatibility_mask().unwrap_or(mask) & mask == mask);

        match header {
            igvm_parser::igvm::IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask: _,
                flags,
                data_type,
                data,
            } => {
                if !gpa_found {
                    first_gpa = *gpa;
                    gpa_found = true;
                }
                debug_assert!(data.len() as u64 % HV_PAGE_SIZE == 0);

                // TODO: only 4k or empty page datas supported right now
                assert!(data.len() as u64 == HV_PAGE_SIZE || data.is_empty());

                let acceptance = match *data_type {
                    IgvmPageDataType::NORMAL => {
                        if flags & IGVM_VHF_PAGE_DATA_FLAGS_UNMEASURED
                            == IGVM_VHF_PAGE_DATA_FLAGS_UNMEASURED
                        {
                            gpas.push(GpaPages {
                                gpa: *gpa,
                                page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_UNMEASURED,
                                page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                            });
                            BootPageAcceptance::ExclusiveUnmeasured
                        } else {
                            gpas.push(GpaPages {
                                gpa: *gpa,
                                page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_NORMAL,
                                page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                            });
                            BootPageAcceptance::Exclusive
                        }
                    }
                    IgvmPageDataType::SECRETS => {
                        gpas.push(GpaPages {
                            gpa: *gpa,
                            page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_SECRETS,
                            page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                        });
                        BootPageAcceptance::SecretsPage
                    }
                    IgvmPageDataType::CPUID_DATA => {
                        unsafe {
                            println!("IgvmPageDataType::CPUID_DATA 1: gpa: {:0x}, data len: {:?}", gpa, data.len());
                            let cpuid_page_p: *mut hv_psp_cpuid_page = data.as_ptr() as *mut hv_psp_cpuid_page;// as *mut hv_psp_cpuid_page;
                            let cpuid_page: &mut hv_psp_cpuid_page = &mut *cpuid_page_p;
                            println!("IgvmPageDataType::CPUID_DATA 2");
                            println!("Really this is correct count: {:?}", cpuid_page.count);
                            let i: usize = 0; /* Type usize */;
                            for i in 0..cpuid_page.count {
                                let leaf = cpuid_page.cpuid_leaf_info[i as usize];
                                println!("IN: {:0x} {:0x} xfem:{:?}", leaf.eax_in, leaf.ecx_in, leaf.xfem_in);
                                let mut in_leaf = cpu_manager.lock().unwrap().get_cpuid_leaf(0, leaf.eax_in, leaf.ecx_in, leaf.xfem_in, leaf.xss_in).unwrap();
                                if leaf.eax_in == 1 {
                                    in_leaf[2] &= 0x7FFFFFFF;
                                }
                                cpuid_page.cpuid_leaf_info[i as usize].eax_out = in_leaf[0];
                                cpuid_page.cpuid_leaf_info[i as usize].ebx_out = in_leaf[1];
                                cpuid_page.cpuid_leaf_info[i as usize].ecx_out = in_leaf[2];
                                cpuid_page.cpuid_leaf_info[i as usize].edx_out = in_leaf[3];

                            }
                            println!("IgvmPageDataType::CPUID_DATA 4");
                        }
                        //panic!("IgvmPageDataType::CPUID_DATA");
                        gpas.push(GpaPages {
                            gpa: *gpa,
                            page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_CPUID,
                            page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                        });
                        BootPageAcceptance::CpuidPage
                    }
                    // TODO: other data types SNP / TDX only, unsupported
                    _ => todo!("unsupported IgvmPageDataType"),
                };

                loader
                    .import_pages(gpa / HV_PAGE_SIZE, 1, acceptance, data)
                    .map_err(Error::Loader)?;
            }
            igvm_parser::igvm::IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                initial_data,
            } => {
                debug_assert!(number_of_bytes % HV_PAGE_SIZE == 0);
                debug_assert!(
                    initial_data.is_empty() || initial_data.len() as u64 == *number_of_bytes
                );

                // Allocate a new parameter area. It must not be already used.
                if parameter_areas
                    .insert(
                        *parameter_area_index,
                        ParameterAreaState::Allocated {
                            data: initial_data.clone(),
                            max_size: *number_of_bytes,
                        },
                    )
                    .is_some()
                {
                    panic!("IgvmFile is not valid, invalid invariant");
                }
            }
            igvm_parser::igvm::IgvmDirectiveHeader::VpCount(info) => {
                import_parameter(&mut parameter_areas, info, proc_count.as_bytes())?;
            }
            // igvm_parser::igvm::IgvmDirectiveHeader::Srat(info) => {
            //     import_parameter(&mut parameter_areas, info, acpi_tables.unwrap().srat)?;
            // }
            // igvm_parser::igvm::IgvmDirectiveHeader::Madt(info) => {
            //     import_parameter(&mut parameter_areas, info, acpi_tables.unwrap().madt)?;
            // }
            // igvm_parser::igvm::IgvmDirectiveHeader::Slit(info) => {
            //     if let Some(slit) = acpi_tables.unwrap().slit {
            //         import_parameter(&mut parameter_areas, info, slit)?;
            //     } else {
            //         warn!("igvm file requested a SLIT, but no SLIT was provided")
            //     }
            // }
            // igvm_parser::igvm::IgvmDirectiveHeader::Pptt(info) => {
            //     if let Some(pptt) = acpi_tables.unwrap().pptt {
            //         import_parameter(&mut parameter_areas, info, pptt)?;
            //     } else {
            //         warn!("igvm file requested a PPTT, but no PPTT was provided")
            //     }
            // }
            igvm_parser::igvm::IgvmDirectiveHeader::MmioRanges(info) => {
                todo!("unsupported IgvmPageDataType");
            }
            igvm_parser::igvm::IgvmDirectiveHeader::MemoryMap(info) => {
                let mut memory_map: Vec<IGVM_VHS_MEMORY_MAP_ENTRY> = Vec::new();

                for mem in mem_regions.iter() {
                    if mem.r_type == RegionType::Ram {
                        memory_map.push(memory_map_entry(&mem));
                    }
                }
                import_parameter(&mut parameter_areas, info, memory_map.as_bytes())?;
            }
            igvm_parser::igvm::IgvmDirectiveHeader::CommandLine(info) => {
                import_parameter(&mut parameter_areas, info, command_line.as_bytes_with_nul())?;
            }
            igvm_parser::igvm::IgvmDirectiveHeader::RequiredMemory {
                gpa,
                compatibility_mask: _,
                number_of_bytes,
                flags,
            } => {
                if !gpa_found {
                    first_gpa = *gpa;
                    gpa_found = true;
                }
                let memory_type = if flags & IGVM_VHF_REQUIRED_MEMORY_FLAGS_VTL2_PROTECTABLE
                    == IGVM_VHF_REQUIRED_MEMORY_FLAGS_VTL2_PROTECTABLE
                {
                    StartupMemoryType::Vtl2ProtectableRam
                } else {
                    StartupMemoryType::Ram
                };
                loaded_info.gpas.push(*gpa);
                loader
                    .verify_startup_memory_available(
                        gpa / HV_PAGE_SIZE,
                        *number_of_bytes as u64 / HV_PAGE_SIZE,
                        memory_type,
                    )
                    .map_err(Error::Loader)?;
            }
            igvm_parser::igvm::IgvmDirectiveHeader::SnpVpContext {
                gpa,
                compatibility_mask,
                vp_index,
                vmsa,
            } => {
                if !gpa_found {
                    first_gpa = *gpa;
                    gpa_found = true;
                }
                assert_eq!(gpa % HV_PAGE_SIZE, 0);
                let mut data: [u8; 4096] = [0; 4096];
                let len = size_of::<SEV_VMSA>();
                // Only supported for index zero
                if *vp_index == 0 {
                    data[..len].copy_from_slice(vmsa.as_bytes());
                    loader
                        .import_pages(gpa / HV_PAGE_SIZE, 1, BootPageAcceptance::VpContext, &data)
                        .map_err(Error::Loader)?;
                }
                loaded_info.vmsa_gpa = *gpa;
                loaded_info.vmsa = **vmsa;
                gpas.push(GpaPages {
                    gpa: *gpa,
                    page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_VMSA,
                    page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                });
            }
            igvm_parser::igvm::IgvmDirectiveHeader::SnpIdBlock {
                compatibility_mask,
                author_key_enabled,
                reserved,
                ld,
                family_id,
                image_id,
                version,
                guest_svn,
                id_key_algorithm,
                author_key_algorithm,
                id_key_signature,
                id_public_key,
                author_key_signature,
                author_public_key,
            } => {
                loaded_info.snp_id_block.compatibility_mask = *compatibility_mask;
                loaded_info.snp_id_block.author_key_enabled = *author_key_enabled;
                loaded_info.snp_id_block.reserved[..3].copy_from_slice(reserved);
                loaded_info.snp_id_block.ld[..48].copy_from_slice(ld);
                loaded_info.snp_id_block.family_id[..16].copy_from_slice(family_id);
                loaded_info.snp_id_block.image_id[..16].copy_from_slice(image_id);
                loaded_info.snp_id_block.version = *version;
                loaded_info.snp_id_block.guest_svn = *guest_svn;
                loaded_info.snp_id_block.id_key_algorithm = *id_key_algorithm;
                loaded_info.snp_id_block.author_key_algorithm = *author_key_algorithm;
                loaded_info.snp_id_block.id_key_signature = **id_key_signature;
                loaded_info.snp_id_block.id_public_key = **id_public_key;
                loaded_info.snp_id_block.author_key_signature = **author_key_signature;
                loaded_info.snp_id_block.author_public_key = **author_public_key;
            }
            igvm_parser::igvm::IgvmDirectiveHeader::VbsVpContext {
                vtl,
                registers,
                compatibility_mask: _,
            } => {
                todo!("VbsVpContext not supported");
            }
            igvm_parser::igvm::IgvmDirectiveHeader::VbsMeasurement { .. } => {
                todo!("VbsMeasurement not supported")
            }
            igvm_parser::igvm::IgvmDirectiveHeader::ParameterInsert(
                IGVM_VHS_PARAMETER_INSERT {
                    gpa,
                    compatibility_mask: _,
                    parameter_area_index,
                },
            ) => {
                if !gpa_found {
                    first_gpa = *gpa;
                    gpa_found = true;
                }
                debug_assert!(gpa % HV_PAGE_SIZE == 0);

                let area = parameter_areas
                    .get_mut(parameter_area_index)
                    .expect("igvmfile should be valid");
                match area {
                    ParameterAreaState::Allocated { data, max_size } => loader
                        .import_pages(
                            gpa / HV_PAGE_SIZE,
                            *max_size / HV_PAGE_SIZE,
                            BootPageAcceptance::ExclusiveUnmeasured,
                            data,
                        )
                        .map_err(Error::Loader)?,
                    ParameterAreaState::Inserted => panic!("igvmfile is invalid, multiple insert"),
                }
                *area = ParameterAreaState::Inserted;
                gpas.push(GpaPages {
                    gpa: *gpa,
                    page_type: hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_NORMAL,
                    page_size: hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                });
            }
            igvm_parser::igvm::IgvmDirectiveHeader::ErrorRange { .. } => {
                todo!("Error Range not supported")
            }
            _ => {
                todo!("Header not supported!!")
            }
        }
    }
    loaded_info.first_gpa = first_gpa;
    loaded_info.length = loader.gets_total_bytes_written();

    #[cfg(feature = "snp")]
    {
        memory_manager
            .lock()
            .unwrap()
            .allocate_address_space()
            .map_err(Error::MemoryManager)?;

        println!("Start importing vmsa pages!");
        memory_manager
            .lock()
            .unwrap()
            .vm
            .import_isolated_pages(
                hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_VMSA,
                hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                &gpas
                    .iter()
                    .filter(|x| {
                        x.page_type == hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_VMSA as u32
                    })
                    .map(|x| x.gpa / 4096)
                    .collect::<Vec<u64>>(),
            )
            .map_err(Error::ImportIsolatedPages)?;

        println!("Start importing normal pages!");
        memory_manager
            .lock()
            .unwrap()
            .vm
            .import_isolated_pages(
                hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_NORMAL,
                hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                &gpas
                    .iter()
                    .filter(|x| {
                        x.page_type == hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_NORMAL as u32
                    })
                    .map(|x| x.gpa / 4096)
                    .collect::<Vec<u64>>(),
            )
            .map_err(Error::ImportIsolatedPages)?;

        println!("Start importing zero pages!");
        memory_manager
            .lock()
            .unwrap()
            .vm
            .import_isolated_pages(
                hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_ZERO,
                hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                &gpas
                    .iter()
                    .filter(|x| {
                        x.page_type == hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_ZERO as u32
                    })
                    .map(|x| x.gpa / 4096)
                    .collect::<Vec<u64>>(),
            )
            .map_err(Error::ImportIsolatedPages)?;

        println!("Start importing cpuid pages!");
        memory_manager
            .lock()
            .unwrap()
            .vm
            .import_isolated_pages(
                hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_CPUID,
                hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                &gpas
                    .iter()
                    .filter(|x| {
                        x.page_type == hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_CPUID as u32
                    })
                    .map(|x| x.gpa / 4096)
                    .collect::<Vec<u64>>(),
            )
            .map_err(Error::ImportIsolatedPages)?;

        println!("Start importing secrets pages!");
        // memory_manager
        //     .lock()
        //     .unwrap()
        //     .vm
        //     .import_isolated_pages(
        //         hv_isolated_page_type_hv_isolated_page_type_unmeasured,
        //         hv_isolated_page_size_hv_isolated_page_size4_kb,
        //         &gpas
        //             .iter()
        //             .filter(|x| {
        //                 x.page_type == hv_isolated_page_type_hv_isolated_page_type_unmeasured as u32
        //             })
        //             .map(|x| x.gpa)
        //             .collect::<Vec<u64>>(),
        //     )
        //     .map_err(Error::ImportIsolatedPages)?;
        memory_manager
            .lock()
            .unwrap()
            .vm
            .import_isolated_pages(
                hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_SECRETS,
                hv_isolated_page_size_HV_ISOLATED_PAGE_SIZE4_KB,
                &gpas
                    .iter()
                    .filter(|x| {
                        x.page_type == hv_isolated_page_type_HV_ISOLATED_PAGE_TYPE_SECRETS as u32
                    })
                    .map(|x| x.gpa / 4096)
                    .collect::<Vec<u64>>(),
            )
            .map_err(Error::ImportIsolatedPages)?;

        // Call Complete Isolated Import since we are done importing isolated pages
        memory_manager
            .lock()
            .unwrap()
            .vm
            .complete_isolated_import(loaded_info.snp_id_block, &host_data_file_contents)
            .map_err(Error::CompleteIsolatedImport)?;
    }
    println!("loaded info xcr0: {:0x}", loaded_info.vmsa.xcr0);
    Ok(loaded_info)
}
