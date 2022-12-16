use vm_memory::GuestMemoryMmap;
use igvm_parser::hvdef::Vtl;
use igvm_parser::igvm::IgvmParameterPageType;
use igvm_parser::importer::{
    BootPageAcceptance, IsolationConfig, IsolationType, Register, StartupMemoryType, HV_PAGE_SIZE,
};
use igvm_parser::map_range::{Entry, RangeMap};

use std::collections::HashMap;
use std::mem::Discriminant;
use thiserror::Error;
use vm_memory::{Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic};
use vm_memory::{GuestMemory, GuestMemoryRegion};

#[derive(Debug)]
pub struct ImportRegion {
    pub page_base: u64,
    pub page_count: u64,
    pub acceptance: BootPageAcceptance,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("overlaps with existing import region {0:?}")]
    OverlapsExistingRegion(ImportRegion),
    #[error("invalid parameter area index {0:?}")]
    InvalidParameterAreaIndex(ParameterAreaIndex),
    #[error("invalid vtl")]
    InvalidVtl,
    #[error("memory unvailable")]
    MemoryUnavailable,
    #[error("invalid vp context memory")]
    InvalidVpContextMemory(&'static str),
    #[error("data larger than imported region")]
    DataTooLarge,
    #[error("no vp context page set")]
    NoVpContextPageSet,
    #[error("overlaps existing relocation region")]
    RelocationOverlap,
    #[error("region alignment is not aligned to 4K")]
    RelocationAlignment,
    #[error("relocation base gpa is not aligned to relocation alignment")]
    RelocationBaseGpa,
    #[error("relocation minimum gpa is not aligned to relocation alignment")]
    RelocationMinimumGpa,
    #[error("relocation maximum gpa is not aligned to relocation alignment")]
    RelocationMaximumGpa,
    #[error("relocation size is not 4K aligned")]
    RelocationSize,
    #[error("page table relocation is already set, only a single allowed")]
    PageTableRelocationSet,
    #[error("page table relocation used size is greater than the region size")]
    PageTableUsedSize,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct ParameterAreaIndex(pub u32);

pub trait ImageLoad {
    /// Get the isolation configuration for this loader. This can be used by loaders
    /// to load different state depening on the platform.
    fn get_isolation_config(&self) -> IsolationConfig;

    /// Create a parameter area for the given page_base and page_count,
    /// which can be used to import parameters.
    fn create_parameter_area(
        &mut self,
        page_base: u64,
        page_count: u32,
    ) -> Result<ParameterAreaIndex, Error>;

    /// Create a parameter area for the given page_base, page_count, and initial_data
    /// which can be used to import parameters.
    fn create_parameter_area_with_data(
        &mut self,
        page_base: u64,
        page_count: u32,
        initial_data: &[u8],
    ) -> Result<ParameterAreaIndex, Error>;

    /// Import an IGVM parameter into the given parameter area index at the given offset.
    ///
    /// IGVM Parameters are used to specify where OS agnostic runtime dynamic information
    /// should be loaded into the guest memory space. This allows loaders to load a base IGVM
    /// file with a given measurement that can be specialized with runtime unmeasured parameters.
    fn import_parameter(
        &mut self,
        parameter_area: ParameterAreaIndex,
        byte_offset: u32,
        parameter_type: IgvmParameterPageType,
    ) -> Result<(), Error>;

    /// Import data into the guest address space with the given acceptance type.
    /// data.len() must be smaller than or equal to the number of pages being imported.
    fn import_pages(
        &mut self,
        page_base: u64,
        page_count: u64,
        acceptance: BootPageAcceptance,
        data: &[u8],
    ) -> Result<(), Error>;

    /// Import a register into the BSP at the given VTL.
    fn import_vp_register(&mut self, vtl: Vtl, register: Register) -> Result<(), Error>;

    /// Verify with the loader that memory is available in guest address space with the given type.
    fn verify_startup_memory_available(
        &mut self,
        page_base: u64,
        page_count: u64,
        memory_type: StartupMemoryType,
    ) -> Result<(), Error>;

    /// Notify the loader to deposit architecture specific VP context information at the given page.
    ///
    /// TODO: It probably makes sense to use a different acceptance type than the default one?
    fn set_vp_context_page(
        &mut self,
        vtl: Vtl,
        page_base: u64,
        acceptance: BootPageAcceptance,
    ) -> Result<(), Error>;

    /// Obtain the page base of the GPA range to be used for architecture specific VP context data.
    fn vp_context_page(&self, vtl: Vtl) -> Result<u64, Error>;

    /// Specify this region as relocatable.
    fn relocation_region(
        &mut self,
        gpa: u64,
        size_bytes: u64,
        relocation_alignment: u64,
        minimum_relocation_gpa: u64,
        maximum_relocation_gpa: u64,
        is_vtl2: bool,
        apply_rip_offset: bool,
        apply_gdtr_offset: bool,
        vp_index: u16,
        vtl: Vtl,
    ) -> Result<(), Error>;

    /// Specify a region as relocatable page table memory.
    fn page_table_relocation(
        &mut self,
        page_table_gpa: u64,
        size_pages: u64,
        used_pages: u64,
        vp_index: u16,
        vtl: Vtl,
    ) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct Loader {
    memory: GuestMemoryAtomic<GuestMemoryMmap>,
    regs: HashMap<Discriminant<Register>, Register>,
    accepted_ranges: RangeMap<u64, BootPageAcceptance>,
    max_vtl: Vtl,
    bytes_written: u64,

}

impl Loader {
    pub fn new(memory: GuestMemoryAtomic<GuestMemoryMmap>, max_vtl: Vtl) -> Loader {
        Loader {
            memory,
            regs: HashMap::new(),
            accepted_ranges: RangeMap::new(),
            max_vtl,
            bytes_written: 0,
        }
    }

    pub fn get_initial_regs(self) -> Vec<Register> {
        self.regs.into_values().collect()
    }
     /// Accept a new page range with a given acceptance into the map of accepted ranges.
     pub fn accept_new_range(
        &mut self,
        page_base: u64,
        page_count: u64,
        acceptance: BootPageAcceptance,
    ) -> Result<(), Error> {
        let page_end = page_base + page_count - 1;
        match self.accepted_ranges.entry(page_base, page_end) {
            Entry::Overlapping(entry) => {
                let &(overlap_start, overlap_end, overlap_acceptance) = entry.get();

                Err(Error::OverlapsExistingRegion(ImportRegion {
                    page_base: overlap_start,
                    page_count: overlap_end - overlap_start + 1,
                    acceptance: overlap_acceptance,
                }))
            }
            Entry::Vacant(entry) => {
                entry.insert(acceptance);
                Ok(())
            }
        }
    }
    pub fn gets_total_bytes_written(self) -> u64 {
        self.bytes_written
    }
}

impl ImageLoad for Loader {
    fn get_isolation_config(&self) -> IsolationConfig {
        IsolationConfig {
            paravisor_present: false,
            isolation_type: IsolationType::None,
            shared_gpa_boundary_bits: None,
        }
    }

    fn import_pages(
        &mut self,
        page_base: u64,
        page_count: u64,
        acceptance: BootPageAcceptance,
        data: &[u8],
    ) -> Result<(), Error> {
        debug!(
            "importing pages: {:?}, {:?}, {:?}",
            page_base, page_count, acceptance
        );

        // Track accepted ranges for duplicate imports.
        self.accept_new_range(page_base, page_count, acceptance)?;

        // Page count must be larger or equal to data.
        if page_count * HV_PAGE_SIZE < data.len() as u64 {
            return Err(Error::DataTooLarge);
        }

        self.memory
            .memory()
            .write(data, GuestAddress(page_base * HV_PAGE_SIZE))
            .map_err(|e| {
                debug!("Importing pages failed due to MemoryError");
                Error::MemoryUnavailable
            })?;
        self.bytes_written += page_count * HV_PAGE_SIZE;
        Ok(())
    }

    fn import_vp_register(&mut self, vtl: Vtl, register: Register) -> Result<(), Error> {
        // Only importing to the max VTL for registers is currently allowed, as only one set of registers is stored.
        if vtl != self.max_vtl {
            return Err(Error::InvalidVtl);
        }

        let entry = self.regs.entry(std::mem::discriminant(&register));
        match entry {
            std::collections::hash_map::Entry::Occupied(_) => {
                panic!("duplicate register import {:?}", register)
            }
            std::collections::hash_map::Entry::Vacant(ve) => ve.insert(register),
        };

        Ok(())
    }

    fn verify_startup_memory_available(
        &mut self,
        page_base: u64,
        page_count: u64,
        memory_type: StartupMemoryType,
    ) -> Result<(), Error> {
        // Allow Vtl2ProtectableRam only if VTL2 is enabled.
        if self.max_vtl == Vtl::Vtl2 {
            match memory_type {
                StartupMemoryType::Ram => {}
                StartupMemoryType::Vtl2ProtectableRam => {
                    // TODO: Should enable VTl2 memory protections on this region? Or do we allow VTL2 memory protections
                    //       on the whole address space when VTL memory protections work?
                    warn!(
                        "vtl2 protectable ram requested: {:?} {:?}",
                        page_base, page_count,
                    );
                }
            }
        } else if memory_type != StartupMemoryType::Ram {
            return Err(Error::MemoryUnavailable);
        }

        let mut memory_found = false;

        for range in self.memory.memory().iter() {
            // Today, the memory layout only describes normal ram and mmio. Thus the memory
            // request must live completely within a single range, since any gaps are mmio.
            let base_address = page_base * HV_PAGE_SIZE;
            let end_address = base_address + (page_count * HV_PAGE_SIZE) - 1;

            if base_address >= range.start_addr().0 && base_address < range.last_addr().0 {
                if end_address > range.last_addr().0 {
                    debug!("startup memory end bigger than the current range");
                    return Err(Error::MemoryUnavailable);
                }

                memory_found = true;
            }
        }

        if memory_found {
            Ok(())
        } else {
            debug!("no valid memory range available for startup memory verify");
            Err(Error::MemoryUnavailable)
        }
    }

    fn set_vp_context_page(
        &mut self,
        _vtl: Vtl,
        _page_base: u64,
        _acceptance: BootPageAcceptance,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    fn vp_context_page(&self, _vtl: Vtl) -> Result<u64, Error> {
        unimplemented!()
    }

    fn create_parameter_area(
        &mut self,
        _page_base: u64,
        _page_count: u32,
    ) -> Result<ParameterAreaIndex, Error> {
        unimplemented!()
    }

    fn create_parameter_area_with_data(
        &mut self,
        _page_base: u64,
        _page_count: u32,
        _initial_data: &[u8],
    ) -> Result<ParameterAreaIndex, Error> {
        unimplemented!()
    }

    fn import_parameter(
        &mut self,
        _parameter_area: ParameterAreaIndex,
        _byte_offset: u32,
        _parameter_type: IgvmParameterPageType,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    fn relocation_region(
        &mut self,
        _gpa: u64,
        _size_bytes: u64,
        _relocation_alignment: u64,
        _minimum_relocation_gpa: u64,
        _maximum_relocation_gpa: u64,
        _is_vtl2: bool,
        _apply_rip_offset: bool,
        _apply_gdtr_offset: bool,
        _vp_index: u16,
        _vtl: Vtl,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    fn page_table_relocation(
        &mut self,
        _page_table_gpa: u64,
        _size_pages: u64,
        _used_pages: u64,
        _vp_index: u16,
        _vtl: Vtl,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}
