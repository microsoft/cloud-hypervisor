use crate::GuestMemoryMmap;
use igvm_parser::hvdef::Vtl;
use igvm_parser::igvm::IgvmParameterPageType;
use igvm_parser::importer::{BootPageAcceptance, IsolationConfig, Register, StartupMemoryType};
use igvm_parser::map_range::RangeMap;

use std::collections::HashMap;
use std::mem::Discriminant;
use thiserror::Error;
use vm_memory::GuestMemoryAtomic;

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
}

impl Loader {
    pub fn new(memory: GuestMemoryAtomic<GuestMemoryMmap>, max_vtl: Vtl) -> Loader {
        Loader {
            memory,
            regs: HashMap::new(),
            accepted_ranges: RangeMap::new(),
            max_vtl,
        }
    }

    pub fn get_initial_regs(self) -> Vec<Register> {
        self.regs.into_values().collect()
    }
}
