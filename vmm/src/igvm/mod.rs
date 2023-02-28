pub mod igvm_loader;
mod loader;
use igvm_parser::igvm::IgvmVhsSnpIdBlock;
use igvm_parser::snp::SEV_VMSA;
use std::mem::MaybeUninit;

#[derive(Debug, Clone)]
pub struct IgvmLoadedInfo {
    pub gpas: Vec<u64>,
    pub vmsa_gpa: u64,
    pub first_gpa: u64,
    pub snp_id_block: IgvmVhsSnpIdBlock,
    pub start_gpa: u64,
    pub length: u64,
    pub vmsa: SEV_VMSA,
}

impl Default for IgvmLoadedInfo {
    fn default() -> Self {
        let ret = MaybeUninit::<IgvmLoadedInfo>::zeroed();
        unsafe { ret.assume_init() }
    }
}
impl IgvmLoadedInfo {
    pub fn new() -> Self {
        IgvmLoadedInfo {
            gpas: Vec::new(),
            ..Default::default()
        }
    }
    pub fn gpas_as_array(&self) -> &[u64] {
        &self.gpas[..]
    }
}
