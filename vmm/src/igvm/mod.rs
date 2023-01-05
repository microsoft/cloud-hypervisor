mod igvm_loader;
mod loader;
use igvm_parser::igvm::IgvmVhsSnpIdBlock;
use igvm_parser::snp::SEV_VMSA;

#[derive(Debug, Copy, Clone)]
pub struct IgvmLoadedInfo {
    pub vmsa_gpa: u64,
    pub first_gpa: u64,
    pub snp_id_block: IgvmVhsSnpIdBlock,
    pub start_gpa: u64,
    pub length: u64,
    pub vmsa : SEV_VMSA,
}

impl Default for IgvmLoadedInfo {
    fn default() -> Self {
        // SAFETY: ALPC_HANDLE_ATTR has no safety invariants
        unsafe { std::mem::zeroed() }
    }
}
