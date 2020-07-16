#![allow(dead_code)]

use zerocopy::{AsBytes, FromBytes};

pub const X64_CR0_PE: u64 = 0x0000000000000001; // protection enable
pub const X64_CR0_MP: u64 = 0x0000000000000002; // math present
pub const X64_CR0_EM: u64 = 0x0000000000000004; // emulate math coprocessor
pub const X64_CR0_TS: u64 = 0x0000000000000008; // task switched
pub const X64_CR0_ET: u64 = 0x0000000000000010; // extension type (80387)
pub const X64_CR0_NE: u64 = 0x0000000000000020; // numeric error
pub const X64_CR0_WP: u64 = 0x0000000000010000; // write protect
pub const X64_CR0_AM: u64 = 0x0000000000040000; // alignment mask
pub const X64_CR0_NW: u64 = 0x0000000020000000; // not write-through
pub const X64_CR0_CD: u64 = 0x0000000040000000; // cache disable
pub const X64_CR0_PG: u64 = 0x0000000080000000; // paging

pub const X64_CR4_PAE: u64 = 0x0000000000000020; // Physical address extensions

pub const X64_EFER_SCE: u64 = 0x0000000000000001; // Syscall Enable
pub const X64_EFER_LME: u64 = 0x0000000000000100; // Long Mode Enabled
pub const X64_EFER_LMA: u64 = 0x0000000000000400; // Long Mode Active
pub const X64_EFER_NXE: u64 = 0x0000000000000800; // No-execute Enable
pub const X64_EFER_FFXSR: u64 = 0x0000000000004000; // Fast save/restore enabled

pub const X86X_MSR_DEFAULT_PAT: u64 = 0x0007040600070406;
pub const X64_DEFAULT_CODE_SEGMENT_ATTRIBUTES: u16 = 0xa09b; // Long Mode
pub const X64_DEFAULT_DATA_SEGMENT_ATTRIBUTES: u16 = 0xc093;

pub const X86X_IA32_MSR_PLATFORM_ID: u32 = 0x17;

#[repr(C)]
#[derive(Clone, Copy, Default, AsBytes, FromBytes)]
pub struct GdtEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_middle: u8,
    pub attr_low: u8,
    pub attr_high: u8,
    pub base_high: u8,
}
