// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Implements virtio queues

use std::fmt::{self, Debug};
use std::sync::Arc;
use virtio_queue::{Queue, QueueT};
use vm_memory::GuestAddress;

pub mod queue;
pub use queue::*;

pub const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

// Types taken from linux/virtio_ids.h
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub enum VirtioDeviceType {
    Net = 1,
    Block = 2,
    Console = 3,
    Rng = 4,
    Balloon = 5,
    Fs9P = 9,
    Gpu = 16,
    Input = 18,
    Vsock = 19,
    Iommu = 23,
    Mem = 24,
    Fs = 26,
    Pmem = 27,
    Watchdog = 35, // Temporary until official number allocated
    Unknown = 0xFF,
}

/* The standard layout for the ring is a continuous chunk of memory which looks
 * like this.  We assume num is a power of 2.
 *
 * struct vring
 * {
 *	// The actual descriptors (16 bytes each)
 *	struct vring_desc desc[num];
 *
 *	// A ring of available descriptor heads with free-running index.
 *	__virtio16 avail_flags;
 *	__virtio16 avail_idx;
 *	__virtio16 available[num];
 *	__virtio16 used_event_idx;
 *
 *	// Padding to the next align boundary.
 *	char pad[];
 *
 *	// A ring of used descriptor heads with free-running index.
 *	__virtio16 used_flags;
 *	__virtio16 used_idx;
 *	struct vring_used_elem used[num];
 *	__virtio16 avail_event_idx;
 * };
 * struct vring_desc {
 *	__virtio64 addr;
 *	__virtio32 len;
 *	__virtio16 flags;
 *	__virtio16 next;
 * };
 *
 * struct vring_avail {
 *	__virtio16 flags;
 *	__virtio16 idx;
 *	__virtio16 ring[];
 * };
 *
 * // u32 is used here for ids for padding reasons.
 * struct vring_used_elem {
 *	// Index of start of used descriptor chain.
 *	__virtio32 id;
 *	// Total length of the descriptor chain which was used (written to)
 *	__virtio32 len;
 * };
*
 * Kernel header used for this reference: include/uapi/linux/virtio_ring.h
 * Virtio Spec: https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html
 *
 */
#[cfg(feature = "sev_snp")]
const VRING_DESC_ELEMENT_SIZE: usize = 16;
#[cfg(feature = "sev_snp")]
const VRING_AVAIL_ELEMENT_SIZE: usize = 2;
#[cfg(feature = "sev_snp")]
const VRING_USED_ELEMENT_SIZE: usize = 8;
#[cfg(feature = "sev_snp")]
pub enum VringType {
    Desc,
    Avail,
    Used,
}

#[cfg(feature = "sev_snp")]
pub fn get_vring_size(t: VringType, queue_size: u16) -> usize {
    let (length_except_ring, element_size) = match t {
        VringType::Desc => (0, VRING_DESC_ELEMENT_SIZE),
        VringType::Avail => (6, VRING_AVAIL_ELEMENT_SIZE),
        VringType::Used => (6, VRING_USED_ELEMENT_SIZE),
    };
    length_except_ring + element_size * queue_size as usize
}

impl From<u32> for VirtioDeviceType {
    fn from(t: u32) -> Self {
        match t {
            1 => VirtioDeviceType::Net,
            2 => VirtioDeviceType::Block,
            3 => VirtioDeviceType::Console,
            4 => VirtioDeviceType::Rng,
            5 => VirtioDeviceType::Balloon,
            9 => VirtioDeviceType::Fs9P,
            16 => VirtioDeviceType::Gpu,
            18 => VirtioDeviceType::Input,
            19 => VirtioDeviceType::Vsock,
            23 => VirtioDeviceType::Iommu,
            24 => VirtioDeviceType::Mem,
            26 => VirtioDeviceType::Fs,
            27 => VirtioDeviceType::Pmem,
            35 => VirtioDeviceType::Watchdog,
            _ => VirtioDeviceType::Unknown,
        }
    }
}

// In order to use the `{}` marker, the trait `fmt::Display` must be implemented
// manually for the type VirtioDeviceType.
impl fmt::Display for VirtioDeviceType {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = match *self {
            VirtioDeviceType::Net => "net",
            VirtioDeviceType::Block => "block",
            VirtioDeviceType::Console => "console",
            VirtioDeviceType::Rng => "rng",
            VirtioDeviceType::Balloon => "balloon",
            VirtioDeviceType::Gpu => "gpu",
            VirtioDeviceType::Fs9P => "9p",
            VirtioDeviceType::Input => "input",
            VirtioDeviceType::Vsock => "vsock",
            VirtioDeviceType::Iommu => "iommu",
            VirtioDeviceType::Mem => "mem",
            VirtioDeviceType::Fs => "fs",
            VirtioDeviceType::Pmem => "pmem",
            VirtioDeviceType::Watchdog => "watchdog",
            VirtioDeviceType::Unknown => "UNKNOWN",
        };
        write!(f, "{output}")
    }
}

/// Trait for devices with access to data in memory being limited and/or
/// translated.
pub trait AccessPlatform: Send + Sync + Debug {
    /// Provide a way to translate GVA address ranges into GPAs.
    fn translate_gva(&self, base: u64, size: u64) -> std::result::Result<u64, std::io::Error>;
    /// Provide a way to translate GPA address ranges into GVAs.
    fn translate_gpa(&self, base: u64, size: u64) -> std::result::Result<u64, std::io::Error>;
}

pub trait Translatable {
    fn translate_gva(&self, access_platform: Option<&Arc<dyn AccessPlatform>>, len: usize) -> Self;
    fn translate_gpa(&self, access_platform: Option<&Arc<dyn AccessPlatform>>, len: usize) -> Self;
    fn translate_gva_with_vmfd(
        &self,
        access_platform: Option<&Arc<dyn AccessPlatform>>,
        len: usize,
        #[cfg(all(feature = "mshv", feature = "sev_snp"))] vm: Option<&Arc<dyn hypervisor::Vm>>,
    ) -> Self;
}

impl Translatable for GuestAddress {
    fn translate_gva(&self, access_platform: Option<&Arc<dyn AccessPlatform>>, len: usize) -> Self {
        GuestAddress(self.0.translate_gva(access_platform, len))
    }
    fn translate_gpa(&self, access_platform: Option<&Arc<dyn AccessPlatform>>, len: usize) -> Self {
        GuestAddress(self.0.translate_gpa(access_platform, len))
    }
    fn translate_gva_with_vmfd(
        &self,
        access_platform: Option<&Arc<dyn AccessPlatform>>,
        len: usize,
        #[cfg(all(feature = "mshv", feature = "sev_snp"))] vm: Option<&Arc<dyn hypervisor::Vm>>,
    ) -> Self {
        GuestAddress(self.0.translate_gva_with_vmfd(
            access_platform,
            len,
            #[cfg(all(feature = "mshv", feature = "sev_snp"))]
            vm,
        ))
    }
}

impl Translatable for u64 {
    fn translate_gva(&self, access_platform: Option<&Arc<dyn AccessPlatform>>, len: usize) -> Self {
        if let Some(access_platform) = access_platform {
            access_platform.translate_gva(*self, len as u64).unwrap()
        } else {
            *self
        }
    }
    fn translate_gpa(&self, access_platform: Option<&Arc<dyn AccessPlatform>>, len: usize) -> Self {
        if let Some(access_platform) = access_platform {
            access_platform.translate_gpa(*self, len as u64).unwrap()
        } else {
            *self
        }
    }
    fn translate_gva_with_vmfd(
        &self,
        access_platform: Option<&Arc<dyn AccessPlatform>>,
        len: usize,
        #[cfg(all(feature = "mshv", feature = "sev_snp"))] vm: Option<&Arc<dyn hypervisor::Vm>>,
    ) -> Self {
        cfg_if::cfg_if! {
            if #[cfg(all(feature = "mshv", feature = "sev_snp"))] {
                if let Some(_vm) = vm {
                    _vm.gain_page_access(*self, len  as u32).unwrap();
                }
                if let Some(access_platform) = access_platform {
                    access_platform.translate_gva(*self, len as u64).unwrap()
                } else {
                    *self
                }
            } else {
                if let Some(access_platform) = access_platform {
                    access_platform.translate_gva(*self, len as u64).unwrap()
                } else {
                    *self
                }
            }
        }
    }
}

/// Helper for cloning a Queue since QueueState doesn't derive Clone
pub fn clone_queue(
    queue: &Queue,
    #[cfg(feature = "sev_snp")] vm: Option<&Arc<dyn hypervisor::Vm>>,
) -> Queue {
    let mut q = Queue::new(queue.max_size()).unwrap();

    q.set_next_avail(queue.next_avail());
    q.set_next_used(queue.next_used());
    q.set_event_idx(queue.event_idx_enabled());
    q.set_size(queue.size());
    q.set_ready(queue.ready());

    #[cfg(feature = "sev_snp")]
    if let Some(_vm) = vm {
        let desc_a = GuestAddress(queue.desc_table());
        let avail_a = GuestAddress(queue.avail_ring());
        let ring_a = GuestAddress(queue.used_ring());

        desc_a.translate_gva_with_vmfd(None, get_vring_size(VringType::Desc, queue.size()), vm);
        avail_a.translate_gva_with_vmfd(None, get_vring_size(VringType::Avail, queue.size()), vm);
        ring_a.translate_gva_with_vmfd(None, get_vring_size(VringType::Used, queue.size()), vm);
    }

    q.try_set_desc_table_address(GuestAddress(queue.desc_table()))
        .unwrap();
    q.try_set_avail_ring_address(GuestAddress(queue.avail_ring()))
        .unwrap();
    q.try_set_used_ring_address(GuestAddress(queue.used_ring()))
        .unwrap();

    q
}
