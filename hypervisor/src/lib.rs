// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2020, Microsoft Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

//! A generic abstraction around hypervisor functionality
//!
//! This crate offers a trait abstraction for underlying hypervisors
//!
//! # Platform support
//!
//! - x86_64
//! - arm64
//!

extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate thiserror;
#[macro_use]
extern crate anyhow;

#[cfg(feature = "kvm")]
/// KVM implementation module
pub mod kvm;

#[cfg(all(feature = "hyperv", target_arch = "x86_64"))]
pub mod hyperv;
/// Hypevisor related module
pub mod hypervisor;

/// Vm related module
pub mod vm;

/// Architecture specific definitions
pub mod arch;

/// CPU related module
mod cpu;

/// Device related module
mod device;

pub use crate::hypervisor::{Hypervisor, HypervisorError};
pub use cpu::{HypervisorCpuError, Vcpu, VmExit};
pub use device::{Device, HypervisorDeviceError};
#[cfg(all(feature = "hyperv", target_arch = "x86_64"))]
pub use hyperv::*;
#[cfg(feature = "kvm")]
pub use kvm::*;
pub use vm::{DataMatch, HypervisorVmError, Vm};

use std::sync::Arc;
pub fn new() -> std::result::Result<Arc<dyn Hypervisor>, HypervisorError> {
    #[cfg(feature = "kvm")]
    let hv = kvm::KvmHypervisor::new()?;

    Ok(Arc::new(hv))
}
