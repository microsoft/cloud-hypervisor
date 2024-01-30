// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2024, Microsoft Corporation
//
use core::sync::atomic::Ordering;

// Define a trait for atomic bitmap operation
pub trait AtomicBitmapOps {
    // Size in total number of bits can be stored
    fn bit_size(&self) -> usize;
    // Get the bit value for an index
    fn get_bit(&self, index: usize) -> bool;
    // Set the bit  for an index
    fn set_bit(&self, index: usize);
    // Rest the bit for an index
    fn reset_bit(&self, index: usize);
    // Load the bit for an index with ordering
    fn load_bit(&self, index: usize, _order: Ordering) -> bool;
    // Capacity without self
    fn capacity() -> usize;
}
