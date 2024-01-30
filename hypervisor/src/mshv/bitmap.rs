// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
// Copyright © 2024, Microsoft Corporation
//
use core::{
    mem,
    sync::atomic::{AtomicU64, Ordering},
};

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

impl AtomicBitmapOps for AtomicU64 {
    fn bit_size(&self) -> usize {
        8 * mem::size_of::<AtomicU64>()
    }

    fn get_bit(&self, index: usize) -> bool {
        self.load_bit(index, Ordering::Acquire)
    }

    fn set_bit(&self, index: usize) {
        self.fetch_or(1 << index, Ordering::SeqCst);
    }

    fn reset_bit(&self, index: usize) {
        self.fetch_and(!(1 << index), Ordering::SeqCst);
    }

    fn load_bit(&self, index: usize, order: Ordering) -> bool {
        if index >= self.bit_size() {
            panic!(
                "Index: {:?} is greater than size: {:?}",
                index,
                self.bit_size()
            );
        }
        1 == 1 & (self.load(order) >> index)
    }

    fn capacity() -> usize {
        8 * mem::size_of::<AtomicU64>()
    }
}
