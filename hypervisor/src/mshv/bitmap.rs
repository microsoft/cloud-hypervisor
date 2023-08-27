use core::{
    mem,
    sync::atomic::{AtomicU64, Ordering},
};
pub trait AtomicBitmapOps {
    fn bit_size(&self) -> usize;
    fn get_bit(&self, index: usize) -> bool;
    fn set_bit(&self, index: usize);
    fn reset_bit(&self, index: usize);
    fn load_bit(&self, index: usize, _order: Ordering) -> bool;
    fn capacity() -> usize;
}

const INDEX_MASK: usize = 63;

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

#[derive(Debug)]
pub struct SimpleAtomicBitmap {
    map: Vec<AtomicU64>,
    size: usize,
    map_size: usize,
}

#[allow(clippy::len_without_is_empty)]
impl SimpleAtomicBitmap {
    pub fn new(size: usize) -> Self {
        let map_size = size / AtomicU64::capacity()
            + if size % AtomicU64::capacity() > 0 {
                1
            } else {
                0
            };
        let map: Vec<AtomicU64> = (0..map_size).map(|_| AtomicU64::new(0)).collect();
        SimpleAtomicBitmap {
            map,
            size,
            map_size,
        }
    }
    pub fn new_with_bytes(size: usize, page_size: usize) -> Self {
        let mut num_pages = size / page_size;
        if size % page_size > 0 {
            num_pages += 1;
        }
        SimpleAtomicBitmap::new(num_pages)
    }
    pub fn is_bit_set(&self, index: usize) -> bool {
        if index >= self.size {
            panic!("Index: {:?} is greater than size: {:?}", index, self.size);
        }
        self.map[index >> 6].get_bit(index & INDEX_MASK)
    }

    pub fn set_bits_range(&self, start_bit: usize, len: usize) {
        if len == 0 {
            return;
        }
        let last_bit = start_bit.saturating_add(len - 1);
        for n in start_bit..=last_bit {
            if n >= self.size {
                break;
            }
            self.map[n >> 6].set_bit(n & INDEX_MASK);
        }
    }
    pub fn reset_bits_range(&self, start_bit: usize, len: usize) {
        if len == 0 {
            return;
        }

        let last_bit = start_bit.saturating_add(len - 1);
        for n in start_bit..=last_bit {
            if n >= self.size {
                break;
            }
            self.map[n >> 6].reset_bit(n & INDEX_MASK);
        }
    }
    pub fn set_bit(&self, index: usize) {
        if index >= self.size {
            panic!("Index: {:?} is greater than size: {:?}", index, self.size);
        }
        self.map[index >> 6].set_bit(index & INDEX_MASK)
    }
    pub fn reset_bit(&self, index: usize) {
        if index >= self.size {
            panic!("Index: {:?} is greater than size: {:?}", index, self.size);
        }
        self.map[index >> 6].reset_bit(index & INDEX_MASK)
    }

    pub fn len(&self) -> usize {
        self.size
    }
    pub fn size_in_bytes(&self) -> usize {
        self.map_size * 8
    }
    pub fn reset(&self) {
        for it in self.map.iter() {
            it.store(0, Ordering::Release);
        }
    }
}
impl Default for SimpleAtomicBitmap {
    fn default() -> Self {
        SimpleAtomicBitmap::new(0)
    }
}
