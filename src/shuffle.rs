//! Shuffling functions

use crate::prng;

use core::{ptr, mem};

const unsafe fn swap<T>(left: *mut T, right: *mut T) {
    let mut tmp = mem::MaybeUninit::<T>::uninit();

    unsafe {
        ptr::copy_nonoverlapping(left, tmp.as_mut_ptr(), 1);
        ptr::copy(right, left, 1);
        ptr::copy_nonoverlapping(tmp.as_ptr(), right, 1);

    }
}

///Implementation of Fisher-Yates shuffling algorithm.
///
///Implementation uses PRNG with specified key to initialize predictable random generator in order
///to guarantee reverse-ability.
///
///Care must be taken to retain this seed.
///
///Reference: <https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle>
pub struct FisherYates {
    seed: u64,
}

impl FisherYates {
    #[inline]
    ///Creates new instance with provided `seed`
    pub const fn with_seed(seed: u64) -> Self {
        Self {
            seed,
        }
    }

    #[inline]
    ///Performs shuffle
    pub const fn shuffle<'a>(&self, in_out: &'a mut [u8]) -> &'a mut [u8] {
        let len = in_out.len();
        let mut idx = 0;
        let ptr = in_out.as_mut_ptr();
        let mut prng = prng::Squares::new(self.seed);

        while idx < len {
            let swap_idx = prng.next() % len as u64;
            unsafe {
                swap(ptr.add(idx), ptr.add(swap_idx as _));
            }
            idx = idx.saturating_add(1);
        }

        in_out
    }

    #[inline(always)]
    ///Performs shuffle of constant array
    pub const fn shuffle_const<const N: usize>(&self, mut data: [u8; N]) -> [u8; N] {
        self.shuffle(&mut data);
        data
    }

    #[inline]
    ///Performs reverse shuffle
    pub const fn reverse<'a>(&self, in_out: &'a mut [u8]) -> &'a mut [u8] {
        let len = in_out.len();
        let mut idx = len.wrapping_sub(1);
        let ptr = in_out.as_mut_ptr();
        let mut prng = prng::Squares::new(self.seed.wrapping_add(idx as u64));

        while idx < len {
            let swap_idx = prng.back() % len as u64;
            unsafe {
                swap(ptr.add(idx), ptr.add(swap_idx as _));
            }
            idx = idx.wrapping_sub(1);
        }

        in_out
    }

    #[inline(always)]
    ///Performs reverse shuffle of constant array
    pub const fn reverse_const<const N: usize>(&self, mut data: [u8; N]) -> [u8; N] {
        self.reverse(&mut data);
        data
    }
}
