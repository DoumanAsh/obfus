//!Necessary Crypto functions

use crate::utils;
use aes_gcm::Aes256Gcm;

const NONCE_SIZE: usize = 12;
pub(crate) const TAG_SIZE: usize = 16;

///Calculates buffer size to hold `size` data (it adds size of AEAD tag to be appended)
pub const fn required_buffer_size(size: usize) -> usize {
    size + TAG_SIZE
}

///Buffer to store [Crypto](struct.Crypto.html) output
///
///Note that buffer's capacity should be calculated using [required_buffer_size](fn.required_buffer_size.html)
pub struct Buffer<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> Buffer<N> {
    const DATA_SIZE: usize = N - TAG_SIZE;

    #[inline]
    ///Creates new instance
    pub const fn new() -> Self {
        debug_assert!(Self::DATA_SIZE > 0, "Buffer capacity should be greater than 16 bytes");
        Self {
            data: [0; N],
            len: 0,
        }
    }

    #[inline]
    ///Access written data
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }

    #[inline]
    ///Access written data
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl<const N: usize> AsRef<[u8]> for Buffer<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl<const N: usize> AsMut<[u8]> for Buffer<N> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}

impl<const N: usize> aes_gcm::aead::Buffer for Buffer<N> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        let remaining_capacity = N.saturating_sub(self.len);
        if other.len() <= remaining_capacity {
            self.data[self.len..self.len.saturating_add(other.len())].copy_from_slice(other);
            self.len = self.len.saturating_add(other.len());
            Ok(())
        } else {
            Err(aes_gcm::aead::Error)
        }
    }

    #[inline]
    fn truncate(&mut self, len: usize) {
        debug_assert!(len < N);

        if len < self.len {
            utils::secure_memset(&mut self.data_mut()[len..], 0);
            self.len = len;
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }
    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

///AES-256 wrapper
pub struct Crypto {
    aes: Aes256Gcm
}

impl Crypto {
    #[inline]
    ///Creates new instance using provided key
    pub fn new(key: [u8; 32]) -> Self {
        use aes_gcm::KeyInit;

        Self {
            aes: Aes256Gcm::new(&(key.into()))
        }
    }

    #[inline]
    ///Encrypts content inside `buffer`
    ///
    ///Note that buffer's capacity should be calculated using [required_buffer_size](fn.required_buffer_size.html)
    pub fn encrypt<const N: usize>(&self, nonce: [u8; NONCE_SIZE], in_out: &mut Buffer<N>) -> Result<(), aes_gcm::Error> {
        use aes_gcm::AeadInOut;

        self.aes.encrypt_in_place(&(nonce.into()), &[], in_out)
    }

    #[inline]
    ///Decrypts content inside `buffer`
    ///
    ///Note that buffer's capacity should be calculated using [required_buffer_size](fn.required_buffer_size.html)
    ///
    ///On success `in_out` length will be truncated to the size of original data
    pub fn decrypt<const N: usize>(&self, nonce: [u8; NONCE_SIZE], in_out: &mut Buffer<N>) -> Result<(), aes_gcm::Error> {
        use aes_gcm::AeadInOut;

        self.aes.decrypt_in_place(&(nonce.into()), &[], in_out)
    }
}
