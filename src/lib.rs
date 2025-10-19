//!Obfuscation tools
//!
//!The purpose of this library is to provide building blocks to obfuscate information within your
//!binary

#![no_std]
#![warn(missing_docs)]
#![allow(clippy::style)]

use core::marker;

pub mod crypto;
pub mod prng;
pub mod shuffle;
pub mod utils;

pub use aes_gcm;

mod seal {
    pub trait Seal {}
}
///Trait for [Secret](struct.Secret.html) tag
pub trait SecretType: seal::Seal {}

macro_rules! impl_seal {
    ($($name:ident),* $(,)?) => {
        $(
            impl seal::Seal for $name {}
            impl SecretType for $name {}
        )*
    };
}

///Marker indicating [Secret](struct.Secret.html) holds binary data
pub struct Binary;
///Marker indicating [Secret](struct.Secret.html) holds utf-8 text
pub struct Text;
impl_seal!(Binary, Text);

///Secret storage
///
///On drop data is zeroed
pub struct Secret<const N: usize, TAG: SecretType> {
    data: [u8; N],
    _tag: marker::PhantomData<TAG>
}

impl<const N: usize, T: SecretType> Secret<N, T> {
    #[inline(always)]
    ///Access raw data
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl<const N: usize> Secret<N, Binary> {
    #[inline]
    ///Creates new instance
    pub const fn new(data: [u8; N]) -> Self {
        Self {
            data,
            _tag: marker::PhantomData
        }

    }
}


impl<const N: usize> Secret<N, Text> {
    #[inline]
    ///Creates new instance, without checking if content is utf-8
    pub const unsafe fn new(data: [u8; N]) -> Self {
        Self {
            data,
            _tag: marker::PhantomData
        }
    }

    #[inline]
    ///Creates new instance, checking if content is valid utf-8
    pub fn try_new(data: [u8; N]) -> Option<Self> {
        if core::str::from_utf8(&data).is_ok() {
            Some(Self {
                data,
                _tag: marker::PhantomData
            })
        } else {
            None
        }
    }

    #[inline(always)]
    ///Access secret as string
    pub fn as_str(&self) -> &str {
        unsafe {
            core::str::from_utf8_unchecked(self.data())
        }
    }
}

impl<const N: usize, T: SecretType> AsRef<[u8]> for Secret<N, T> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl<const N: usize> AsRef<str> for Secret<N, Text> {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize, T: SecretType> Drop for Secret<N, T> {
    #[inline(always)]
    fn drop(&mut self) {
        utils::secure_memset(&mut self.data, 0);
    }
}

///Secret storage interface
pub trait SecretStorage<const N: usize> {
    ///Indicator of secret type
    type Type: SecretType;

    ///Retrieves decrypted secret value (it is also available as plain method for convenience)
    fn get_secret(&self) -> Secret<N, Self::Type>;
}
