//! PRNG functions

const KEY: u64 = 0x7d8b63f54b86ca59;

#[inline]
///Generates random `u64`
///
///- `counter` - Integer counter which acts as state. Should be increased to generate new
///number.
///- `key` - Integer which in general should be irregular bit pattern with approximately equal
///number of zeros and ones. Generally should be constant, but can be changed when new range of
///random numbers is required.
pub const fn squares(key: u64, counter: u64) -> u64 {
    let mut x = counter.wrapping_mul(key);
    let y = x;
    let z = y.wrapping_add(key);

    x = x.wrapping_mul(x).wrapping_add(y);
    x = (x >> 32) | (x << 32);

    x = x.wrapping_mul(x).wrapping_add(z);
    x = (x >> 32) | (x << 32);

    x = x.wrapping_mul(x).wrapping_add(y);
    x = (x >> 32) | (x << 32);

    x = x.wrapping_mul(x).wrapping_add(z);
    let t = x;
    x = (x >> 32) | (x << 32);

    t ^ (x.wrapping_mul(x).wrapping_add(y) >> 32)
}

///Squares PRNG
///
///Reference: <https://arxiv.org/abs/2004.06278v7>
pub struct Squares {
    key: u64,
    seed: u64,
}

impl Squares {
    ///Creates new instance using default key and provided `seed
    pub const fn new(seed: u64) -> Self {
        Self::with_key(KEY, seed)
    }

    ///Creates new instance using provided `key` and `seed`
    ///
    ///It is recommended to select key with aproxximately equal number of ones and zeros bits
    ///
    ///See samples [here](https://gist.githubusercontent.com/DoumanAsh/a57bc65434702d5d7fb88343c65f3145/raw/a9b45f7155c483f689318ee501222e72be0d66ec/keys)
    pub const fn with_key(key: u64, seed: u64) -> Self {
        Self {
            key,
            seed,
        }
    }

    ///Generates new number, advancing seed
    pub const fn next(&mut self) -> u64 {
        let result = squares(self.key, self.seed);
        self.seed = self.seed.wrapping_add(1);
        result
    }

    ///Generates new number, decreasing seed
    pub const fn back(&mut self) -> u64 {
        let result = squares(self.key, self.seed);
        self.seed = self.seed.wrapping_sub(1);
        result
    }
}
