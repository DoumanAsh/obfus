use obfus::crypto;
use obfus::shuffle::FisherYates;
use obfus::utils::secure_memset;

fn inner_should_validate_fisher_yates_shuffle_variety(shuffle: FisherYates) {
    let mut buffer = [0; 1024];
    for idx in 0..buffer.len() {
        if idx % 2 == 0 {
            buffer[idx] = b'0' + (idx % ((b'9' - b'0') as usize)) as u8;
        } else {
            buffer[idx] = b'A' + (idx % ((b'Z' - b'A') as usize)) as u8;
        }

        let mut reversed = [0; 1024];
        reversed[..idx].copy_from_slice(&buffer[..idx]);
        shuffle.shuffle(&mut reversed);
        if idx > 1 {
            assert_ne!(core::str::from_utf8(&buffer[..idx]).unwrap(), core::str::from_utf8(&reversed[..idx]).unwrap());
        }
        shuffle.reverse(&mut reversed);
        assert_eq!(core::str::from_utf8(&buffer[..idx]).unwrap(), core::str::from_utf8(&reversed[..idx]).unwrap());
    }
}

#[test]
fn should_handle_zero_fisher_yates_shuffle() {
    const SHUFFLE: FisherYates = FisherYates::with_seed(1);

    SHUFFLE.shuffle_const([]);
    SHUFFLE.reverse_const([]);
}

#[test]
fn should_validate_fisher_yates_shuffle() {
    const SHUFFLE: FisherYates = FisherYates::with_seed(1);

    const REVERSED: [u8; 4] = SHUFFLE.shuffle_const(*b"test");
    const UNREVERSED: [u8; 4] = SHUFFLE.reverse_const(REVERSED);

    let expected_text = "hello world";
    let mut buffer = [0; 11];
    buffer.copy_from_slice(expected_text.as_bytes());

    SHUFFLE.shuffle(&mut buffer);
    SHUFFLE.reverse(&mut buffer);

    assert_eq!(expected_text, core::str::from_utf8(&buffer).unwrap());
    assert_eq!("test", core::str::from_utf8(&UNREVERSED).unwrap());
}

#[cfg_attr(miri, ignore)]
#[test]
fn should_validate_fisher_yates_shuffle_variety() {
    const SHUFFLE: FisherYates = FisherYates::with_seed(1);

    inner_should_validate_fisher_yates_shuffle_variety(SHUFFLE);
}

#[test]
fn should_validate_fisher_yates_shuffle_wrapping() {
    const SHUFFLE: FisherYates = FisherYates::with_seed(u64::MAX - 1);

    const REVERSED: [u8; 4] = SHUFFLE.shuffle_const(*b"test");
    const UNREVERSED: [u8; 4] = SHUFFLE.reverse_const(REVERSED);

    let expected_text = "hello world";
    let mut buffer = [0; 11];
    buffer.copy_from_slice(expected_text.as_bytes());

    SHUFFLE.shuffle(&mut buffer);
    SHUFFLE.reverse(&mut buffer);

    assert_eq!(expected_text, core::str::from_utf8(&buffer).unwrap());
    assert_eq!("test", core::str::from_utf8(&UNREVERSED).unwrap());
}

#[cfg_attr(miri, ignore)]
#[test]
fn should_validate_fisher_yates_shuffle_wrapping_variety() {
    const SHUFFLE: FisherYates = FisherYates::with_seed(u64::MAX - 1);

    inner_should_validate_fisher_yates_shuffle_variety(SHUFFLE);
}

#[cfg_attr(miri, ignore)]
#[test]
fn should_validate_fisher_yates_shuffle_various_seeds() {
    for seed in 0..16 {
        println!("seed={seed}");
        inner_should_validate_fisher_yates_shuffle_variety(FisherYates::with_seed(seed));
    }

    for seed in u64::MAX-16..u64::MAX {
        println!("seed={seed}");
        inner_should_validate_fisher_yates_shuffle_variety(FisherYates::with_seed(seed));
    }
}

#[test]
fn should_verify_secure_memset() {
    let mut buffer: [u8; 0] = [];
    secure_memset(&mut buffer, 1);
    let mut buffer = [255u8; 15];
    secure_memset(&mut buffer, 1);
    assert_eq!(buffer, [1u8; 15]);
}

#[test]
fn should_verify_buffer_api() {
    use aes_gcm::aead::Buffer;

    let mut buffer = crypto::Buffer::<22>::new();
    assert!(buffer.is_empty());
    assert_eq!(buffer.len(), 0);

    //Initial insert
    buffer.extend_from_slice(b"1234567891").expect("Success");
    assert!(!buffer.is_empty());
    assert_eq!(buffer.len(), 10);
    assert_eq!(buffer.data(), b"1234567891");

    //New insert
    buffer.extend_from_slice(b"asdfghjkl;").expect("Success");
    assert!(!buffer.is_empty());
    assert_eq!(buffer.len(), 20);
    assert_eq!(buffer.data(), b"1234567891asdfghjkl;");

    //Fit buffer
    buffer.extend_from_slice(b"123").expect_err("Buffer overflow");
    buffer.extend_from_slice(b"12").expect("Fit buffer");
    assert!(!buffer.is_empty());
    assert_eq!(buffer.len(), 22);
    assert_eq!(buffer.data(), b"1234567891asdfghjkl;12");

    //Make sure buffer handles inserts at full capacity too
    buffer.extend_from_slice(&[]).expect("Fit buffer");
    buffer.extend_from_slice(b"1").expect_err("Buffer overflow");

    //Truncate to free one byte
    buffer.truncate(21);
    assert!(!buffer.is_empty());
    assert_eq!(buffer.len(), 21);
    assert_eq!(buffer.data(), b"1234567891asdfghjkl;1");

    //Try to insert over capacity after truncate
    buffer.extend_from_slice(b"23").expect_err("Buffer overflow");
    assert!(!buffer.is_empty());
    assert_eq!(buffer.len(), 21);
    assert_eq!(buffer.data(), b"1234567891asdfghjkl;1");

    //Insert to full capacity again
    buffer.extend_from_slice(b"3").expect("Fit buffer");
    assert!(!buffer.is_empty());
    assert_eq!(buffer.len(), 22);
    assert_eq!(buffer.data(), b"1234567891asdfghjkl;13");
}

#[test]
fn should_verify_crypto_api() {
    use aes_gcm::aead::Buffer;

    const DATA: &str = "data";
    const BUFFER_SIZE: usize = crypto::required_buffer_size(DATA.len());
    const NONCE: [u8; 12] = [2; 12];
    type DataBuffer = crypto::Buffer<BUFFER_SIZE>;

    let crypto = crypto::Crypto::new([1; 32]);

    let mut buffer = DataBuffer::new();
    buffer.extend_from_slice(DATA.as_bytes()).expect("success");

    crypto.encrypt(NONCE, &mut buffer).expect("to encrypt");
    assert_eq!(buffer.len(), BUFFER_SIZE);
    assert_ne!(&buffer.data()[..DATA.len()], DATA.as_bytes());

    crypto.decrypt([0; 12], &mut buffer).expect_err("cannot decrypt with invalid nonce");
    assert_eq!(buffer.len(), BUFFER_SIZE);

    crypto.decrypt(NONCE, &mut buffer).expect("to decrypt");
    assert_eq!(buffer.len(), DATA.len());
    assert_eq!(buffer.data(), DATA.as_bytes());
}
