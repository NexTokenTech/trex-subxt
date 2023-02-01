use codec::{Decode, Encode};
use sha2::{Digest, Sha256};
use subxt::{
    ext::{
        sp_core::U256,
    },
};

/// One minute in milliseconds.
pub const ONE_MINUTE: u64 = 60 * 1000;
/// Size of aes key
pub const KEY_SIZE: usize = 32;
/// AES NONCE: This nonce must be 12 bytes long.
pub const AES_NONCE: &[u8; 12] = b"unique nonce";
/// 256bit AES key plus 96bit nonce
pub const AES_KEY_MAX_SIZE: usize = 32 + 12;
/// alias for Vec<u8>
pub type ShieldedKey = Vec<u8>;

/// A not-yet-computed attempt to solve the proof of work. Calling the
/// compute method will compute the SHA256 hash and return the seal.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub struct Sha256PrivateKeyTime {
    pub aes_private_key: Vec<u8>,
    pub timestamp: u64,
}

/// Structure containing private key and private_key_time hash
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub struct Sha256PrivateKeyHash {
    pub aes_private_key: Vec<u8>,
    pub hash: Vec<u8>,
}

/// Methods related to hashing and nonce updating in block headers.
pub trait Hash<I, E: Encode> {
    fn hash(&self) -> I;
}

/// Impl Hash trait for Sha256PrivateKeyTime
impl Hash<Vec<u8>, U256> for Sha256PrivateKeyTime {
    fn hash(&self) -> Vec<u8> {
        // digest nonce by hashing with header data.
        let data = &self.encode()[..];
        let mut hasher = Sha256::new();
        hasher.update(&data);
        // convert hash results to integer in little endian order.
        hasher.finalize().as_slice().to_vec()
    }
}