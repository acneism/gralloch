//! Cryptographic hashes of the raw sample bytes.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

pub fn compute(bytes: &[u8]) -> Hashes {
    Hashes {
        md5: hex::encode(Md5::digest(bytes)),
        sha1: hex::encode(Sha1::digest(bytes)),
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}
