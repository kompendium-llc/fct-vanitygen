use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use sha2::{Sha256, Sha512, Digest};

const CHECKSUM_LENGTH: usize = 4;

pub fn generate_ed25519_keypair()-> Keypair {
    let mut csprng: OsRng = OsRng::new().unwrap();
    Keypair::generate::<Sha512, _>(&mut csprng)  
}

pub fn fct_rcd(key: [u8; 32]) -> [u8; 32]{
    let mut input = [0x1; 33];
    for (i, byte) in key.iter().enumerate() {
        input[i+1] = *byte;
    }
    double_sha(&input)
}

// No op. RCD isnt used for EC addresses.
pub fn ec_rcd(key: [u8; 32])-> [u8; 32] {
    key
}

fn double_sha(input: &[u8])-> [u8; 32] {
    let h1 = Sha256::digest(input);
    let h2 = Sha256::digest(&h1);
    slice_to_array(&h2)
}

fn slice_to_array(slice: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in slice.iter().enumerate(){
        out[i] = *byte;
    }
    out
}

pub fn readable_address(prefix: &[u8], raw: &[u8])-> String {
    let (mut key, mut output) = (Vec::new(), Vec::new());
    key.extend_from_slice(prefix);
    key.extend_from_slice(&raw);
    let checksum = &double_sha(&key)[..CHECKSUM_LENGTH];
    output.extend_from_slice(&key);
    output.extend_from_slice(checksum);
    bs58::encode(output).into_string()
}
