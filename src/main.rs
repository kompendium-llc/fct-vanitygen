use num_bigint::{BigUint, RandBigInt};
use sha2::{Sha256, Digest};

const key_length: usize = 32;
const checksum_length: usize = 4;


fn main() {
    let mut rng = rand::thread_rng();
    let unsigned: BigUint = rng.gen_biguint(256);
    println!("{}", unsigned);
}

fn rcd(key: [u8; 32])-> [u8; 32]{
    let mut input = [0x1; 33];
    for (i, byte) in key.iter().enumerate() {
        input[i] = *byte;
    }
    shad(&input)
}

fn shad(input: &[u8])-> [u8; 32] {
    let h1 = Sha256::digest(input);
    let h2 = Sha256::digest(&h1[..]);
    slice_to_array(&h2[..])
}

fn slice_to_array(slice: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in slice.iter().enumerate(){
        out[i] = *byte;
    }
    out
}