use num_bigint::{BigUint, RandBigInt};
use sha2::{Sha256, Sha512, Digest};
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;

const key_length: usize = 32;
const checksum_length: usize = 4;

const pub_prefix: [u8; 2] = [0x5f, 0xb1];
const priv_prefix: [u8; 2] = [0x64, 0x78];

const filepath: &str = "prefixes";


fn main() {
    let keypair = generate_ed25519_keypair();
    let pub_address = human_readable_address(&pub_prefix, &rcd(keypair.public.to_bytes()));
    let priv_address = human_readable_address(&priv_prefix, &keypair.secret.to_bytes());
    println!("{}\n{}", pub_address, priv_address);

}

fn generate_256_uint()-> BigUint {
    let mut rng = rand::thread_rng();
    rng.gen_biguint(256)
}

fn generate_ed25519_keypair()-> Keypair {
    let mut csprng: OsRng = OsRng::new().unwrap();
    Keypair::generate::<Sha512, _>(&mut csprng)  
}

fn rcd(key: [u8; 32])-> [u8; 32]{
    let mut input = [0x1; 33];
    for (i, byte) in key.iter().enumerate() {
        input[i+1] = *byte;
    }
    double_sha(&input)
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

fn human_readable_address(prefix: &[u8], raw: &[u8])-> String {
    let (mut key, mut output) = (Vec::new(), Vec::new());
    key.extend_from_slice(prefix);
    key.extend_from_slice(&raw[..key_length]);
    let checksum = &double_sha(&key)[..checksum_length];
    output.extend_from_slice(&key);
    output.extend_from_slice(checksum);
    bs58::encode(output).into_string()
}

