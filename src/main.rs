

use rand::rngs::OsRng;
use std::env::current_dir;
use ed25519_dalek::Keypair;
use sha2::{Sha256, Sha512, Digest};

mod config;
mod files;
mod matching;

use config::parse_args;
use files::*;
use matching::*;

const CHECKSUM_LENGTH: usize = 4;

fn main() {
    dbg!(current_dir().unwrap());
    let config = parse_args();
    let names = read_file(&config.input);
    let set = compile_regex(names, config.case, &config.regex_prefix);
    let mut keys_file = initialise_output_file(&config.output);
    let rcd = if config.ec {ec_rcd} else {fct_rcd};

    loop {
        let keypair = generate_ed25519_keypair();
        let pub_address = readable_address(&config.pub_prefix, &rcd(keypair.public.to_bytes()));
        if set.is_match(&pub_address){
            let priv_address = readable_address(&config.priv_prefix, &keypair.secret.to_bytes());
            write_keys(&mut keys_file, &pub_address, &priv_address);
            if config.verbose {
                println!("Public Address: {}\nPrivate Address: {}\n",
                         pub_address, priv_address);
            }
        }
    }
}



fn generate_ed25519_keypair()-> Keypair {
    let mut csprng: OsRng = OsRng::new().unwrap();
    Keypair::generate::<Sha512, _>(&mut csprng)  
}

fn fct_rcd(key: [u8; 32]) -> [u8; 32]{
    let mut input = [0x1; 33];
    for (i, byte) in key.iter().enumerate() {
        input[i+1] = *byte;
    }
    double_sha(&input)
}

// Dummy function, returns key. Rcd isnt used for EC addresses.
fn ec_rcd(key: [u8; 32])-> [u8; 32] {
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

fn readable_address(prefix: &[u8], raw: &[u8])-> String {
    let (mut key, mut output) = (Vec::new(), Vec::new());
    key.extend_from_slice(prefix);
    key.extend_from_slice(&raw);
    let checksum = &double_sha(&key)[..CHECKSUM_LENGTH];
    output.extend_from_slice(&key);
    output.extend_from_slice(checksum);
    bs58::encode(output).into_string()
}

