use num_bigint::{BigUint, RandBigInt};
use sha2::{Sha256, Sha512, Digest};
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

const KEY_LENGTH: usize = 32;
const CHECKSUM_LENGTH: usize = 4;

const PUB_PREFIX: [u8; 2] = [0x5f, 0xb1];
const PRIV_PREFIX: [u8; 2] = [0x64, 0x78];

const FILEPATH: &str = "prefixes";
const B58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYzabcdefghijkmnopqrstuvwxyz";


fn main() {
    let keypair = generate_ed25519_keypair();
    let pub_address = human_readable_address(&PUB_PREFIX, &rcd(keypair.public.to_bytes()));
    let priv_address = human_readable_address(&PRIV_PREFIX, &keypair.secret.to_bytes());
    println!("{}\n{}", pub_address, priv_address);

}

fn base58_char(c: char)-> Option<char> {
    B58_ALPHABET.chars().find(|x: &char| x == &c)
}

fn is_valid_base58(prefix: String) -> bool {
    let mut valid = false;
    for letter in prefix.chars() {
        match base58_char(letter) {
            Some(_) => valid = true,
            None => {valid = false; break;} 
        }
    }
    valid
}

fn read_file() -> Vec<String> {
    let mut prefixes = Vec::new();
    let lines = parse_lines(FILEPATH).expect("Unable to open prefixes file");
    for prefix in lines {
        let word = prefix.unwrap();
        if word.is_ascii() {
            prefixes.push(word);
        }
        
    }
    prefixes
}

fn prefixes_as_bytes(prefixes: Vec<String>) -> Vec<Vec<u8>> {
    let mut prefix_bytes = Vec::new(); 
    for prefix in prefixes {
        prefix_bytes.push(prefix.as_bytes().to_vec())
    }
    prefix_bytes
}

fn parse_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
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

fn assemble_address_bytes(prefix: &[u8], raw: &[u8])-> Vec<u8> {
    let (mut key, mut output) = (Vec::new(), Vec::new());
    key.extend_from_slice(prefix);
    key.extend_from_slice(&raw[..KEY_LENGTH]);
    let checksum = &double_sha(&key)[..CHECKSUM_LENGTH];
    output.extend_from_slice(&key);
    output.extend_from_slice(checksum);
    output
}

fn human_readable_address(prefix: &[u8], raw: &[u8])-> String {
    let (mut key, mut output) = (Vec::new(), Vec::new());
    key.extend_from_slice(prefix);
    key.extend_from_slice(&raw[..KEY_LENGTH]);
    let checksum = &double_sha(&key)[..CHECKSUM_LENGTH];
    output.extend_from_slice(&key);
    output.extend_from_slice(checksum);
    bs58::encode(output).into_string()
}

