use std::path::Path;
use std::io::prelude::*;
use std::io::{self, BufRead};
use std::fs::{File, OpenOptions};
use regex::RegexSet;
use rand::rngs::OsRng;
use std::env::current_dir;
use ed25519_dalek::Keypair;
use sha2::{Sha256, Sha512, Digest};

mod config;

use config::parse_args;

const CHECKSUM_LENGTH: usize = 4;
const B58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYzabcdefghijkmnopqrstuvwxyz";


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

fn write_keys(keys_file: &mut File, public: &str, private: &str) {
    if let Err(e) = writeln!(keys_file,"{}\n{}\n", &public, &private) {
        eprintln!("Couldn't write to file: {}", e);
    }       
}

fn initialise_output_file(output_file: &str) -> File {
    OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(output_file))
            .expect("Unable to initialise output file")
}





fn compile_regex(names: Vec<String>, case_sensitive: bool, prefix: &str) -> RegexSet{
    let mut set = Vec::new();
    let case_flag = if case_sensitive { "(?i)" } else { "" };
    for name in names.iter() {
        set.push(format!(r"^{}{}{}\w*", prefix, case_flag, name));
    }
    RegexSet::new(&set).unwrap()
}

fn base58_char(c: char)-> Option<char> {
    B58_ALPHABET.chars().find(|x: &char| x == &c)
}

fn valid_base58(prefix: &str) -> bool {
    let mut valid = false;
    for letter in prefix.chars() {
        match base58_char(letter) {
            Some(_) => valid = true,
            None => {valid = false; break;} 
        }
    }
    valid
}

fn read_file(filepath: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    let path = Path::new(filepath);
    let lines = parse_lines(path).expect("Unable to open prefix file");
    for prefix in lines {
        let name = prefix.unwrap();
        if valid_base58(&name) {
            prefixes.push(name);
        }
        else {
            println!("Skipping invalid base58 name: {}", name);
        }
    }
    prefixes
}

fn parse_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
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

