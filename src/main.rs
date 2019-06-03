use std::path::Path;
use std::io::prelude::*;
use std::io::{self, BufRead};
use std::fs::{File, OpenOptions};
use regex::RegexSet;
use rand::rngs::OsRng;
use std::env::current_dir;
use ed25519_dalek::Keypair;
use clap::{Arg, App, ArgMatches};
use sha2::{Sha256, Sha512, Digest};

const KEY_LENGTH: usize = 32;
const CHECKSUM_LENGTH: usize = 4;

const PUB_PREFIX: [u8; 2] = [0x5f, 0xb1];
const PRIV_PREFIX: [u8; 2] = [0x64, 0x78];

const FILEPATH: &str = "target\\debug\\names.txt";
const KEYSPATH: &str = "keys.txt";
const B58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYzabcdefghijkmnopqrstuvwxyz";

struct Args {
    input: Box<Path>,
    output: Box<Path>,
    verbose: bool
}

fn main() {
    dbg!(current_dir().unwrap());
    let args = parse_args();
    let input_file = args.value_of("Input").unwrap_or(FILEPATH);
    let output_file = args.value_of("Output").unwrap_or(KEYSPATH);
    let verbose = args.is_present("Verbose");
    let names = read_file(input_file);
    let set = compile_regex(names);
    let mut keys_file = initialise_output_file(output_file);

    loop {
        let keypair = generate_ed25519_keypair();
        let pub_address = readable_address(&PUB_PREFIX, &rcd(keypair.public.to_bytes()));
        if check_match(&pub_address, &set){
            let priv_address = readable_address(&PRIV_PREFIX, &keypair.secret.to_bytes());
            write_keys(&mut keys_file, &pub_address, &priv_address);
            if verbose {
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
            .append(true)
            .open(output_file)
            .expect("Unable to initialise output file")
}

fn parse_args<'a>() -> ArgMatches<'a>{
    App::new("fct address generator")
            .version(clap::crate_version!())
            .author("Mitchell Berry")
            .about("Creates custom factoid addresses")
            .arg(Arg::with_name("Verbose")
                .short("v")
                .long("verbose")
                .help("Prints matched address and private key"))
            .arg(Arg::with_name("Input")
                .short("i")
                .long("input")
                .takes_value(true)
                .help("Sets the input file to use (Default: names.txt)"))
            .arg(Arg::with_name("Output")
                .short("o")
                .long("output")
                .takes_value(true)
                .help("Sets the output file for matched keys (Default: keys.txt)"))
            .get_matches()
}

fn compile_regex(names: Vec<String>) -> RegexSet{
    let mut set = Vec::new();
    for name in names.iter() {
        set.push(format!(r"^FA[123]{}\w*", name));
    }
    RegexSet::new(&set).unwrap()
}

fn check_match(pub_address: &str, set: &RegexSet) -> bool {
    set.is_match(pub_address)
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

fn readable_address(prefix: &[u8], raw: &[u8])-> String {
    let (mut key, mut output) = (Vec::new(), Vec::new());
    key.extend_from_slice(prefix);
    key.extend_from_slice(&raw[..KEY_LENGTH]);
    let checksum = &double_sha(&key)[..CHECKSUM_LENGTH];
    output.extend_from_slice(&key);
    output.extend_from_slice(checksum);
    bs58::encode(output).into_string()
}

