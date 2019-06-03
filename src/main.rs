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

const CHECKSUM_LENGTH: usize = 4;

const FCT_PUB: [u8; 2] = [0x5f, 0xb1];
const FCT_PRIV: [u8; 2] = [0x64, 0x78];
const EC_PUB: [u8; 2] = [0x59, 0x2a];
const EC_PRIV: [u8; 2] = [0x5d, 0xb6];


const FILEPATH: &str = "names.txt";
const KEYSPATH: &str = "keys.txt";
const B58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYzabcdefghijkmnopqrstuvwxyz";

#[derive(Default)]
struct Config {
    input: String,
    output: String,
    verbose: bool,
    case: bool,
    ec: bool,
    regex_prefix: String,
    pub_prefix: [u8; 2],
    priv_prefix: [u8; 2],
}

fn main() {
    dbg!(current_dir().unwrap());
    let args = parse_args();

    let set = compile_regex(names, case, regex_prefix);
    let mut keys_file = initialise_output_file(output_file);

    loop {
        let keypair = generate_ed25519_keypair();
        let pub_address = readable_address(&pub_prefix, &rcd(keypair.public.to_bytes()));
        if set.is_match(&pub_address){
            let priv_address = readable_address(&priv_prefix, &keypair.secret.to_bytes());
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
            .create(true)
            .append(true)
            .open(Path::new(output_file))
            .expect("Unable to initialise output file")
}

fn parse_args() -> Config {
    let args = get_args();
    let mut config = Config {
        input: args.value_of("Input").unwrap_or(FILEPATH).to_string(),
        output: args.value_of("Output").unwrap_or(KEYSPATH).to_string(),
        verbose: args.is_present("Verbose"),
        case: args.is_present("Ignore Case"),
        ec: args.is_present("Entry Credit Address"),
        ..Default::default()
    };

    config.regex_prefix = if config.ec {"EC[123]"} else {"FA[123]"}.to_string();
    config.pub_prefix = if config.ec {EC_PUB} else {FCT_PUB};
    config.priv_prefix = if config.ec {EC_PRIV} else {FCT_PRIV};

    config

    // let input_file = args.value_of("Input").unwrap_or(FILEPATH);
    // let output_file = args.value_of("Output").unwrap_or(KEYSPATH);
    // let verbose = args.is_present("Verbose");
    // let case = args.is_present("Ignore Case");
    // let ec = args.is_present("Entry Credit Address");
    // let names = read_file(input_file);
    // let regex_prefix = if ec {"EC[123]"} else {"FA[123]"};
    // let pub_prefix = if ec {EC_PUB} else {FCT_PUB};
    // let priv_prefix = if ec {EC_PRIV} else {FCT_PRIV};
    // let rcd = if ec {ec_rcd} else {fct_rcd};
}

fn get_args<'a>() -> ArgMatches<'a>{
    App::new("fct address generator")
            .version(clap::crate_version!())
            .author("Mitchell Berry")
            .about("Creates custom factoid addresses")
            .arg(Arg::with_name("Entry Credit Address")
                .short("e")
                .long("entry-credit")
                .help("Generates entry redit addresses instead of factoid addresses"))
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
            .arg(Arg::with_name("Ignore Case")
                .short("c")
                .long("ignore-case")
                .help("Ignores case when matching addresses, dramatically increases output"))
            .get_matches()
}

fn compile_regex(names: Vec<String>, case_sensitive: bool, prefix: &str) -> RegexSet{
    let mut set = Vec::new();
    let case_flag = if case_sensitive { "(?i)" } else { "" };
    for name in names.iter() {
        set.push(format!(r"^{}{}\w*{}", prefix, name, case_flag));
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

