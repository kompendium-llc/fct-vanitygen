use std::path::Path;
use std::io::prelude::*;
use std::io::{self, BufRead};
use std::fs::{File, OpenOptions};
use super::valid_base58;

pub fn read_file(filepath: &str) -> Vec<String> {
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

pub fn initialise_output_file(output_file: &str) -> File {
    OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(output_file))
            .expect("Unable to initialise output file")
}

pub fn write_keys(keys_file: &mut File, public: &str, private: &str) {
    if let Err(e) = writeln!(keys_file,"{}\n{}\n", &public, &private) {
        eprintln!("Couldn't write to file: {}", e);
    }       
}

