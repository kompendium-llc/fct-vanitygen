mod files;
mod config;
mod address;
mod matching;

use files::*;
use address::*;
use matching::*;
use config::parse_args;
use rayon::ThreadPoolBuilder;

fn main() {
    
    
    let config = parse_args();
    let names = read_file(&config.input);
    let rcd = if config.ec {ec_rcd} else {fct_rcd};
    let mut keys_file = initialise_output_file(&config.output);
    let set = compile_regex(names, config.case, &config.regex_prefix);
    let pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();

    
    loop {
        pool.install(|| {
            let keypair = generate_ed25519_keypair();
            let pub_address = readable(&config.pub_prefix,
                                        &rcd(keypair.public.to_bytes()));
            if set.is_match(&pub_address){
                let priv_address = readable(&config.priv_prefix,
                                            &keypair.secret.to_bytes());
                write_keys(&mut keys_file, &pub_address, &priv_address);
                if config.verbose {
                    println!("Public Address: {}\nPrivate Address: {}\n",
                            pub_address, priv_address);
                }
            }
        })
    }
}
