use clap::{Arg, App, ArgMatches};

const FCT_PUB: [u8; 2] = [0x5f, 0xb1];
const FCT_PRIV: [u8; 2] = [0x64, 0x78];
const EC_PUB: [u8; 2] = [0x59, 0x2a];
const EC_PRIV: [u8; 2] = [0x5d, 0xb6];

const FILEPATH: &str = "names.txt";
const KEYSPATH: &str = "keys.txt";

#[derive(Default)]
pub struct Config {
    pub input: String,
    pub output: String,
    pub verbose: bool,
    pub threads: u8,
    pub case: bool,
    pub ec: bool,
    pub regex_prefix: String,
    pub pub_prefix: [u8; 2],
    pub priv_prefix: [u8; 2],
}

pub fn parse_args() -> Config {
    let args = get_args();
    let mut config = Config {
        input: args.value_of("Input File").unwrap_or(FILEPATH).to_string(),
        output: args.value_of("Output File").unwrap_or(KEYSPATH).to_string(),
        verbose: args.is_present("Verbose"),
        threads: args.value_of("Threads").unwrap_or("2")
                        .parse::<u8>().expect("Invalid Thread Number"),
        case: args.is_present("Ignore Case"),
        ec: args.is_present("Entry Credit Address"),
        ..Default::default()
    };
    config.regex_prefix = if config.ec {"EC[123]"} else {"FA[123]"}.to_string();
    config.pub_prefix = if config.ec {EC_PUB} else {FCT_PUB};
    config.priv_prefix = if config.ec {EC_PRIV} else {FCT_PRIV};
    config
}

fn get_args<'a>() -> ArgMatches<'a>{
    App::new("fct address generator")
            .version(clap::crate_version!())
            .author("©Mitchell Berry 2019 - MIT Licensed")
            .about("\nCreates custom addresses for use with the Factom protocol")
            .arg(Arg::with_name("Entry Credit Address")
                .short("e")
                .long("entry-credit")
                .help("Generates entry credit addresses instead of factoid addresses"))
            .arg(Arg::with_name("Threads")
                .short("t")
                .long("threads")
                .takes_value(true)
                .help("Number of simultaneous threads to use. Default: 2"))
            .arg(Arg::with_name("Verbose")
                .short("v")
                .long("verbose")
                .help("Prints matched address and private key"))
            .arg(Arg::with_name("Input File")
                .short("i")
                .long("input")
                .takes_value(true)
                .help("Sets the input file of names seperated by newlines. Default: names.txt"))
            .arg(Arg::with_name("Output File")
                .short("o")
                .long("output")
                .takes_value(true)
                .help("Sets the output file for matched keys. Default: keys.txt"))
            .arg(Arg::with_name("Ignore Case")
                .short("c")
                .long("ignore-case")
                .help("Ignores case when matching addresses"))
            .get_matches()
}