# FCT-VanityGen

Generates custom Factoid and Entry Credit addresses for use with the Factom protocol. 

Factoid addresses will range between `FA1y5ZGuHSLmf2TqNf6hVMkPiNGyQpQDTFJvDLRkKQaoPo4bmbgu` and `FA3upjWMKHmStAHR5ZgKVK4zVHPb8U74L2wzKaaSDQEonHajiLeq`

Entry Credit addresses will range between `EC1m9mouvUQeEidmqpUYpYtXg8fvTYi6GNHaKg8KMLbdMBrFfmUa` and `EC3htx3MxKqKTrTMYj4ApWD8T3nYBCQw99veRvH1FLFdjgN6GuNK`

This tool ignores the first 3 characters of an address.

### Installation
#### Binaries
Pre-built binaries are available on the [releases](https://github.com/MitchellBerry/fctutils/releases/tag/v0.1.0) page.

#### Cargo
```bash
cargo install fct-vanitygen
```

#### Building from source
```bash
git clone https://github.com/MitchellBerry/fctutils.git
cd fct-vanitygen
cargo build --release
```

### Usage

The program will by default read from a newline seperated file called `names.txt` placed in the same folder. Any matches will be written to an output file called `keys.txt`. These defaults can be changed with the `-i` and `-o` flags respectively. 

Names in the names.txt file will be treated as case sensitive, to match all upper and lower-case variations use the `-c` flag.

By default 2 threads will be used, to modify this use the `-t` flag. Eg. `-t 4`

To print out secret and public keys to the console use the verbose flag `-v`.

The help flag prints out all the options:

```
USAGE:
    fct-vanitygen.exe [FLAGS] [OPTIONS]

FLAGS:
    -e, --entry-credit    Generates entry credit addresses instead of factoid addresses
    -c, --ignore-case     Ignores case when matching addresses
    -v, --verbose         Prints matched address and private key
    -h, --help            Prints help information
    -V, --version         Prints version information

OPTIONS:
    -i, --input <Input File>      Sets the input file of names seperated by newlines. Default: names.txt
    -o, --output <Output File>    Sets the output file for matched keys. Default: keys.txt
    -t, --threads <Threads>       Number of simultaneous threads to use. Default: 2
```





