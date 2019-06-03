# FCT-VanityGen

Generates custom Factoid and Entry Credit addresses for use with the Factom protocol.

### Installation
#### Binaries
Download a binary from the releases page.

#### Cargo
```bash
cargo install fct-vanitygen
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





