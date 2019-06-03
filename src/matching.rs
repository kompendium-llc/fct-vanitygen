use regex::RegexSet;

const B58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYzabcdefghijkmnopqrstuvwxyz";

pub fn compile_regex(names: Vec<String>, case_sensitive: bool, prefix: &str) -> RegexSet{
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

pub fn valid_base58(prefix: &str) -> bool {
    let mut valid = false;
    for letter in prefix.chars() {
        match base58_char(letter) {
            Some(_) => valid = true,
            None => {valid = false; break;} 
        }
    }
    valid
}