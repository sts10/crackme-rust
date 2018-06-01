extern crate ring;
extern crate time;
use std::time::SystemTime;

use ring::{digest, pbkdf2}; // https://briansmith.org/rustdoc/ring/pbkdf2/index.html
use std::fmt::Write;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN; // or just put 32
pub type Credential = [u8; CREDENTIAL_LEN];

fn main() {
    // let's try to crack the 100th password on the list
    let password = "aardvark aardvark accolade";
    // first, we'll derive the hash of this password
    let salt = "00bb202b205f064e30f6fae101162a2e";
    let iterations = 100000;
    let derived = derive(iterations, salt, password);

    // now, let's try to crack that derived hash
    let start_time = SystemTime::now();
    run_crack(iterations, salt, &derived);
    let end_time = SystemTime::now();
    print_benchmark_info(start_time, end_time);
}

fn run_crack(given_iterations: u32, given_salt: &str, given_derived: &str) -> Option<String> {
    let words = make_word_list("agile_words.txt");

    for word1 in &words {
        for word2 in &words {
            for word3 in &words {
                let password_guess = format!("{} {} {}", word1, word2, word3);
                if guess(&password_guess, given_iterations, given_salt, given_derived) {
                    println!("Found it! {}", password_guess);
                    return Some(password_guess);
                } else {
                    println!("Tried {} unsuccessfully", password_guess);
                }
            }
        }
    }
    None
}

fn make_word_list(filename: &str) -> Vec<String> {
    let mut words_vec: Vec<String> = [].to_vec();

    let f = File::open(filename).unwrap();
    let file = BufReader::new(&f);
    for line in file.lines() {
        let line = line.unwrap();
        words_vec.push(line);
    }
    words_vec
}
fn guess(password_guess: &str, iterations: u32, salt: &str, derived: &str) -> bool {
    derive(iterations, salt, password_guess) == derived
}
fn derive(iterations: u32, salt: &str, password: &str) -> String {
    // first, make salt_vec (thanks to https://stackoverflow.com/a/44532957)
    let mut salt_vec = vec![];
    for i in 0..(salt.len() / 2) {
        let mut byte = u8::from_str_radix(&salt[2 * i..2 * i + 2].to_string(), 16).unwrap();
        salt_vec.push(byte);
    }

    let mut derived_hash: Credential = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        DIGEST_ALG,
        iterations,
        &salt_vec,
        password.as_bytes(),
        &mut derived_hash,
    );

    // println!("out: {:?}", derived_hash);

    let mut lower = String::new();
    for &byte in derived_hash.iter() {
        write!(&mut lower, "{:02x}", byte).expect("Unable to write byte");
    }
    return lower;
}

fn print_benchmark_info(start_time: std::time::SystemTime, end_time: std::time::SystemTime) {
    let duration = end_time.duration_since(start_time).expect("Time backwards");

    let duration_ms = duration.as_secs() * 1000 + duration.subsec_nanos() as u64 / 1_000_000;
    println!("I just ran for {:?} milliseconds", duration_ms);

    let word_count: u64 = 18328;
    let total_passwords_to_check: u64 = word_count * word_count * word_count;
    let ms_in_a_year = 1000 * 60 * 60 * 24 * 365;
    let portion_of_total_work: u64 = total_passwords_to_check / 100;
    println!("portion_of_total_work is {}", portion_of_total_work);
    let estimated_run_through = duration_ms * portion_of_total_work / ms_in_a_year;
    println!(
        "Estimated full run through: {:?} years",
        estimated_run_through
    );
    println!("Lets say I figured out how to run this on my 8 threads, and that the mystery password is halfway through the list. That's still {:?} years.",
             estimated_run_through / 16);
}

#[test]
fn derive_example1() {
    let password = "tanbark artistic callus";
    let salt = "00bb202b205f064e30f6fae101162a2e";
    let derived = "91976be95cd28e55e580ee9f69a2139202a9b65eabfbbf33c99bc42e3665564d";
    assert_eq!(derive(100000, salt, password), derived);
}

#[test]
fn derive_example2() {
    let password = "node tuesday imperial";
    let salt = "e628cf2534f66ca172b1ebd82394563a";
    let derived = "703daeb5f1d90feaee8a62273eedbe539e1c7db158f3d720ab9264e3e8e08e6a";
    assert_eq!(derive(100000, salt, password), derived);
}

#[test]
fn derive_example3() {
    let password = "ambulant horsefly capstone";
    let salt = "5ed20a9710cddc0278cbb345c5a4ac3d";
    let derived = "524098d90da74ed38cb86a5ebf5f4cecd39e52d200d7c32b4606731d5696b3d5";
    assert_eq!(derive(100000, salt, password), derived);
}

#[test]
fn guess_example1() {
    let incorrect_password = "smith artistic callus";
    let correct_password = "tanbark artistic callus";

    let salt = "00bb202b205f064e30f6fae101162a2e";
    let derived = "91976be95cd28e55e580ee9f69a2139202a9b65eabfbbf33c99bc42e3665564d";

    assert_eq!(guess(incorrect_password, 100000, salt, derived), false);
    assert_eq!(guess(correct_password, 100000, salt, derived), true);
}

#[test]
fn crack_test1() {
    let password = "aardvark aardvark abandon";
    let salt = "00bb202b205f064e30f6fae101162a2e";
    let iterations = 100000;
    let derived = derive(iterations, salt, password);

    assert_eq!(run_crack(iterations, salt, &derived).unwrap(), password);
}

// #[test]
// fn crack_test2() {
//     let password = "aardvark abaci meeting";
//     let salt = "00bb202b205f064e30f6fae101162a2e";
//     let iterations = 100000;
//     let derived = derive(iterations, salt, password);

//     assert_eq!(run_crack(iterations, salt, &derived), password);
// }
