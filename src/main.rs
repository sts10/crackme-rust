extern crate ring;

use ring::{digest, pbkdf2};
// https://briansmith.org/rustdoc/ring/pbkdf2/index.html
use std::fmt::Write;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN; // or just put 32
pub type Credential = [u8; CREDENTIAL_LEN];

fn main() {
    let salt = "00bb202b205f064e30f6fae101162a2e";
    let derived = "dc61e18eaa1add3e555cd493acb9088449d2ac07a739eec15cd299a327bf45b0";
    // let password = "node tuesday imperial";
    // let salt = "e628cf2534f66ca172b1ebd82394563a";
    let iterations = 100000;
    run_crack2(iterations, salt, derived);
}
// fn run_crack(given_iterations: u32, given_salt: &str, given_derived: &str) -> String {
//     let first_words = make_word_list("agile_words.txt");
//     let second_words = make_word_list("agile_words.txt");
//     let third_words = make_word_list("agile_words.txt");
//     for first_word in first_words {
//         for second_word in second_words {
//             for third_word in third_words {
//                 let password_guess = first_word + " " + &second_word + " " + &third_word;
//                 if guess(&password_guess, given_iterations, given_salt, given_derived) {
//                     println!("Found it! {}", password_guess);
//                     return password_guess;
//                 }
//             }
//         }
//     }
//     return "Didn't crack".to_string();
// }

fn run_crack2(given_iterations: u32, given_salt: &str, given_derived: &str) {
    let words1 = make_word_list("agile_words.txt");
    let words2 = make_word_list("agile_words.txt");
    let words3 = make_word_list("agile_words.txt");
    let mut password_guess = String::new();
    let mut password_guess_vec: Vec<&str> = [].to_vec();

    for i in 0..words1.len() {
        let first_word = &words1[i];
        password_guess_vec.push(first_word);
        for j in 0..words2.len() {
            let second_word = &words2[j];
            // password_guess_vec.push(" ");
            password_guess_vec.push(second_word);
            for k in 0..words3.len() {
                // password_guess_vec.push(" ");
                password_guess_vec.push(&words3[k]);
                password_guess = password_guess_vec.join(" ");
                // password_guess = first_word + " " + &second_word + " " + &words3[k];
                if guess(&password_guess, given_iterations, given_salt, given_derived) {
                    println!("Found it! {}", password_guess);
                // return password_guess;
                } else {
                    println!("Tried {} unsuccessfully", password_guess);
                    // clear third_word
                    password_guess_vec.truncate(2);
                    println!("vec is now {:?}", password_guess_vec);
                }
            }
            // clear second_word
            password_guess_vec.truncate(1);
            println!("vec is now {:?}", password_guess_vec);
        }
        // clear first_word
        password_guess_vec = [].to_vec();
    }
    // let fail = "didn't crack";
    // return fail;
}

fn make_word_list(filename: &str) -> (Vec<String>) {
    let mut words_vec: Vec<String> = [].to_vec();

    let f = File::open(filename).unwrap();
    let file = BufReader::new(&f);
    for line in file.lines() {
        let l = line.unwrap();
        words_vec.push(String::from(l));
    }
    return words_vec;
}
fn guess(password_guess: &str, iterations: u32, salt: &str, derived: &str) -> bool {
    if derive(iterations, salt, password_guess) == derived {
        return true;
    } else {
        return false;
    }
}
fn derive(iterations: u32, salt: &str, password: &str) -> String {
    // first, make salt_vec (thanks to https://stackoverflow.com/a/44532957)
    let mut salt_vec = Vec::new();
    for i in 0..(salt.len() / 2) {
        let mut byte = u8::from_str_radix(&salt[2 * i..2 * i + 2].to_string(), 16).unwrap();
        salt_vec.push(byte);
    }

    println!("------------------");
    let mut derived_hash: Credential = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        DIGEST_ALG,
        iterations,
        &salt_vec,
        password.as_bytes(),
        &mut derived_hash,
    );

    // println!("out: {:?}", derived_hash);
    // println!("out length: {}", derived_hash.len());

    let mut lower = String::new();
    for &byte in derived_hash.iter() {
        write!(&mut lower, "{:02x}", byte).expect("Unable to write byte");
    }
    return lower;
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
