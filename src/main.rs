extern crate ring;

use ring::{digest, pbkdf2};
// https://briansmith.org/rustdoc/ring/pbkdf2/index.html
use std::fmt::Write;

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN; // or just put 32
pub type Credential = [u8; CREDENTIAL_LEN];

fn main() {
    let password = "tanbark artistic callus";
    let salt = "00bb202b205f064e30f6fae101162a2e";
    // let password = "node tuesday imperial";
    // let salt = "e628cf2534f66ca172b1ebd82394563a";
    let iterations = 100000;

    derive(iterations, salt, password);
}
fn derive(iterations: u32, salt: &str, password: &str) {
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
        write!(&mut lower, "{:02x}", byte);
    }

    println!("as string {}", lower);
    println!("should be 91976be95cd28e55e580ee9f69a2139202a9b65eabfbbf33c99bc42e3665564d");
    println!("should be 703daeb5f1d90feaee8a62273eedbe539e1c7db158f3d720ab9264e3e8e08e6a");
    // according to https://github.com/agilebits/crackme/blob/master/doc/answers-2018-03-30.json#L9
    //
    // return lower.as_str();
}
