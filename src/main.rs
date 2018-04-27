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
    // might be able to just do 'let salt = "e628cf2534f66ca172b1ebd82394563a".as_bytes();`
    // but I'm not sure
    let mut salt_vec = Vec::new(); // gonna be Vec<u8>
    for c in salt.chars() {
        salt_vec.push(c as u8);
    }

    println!("salt vec is {:?}", salt_vec);

    let iterations = 100000;
    let mut to_store: Credential = [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        DIGEST_ALG,
        iterations,
        &salt_vec,
        password.as_bytes(),
        &mut to_store,
    );

    println!("out: {:?}", to_store);

    let mut lower = String::new();
    for &byte in to_store.iter() {
        write!(&mut lower, "{:x}", byte);
    }

    println!("as string {}", lower);
    // I get e6941d24abc7fb69af91d69b8710175c3f7ac67969ec1fa8f7cf819c8d3e7
    println!("should be 91976be95cd28e55e580ee9f69a2139202a9b65eabfbbf33c99bc42e3665564d");
    // according to https://github.com/agilebits/crackme/blob/master/doc/answers-2018-03-30.json#L9
}
