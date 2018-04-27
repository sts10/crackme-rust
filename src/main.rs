extern crate ring;

use ring::{digest, pbkdf2};
use std::fmt::Write;
// use std::collections::HashMap;

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

fn main() {
    let password = "tanbark artistic callus";
    let salt = "00bb202b205f064e30f6fae101162a2e".as_bytes();
    let iterations = 100000;
    let mut to_store: Credential = [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        DIGEST_ALG,
        iterations,
        &salt,
        password.as_bytes(),
        &mut to_store,
    );

    // println!("out: {:?}", to_store);

    let mut s = String::new();
    for &byte in to_store.iter() {
        write!(&mut s, "{:X}", byte);
    }

    println!("as string {}", s);
}
