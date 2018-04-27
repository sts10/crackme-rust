extern crate ring;

use ring::{digest, pbkdf2};
use std::fmt::Write;
// use std::collections::HashMap;

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

fn main() {
    let password = "node tuesday imperial";
    let salt = "e628cf2534f66ca172b1ebd82394563a".as_bytes();
    let iterations = 100000;
    let mut to_store: Credential = [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        DIGEST_ALG,
        iterations,
        &salt,
        password.as_bytes(),
        &mut to_store,
    );

    println!("out: {:?}", to_store);

    let mut upper = String::new();
    let mut lower = String::new();
    for &byte in to_store.iter() {
        write!(&mut upper, "{:X}", byte);
        write!(&mut lower, "{:x}", byte);
    }

    println!("as string {}", lower);
}
