I'm tepidly trying Agile Bits' [CrackMe](https://github.com/agilebits/crackme) password cracking challenge, using Rust.

## Some notes

We're attempting to "crack" a three-word passphrase chosen randomly from a list of 18,328 words. An example would be "taffrail highborn shoe".

Just to note: I'm pretty sure such a passphrase has 42.485 bits of entropy (`(log2 of 18328) * 3 ~= 42.385`).

Given the salt "cdb02877fbb1e7d62fc8b7ddd30de2a9", 100000 rounds of HMAC-SHA256, the passphrase "taffrail highborn shoe" gives us a derived hash of "dc61e18eaa1add3e555cd493acb9088449d2ac07a739eec15cd299a327bf45b0". 

The trick here is to work backwards, from the derived hash back to the passphrase.

## Next steps for the program

Implement Rust threads to speed up the hash-guessing process.
