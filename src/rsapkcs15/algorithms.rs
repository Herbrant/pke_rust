use rug::rand::RandState;

use crate::{
    rsa::{
        algorithms::RSA,
        keys::{RSAPublicKey, RSASecretKey},
    },
    traits::public_enc::PublicEnc,
};

pub struct RSAPKCS15;

impl RSAPKCS15 {
    fn pkcs_encode(
        mod_bytes: usize,
        plaintext: &[u8],
        rng: &mut rug::rand::RandState,
    ) -> Result<Vec<u8>, &'static str> {
        let plaintext_size = plaintext.len();
        let padded_plaintext_size = plaintext_size + 3 + 8;

        if padded_plaintext_size > mod_bytes {
            return Err("The plaintext is too long.");
        }

        let padding_bytes = mod_bytes - plaintext_size;
        let mut padded_plaintext: Vec<u8> = Vec::with_capacity(mod_bytes);

        padded_plaintext.push(0);
        padded_plaintext.push(2);

        let mut x: u8;

        for _ in 2..padding_bytes {
            loop {
                x = rng.bits(8) as u8;

                if x != 0 {
                    break;
                }
            }

            padded_plaintext.push(x);
        }

        padded_plaintext.push(0);
        padded_plaintext.extend(plaintext);

        Ok(padded_plaintext)
    }

    fn pkcs_decode(mod_bytes: usize, padded_plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        todo!()
    }
}

impl PublicEnc<RSASecretKey, RSAPublicKey> for RSAPKCS15 {
    fn keygen(
        sec_level: u64,
        rng: &mut rug::rand::RandState,
    ) -> Result<(RSASecretKey, RSAPublicKey), &'static str> {
        RSA::keygen(sec_level, rng)
    }

    fn encrypt(
        pk: &RSAPublicKey,
        plaintext: &[u8],
        rng: &mut rug::rand::RandState,
    ) -> Result<Vec<u8>, &'static str> {
        let padded_plaintext =
            RSAPKCS15::pkcs_encode(pk.n.significant_digits::<u8>(), plaintext, rng)?;

        RSA::encrypt(pk, &padded_plaintext, rng)
    }

    fn decrypt(
        pk: &RSAPublicKey,
        sk: &RSASecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let padded_plaintext = RSA::decrypt(pk, sk, ciphertext)?;
        let plaintext = RSAPKCS15::pkcs_decode(pk.n.significant_digits::<u8>(), &padded_plaintext)?;

        Ok(plaintext)
    }
}
