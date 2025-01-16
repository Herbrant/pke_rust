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

    fn pkcs_decode(mod_bytes: usize, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let plaintext_size = plaintext.len();

        if plaintext_size < mod_bytes {
            return Err("The plaintext size is less than mod_bytes.");
        }

        if plaintext[0] != 2 {
            return Err("Malformed PKCS1.5 encoding: init bytes");
        }

        let padding_ends = plaintext[1..plaintext_size - 2]
            .iter()
            .position(|&x| x == 0)
            .ok_or("Malformed PKCS1.5 encoding: padding_ends")?;

        if (padding_ends - 1) < 8 {
            return Err("Malformed PKCS1.5 encoding: padding size is less than 8 bytes.");
        }

        let out = plaintext[padding_ends + 2..].to_vec();

        Ok(out)
    }
}

impl PublicEnc for RSAPKCS15 {
    type SecretKey = RSASecretKey;
    type PublicKey = RSAPublicKey;

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

#[cfg(test)]
mod test {
    use rug::{integer::Order, rand::RandState};

    use crate::{
        rsapkcs15::algorithms::RSAPKCS15, traits::public_enc::PublicEnc,
        utils::rand::rug_randseed_os_rng,
    };

    #[test]
    fn rsa_pkcs15_encrypt_failes_for_message_out_of_range() {
        let mut rng = RandState::new();

        match rug_randseed_os_rng(128, &mut rng) {
            Ok(()) => (),
            Err(e) => panic!("{}", e),
        };

        let (_, pk) = RSAPKCS15::keygen(128, &mut rng).unwrap();

        let m: Vec<u8> = pk.n.to_digits(Order::MsfBe);
        assert!(RSAPKCS15::encrypt(&pk, &m, &mut rng).is_err());
    }

    #[test]
    fn rsa_pkcs15_encrypt_works_as_expected() {
        let mut rng = RandState::new();

        rug_randseed_os_rng(128, &mut rng).unwrap();

        let (sk, pk) = RSAPKCS15::keygen(128, &mut rng).unwrap();
        let input = ["test1", "test2", "test3"];

        for s in input {
            let m = s.as_bytes();
            let c = RSAPKCS15::encrypt(&pk, m, &mut rng).unwrap();

            let decrypted_message = RSAPKCS15::decrypt(&pk, &sk, &c).unwrap();
            assert_eq!(m, &decrypted_message);
        }
    }
}
