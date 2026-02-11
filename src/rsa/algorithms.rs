use std::cmp::Ordering;

use rug::{
    integer::{IntegerExt64, IsPrime, Order},
    rand::RandState,
    Assign, Complete, Integer,
};

use crate::traits::public_enc::PublicEnc;

use super::keys::{RSAPublicKey, RSASecretKey};

pub struct RSA;
const DEFAULT_E: u64 = 65537;

impl RSA {
    fn get_mod_bits(sec_level: u64) -> Result<u64, String> {
        let mod_bits = match sec_level {
            80 => 1024,
            112 => 2048,
            128 => 3072,
            192 => 7680,
            256 => 15360,
            _ => return Err("Invalid security level.".to_string()),
        };

        Ok(mod_bits)
    }
}

impl PublicEnc for RSA {
    type SecretKey = RSASecretKey;
    type PublicKey = RSAPublicKey;

    fn keygen(
        sec_level: u64,
        rng: &mut RandState,
    ) -> Result<(Self::SecretKey, Self::PublicKey), String> {
        log::debug!("Generating a new key pair...");

        let mod_bits = RSA::get_mod_bits(sec_level)?;
        let p_bits: u64 = mod_bits >> 1;
        let q_bits: u64 = mod_bits - p_bits;

        let e = Integer::from(DEFAULT_E);
        let mut p: Integer = Integer::new();
        let mut q: Integer = Integer::new();

        // Generates p and q
        let mut phi_n: Integer;

        loop {
            loop {
                p.assign(Integer::random_bits_64(p_bits, rng));

                if p.significant_bits_64() >= p_bits && p.is_probably_prime(12) == IsPrime::Probably
                {
                    break;
                }
            }

            // Generates q
            loop {
                q.assign(Integer::random_bits_64(q_bits, rng));

                if q.significant_bits_64() >= q_bits && q.is_probably_prime(12) == IsPrime::Probably
                {
                    break;
                }
            }

            // phi(n)
            phi_n = (&p - Integer::ONE).complete() * (&q - Integer::ONE).complete();

            let gcd = phi_n.gcd_ref(&e).complete();

            match gcd.cmp(Integer::ONE) {
                Ordering::Equal => break,
                _ => (),
            }
        }

        // Generates the private exponent
        let d: Integer = match e.invert_ref(&phi_n) {
            Some(el) => el.complete(),
            None => return Err("error while inverting the public exponent".to_string()),
        };

        let n = (&p * &q).complete();

        // d_p = d mod (p - 1)
        let p_minus_one = (&p - Integer::ONE).complete();
        let d_p = d.modulo_ref(&p_minus_one).complete();

        // d_q = d mod (q - 1)
        let q_minus_one = (&q - Integer::ONE).complete();
        let d_q = d.modulo_ref(&q_minus_one).complete();

        // q_inv = q^-1 mod p
        let q_inv = match q.invert_ref(&p) {
            Some(val) => val.complete(),
            None => return Err("Error while computing q_inv value.".to_string()),
        };

        let pk = Self::PublicKey::new(n, e);
        let sk = Self::SecretKey::new(p, q, d_p, d_q, q_inv);

        log::debug!("{:?}", sk);

        Ok((sk, pk))
    }

    fn encrypt(
        pk: &Self::PublicKey,
        plaintext: &[u8],
        _rng: &mut RandState,
    ) -> Result<Vec<u8>, String> {
        let m = Integer::from_digits(plaintext, Order::MsfBe);
        log::debug!("Encrypting the message: {}", m);

        if &m >= &pk.n || &m <= Integer::ONE {
            return Err("The message is out of range.".to_string());
        }

        // The function pow_mod is not designed for cryptographic purposes
        // let c: Integer = match m.pow_mod_ref(&pk.e, &pk.n) {
        //     Some(val) => val.into(),
        //     None => return Err("Error while computing c.".to_string()),
        // };

        // The function secure_pow_mod is designed to take the same time and use the same cache access
        // patterns for same-sized arguments, assuming that the arguments are placed
        // at the same position and the machine state is identical when starting.
        let c = m.secure_pow_mod_ref(&pk.e, &pk.n).complete();

        let c: Vec<u8> = c.to_digits(Order::MsfBe);

        Ok(c)
    }

    fn decrypt(
        _pk: &Self::PublicKey,
        sk: &Self::SecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let c = Integer::from_digits(ciphertext, Order::MsfBe);
        log::debug!("Decrypting the ciphertext: {}", c);

        // m_p = (c mod p)^(d_p) mod p
        let m_p = match c.modulo_ref(&sk.p).complete().pow_mod(&sk.d_p, &sk.p) {
            Ok(val) => val,
            Err(_) => return Err("Error while computing m_p".to_string()),
        };

        // m_q = (c mod q)^(d_q) mod q
        let m_q = match c.modulo_ref(&sk.q).complete().pow_mod(&sk.d_q, &sk.q) {
            Ok(val) => val,
            Err(_) => return Err("Error while computing m_q".to_string()),
        };

        // m = m_q + ( (m_p - m_q) * (q_inv) mod p ) * q
        let m = ((&m_p - &m_q).complete() * &sk.q_inv).modulo(&sk.p);
        let m = &m * &sk.q + m_q;
        let m = m.to_digits(Order::MsfBe);

        Ok(m)
    }
}

#[cfg(test)]
mod test {
    use rug::{integer::Order, rand::RandState};

    use crate::{
        rsa::algorithms::RSA, traits::public_enc::PublicEnc, utils::rand::rug_randseed_os_rng,
    };

    #[test]
    fn rsa_encrypt_failes_for_message_out_of_range() {
        let mut rng = RandState::new();

        rug_randseed_os_rng(80, &mut rng).unwrap();

        let (_, pk) = RSA::keygen(80, &mut rng).unwrap();

        let m: Vec<u8> = pk.n.to_digits(Order::MsfBe);
        assert!(RSA::encrypt(&pk, &m, &mut rng).is_err());
    }

    #[test]
    fn rsa_encrypt_works_as_expected() {
        let mut rng = RandState::new();

        rug_randseed_os_rng(80, &mut rng).unwrap();

        let (sk, pk) = RSA::keygen(80, &mut rng).unwrap();
        let input = ["test1", "test2", "test3"];

        for s in input {
            let m = s.as_bytes();
            let c = RSA::encrypt(&pk, m, &mut rng).unwrap();

            let decrypted_message = RSA::decrypt(&pk, &sk, &c).unwrap();
            assert_eq!(m, &decrypted_message);
        }
    }
}
