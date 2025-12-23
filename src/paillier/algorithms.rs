use rug::{
    integer::{IntegerExt64, IsPrime, Order},
    Assign, Complete, Integer,
};

use crate::traits::public_enc::PublicEnc;

use super::keys::{PaillierPublicKey, PaillierSecretKey};

pub struct Paillier;

impl Paillier {
    fn get_mod_bits(sec_level: u64) -> Result<u64, &'static str> {
        let mod_bits = match sec_level {
            80 => 1024,
            112 => 2048,
            128 => 3072,
            192 => 7680,
            256 => 15360,
            _ => return Err("Invalid security level."),
        };

        Ok(mod_bits)
    }
}

impl PublicEnc for Paillier {
    type SecretKey = PaillierSecretKey;
    type PublicKey = PaillierPublicKey;

    fn keygen(
        sec_level: u64,
        rng: &mut rug::rand::RandState,
    ) -> Result<(PaillierSecretKey, PaillierPublicKey), String> {
        // Generate two primes p,q s.t. gcd(pq, (p-1)(q-1)) = 1
        // Note that if, |p| = |q| this property is assured, for more information
        // see Jonathan Katz, Yehuda Lindell, "Introduction to Modern Cryptography: Principles and Protocols

        let mod_bits = Paillier::get_mod_bits(sec_level)?;
        let p_bits: u64 = mod_bits >> 1;
        let q_bits: u64 = mod_bits - p_bits;

        assert_eq!(p_bits, q_bits);

        let mut p: Integer = Integer::new();
        let mut q: Integer = Integer::new();

        loop {
            p.assign(Integer::random_bits_64(p_bits, rng));

            if p.significant_bits_64() == p_bits && p.is_probably_prime(12) == IsPrime::Probably {
                break;
            }
        }

        loop {
            q.assign(Integer::random_bits_64(q_bits, rng));

            if q.significant_bits_64() == q_bits && q.is_probably_prime(12) == IsPrime::Probably {
                break;
            }
        }

        // Compute n = pq
        let n = (&p * &q).complete();

        // Compute n^2
        let n_square = n.square_ref().complete();

        // Select a g = n + 1
        let g = (&n + Integer::ONE).complete();

        // Compute lambda = (p-1)*(q-1)
        let lambda = (&p - Integer::ONE).complete() * (&q - Integer::ONE).complete();

        // Compute mu = lambda^{-1}
        let mu;

        match lambda.invert_ref(&n) {
            Some(x) => mu = x.complete(),
            None => return Err("Error while computing mu.".to_string()),
        };

        let pk = PaillierPublicKey::new(n, n_square, g);
        let sk = PaillierSecretKey::new(lambda, mu);

        Ok((sk, pk))
    }

    fn encrypt(
        pk: &PaillierPublicKey,
        plaintext: &[u8],
        rng: &mut rug::rand::RandState,
    ) -> Result<Vec<u8>, String> {
        let m = Integer::from_digits(plaintext, Order::MsfBe);

        if m.is_negative() || m >= pk.n {
            return Err("The message is not in the message space.".to_string());
        }

        // Select a random 0 < r < n s.t. gcd(r,n) = 1
        let mut r: Integer = Integer::new();
        let r_size = pk.n.significant_bits_64();

        loop {
            r.assign(Integer::random_bits_64(r_size, rng));

            if r.significant_bits_64() == r_size && &r.gcd_ref(&pk.n).complete() == Integer::ONE {
                break;
            }
        }

        let mut c = pk.g.secure_pow_mod_ref(&m, &pk.n_square).complete();
        c = (&c * &(r.secure_pow_mod(&pk.n, &pk.n_square))).complete();
        c = c.modulo_ref(&pk.n_square).complete();

        let c: Vec<u8> = c.to_digits(Order::MsfBe);
        Ok(c)
    }

    fn decrypt(
        pk: &PaillierPublicKey,
        sk: &PaillierSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let c = Integer::from_digits(ciphertext, Order::MsfBe);

        if c.is_zero() || &c > &pk.n_square {
            return Err("The ciphertext is out of range.".to_string());
        }

        let mut m = c.secure_pow_mod(&sk.lambda, &pk.n_square) * &sk.mu;
        m = (&m - Integer::ONE).complete() / &pk.n;
        m = m.modulo(&pk.n);

        let m: Vec<u8> = m.to_digits(Order::MsfBe);
        Ok(m)
    }
}

#[cfg(test)]
mod test {
    use rug::{integer::Order, rand::RandState};

    use crate::{
        paillier::algorithms::Paillier, traits::public_enc::PublicEnc,
        utils::rand::rug_randseed_os_rng,
    };

    #[test]
    fn paillier_encrypt_failes_for_message_out_of_range() {
        let mut rng = RandState::new();

        rug_randseed_os_rng(128, &mut rng).unwrap();

        let (_, pk) = Paillier::keygen(128, &mut rng).unwrap();

        let m: Vec<u8> = pk.n.to_digits(Order::MsfBe);
        assert!(Paillier::encrypt(&pk, &m, &mut rng).is_err());
    }

    #[test]
    fn paillier_encrypt_works_as_expected() {
        let mut rng = RandState::new();

        rug_randseed_os_rng(128, &mut rng).unwrap();

        let (sk, pk) = Paillier::keygen(128, &mut rng).unwrap();
        let input = ["t1", "t1", "t1"];

        for s in input {
            let m = s.as_bytes();
            let c = Paillier::encrypt(&pk, m, &mut rng).unwrap();

            let decrypted_message = Paillier::decrypt(&pk, &sk, &c).unwrap();
            assert_eq!(m, &decrypted_message);
        }
    }
}
