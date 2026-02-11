use rug::{
    integer::{IntegerExt64, IsPrime, Order},
    rand::RandState,
    Assign, Complete, Integer,
};

use crate::traits::public_enc::PublicEnc;

use super::keys::{ElGamalPublicKey, ElGamalSecretKey};

pub struct ElGamal;

impl ElGamal {
    const SMALL_PRIMES: &[u32] = &[3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];

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

impl PublicEnc for ElGamal {
    type SecretKey = ElGamalSecretKey;
    type PublicKey = ElGamalPublicKey;

    fn keygen(
        sec_level: u64,
        rng: &mut RandState,
    ) -> Result<(Self::SecretKey, Self::PublicKey), String> {
        let p_bits = Self::get_mod_bits(sec_level)?;
        let q_bits = p_bits - 1;

        let mut p = Integer::new();
        let mut q = Integer::new();

        loop {
            q.assign(Integer::random_bits_64(q_bits, rng));
            q.set_bit((q_bits - 1) as u32, true);
            q.set_bit(0, true);

            if q.mod_u(3) != 2 {
                continue;
            }

            let mut is_composite = false;
            for &sp in Self::SMALL_PRIMES {
                let rem_q = q.mod_u(sp);
                if rem_q == 0 {
                    is_composite = true;
                    break;
                }

                if (2 * rem_q + 1) % sp == 0 {
                    is_composite = true;
                    break;
                }
            }
            if is_composite {
                continue;
            }

            if q.is_probably_prime(2) == IsPrime::No {
                continue;
            }

            p.assign(&q);
            p <<= 1;
            p += 1;

            if p.is_probably_prime(12) != IsPrime::No {
                if q.is_probably_prime(12) != IsPrime::No {
                    break;
                }
            }
        }

        // Zp generator
        let g = Integer::from(4);

        // secret exponent
        let p_minus_one = (&p - Integer::ONE).complete();
        let mut x = Integer::new();

        loop {
            x.assign(p_minus_one.random_below_ref(rng).complete());

            if &x > Integer::ONE {
                break;
            }
        }

        // Compute h
        let h = g.secure_pow_mod_ref(&x, &p).complete();

        let sk = Self::SecretKey::new(x);
        let pk = Self::PublicKey::new(p, q, g, h);

        Ok((sk, pk))
    }

    fn encrypt(
        pk: &Self::PublicKey,
        plaintext: &[u8],
        rng: &mut RandState,
    ) -> Result<Vec<u8>, String> {
        let m = Integer::from_digits(plaintext, Order::MsfBe);
        let p_minus_one = (&pk.p - Integer::ONE).complete();

        if m > p_minus_one {
            return Err("The message is out of message space.".to_string());
        }

        // Generate a random k in [2,p-2]
        let mut k = Integer::new();

        loop {
            k.assign(p_minus_one.random_below_ref(rng).complete());

            if &k > Integer::ONE {
                break;
            }
        }

        // Compute c1
        let c1 = pk.g.secure_pow_mod_ref(&k, &pk.p).complete();

        // Compute c2
        let c2 = ((pk.h.secure_pow_mod_ref(&k, &pk.p).complete()) * m)
            .modulo_ref(&pk.p)
            .complete();

        let c1: Vec<u8> = c1.to_digits(Order::MsfBe);
        let c2: Vec<u8> = c2.to_digits(Order::MsfBe);
        let c: Vec<u8> = bincode::serialize(&(c1, c2)).unwrap();

        Ok(c)
    }

    fn decrypt(
        pk: &Self::PublicKey,
        sk: &Self::SecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let (c1, c2): (Vec<u8>, Vec<u8>) = match bincode::deserialize(ciphertext) {
            Ok(c) => c,
            Err(_) => return Err("Deserialization error.".to_string()),
        };

        let c1 = Integer::from_digits(&c1, Order::MsfBe);
        let c2 = Integer::from_digits(&c2, Order::MsfBe);

        let p_minus_one = (&pk.p - Integer::ONE).complete();
        let p_minus_one_minus_x = p_minus_one - &sk.x;

        let m = (c1
            .secure_pow_mod_ref(&p_minus_one_minus_x, &pk.p)
            .complete()
            * c2)
            .modulo(&pk.p);

        Ok(m.to_digits(Order::MsfBe))
    }
}

#[cfg(test)]
mod test {
    use rug::{integer::Order, rand::RandState};

    use crate::{
        el_gamal::algorithms::ElGamal, traits::public_enc::PublicEnc,
        utils::rand::rug_randseed_os_rng,
    };

    #[test]
    fn el_gamal_encrypt_failes_for_message_out_of_range() {
        let mut rng = RandState::new();

        rug_randseed_os_rng(80, &mut rng).unwrap();

        let (_, pk) = ElGamal::keygen(80, &mut rng).unwrap();

        let m: Vec<u8> = pk.p.to_digits(Order::MsfBe);
        assert!(ElGamal::encrypt(&pk, &m, &mut rng).is_err());
    }

    #[test]
    fn el_gamal_encrypt_works_as_expected() {
        let mut rng = RandState::new();

        rug_randseed_os_rng(80, &mut rng).unwrap();

        let (sk, pk) = ElGamal::keygen(80, &mut rng).unwrap();
        let input = ["test1", "test2", "test3"];

        for s in input {
            let m = s.as_bytes();
            let c = ElGamal::encrypt(&pk, m, &mut rng).unwrap();

            let decrypted_message = ElGamal::decrypt(&pk, &sk, &c).unwrap();
            assert_eq!(m, &decrypted_message);
        }
    }
}
