use rug::{
    integer::{IntegerExt64, IsPrime, Order},
    Assign, Complete, Integer,
};

use crate::traits::public_enc::PublicEnc;

use super::keys::{ElGamalPublicKey, ElGamalSecretKey};

pub struct ElGamal;

impl ElGamal {
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
        rng: &mut rug::rand::RandState,
    ) -> Result<(ElGamalSecretKey, ElGamalPublicKey), &'static str> {
        let p_bits = Self::get_mod_bits(sec_level)?;
        let q_bits = p_bits >> 1;

        let mut p = Integer::new();
        let mut q = Integer::new();

        loop {
            q.assign(Integer::random_bits_64(p_bits, rng));

            if q.significant_bits_64() >= q_bits && q.is_probably_prime(12) == IsPrime::Probably {
                break;
            }
        }

        loop {
            p = Integer::from(2) * &p + Integer::ONE;

            if p.significant_bits_64() >= p_bits && p.is_probably_prime(12) == IsPrime::Probably {
                break;
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

        let sk = ElGamalSecretKey::new(x);
        let pk = ElGamalPublicKey::new(p, q, g, h);

        Ok((sk, pk))
    }

    fn encrypt(
        pk: &ElGamalPublicKey,
        plaintext: &[u8],
        rng: &mut rug::rand::RandState,
    ) -> Result<Vec<u8>, &'static str> {
        let m = Integer::from_digits(plaintext, Order::MsfBe);
        log::debug!("Encrypting the message: {}", m);

        let p_minus_one = (&pk.p - Integer::ONE).complete();

        if m > p_minus_one {
            return Err("The message is out of message space.");
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
        let c2 = (pk.h.secure_pow_mod_ref(&k, &pk.p).complete()) * m;

        let c1: Vec<u8> = c1.to_digits(Order::MsfBe);
        let c2: Vec<u8> = c2.to_digits(Order::MsfBe);
        let c: Vec<u8> = bincode::serialize(&(c1, c2)).unwrap();

        Ok(c)
    }

    fn decrypt(
        pk: &ElGamalPublicKey,
        sk: &ElGamalSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        // TO-FIX: unwrap
        let (c1, c2): (Vec<u8>, Vec<u8>) = bincode::deserialize(ciphertext).unwrap();
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

        match rug_randseed_os_rng(128, &mut rng) {
            Ok(()) => (),
            Err(e) => panic!("{}", e),
        };

        let (_, pk) = ElGamal::keygen(128, &mut rng).unwrap();

        let m: Vec<u8> = pk.p.to_digits(Order::MsfBe);
        assert!(ElGamal::encrypt(&pk, &m, &mut rng).is_err());
    }

    #[test]
    fn el_gamal_encrypt_works_as_expected() {
        let mut rng = RandState::new();

        rug_randseed_os_rng(128, &mut rng).unwrap();

        let (sk, pk) = ElGamal::keygen(128, &mut rng).unwrap();
        let input = ["test1", "test2", "test3"];

        for s in input {
            let m = s.as_bytes();
            let c = ElGamal::encrypt(&pk, m, &mut rng).unwrap();

            let decrypted_message = ElGamal::decrypt(&pk, &sk, &c).unwrap();
            assert_eq!(m, &decrypted_message);
        }
    }
}
