use rug::{
    integer::{IntegerExt64, IsPrime},
    Assign, Complete, Integer,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::traits::digital_signature::DigitalSignature;

use super::keys::{DSAPublicKey, DSASecretKey, DSASignature};

pub struct DSA;

impl DSA {
    
    fn get_dsa_params(sec_level: u64) -> Result<(u64, u64), &'static str> {
        let (l, n) = match sec_level {
            80 => (1024, 160),
            112 => (2048, 224),
            128 => (2048, 256),
            192 => (3072, 256),
            256 => (3072, 256),
            _ => return Err("Invalid security level for DSA."),
        };
        Ok((l, n))
    }

    fn generate_domain_params(l: u64, n: u64, rng: &mut rug::rand::RandState) -> Result<(Integer, Integer, Integer), &'static str> {

        let mut q = Integer::new();
        loop {
            q.assign(Integer::random_bits_64(n, rng));
            q.set_bit((n - 1) as u32, true);
            q.set_bit(0, true);
            
            if q.is_probably_prime(20) == IsPrime::Probably {
                break;
            }
        }

        let mut p;
        let mut counter = 0;
        let max_counter = 4 * l;
        
        loop {
            if counter > max_counter {
                return Err("Failed to generate suitable p parameter");
            }
            
            let temp: Integer = Integer::random_bits_64(l, rng).into();
            let mut temp = temp;
            temp.set_bit((l - 1) as u32, true);
            temp.set_bit(0, true);
            
            let k: Integer = (&temp / &q).complete();
            p = &k * &q + Integer::from(1);
            
            if p.significant_bits_64() == l && p.is_probably_prime(20) == IsPrime::Probably {
                break;
            }
            counter += 1;
        }

        let p_minus_one = &p - Integer::from(1);
        let h_exp = (&p_minus_one / &q).complete();
        
        let g;
        loop {
            let h = Integer::from(2) + Integer::random_below_ref(&p_minus_one, rng).complete();
            let temp_g = h.pow_mod_ref(&h_exp, &p).unwrap().into();
            
            if temp_g > 1 {
                g = temp_g;
                break;
            }
        }

        Ok((p, q, g))
    }

    fn hash_message(message: &[u8]) -> Integer {
        let mut hasher = DefaultHasher::new();
        message.hash(&mut hasher);
        Integer::from(hasher.finish())
    }
}

impl DigitalSignature for DSA {
    type SecretKey = DSASecretKey;
    type PublicKey = DSAPublicKey;
    type Signature = DSASignature;

    fn keygen(
        sec_level: u64,
        rng: &mut rug::rand::RandState,
    ) -> Result<(DSASecretKey, DSAPublicKey), &'static str> {
        let (l, n) = DSA::get_dsa_params(sec_level)?;
        
        let (p, q, g) = DSA::generate_domain_params(l, n, rng)?;

        let mut x = Integer::new();
        loop {
            x.assign(q.random_below_ref(rng).complete());
            if x > 1 {
                break;
            }
        }

        let y = g.pow_mod_ref(&x, &p).unwrap().into();

        let sk = DSASecretKey::new(x, p.clone(), q.clone(), g.clone());
        let pk = DSAPublicKey::new(p, q, g, y);

        Ok((sk, pk))
    }

    fn sign(
        sk: &DSASecretKey,
        message: &[u8],
        rng: &mut rug::rand::RandState,
    ) -> Result<DSASignature, &'static str> {
        let h = DSA::hash_message(message);
        
        let h = h.modulo(&sk.q);

        loop {
            let mut k = Integer::new();
            loop {
                k.assign(sk.q.random_below_ref(rng).complete());
                if k > Integer::ZERO {
                    break;
                }
            }

            let r = sk.g.pow_mod_ref(&k, &sk.p).unwrap().complete().modulo(&sk.q);
            
            if r.is_zero() {
                continue; 
            }

            if let Some(k_inv) = k.invert_ref(&sk.q) {
                let s = (k_inv.complete() * (&h + &sk.x * &r).complete()).modulo(&sk.q);
                
                if !s.is_zero() {
                    return Ok(DSASignature::new(r, s));
                }
            }

        }
    }

    fn verify(
        pk: &DSAPublicKey,
        message: &[u8],
        signature: &DSASignature,
    ) -> Result<bool, &'static str> {

        if signature.r.is_zero() || signature.r >= pk.q ||
           signature.s.is_zero() || signature.s >= pk.q {
            return Ok(false);
        }

        let h = DSA::hash_message(message);
        
        let h = h.modulo(&pk.q);

        let w = match signature.s.invert_ref(&pk.q) {
            Some(inv) => inv.complete(),
            None => return Ok(false),
        };

        let h_w = (&h * &w).complete();
        let u1: Integer = h_w.modulo(&pk.q);
        
        let r_w = (&signature.r * &w).complete();
        let u2: Integer = r_w.modulo(&pk.q);

        let g_u1 = pk.g.pow_mod_ref(&u1, &pk.p).unwrap().complete();
        let y_u2 = pk.y.pow_mod_ref(&u2, &pk.p).unwrap().complete();
        let product: Integer = (&g_u1 * &y_u2).complete();
        let v = product.modulo(&pk.p).modulo(&pk.q);

        Ok(v == signature.r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rug::rand::RandState;
    use crate::utils::rand::rug_randseed_os_rng;

    #[test]
    fn test_dsa_keygen() {
        let mut rng = RandState::new();
        rug_randseed_os_rng(128, &mut rng).unwrap();

        let result = DSA::keygen(112, &mut rng);
        assert!(result.is_ok());
        
        let (sk, pk) = result.unwrap();
        
        assert!(pk.p > Integer::ZERO);
        assert!(pk.q > Integer::ZERO);
        assert!(pk.g > 1);
        assert!(pk.y > 1);
        assert!(sk.x > Integer::ZERO);
        assert!(sk.x < pk.q);
    }

    #[test]
    fn test_domain_params_generation() {
        let mut rng = RandState::new();
        rug_randseed_os_rng(128, &mut rng).unwrap();

        let result = DSA::generate_domain_params(1024, 160, &mut rng);
        assert!(result.is_ok());
        
        let (p, q, g) = result.unwrap();
        
        assert_eq!(p.significant_bits_64(), 1024);
        assert_eq!(q.significant_bits_64(), 160);
        assert!(g > 1);
        
        let p_minus_one = &p - Integer::from(1);
        let remainder = p_minus_one % &q;
        assert_eq!(remainder, Integer::ZERO);
    }

    #[test]
    fn test_dsa_sign_verify() {
        let mut rng = RandState::new();
        rug_randseed_os_rng(128, &mut rng).unwrap();
        let result = DSA::keygen(80, &mut rng);
        assert!(result.is_ok());
        
        let (sk, pk) = result.unwrap();
        let message = b"Test message for DSA signing";

        let signature = DSA::sign(&sk, message, &mut rng);
        assert!(signature.is_ok(), "Signing should succeed");
        
        let sig = signature.unwrap();
        
        assert!(sig.r > Integer::ZERO && sig.r < pk.q);
        assert!(sig.s > Integer::ZERO && sig.s < pk.q);
        
        let verification = DSA::verify(&pk, message, &sig);
        assert!(verification.is_ok(), "Verification should not error");
        assert!(verification.unwrap(), "Signature should be valid");
        
        let wrong_message = b"Wrong message for DSA signing";
        let wrong_verification = DSA::verify(&pk, wrong_message, &sig);
        assert!(wrong_verification.is_ok(), "Verification should not error");
        assert!(!wrong_verification.unwrap(), "Wrong message should fail verification");
    }

    #[test]
    fn test_dsa_invalid_signature() {
        let mut rng = RandState::new();
        rug_randseed_os_rng(128, &mut rng).unwrap();

        let (_, pk) = DSA::keygen(80, &mut rng).unwrap();
        let message = b"Test message";

        let invalid_sig1 = DSASignature::new(Integer::ZERO, Integer::from(123));
        let result1 = DSA::verify(&pk, message, &invalid_sig1).unwrap();
        assert!(!result1, "Signature with r=0 should be invalid");

        let invalid_sig2 = DSASignature::new(Integer::from(123), Integer::ZERO);
        let result2 = DSA::verify(&pk, message, &invalid_sig2).unwrap();
        assert!(!result2, "Signature with s=0 should be invalid");

        let invalid_sig3 = DSASignature::new(pk.q.clone(), Integer::from(123));
        let result3 = DSA::verify(&pk, message, &invalid_sig3).unwrap();
        assert!(!result3, "Signature with r>=q should be invalid");
    }

    #[test]
    fn test_dsa_mathematical_properties() {
        let mut rng = RandState::new();
        rug_randseed_os_rng(128, &mut rng).unwrap();

        let (sk, pk) = DSA::keygen(80, &mut rng).unwrap();

        let g_q = pk.g.pow_mod_ref(&pk.q, &pk.p).unwrap().into();
        assert_eq!(g_q, Integer::from(1), "g^q should be 1 mod p");

        let p_minus_one = &pk.p - Integer::from(1);
        let remainder = &p_minus_one % &pk.q;
        assert_eq!(remainder, Integer::ZERO, "q should divide (p-1)");

        assert_eq!(pk.p.is_probably_prime(50), IsPrime::Probably, "p should be prime");
        assert_eq!(pk.q.is_probably_prime(50), IsPrime::Probably, "q should be prime");

        let calculated_y = pk.g.pow_mod_ref(&sk.x, &pk.p).unwrap().into();
        assert_eq!(calculated_y, pk.y, "y should equal g^x mod p");

        assert!(sk.x > Integer::ZERO && sk.x < pk.q, "Private key should be in range (0, q)");

        println!(" Tutte le proprietà matematiche DSA sono verificate!");
    }

    #[test]
    fn test_dsa_deterministic_verification() {
        let mut rng = RandState::new();
        rug_randseed_os_rng(128, &mut rng).unwrap();

        let (sk, pk) = DSA::keygen(80, &mut rng).unwrap();
        let message = b"Test message for deterministic verification";

        let mut signatures = Vec::new();
        for _ in 0..5 {
            let sig = DSA::sign(&sk, message, &mut rng).unwrap();
            signatures.push(sig);
        }

        for (i, sig) in signatures.iter().enumerate() {
            let is_valid = DSA::verify(&pk, message, sig).unwrap();
            assert!(is_valid, "Signature {} should be valid", i);
        }

        for i in 0..signatures.len() {
            for j in i+1..signatures.len() {
                assert!(
                    signatures[i].r != signatures[j].r || signatures[i].s != signatures[j].s,
                    "Signatures {} and {} should be different due to randomness", i, j
                );
            }
        }

        println!("Deterministic verification completed: all signatures are valid and unique!");
    }
}
