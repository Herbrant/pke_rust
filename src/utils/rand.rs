use rand_core::{OsRng, RngCore};
use rug::integer::Order::MsfBe;
use rug::{rand::RandState, Integer};

pub fn get_randseed_os_rng(seed_bits: usize) -> Result<Integer, &'static str> {
    let seed_bytes: usize = seed_bits / 8;

    if seed_bytes < 1 {
        return Err("seed_bytes < 1");
    }

    let mut seed: Vec<u8> = vec![0; seed_bytes];
    OsRng.fill_bytes(&mut seed);

    let seed: Integer = Integer::from_digits(&seed, MsfBe);
    Ok(seed)
}

pub fn rug_randseed_os_rng(seed_bits: usize, rng: &mut RandState) -> Result<(), &'static str> {
    let seed = get_randseed_os_rng(seed_bits)?;
    rng.seed(&seed);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_randseed_os_rng_seed_bits_error() {
        for i in 0..8 {
            let r = get_randseed_os_rng(i);
            assert!(r.is_err());
        }
    }

    #[test]
    fn get_randseed_os_rng_works_as_expected() {
        for seed_bits in [1024, 2048, 3072, 4096] {
            let mut v: Vec<Integer> = Vec::new();

            for _ in 0..100 {
                match get_randseed_os_rng(seed_bits) {
                    Ok(s) => v.push(s),
                    Err(e) => panic!("{}", e),
                }
            }

            for s in v.windows(2) {
                assert_ne!(s[0], s[1]);
            }
        }
    }
}
