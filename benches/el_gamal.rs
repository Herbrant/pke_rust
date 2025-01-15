mod el_gamal {
    use divan::black_box;
    use divan::Bencher;
    use pke_rust::el_gamal::algorithms::ElGamal;
    use pke_rust::traits::public_enc::PublicEnc;
    use rug::rand::RandState;

    const SECURY_LEVEL: u64 = 128;
    const VALUES: &[u64] = &[1, 5, 10, 20, 30, 40];

    #[divan::bench]
    fn el_gamal_keygen() {
        let mut rng = RandState::new();
        let _ = ElGamal::keygen(black_box(SECURY_LEVEL), black_box(&mut rng)).unwrap();
    }

    #[divan::bench(args=VALUES)]
    fn el_gamal_encrypt(bencher: Bencher, m: u64) {
        let mut rng = RandState::new();
        let (_, pk) = ElGamal::keygen(black_box(SECURY_LEVEL), black_box(&mut rng)).unwrap();

        let m = m.to_le_bytes();

        bencher.bench_local(|| {
            let _ = ElGamal::encrypt(&pk, &m, &mut rng).unwrap();
        });
    }

    #[divan::bench(args=VALUES)]
    fn el_gamal_decrypt(bencher: Bencher, m: u64) {
        let mut rng = RandState::new();
        let (sk, pk) = ElGamal::keygen(black_box(SECURY_LEVEL), black_box(&mut rng)).unwrap();

        let m: [u8; 8] = m.to_le_bytes();
        let c = ElGamal::encrypt(&pk, &m, &mut rng).unwrap();

        bencher.bench_local(|| {
            let _ = ElGamal::decrypt(&pk, &sk, &c).unwrap();
        });
    }
}

fn main() {
    divan::main();
}
