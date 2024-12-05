mod rsa {
    use divan::black_box;
    use divan::Bencher;
    use pke_rust::rsapkcs15::algorithms::RSAPKCS15;
    use pke_rust::traits::public_enc::PublicEnc;
    use rug::rand::RandState;

    const SECURY_LEVEL: u64 = 128;
    const VALUES: &[u64] = &[1, 5, 10, 20, 30, 40];

    #[divan::bench]
    fn rsa_pkcs15_keygen() {
        let mut rng = RandState::new();
        let _ = RSAPKCS15::keygen(black_box(SECURY_LEVEL), black_box(&mut rng)).unwrap();
    }

    #[divan::bench(args=VALUES)]
    fn rsa_pkcs15_encrypt(bencher: Bencher, m: u64) {
        let mut rng = RandState::new();
        let (_, pk) = RSAPKCS15::keygen(black_box(SECURY_LEVEL), black_box(&mut rng)).unwrap();

        let m = m.to_le_bytes();

        bencher.bench_local(|| {
            let _ = RSAPKCS15::encrypt(&pk, &m, &mut rng).unwrap();
        });
    }

    #[divan::bench(args=VALUES)]
    fn rsa_pkcs15_decrypt(bencher: Bencher, m: u64) {
        let mut rng = RandState::new();
        let (sk, pk) = RSAPKCS15::keygen(black_box(SECURY_LEVEL), black_box(&mut rng)).unwrap();

        let m: [u8; 8] = m.to_le_bytes();
        let c = RSAPKCS15::encrypt(&pk, &m, &mut rng).unwrap();

        bencher.bench_local(|| {
            let _ = RSAPKCS15::decrypt(&pk, &sk, &c).unwrap();
        });
    }
}

fn main() {
    divan::main();
}
