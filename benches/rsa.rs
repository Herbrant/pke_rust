use divan::black_box;
use divan::Bencher;
use pke_rust::{rsa::algorithms::RSA, traits::public_enc::PublicEnc};
use rug::rand::RandState;

const SECURY_LEVEL: u64 = 128;
const VALUES: &[u64] = &[1, 5, 10, 20, 30, 40];

#[divan::bench]
fn rsa_keygen() {
    let mut rng = RandState::new();
    let _ = RSA::keygen(black_box(SECURY_LEVEL), black_box(&mut rng)).unwrap();
}

#[divan::bench(args=VALUES)]
fn rsa_encrypt(bencher: Bencher, m: u64) {
    let mut rng = RandState::new();
    let (_, pk) = RSA::keygen(SECURY_LEVEL, &mut rng).unwrap();

    let m = m.to_le_bytes();

    bencher.bench_local(|| {
        let _ = RSA::encrypt(black_box(&pk), black_box(&m), black_box(&mut rng)).unwrap();
    });
}

#[divan::bench(args=VALUES)]
fn rsa_decrypt(bencher: Bencher, m: u64) {
    let mut rng = RandState::new();
    let (sk, pk) = RSA::keygen(SECURY_LEVEL, &mut rng).unwrap();

    let m = m.to_le_bytes();
    let c = RSA::encrypt(&pk, &m, &mut rng).unwrap();

    bencher.bench_local(|| {
        let _ = RSA::decrypt(black_box(&pk), black_box(&sk), black_box(&c)).unwrap();
    });
}

fn main() {
    divan::main();
}
