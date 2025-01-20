use divan::black_box;
use divan::Bencher;
use pke_rust::paillier::algorithms::Paillier;
use pke_rust::traits::public_enc::PublicEnc;
use rug::rand::RandState;

const SECURY_LEVEL: u64 = 128;
const VALUES: &[u64] = &[1, 5, 10, 20, 30, 40];

#[divan::bench]
fn paillier_keygen() {
    let mut rng = RandState::new();
    let _ = Paillier::keygen(black_box(SECURY_LEVEL), black_box(&mut rng)).unwrap();
}

#[divan::bench(args=VALUES)]
fn paillier_encrypt(bencher: Bencher, m: u64) {
    let mut rng = RandState::new();
    let (_, pk) = Paillier::keygen(SECURY_LEVEL, &mut rng).unwrap();

    let m = m.to_le_bytes();

    bencher.bench_local(|| {
        let _ = Paillier::encrypt(black_box(&pk), black_box(&m), black_box(&mut rng)).unwrap();
    });
}

#[divan::bench(args=VALUES)]
fn paillier_decrypt(bencher: Bencher, m: u64) {
    let mut rng = RandState::new();
    let (sk, pk) = Paillier::keygen(SECURY_LEVEL, &mut rng).unwrap();

    let m: [u8; 8] = m.to_le_bytes();
    let c = Paillier::encrypt(&pk, &m, &mut rng).unwrap();

    bencher.bench_local(|| {
        let _ = Paillier::decrypt(black_box(&pk), black_box(&sk), black_box(&c)).unwrap();
    });
}

fn main() {
    divan::main();
}
