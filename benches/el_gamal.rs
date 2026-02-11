use divan::black_box;
use divan::Bencher;
use pke_rust::el_gamal::algorithms::ElGamal;
use pke_rust::traits::public_enc::PublicEnc;
use pke_rust::utils::rand::rug_randseed_os_rng;
use rug::rand::RandState;

const SECURY_LEVEL: u64 = 80;
const VALUES: &[u64] = &[1, 5, 10, 20, 30, 40];

#[divan::bench(max_time = 20)]
fn el_gamal_keygen(bencher: Bencher) {
    let mut rng = RandState::new();
    rug_randseed_os_rng(80, &mut rng).unwrap();

    bencher.bench_local(|| {
        let _ = ElGamal::keygen(black_box(SECURY_LEVEL), black_box(&mut rng)).unwrap();
    });
}

#[divan::bench(args=VALUES)]
fn el_gamal_encrypt(bencher: Bencher, m: u64) {
    let mut rng = RandState::new();
    rug_randseed_os_rng(80, &mut rng).unwrap();
    let (_, pk) = ElGamal::keygen(SECURY_LEVEL, &mut rng).unwrap();

    let m = m.to_le_bytes();

    bencher.bench_local(|| {
        let _ = ElGamal::encrypt(black_box(&pk), black_box(&m), black_box(&mut rng)).unwrap();
    });
}

#[divan::bench(args=VALUES)]
fn el_gamal_decrypt(bencher: Bencher, m: u64) {
    let mut rng = RandState::new();
    let (sk, pk) = ElGamal::keygen(SECURY_LEVEL, &mut rng).unwrap();

    let m: [u8; 8] = m.to_le_bytes();
    let c = ElGamal::encrypt(&pk, &m, &mut rng).unwrap();

    bencher.bench_local(|| {
        let _ = ElGamal::decrypt(black_box(&pk), black_box(&sk), black_box(&c)).unwrap();
    });
}

fn main() {
    divan::main();
}
