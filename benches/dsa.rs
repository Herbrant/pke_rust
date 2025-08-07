use divan::black_box;
use divan::Bencher;
use pke_rust::dsa::algorithms::DSA;
use pke_rust::traits::digital_signature::DigitalSignature;
use rug::rand::RandState;

const SECURITY_LEVEL: u64 = 80;

#[divan::bench]
fn dsa_keygen() {
    let mut rng = RandState::new();
    let _ = DSA::keygen(black_box(SECURITY_LEVEL), black_box(&mut rng)).unwrap();
}

#[divan::bench]
fn dsa_sign(bencher: Bencher) {
    let mut rng = RandState::new();
    let (sk, _) = DSA::keygen(SECURITY_LEVEL, &mut rng).unwrap();
    let message = b"benchmark message for DSA signing";

    bencher.bench_local(|| {
        let _ = DSA::sign(black_box(&sk), black_box(message), black_box(&mut rng)).unwrap();
    });
}

#[divan::bench]
fn dsa_verify(bencher: Bencher) {
    let mut rng = RandState::new();
    let (sk, pk) = DSA::keygen(SECURITY_LEVEL, &mut rng).unwrap();
    let message = b"benchmark message for DSA verification";
    let signature = DSA::sign(&sk, message, &mut rng).unwrap();

    bencher.bench_local(|| {
        let _ = DSA::verify(black_box(&pk), black_box(message), black_box(&signature)).unwrap();
    });
}

fn main() {
    divan::main();
}
