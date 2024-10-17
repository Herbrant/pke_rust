use rug::rand::RandState;

pub trait PublicEnc<SecretKey, PublicKey> {
    // keygen algorithm
    fn keygen(sec_level: u64, rng: &mut RandState) -> Result<(SecretKey, PublicKey), &'static str>;

    // encryption algorithm
    fn encrypt(pk: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, &'static str>;

    // decryption algorithm
    fn decrypt(sk: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str>;
}
