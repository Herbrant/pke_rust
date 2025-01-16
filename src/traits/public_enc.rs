use rug::rand::RandState;

pub trait PublicEnc {
    type SecretKey;
    type PublicKey;

    // keygen algorithm
    fn keygen(
        sec_level: u64,
        rng: &mut RandState,
    ) -> Result<(Self::SecretKey, Self::PublicKey), &'static str>;

    // encryption algorithm
    fn encrypt(
        pk: &Self::PublicKey,
        plaintext: &[u8],
        rng: &mut rug::rand::RandState,
    ) -> Result<Vec<u8>, &'static str>;

    // decryption algorithm
    fn decrypt(
        pk: &Self::PublicKey,
        sk: &Self::SecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str>;
}
