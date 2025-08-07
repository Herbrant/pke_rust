use rug::rand::RandState;

pub trait DigitalSignature {
    type SecretKey;
    type PublicKey;
    type Signature;

    fn keygen(
        sec_level: u64,
        rng: &mut RandState,
    ) -> Result<(Self::SecretKey, Self::PublicKey), &'static str>;

    fn sign(
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut RandState,
    ) -> Result<Self::Signature, &'static str>;

    fn verify(
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, &'static str>;
}
