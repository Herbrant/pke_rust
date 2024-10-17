pub trait SecretKey {
    fn gen(sec_level: u64) -> Result<Self, &'static str>
    where
        Self: Sized;
}

pub trait PublicKey {
    fn gen(sec_level: u64) -> Result<Self, &'static str>
    where
        Self: Sized;
}
