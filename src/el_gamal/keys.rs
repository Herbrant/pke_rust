use rug::Integer;

// Represents the El Gamal's public key
#[derive(Debug)]
pub struct ElGamalPublicKey {
    pub p: Integer,
    pub q: Integer,
    pub g: Integer,
    pub h: Integer,
}

// Represents the El Gamal's secret key
#[derive(Debug)]
pub struct ElGamalSecretKey {
    pub x: Integer,
}

impl ElGamalPublicKey {
    pub fn new(p: Integer, q: Integer, g: Integer, h: Integer) -> Self {
        Self { p, q, g, h }
    }
}

impl ElGamalSecretKey {
    pub fn new(x: Integer) -> Self {
        Self { x }
    }
}
