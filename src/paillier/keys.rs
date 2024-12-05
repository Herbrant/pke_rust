use rug::Integer;

// Represents the Paillier's public key
#[derive(Debug)]
pub struct PaillierPublicKey {
    pub n: Integer,
    pub n_square: Integer,
    pub g: Integer,
}

// Represents the Paillier's secret key
#[derive(Debug)]
pub struct PaillierSecretKey {
    pub lambda: Integer,
    pub mu: Integer,
}

impl PaillierPublicKey {
    pub fn new(n: Integer, n_square: Integer, g: Integer) -> Self {
        PaillierPublicKey { n, n_square, g }
    }
}

impl PaillierSecretKey {
    pub fn new(lambda: Integer, mu: Integer) -> Self {
        PaillierSecretKey { lambda, mu }
    }
}
