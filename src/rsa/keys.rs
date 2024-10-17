use rug::Integer;

// Represents the RSA's public key
#[derive(Debug)]
pub struct RSAPublicKey {
    // RSA modulus N = pq
    pub n: Integer,
    // Public exponent
    pub e: Integer,
}

// Represents the RSA's secret key
#[derive(Debug)]
pub struct RSASecretKey {
    // Prime factor of N
    pub p: Integer,
    pub q: Integer,

    // CRT attributes
    pub d_p: Integer,
    pub d_q: Integer,
    pub q_inv: Integer,
}

impl RSAPublicKey {
    pub fn new(n: Integer, e: Integer) -> Self {
        Self { n, e }
    }
}

impl RSASecretKey {
    pub fn new(p: Integer, q: Integer, d_p: Integer, d_q: Integer, q_inv: Integer) -> Self {
        Self {
            p,
            q,
            d_p,
            d_q,
            q_inv,
        }
    }
}
