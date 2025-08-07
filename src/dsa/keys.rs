use rug::Integer;


#[derive(Debug, Clone)]
pub struct DSAPublicKey {

    pub p: Integer,
    pub q: Integer,
    pub g: Integer,
    pub y: Integer,
}


#[derive(Debug)]
pub struct DSASecretKey {

    pub x: Integer,
    pub p: Integer,
    pub q: Integer,
    pub g: Integer,
}


#[derive(Debug, Clone)]
pub struct DSASignature {

    pub r: Integer,
    pub s: Integer,
}

impl DSAPublicKey {
    pub fn new(p: Integer, q: Integer, g: Integer, y: Integer) -> Self {
        Self { p, q, g, y }
    }
}

impl DSASecretKey {
    pub fn new(x: Integer, p: Integer, q: Integer, g: Integer) -> Self {
        Self { x, p, q, g }
    }
}

impl DSASignature {
    pub fn new(r: Integer, s: Integer) -> Self {
        Self { r, s }
    }
}
