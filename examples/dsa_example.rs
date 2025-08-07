use pke_rust::dsa::algorithms::DSA;
use pke_rust::traits::digital_signature::DigitalSignature;
use pke_rust::utils::rand::rug_randseed_os_rng;
use rug::rand::RandState;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== DSA Digital Signature Example ===\n");
    
    let mut rng = RandState::new();
    rug_randseed_os_rng(128, &mut rng)?;
    
    println!("1. Generating DSA key pair (this may take a moment)...");
    let (secret_key, public_key) = DSA::keygen(80, &mut rng)?;
    println!("    Key pair generated successfully");
    println!("   Domain parameters:");
    println!("     p ({} bits): {}...", public_key.p.significant_bits_64(), 
             public_key.p.to_string().chars().take(50).collect::<String>());
    println!("     q ({} bits): {}...", public_key.q.significant_bits_64(), 
             public_key.q.to_string().chars().take(50).collect::<String>());
    println!("     g: {}...", public_key.g.to_string().chars().take(50).collect::<String>());
    
    let message = b"Hello, this is a test message for DSA digital signature!";
    println!("\n2. Message to sign: {:?}", String::from_utf8_lossy(message));
    
    println!("\n3. Signing the message...");
    let signature = DSA::sign(&secret_key, message, &mut rng)?;
    println!("    Message signed successfully");
    println!("   Signature:");
    println!("     r: {}...", signature.r.to_string().chars().take(50).collect::<String>());
    println!("     s: {}...", signature.s.to_string().chars().take(50).collect::<String>());
    
    println!("\n4. Verifying the signature...");
    let is_valid = DSA::verify(&public_key, message, &signature)?;
    println!("   Signature valid: {}", is_valid);
    
    if is_valid {
        println!(" Signature verification successful!");
    } else {
        println!(" Signature verification failed!");
        return Err(" Signature verification failed");
    }
    
    println!("\n5. Testing with tampered message...");
    let tampered_message = b"Hello, this is a TAMPERED message for DSA digital signature!";
    let is_tampered_valid = DSA::verify(&public_key, tampered_message, &signature)?;
    println!("   Tampered message signature valid: {}", is_tampered_valid);
    
    if !is_tampered_valid {
        println!(" Correctly detected tampered message!");
    } else {
        println!(" Failed to detect tampered message!");
    }
    
    println!("\n6. Testing with tampered signature...");
    let mut tampered_signature = signature.clone();
    tampered_signature.r = &tampered_signature.r + rug::Integer::from(1);
    let is_tampered_sig_valid = DSA::verify(&public_key, message, &tampered_signature)?;
    println!(" Tampered signature valid: {}", is_tampered_sig_valid);
    
    if !is_tampered_sig_valid {
        println!(" Correctly detected tampered signature!");
    } else {
        println!(" Failed to detect tampered signature!");
    }
    
    println!("\n=== DSA Example Complete ===");
    Ok(())
}
