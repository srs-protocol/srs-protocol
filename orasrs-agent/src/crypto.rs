use crate::error::{AgentError, Result};
use blake3;
use ring::{digest, rand, aead};

/// Cryptographic utilities for OraSRS Agent
pub struct CryptoProvider;

impl CryptoProvider {
    /// Generate Blake3 hash of data
    pub fn blake3_hash(data: &[u8]) -> String {
        let hash = blake3::hash(data);
        hash.to_hex().as_str()[..16].to_string() // Use first 16 chars for brevity
    }
    
    /// Generate SM3 hash (placeholder - in real implementation would use actual SM3)
    #[cfg(feature = "sm_crypto")]
    pub fn sm3_hash(data: &[u8]) -> String {
        // Placeholder implementation - would use actual SM3 in real implementation
        use sm_crypto::sm3::{Sm3, Hash};
        let mut sm3 = Sm3::new();
        sm3.update(data);
        let result = sm3.finalize();
        format!("{:x}", result)
    }
    
    /// Generate SM3 hash (fallback without sm_crypto feature)
    #[cfg(not(feature = "sm_crypto"))]
    pub fn sm3_hash(data: &[u8]) -> String {
        // Fallback to Blake3 when SM crypto is not enabled
        Self::blake3_hash(data)
    }
    
    /// Encrypt data using AES-256-GCM (or SM4 if enabled)
    pub fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // Use AES-256-GCM for now
        let rng = rand::SystemRandom::new();
        let key_bytes = if key.len() >= 32 {
            &key[..32]
        } else {
            return Err(AgentError::CryptoError("Key too short".to_string()));
        };
        
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
                .map_err(|e| AgentError::CryptoError(format!("Invalid key: {}", e)))?
        );
        
        let nonce = aead::Nonce::try_assume_unique_for_key(&[0u8; 12][..])
            .map_err(|e| AgentError::CryptoError(format!("Invalid nonce: {}", e)))?;
        
        let aad = aead::Aad::empty();
        
        let mut data_vec = data.to_vec();
        key.seal_in_place_append_tag(nonce, aad, &mut data_vec)
            .map_err(|e| AgentError::CryptoError(format!("Encryption failed: {}", e)))?;
        
        Ok(data_vec)
    }
    
    /// Decrypt data using AES-256-GCM (or SM4 if enabled)
    pub fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // Use AES-256-GCM for now
        let rng = rand::SystemRandom::new();
        let key_bytes = if key.len() >= 32 {
            &key[..32]
        } else {
            return Err(AgentError::CryptoError("Key too short".to_string()));
        };
        
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
                .map_err(|e| AgentError::CryptoError(format!("Invalid key: {}", e)))?
        );
        
        let nonce = aead::Nonce::try_assume_unique_for_key(&[0u8; 12][..])
            .map_err(|e| AgentError::CryptoError(format!("Invalid nonce: {}", e)))?;
        
        let aad = aead::Aad::empty();
        
        let mut data_vec = encrypted_data.to_vec();
        let decrypted = key.open_in_place(nonce, aad, &mut data_vec)
            .map_err(|e| AgentError::CryptoError(format!("Decryption failed: {}", e)))?;
        
        Ok(decrypted.to_vec())
    }
    
    /// Generate a secure random key
    pub fn generate_key() -> Result<Vec<u8>> {
        let rng = rand::SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key)
            .map_err(|e| AgentError::CryptoError(format!("Key generation failed: {}", e)))?;
        Ok(key.to_vec())
    }
    
    /// Sign data with SM2 (placeholder implementation)
    #[cfg(feature = "sm_crypto")]
    pub fn sm2_sign(data: &[u8], private_key: &[u8]) -> Result<String> {
        // Placeholder implementation
        Ok(format!("sm2_signature_placeholder_{}", Self::blake3_hash(data)))
    }
    
    /// Sign data with SM2 (fallback without sm_crypto feature)
    #[cfg(not(feature = "sm_crypto"))]
    pub fn sm2_sign(data: &[u8], _private_key: &[u8]) -> Result<String> {
        // Fallback to regular signature
        Ok(format!("signature_placeholder_{}", Self::blake3_hash(data)))
    }
}