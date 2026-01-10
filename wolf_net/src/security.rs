use anyhow::{anyhow, Result};
use libp2p::identity::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};

/// A secure wrapper for all application-level P2P messages.
///
/// It contains the sender's public key and a signature of the payload,
/// ensuring message authenticity and non-repudiation. The payload itself
/// is sent in the clear, as we rely on the underlying `libp2p-noise`
/// transport for confidentiality.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedEnvelope {
    /// The sender's public key, protobuf encoded.
    pub public_key: Vec<u8>,
    /// The serialized original message/payload.
    pub payload: Vec<u8>,
    /// A signature of the payload bytes.
    pub signature: Vec<u8>,
}

/// A manager for handling application-level network security operations.
/// This provides message signing and verification.
#[derive(Default, Debug)]
pub struct NetworkSecurity;

impl NetworkSecurity {
    /// Creates a new `NetworkSecurity` manager.
    pub const fn new() -> Self {
        Self
    }

    /// Signs a payload with the local keypair and wraps it in a `SignedEnvelope`.
    ///
    /// # Arguments
    /// * `keypair` - The local peer's `Keypair`, used for signing.
    /// * `payload` - The raw bytes of the message to be sent.
    pub fn sign(&self, keypair: &Keypair, payload: &[u8]) -> Result<SignedEnvelope> {
        let signature = keypair
            .sign(payload)
            .map_err(|e| anyhow!("Failed to sign payload: {e}"))?;

        let public_key_bytes = keypair.public().encode_protobuf();

        Ok(SignedEnvelope {
            public_key: public_key_bytes,
            payload: payload.to_vec(),
            signature,
        })
    }

    /// Verifies a `SignedEnvelope`.
    ///
    /// On success, it returns the sender's `PublicKey` and the original payload.
    /// The caller can then use the `PublicKey` to derive the `PeerId` and
    /// check it against a list of known/trusted peers.
    ///
    /// # Arguments
    /// * `envelope` - The `SignedEnvelope` received from the network.
    pub fn verify(&self, envelope: &SignedEnvelope) -> Result<(PublicKey, Vec<u8>)> {
        let public_key = PublicKey::try_decode_protobuf(&envelope.public_key)
            .map_err(|e| anyhow!("Failed to decode public key from envelope: {e}"))?;

        // The public key must verify the signature against the original payload.
        if !public_key.verify(&envelope.payload, &envelope.signature) {
            return Err(anyhow!("Invalid signature for payload"));
        }

        Ok((public_key, envelope.payload.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn test_signing_and_verification_roundtrip() {
        // 1. Setup
        let security = NetworkSecurity::new();
        let local_keypair = Keypair::generate_ed25519();
        let payload = b"This is a highly secret wolf prowler message.";

        // 2. Sign the payload
        let signed_envelope = security.sign(&local_keypair, payload).unwrap();

        // 3. Verify the envelope
        let (sender_pub_key, verified_payload) = security.verify(&signed_envelope).unwrap();

        // 4. Assert correctness
        assert_eq!(
            local_keypair.public(),
            sender_pub_key,
            "Verified public key should match the original sender's key"
        );
        assert_eq!(
            payload.to_vec(),
            verified_payload,
            "Verified payload should match the original payload"
        );
    }

    #[test]
    fn test_verification_fails_with_wrong_key() {
        let security = NetworkSecurity::new();
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519(); // A different peer
        let payload = b"message from keypair1";

        // Sign with keypair1
        let mut signed_envelope = security.sign(&keypair1, payload).unwrap();

        // Tamper with the envelope to claim it's from keypair2
        signed_envelope.public_key = keypair2.public().encode_protobuf();

        // Verification should now fail because keypair2's public key
        // cannot verify a signature made by keypair1.
        let result = security.verify(&signed_envelope);
        assert!(
            result.is_err(),
            "Verification should fail when the public key does not match the signature"
        );
    }
}
