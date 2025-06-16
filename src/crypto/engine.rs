use std::collections::HashMap;

pub use blst::BLST_ERROR;
use blst::min_sig::{AggregatePublicKey, PublicKey, SecretKey, Signature};
pub use ed25519_dalek::{
    Signature as EdSignature, SigningKey as EdSecretKey, Verifier, VerifyingKey as EdPublicKey,
};

use crate::crypto::{process_id::ProcessId, public_params::PublicParams};

#[derive(Debug, Clone)] //Serialize, Deserialize
pub struct CryptoMaterial {
    pub secrets: HashMap<String, SecretKey>,
    pub publics: HashMap<String, PublicKey>,
    pub edsecret: EdSecretKey,
    pub edpublic: EdPublicKey,
}

impl CryptoMaterial {
    pub fn new(sk: SecretKey, pk: PublicKey, ed_sk: EdSecretKey, ed_pk: EdPublicKey) -> Self {
        let mut secrets = HashMap::new();
        let mut publics = HashMap::new();
        secrets.insert("msig".to_string(), sk.clone());
        secrets.insert("vrf".to_string(), sk);
        publics.insert("msig".to_string(), pk.clone());
        publics.insert("vrf".to_string(), pk);
        CryptoMaterial {
            secrets,
            publics,
            edsecret: ed_sk,
            edpublic: ed_pk,
        }
    }

    pub fn fresh() -> Self {
        // For now, we use the same keypair for both msig and vrf.
        // Later, this can be changed to generate distinct keys.
        let (sk, pk) = crate::crypto::multisig::keygen();

        let mut csprng = rand::rngs::OsRng;
        let ed_sk: EdSecretKey = EdSecretKey::generate(&mut csprng);
        let ed_vk = ed_sk.verifying_key();

        Self::new(sk, pk, ed_sk, ed_vk)
    }

    pub fn secret(&self, label: &str) -> Option<&SecretKey> { self.secrets.get(label) }

    #[allow(dead_code)]
    pub fn public(&self, label: &str) -> Option<&PublicKey> { self.publics.get(label) }
}

#[derive(Debug, Clone)]
pub struct CertAuthority {
    pub records: HashMap<ProcessId, HashMap<String, PublicKey>>,
    pub ed_record: HashMap<ProcessId, EdPublicKey>,
}

impl CertAuthority {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            ed_record: HashMap::new(),
        }
    }

    pub fn register(&mut self, id: ProcessId, material: &crate::crypto::engine::CryptoMaterial) {
        self.records.insert(id, material.publics.clone());
        self.ed_record.insert(id, material.edpublic.clone());
    }

    pub fn public_key(&self, id: &ProcessId, label: &str) -> Option<&PublicKey> {
        self.records.get(id).and_then(|map| map.get(label))
    }

    /*pub fn ed_register(&mut self, id: ProcessId, material: &crate::crypto::engine::CryptoMaterial) {
        self.ed_record.insert(id, material.edpublic.clone());
    }*/

    pub fn ed_public_key(&self, id: &ProcessId) -> Option<&EdPublicKey> { self.ed_record.get(id) }
}

/// Verifies a VRF proof using a process ID and the CertAuthority.
#[allow(dead_code)]
pub fn verify_vrf_from_id(
    ca: &CertAuthority,
    id: &ProcessId,
    label: &[u8],
    proof: &Signature,
    params: &PublicParams,
) -> bool {
    if let Some(pk) = ca.public_key(id, "vrf") {
        crate::crypto::vrf::vrf_verify(pk, label, proof, params)
    } else {
        false
    }
}

/// Verifies an Ed25519 signature using the given process ID and the CertAuthority.
pub fn verify_edsig_from_id(
    ca: &CertAuthority,
    id: &ProcessId,
    msg: &[u8],
    proof: &EdSignature,
) -> bool {
    match ca.ed_public_key(id) {
        Some(pk) => pk.verify(msg, proof).is_ok(),
        None => false,
    }
}

/// Verifies a BLS multisignature over a message for a given set of signers.
#[allow(dead_code)]
pub fn verify_msig_from_ids(
    ca: &CertAuthority,
    ids: &[ProcessId],
    msg: &[u8],
    sig: &Signature,
) -> bool {
    let pub_keys: Vec<&blst::min_sig::PublicKey> =
        ids.iter().filter_map(|id| ca.public_key(id, "msig")).collect();

    if pub_keys.len() != ids.len() {
        return false; // Some public keys are missing
    }

    let agg_pk = AggregatePublicKey::aggregate(&pub_keys, true)
        .expect("Failed to aggregate public keys")
        .to_public_key();

    sig.verify(true, msg, crate::crypto::multisig::DST, &[], &agg_pk, true)
        == BLST_ERROR::BLST_SUCCESS
}

/// Verifies a BLS multisignature over a message for a given set of signers.
pub fn verify_msig_from_id(
    ca: &CertAuthority,
    id: &ProcessId,
    msg: &[u8],
    sig: &Signature,
) -> bool {
    if let Some(pk) = ca.public_key(id, "msig") {
        sig.verify(true, msg, crate::crypto::multisig::DST, &[], &pk, true)
            == BLST_ERROR::BLST_SUCCESS
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Signer};

    use super::*;
    use crate::crypto::process_id::ProcessId;

    #[test]
    fn test_crypto_material_fresh_and_access() {
        let cm = CryptoMaterial::fresh();
        assert!(cm.secret("msig").is_some());
        assert!(cm.secret("vrf").is_some());
        assert!(cm.public("msig").is_some());
        assert!(cm.public("vrf").is_some());
    }

    #[test]
    fn test_cert_authority_registration_and_query() {
        let cm = CryptoMaterial::fresh();
        let id = ProcessId(1);
        let mut ca = CertAuthority::new();
        ca.register(id, &cm);

        assert!(ca.public_key(&id, "msig").is_some());
        assert!(ca.public_key(&id, "vrf").is_some());
        assert!(ca.ed_public_key(&id).is_some());
    }

    #[test]
    fn test_verify_edsig_from_id() {
        let cm = CryptoMaterial::fresh();
        let id = ProcessId(7);
        let mut ca = CertAuthority::new();
        ca.register(id, &cm);

        let msg = b"test message";
        let sig: Signature = cm.edsecret.sign(msg);
        assert!(verify_edsig_from_id(&ca, &id, msg, &sig));
    }

    #[test]
    fn test_verify_msig_from_id() {
        let cm = CryptoMaterial::fresh();
        let id = ProcessId(42);
        let mut ca = CertAuthority::new();
        ca.register(id, &cm);

        let msg = b"bls test message";
        let sk = cm.secret("msig").unwrap();
        let sig = sk.sign(msg, crate::crypto::multisig::DST, &[]);

        assert!(verify_msig_from_id(&ca, &id, msg, &sig));
    }

    #[test]
    fn test_verify_msig_from_ids() {
        let mut ca = CertAuthority::new();
        let msg = b"bls group test";
        let mut signers = vec![];
        let mut sigs = vec![];

        for i in 0..5 {
            let cm = CryptoMaterial::fresh();
            let id = ProcessId(i);
            ca.register(id, &cm);
            let sk = cm.secret("msig").unwrap();
            let sig = sk.sign(msg, crate::crypto::multisig::DST, &[]);
            signers.push(id);
            sigs.push(sig);
        }

        let mut agg_sig = blst::min_sig::AggregateSignature::from_signature(&sigs[0]);
        for s in &sigs[1..] {
            let part = blst::min_sig::AggregateSignature::from_signature(s);
            agg_sig.add_aggregate(&part);
        }

        assert!(verify_msig_from_ids(&ca, &signers, msg, &agg_sig.to_signature()));
    }
}
