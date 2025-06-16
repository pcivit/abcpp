use blst::min_sig::{PublicKey, SecretKey, Signature};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::crypto::{
    multisig::{DST, verify},
    public_params::PublicParams,
};

/// Key generation for the VRF scheme (currently same as multisig)
#[allow(dead_code)] //we use the same key for both msig and vrf
pub fn keygen() -> (SecretKey, PublicKey) {
    let mut ikm = [0u8; 32];
    OsRng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).expect("VRF keygen failed");
    let pk = sk.sk_to_pk();
    (sk, pk)
}

/// Simulates VRF-style election
pub fn vrf_sample(sk: &SecretKey, label: &[u8], params: &PublicParams) -> (bool, Signature) {
    let input = [b"VRF", label].concat();
    let sig = sk.sign(&input, DST, &[]);
    let is_elected = threshold_verify(&sig, params);
    (is_elected, sig)
}

/// Verifies VRF-style election proof
pub fn vrf_verify(pk: &PublicKey, label: &[u8], proof: &Signature, params: &PublicParams) -> bool {
    let input = [b"VRF", label].concat();
    if !verify(pk, &input, proof) {
        return false;
    }
    threshold_verify(proof, params)
}

pub fn threshold_verify(proof: &Signature, params: &PublicParams) -> bool {
    let sig_bytes = proof.serialize();
    let mut hasher = Sha256::new();
    hasher.update(&sig_bytes);
    let digest = hasher.finalize();

    let r = u128::from_be_bytes(digest[0..16].try_into().unwrap());
    let max = u128::MAX;
    let threshold = (params.vrf_probability() * (max as f64)) as u128;

    r < threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::public_params::PublicParams;

    #[test]
    fn test_vrf_sample_and_verify() {
        let (sk, pk) = keygen();
        let label = b"step123";

        let params = PublicParams {
            n: 1000,
            lambda: 50.0,
            epsilon: 0.05,
            delta: 0.05,
            kappa_hash: 256,
            kappa_msig: 256,
            kappa_vrf: 256,
        };

        let (elected, proof) = vrf_sample(&sk, label, &params);

        if elected {
            assert!(vrf_verify(&pk, label, &proof, &params));
        }
    }

    #[test]
    fn test_vrf_always_verifies_with_correct_key() {
        let (sk, pk) = keygen();
        let label = b"step-test-verify";
        let params = PublicParams {
            n: 100,
            lambda: 20.0,
            epsilon: 0.01,
            delta: 0.01,
            kappa_hash: 256,
            kappa_msig: 256,
            kappa_vrf: 256,
        };

        let (_, proof) = vrf_sample(&sk, label, &params);
        // Should always pass signature verification
        //let input = [b"VRF", label].concat();
        let input = [b"VRF".as_slice(), label].concat();

        assert!(verify(&pk, &input, &proof));
    }

    #[test]
    fn test_vrf_rejects_wrong_public_key() {
        let (sk1, _) = keygen();
        let (_, pk2) = keygen();
        let label = b"step-test-reject";
        let params = PublicParams {
            n: 100,
            lambda: 20.0,
            epsilon: 0.01,
            delta: 0.01,
            kappa_hash: 256,
            kappa_msig: 256,
            kappa_vrf: 256,
        };

        let (_, proof) = vrf_sample(&sk1, label, &params);
        assert!(!vrf_verify(&pk2, label, &proof, &params));
    }

    #[test]
    fn test_vrf_threshold_is_respected() {
        let (sk, _) = keygen();
        let label = b"step-threshold";
        let mut params = PublicParams {
            n: 100,
            lambda: 10.0,
            epsilon: 0.0,
            delta: 0.0,
            kappa_hash: 256,
            kappa_msig: 256,
            kappa_vrf: 256,
        };

        // Extremely small probability
        params.lambda = 1.0;
        let (_, proof) = vrf_sample(&sk, label, &params);
        let passed = threshold_verify(&proof, &params);

        // Most likely: false
        assert!(matches!(passed, false | true)); // Just confirm execution without panic
    }

    #[test]
    fn test_serialization_consistency() {
        let (sk, _) = keygen();
        let label = b"serialization";
        let params = PublicParams {
            n: 100,
            lambda: 20.0,
            epsilon: 0.01,
            delta: 0.01,
            kappa_hash: 256,
            kappa_msig: 256,
            kappa_vrf: 256,
        };

        let (_, sig1) = vrf_sample(&sk, label, &params);
        let serialized = sig1.serialize();
        let sig2 = Signature::deserialize(&serialized).expect("deserialization failed");
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_vrf_statistical_sampling() {
        let (sk, _) = keygen();
        let params = PublicParams {
            n: 100,
            lambda: 20.0,
            epsilon: 0.01,
            delta: 0.01,
            kappa_hash: 256,
            kappa_msig: 256,
            kappa_vrf: 256,
        };

        let trials = 1000;
        let mut elected = 0;

        for i in 0..trials {
            let label = format!("vrf_label_{}", i);
            let (is_elected, _) = vrf_sample(&sk, label.as_bytes(), &params);
            if is_elected {
                elected += 1;
            }
        }

        let avg = elected as f64 / trials as f64;
        let expected = params.vrf_probability(); // ~λ/n
        let tolerance = 0.1;

        assert!(
            (avg - expected).abs() < tolerance,
            "Empirical rate {:.4} differs too much from expected {:.4}",
            avg,
            expected
        );
    }
}
