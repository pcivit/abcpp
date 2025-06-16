use blst::BLST_ERROR;
pub use blst::min_sig::*;
use rand::{RngCore, rngs::OsRng};

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub fn keygen() -> (SecretKey, PublicKey) {
    let mut ikm = [0u8; 32];
    OsRng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).expect("keygen failed");
    let pk = sk.sk_to_pk();
    (sk, pk)
}

pub fn sign(sk: &SecretKey, msg: &[u8]) -> Signature { sk.sign(msg, DST, &[]) }

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    sig.verify(true, msg, DST, &[], pk, true) == BLST_ERROR::BLST_SUCCESS
}

/*pub fn aggregate_signatures(sigs: &[&Signature]) -> AggregateSignature {
    AggregateSignature::aggregate(sigs, true).expect("aggregation failed")
}*/

pub fn append_signature(mut agg: AggregateSignature, sig: &Signature) -> AggregateSignature {
    let sub_agg = AggregateSignature::from_signature(sig);
    agg.add_aggregate(&sub_agg);
    agg
}

pub fn aggregate_public_keys(pks: &[&PublicKey]) -> AggregatePublicKey {
    AggregatePublicKey::aggregate(pks, true).expect("pk aggregation failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let msg = b"hello world";
        let (sk, pk) = keygen();
        let sig = sign(&sk, msg);
        assert!(verify(&pk, msg, &sig));
    }

    #[test]
    fn test_append_signature_aggregation() {
        let msg = b"aggregate this";
        let mut sigs = Vec::new();
        let mut pks = Vec::new();

        for _ in 0..5 {
            let (sk, pk) = keygen();
            let sig = sign(&sk, msg);
            sigs.push(sig);
            pks.push(pk);
        }

        // Start with first signature as initial aggregate
        let mut agg_sig = AggregateSignature::from_signature(&sigs[0]);
        for sig in &sigs[1..] {
            agg_sig = append_signature(agg_sig, sig);
        }

        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let agg_pk = aggregate_public_keys(&pk_refs);

        let verified =
            agg_sig.to_signature().verify(true, msg, DST, &[], &agg_pk.to_public_key(), true);
        assert_eq!(verified, BLST_ERROR::BLST_SUCCESS);
    }

    #[test]
    fn test_wrong_message_fails_verification() {
        let correct_msg = b"correct message";
        let wrong_msg = b"tampered message";
        let (sk, pk) = keygen();
        let sig = sign(&sk, correct_msg);
        assert!(!verify(&pk, wrong_msg, &sig));
    }

    #[test]
    fn test_wrong_public_key_fails_verification() {
        let msg = b"test message";
        let (sk1, _) = keygen();
        let (_, pk2) = keygen();
        let sig = sign(&sk1, msg);
        assert!(!verify(&pk2, msg, &sig));
    }

    #[test]
    fn test_single_signature_aggregation_is_correct() {
        let msg = b"solo signature";
        let (sk, pk) = keygen();
        let sig = sign(&sk, msg);
        let agg_sig = AggregateSignature::from_signature(&sig);
        let agg_pk = AggregatePublicKey::aggregate(&[&pk], true).unwrap();

        let verified =
            agg_sig.to_signature().verify(true, msg, DST, &[], &agg_pk.to_public_key(), true);
        assert_eq!(verified, BLST_ERROR::BLST_SUCCESS);
    }

    #[test]
    fn test_empty_signature_aggregation_fails() {
        let empty_sigs: Vec<&Signature> = vec![];
        let result = AggregateSignature::aggregate(&empty_sigs, true);
        assert!(result.is_err());
    }
}
