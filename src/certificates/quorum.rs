use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use blst::min_sig::*;
use blst::{
    BLST_ERROR,
    min_sig::{AggregatePublicKey, AggregateSignature},
}; //min_sig::{AggregateSignature, AggregatePublicKey}
use crossbeam::thread;
pub use ed25519_dalek::{Signature as EdSignature, Signer};

use crate::crypto::{
    engine::{CertAuthority, CryptoMaterial},
    multisig::DST,
    process_id::ProcessId,
    public_params::PublicParams,
    vrf::threshold_verify,
};

#[derive(Debug, Clone)]
pub struct SignedSubmission {
    pub step: u64, // Nonce for session/sub-session (e.g., submit message w.r.t. the x-th decision)
    pub hash_value: [u8; 32], // Hash of the submitted value (e.g., sha256(x-th pre-decision))
    pub signer: ProcessId, // Signer's process ID (could have been obtained from the authenticated channel, but this is simpler)
    pub signature: Signature, // Multi-signature over step || hash_value
    pub vrf_proof: Signature, // VRF proof for eligibility (typically BLS signature)
    pub ed_signature: EdSignature, // eddsa signature used for accountability for optimistic verification of aggregated signatures
}

#[derive(Debug, Clone)]
pub struct QuorumCertificate {
    pub step: u64,                                    // Same step as in SignedSubmission
    pub hash_value: [u8; 32],                         // Agreed-upon value's hash
    pub signers: Vec<ProcessId>,                      // List of signers
    pub aggregated_signature: AggregateSignature,     // Multi-signature over step || hash_value
    pub aggregated_public_key: Option<PublicKey>, // Optional for optimistic parallel verification
    pub vrf_proofs: Vec<Signature>, // VRF proof for eligibility (typically BLS signature)
    pub aggregated_vrf_signature: AggregateSignature, // BLS Multi-signature over step used an aggregated VRF proof
}

#[derive(Debug, Clone)]
pub struct SubmissionManager {
    pub id: ProcessId,
    pub engine: Arc<CryptoMaterial>,
    pub ca: Arc<CertAuthority>,
    pub params: Arc<PublicParams>,
    pub proposed: HashMap<u64, ([u8; 32], Option<QuorumCertificate>)>, //maps step to pairs (hash_value, QC)
    pub certificates: HashMap<(u64, [u8; 32]), QuorumCertificate>, //maps pairs (step, hash_value) to QCs
    pub ratified: bool,
    //pub verification_tree: HashMap<(u64, [u8; 32]), SigTreeNode>, //used for moving rapidly from optimistic verif to pessimistic verif
}

#[derive(Debug, Clone)]
pub struct CertManager {
    #[allow(dead_code)]
    id: ProcessId,
    pub ca: Arc<CertAuthority>,
    pub params: Arc<PublicParams>,
    pub known_certificates: HashMap<(u64, [u8; 32]), QuorumCertificate>, //maps pairs (step, hash_value) to QCs
}

/// Combines a step (u64) and a hash value ([u8; 32]) into a message buffer suitable for signing/verifying.
pub fn make_message(step: u64, hash_value: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 32);
    msg.extend_from_slice(&step.to_be_bytes()); // Use big-endian for consistent serialization
    msg.extend_from_slice(hash_value);
    msg
}

/// Build the full message to be signed with EdDSA for accountability.
/// Includes `step`, `hash_value`, `signature`, and `vrf_proof`.
pub fn make_full_submit_message(
    step: u64,
    hash_value: &[u8; 32],
    signature: &Signature,
    vrf_proof: &Signature,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 32 + signature.to_bytes().len() * 2);
    msg.extend_from_slice(&step.to_be_bytes()); // 8 bytes
    msg.extend_from_slice(hash_value); // 32 bytes
    msg.extend_from_slice(&signature.to_bytes()); // 96 bytes (compressed G1)
    msg.extend_from_slice(&vrf_proof.to_bytes()); // 96 bytes (compressed G1)
    msg
}

/*
fn hash256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}*/

impl SignedSubmission {
    pub fn create_if_eligible(
        step: u64,
        hash_value: [u8; 32],
        signer: ProcessId,
        engine: &CryptoMaterial,
        params: &PublicParams,
    ) -> Option<Self> {
        // Check eligibility using VRF
        let sk = engine.secret("vrf")?;
        let (elected, vrf_proof) = crate::crypto::vrf::vrf_sample(sk, &step.to_be_bytes(), params);
        if !elected {
            return None;
        }

        // Sign the message using multisignature scheme
        let msg = make_message(step, &hash_value);
        let signature = crate::crypto::multisig::sign(engine.secret("msig")?, &msg);

        //Sign with eddsa signature for accountability in case of optimistic verification
        let msgfull = make_full_submit_message(step, &hash_value, &signature, &vrf_proof);
        let ed_signature = engine.edsecret.sign(&msgfull);

        Some(Self {
            step,
            hash_value,
            signer,
            signature,
            vrf_proof,
            ed_signature,
        })
    }

    pub fn ed_verify(&self, ca: &CertAuthority) -> bool {
        use crate::crypto::engine::verify_edsig_from_id;
        let msg =
            make_full_submit_message(self.step, &self.hash_value, &self.signature, &self.vrf_proof);
        verify_edsig_from_id(ca, &self.signer, &msg, &self.ed_signature)
    }

    pub fn vrf_threshold_verify(&self, params: &PublicParams) -> bool {
        threshold_verify(&self.vrf_proof, params)
    }

    pub fn optimistic_partial_verify(&self, ca: &CertAuthority, params: &PublicParams) -> bool {
        self.ed_verify(ca) && self.vrf_threshold_verify(params)
    }

    pub fn almost_full_verify(&self, ca: &CertAuthority, params: &PublicParams) -> bool {
        use crate::crypto::engine::verify_msig_from_id;
        let msg = make_message(self.step, &self.hash_value);
        let valid_sig = verify_msig_from_id(ca, &self.signer, &msg, &self.signature);
        let valid_threshold = threshold_verify(&self.vrf_proof, params);
        valid_sig && valid_threshold
    }

    #[allow(dead_code)]
    pub fn full_verify(&self, ca: &CertAuthority, params: &PublicParams) -> bool {
        self.ed_verify(ca) && self.almost_full_verify(ca, params)
    }

    /*
    pub fn verify(&self, ca: &CertAuthority, params: &PublicParams) -> bool {

        //use crate::crypto::engine::verify_vrf_from_id;
        use crate::crypto::engine::verify_msig_from_id;
        //even in optimistic verification
        let valid_ed = self.ed_verify(ca);
        let valid_vrf_threshold = self.vrf_threshold_verify(params);
        let msg = make_message(self.step, &self.hash_value);
        let valid_sig = verify_msig_from_id(ca, &self.signer, &msg, &self.signature);
        let valid_vrf = valid_sig && valid_vrf_threshold ; // in the BLS optimized case
        //let valid_vrf = verify_vrf_from_id(ca, &self.signer, &self.step.to_be_bytes(),&self.vrf_proof,params);


        valid_sig && valid_vrf && valid_ed
    }
    */
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerificationMode {
    #[allow(dead_code)]
    Agnostic, // Verify every VRF proof individually
    BLSOptimized, // Just verify the multi-signature and threshold conditions
    #[allow(dead_code)]
    BLSOptimizedParallelized, // Perform BLSOptimized with parallelization
}

impl QuorumCertificate {
    pub fn new(ca: &CertAuthority, sub: &SignedSubmission) -> Self {
        Self {
            step: sub.step,
            hash_value: sub.hash_value,
            signers: vec![sub.signer],
            aggregated_signature: AggregateSignature::from_signature(&sub.signature),
            aggregated_public_key: ca.public_key(&sub.signer, "msig").copied(),
            vrf_proofs: vec![sub.vrf_proof.clone()],
            aggregated_vrf_signature: AggregateSignature::from_signature(&sub.vrf_proof),
        }
    }

    /*pub fn append(&mut self, sub: &SignedSubmission, ca: &CertAuthority) {
        assert_eq!(self.step, sub.step, "Step mismatch");
        assert_eq!(self.hash_value, sub.hash_value, "Hash mismatch");

        self.signers.push(sub.signer);
        self.vrf_proofs.push(sub.vrf_proof.clone());

        // Aggregate signature with the new one
        self.aggregated_signature = AggregateSignature::aggregate(
            &[&self.aggregated_signature.to_signature(), &sub.signature],
            true,
        ).expect("Signature aggregation failed");

        // Incrementally aggregate public keys
        let new_pk = ca.public_key(&sub.signer, "msig").expect("Missing public key for new signer");

        let updated_agg_pk = if let Some(existing_pk) = &self.aggregated_public_key {
            let agg = AggregatePublicKey::aggregate(&[existing_pk, new_pk], true)
                .expect("Public key aggregation failed");
            //let mut agg = AggregatePublicKey::from_public_key(existing_pk);
            //agg.add_aggregate(new_pk);
            Some(agg.to_public_key())
        } else {
            Some(new_pk.clone())
        };
        self.aggregated_public_key = updated_agg_pk;
    }*/

    pub fn append(&mut self, sub: &SignedSubmission, ca: &CertAuthority) {
        assert_eq!(self.step, sub.step, "Step mismatch");
        assert_eq!(self.hash_value, sub.hash_value, "Hash mismatch");

        self.signers.push(sub.signer);
        self.vrf_proofs.push(sub.vrf_proof.clone());

        use crate::crypto::multisig::append_signature;

        self.aggregated_signature =
            append_signature(self.aggregated_signature.clone(), &sub.signature);

        self.aggregated_vrf_signature =
            append_signature(self.aggregated_vrf_signature.clone(), &sub.vrf_proof);

        // --- Public key aggregation ---
        let new_pk = ca.public_key(&sub.signer, "msig").expect("Missing public key");
        let new_agg_pk = AggregatePublicKey::from_public_key(new_pk);

        let updated_agg_pk = match &self.aggregated_public_key {
            Some(existing_pk) => {
                let mut agg = AggregatePublicKey::from_public_key(existing_pk);
                agg.add_aggregate(&new_agg_pk);
                Some(agg.to_public_key())
            }
            None => Some(new_pk.clone()),
        };

        self.aggregated_public_key = updated_agg_pk;
    }

    #[allow(dead_code)]
    pub fn append_batch(&mut self, subs: &[SignedSubmission], ca: &CertAuthority) {
        let new_sigs: Vec<&Signature> = subs.iter().map(|s| &s.signature).collect();
        let new_keys: Vec<&PublicKey> =
            subs.iter().map(|s| ca.public_key(&s.signer, "msig").expect("Missing key")).collect();

        for sub in subs {
            self.signers.push(sub.signer);
            self.vrf_proofs.push(sub.vrf_proof.clone());
        }

        let new_agg_sig =
            AggregateSignature::aggregate(&new_sigs, true).expect("Signature aggregation failed");
        self.aggregated_signature = AggregateSignature::aggregate(
            &[&self.aggregated_signature.to_signature(), &new_agg_sig.to_signature()],
            true,
        )
        .expect("Total signature aggregation failed");

        if let Some(existing_pk) = &self.aggregated_public_key {
            let new_agg_pk =
                AggregatePublicKey::aggregate(&new_keys, true).expect("New PK aggregation failed");
            let combined =
                AggregatePublicKey::aggregate(&[existing_pk, &new_agg_pk.to_public_key()], true)
                    .expect("Final PK aggregation failed")
                    .to_public_key();
            self.aggregated_public_key = Some(combined);
        } else {
            let full = AggregatePublicKey::aggregate(&new_keys, true)
                .expect("Initial PK aggregation failed")
                .to_public_key();
            self.aggregated_public_key = Some(full);
        }
    }

    pub fn optimistic_verify_msig(&self) -> bool {
        let aggpk = match &self.aggregated_public_key {
            Some(pk) => pk,
            None => return false,
        };

        //multisignature
        let agg_sig_as_simple_sig = self.aggregated_signature.to_signature();
        let msg = make_message(self.step, &self.hash_value);
        let err =
            agg_sig_as_simple_sig.fast_aggregate_verify_pre_aggregated(true, &msg, DST, aggpk);
        if err != BLST_ERROR::BLST_SUCCESS {
            return false; //we did not identify the ill-formed partial signature(s)
        }

        //vrf
        let label = &self.step.to_be_bytes();
        let input = [b"VRF".as_slice(), label].concat();
        let agg_vrf_sig_as_simple_sig = self.aggregated_vrf_signature.to_signature();
        let err_vrf = agg_vrf_sig_as_simple_sig
            .fast_aggregate_verify_pre_aggregated(true, &input, DST, aggpk);
        if err_vrf != BLST_ERROR::BLST_SUCCESS {
            return false; //we did not identify the ill-formed partial signature(s)
        }
        true
    }

    pub fn verify(
        &self,
        ca: &CertAuthority,
        params: &PublicParams,
        mode: VerificationMode,
    ) -> bool {
        if self.signers.len() < params.quorum_threshold() {
            return false;
        }

        let unique: HashSet<_> = self.signers.iter().collect();
        if unique.len() != self.signers.len() {
            return false;
        }

        let mut step_bytes = [0u8; 8];
        step_bytes.copy_from_slice(&self.step.to_be_bytes());

        let msg = make_message(self.step, &self.hash_value);

        match mode {
            VerificationMode::Agnostic => {
                let mut public_keys = Vec::new();

                for (i, id) in self.signers.iter().enumerate() {
                    let pk_vrf = match ca.public_key(id, "vrf") {
                        Some(pk) => pk,
                        None => return false,
                    };
                    let pk_msig = match ca.public_key(id, "msig") {
                        Some(pk) => pk,
                        None => return false,
                    };

                    if !crate::crypto::vrf::vrf_verify(
                        pk_vrf,
                        &step_bytes,
                        &self.vrf_proofs[i],
                        params,
                    ) {
                        return false;
                    }

                    public_keys.push(pk_msig);
                }

                let pk_refs: Vec<&PublicKey> = public_keys.iter().copied().collect();
                let agg_pk = crate::crypto::multisig::aggregate_public_keys(&pk_refs);
                let agg_pk_as_simple_pk = PublicKey::from_aggregate(&agg_pk);
                let agg_sig_as_simple_sig = self.aggregated_signature.to_signature();
                let err = agg_sig_as_simple_sig.fast_aggregate_verify_pre_aggregated(
                    true,
                    &msg,
                    DST,
                    &agg_pk_as_simple_pk,
                );

                if err != BLST_ERROR::BLST_SUCCESS {
                    return false;
                }
            }
            VerificationMode::BLSOptimizedParallelized => {
                let agg_sig_as_simple_sig = self.aggregated_signature.to_signature();
                let msg = make_message(self.step, &self.hash_value);

                // Step (2'): verify aggregated signature against claimed key
                let claimed_pk = match &self.aggregated_public_key {
                    Some(pk) => pk,
                    None => return false,
                };
                let err = agg_sig_as_simple_sig
                    .fast_aggregate_verify_pre_aggregated(true, &msg, DST, claimed_pk);
                if err != BLST_ERROR::BLST_SUCCESS {
                    return false;
                }

                // Step (3): check threshold conditions for VRFs
                for proof in &self.vrf_proofs {
                    if !threshold_verify(proof, params) {
                        return false;
                    }
                }

                // Step (1'): recompute and compare claimed public key
                let mut public_keys = Vec::new();
                for id in &self.signers {
                    let pk = match ca.public_key(id, "msig") {
                        Some(pk) => pk,
                        None => return false,
                    };
                    public_keys.push(pk);
                }
                let pk_refs: Vec<&PublicKey> = public_keys.iter().copied().collect();
                let recomputed = crate::crypto::multisig::aggregate_public_keys(&pk_refs);
                let recomputed_pk = PublicKey::from_aggregate(&recomputed);
                if &recomputed_pk != claimed_pk {
                    return false;
                }
            }

            VerificationMode::BLSOptimized => {
                let claimed_pk = match &self.aggregated_public_key {
                    Some(pk) => pk,
                    None => return false,
                };

                let agg_sig = self.aggregated_signature.to_signature();
                let msg = make_message(self.step, &self.hash_value);

                let mut public_keys = Vec::new();
                for id in &self.signers {
                    let pk = match ca.public_key(id, "msig") {
                        Some(pk) => pk,
                        None => return false,
                    };
                    public_keys.push(pk);
                }
                let pk_refs: Vec<&PublicKey> = public_keys.iter().copied().collect();
                let vrf_proofs = self.vrf_proofs.clone();

                let result = thread::scope(|s| {
                    let verify_sig = s.spawn(|_| {
                        agg_sig.fast_aggregate_verify_pre_aggregated(true, &msg, DST, claimed_pk)
                            == BLST_ERROR::BLST_SUCCESS
                    });

                    let check_vrf =
                        s.spawn(|_| vrf_proofs.iter().all(|proof| threshold_verify(proof, params)));

                    let compare_keys = s.spawn(|_| {
                        let recomputed = crate::crypto::multisig::aggregate_public_keys(&pk_refs);
                        let recomputed_pk = PublicKey::from_aggregate(&recomputed);
                        &recomputed_pk == claimed_pk
                    });

                    let sig_ok = verify_sig.join().expect("Signature verification thread panicked");
                    let vrf_ok = check_vrf.join().expect("VRF threshold check thread panicked");
                    let pk_ok = compare_keys.join().expect("Public key comparison thread panicked");

                    sig_ok && vrf_ok && pk_ok
                })
                .expect("Thread scope failed");

                if !result {
                    return false;
                }
            }
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)] //depends on the benchmark
pub enum AggregationMode {
    Pessimistic,     // Verify each indivdual BLS signature directly
    Optimistic,      // Just verify the multi-signature, the eddsa, and the threshold conditions
    SuperOptimistic, // Just verify the multi-signature, and the threshold conditions (no exposure if it fails)
}

impl SubmissionManager {
    //used by the ratifier
    pub fn new(
        id: ProcessId,
        engine: Arc<CryptoMaterial>,
        ca: Arc<CertAuthority>,
        params: Arc<PublicParams>,
    ) -> Self {
        Self {
            id,
            engine,
            ca,
            params,
            proposed: HashMap::new(),
            certificates: HashMap::new(),
            ratified: false,
        }
    }

    pub fn submit(&mut self, step: u64, hash_value: [u8; 32]) -> Option<SignedSubmission> {
        self.proposed.insert(step, (hash_value, None));
        SignedSubmission::create_if_eligible(step, hash_value, self.id, &self.engine, &self.params)
    }

    pub fn get_certificate(&self, step: u64) -> Option<&QuorumCertificate> {
        if let Some((hash, Some(_))) = self.proposed.get(&step) {
            self.certificates.get(&(step, *hash))
        } else {
            None
        }
    }

    pub fn update(
        &mut self,
        submission: &SignedSubmission,
        agg_mode: AggregationMode,
    ) -> Option<QuorumCertificate> {
        if self.ratified {
            return None;
        }
        let insert_test = match agg_mode {
            AggregationMode::Pessimistic => submission.almost_full_verify(&self.ca, &self.params),
            AggregationMode::Optimistic => {
                submission.optimistic_partial_verify(&self.ca, &self.params)
            }
            AggregationMode::SuperOptimistic => submission.vrf_threshold_verify(&self.params),
        };
        if !insert_test {
            return None;
        }

        let key = (submission.step, submission.hash_value);
        self.certificates
            .entry(key)
            .and_modify(|cert| cert.append(submission, &self.ca))
            .or_insert_with(|| QuorumCertificate::new(&self.ca, submission));

        //return a quorum certificate for the submitted value if possible
        if let Some((expected_hash, slot)) = self.proposed.get_mut(&submission.step) {
            if *expected_hash == submission.hash_value {
                let cert = self.certificates.get(&key).unwrap();
                if cert.signers.len() >= self.params.quorum_threshold() {
                    let final_test = match agg_mode {
                        AggregationMode::Pessimistic => true,
                        AggregationMode::Optimistic => cert.optimistic_verify_msig(),
                        AggregationMode::SuperOptimistic => cert.optimistic_verify_msig(),
                    };
                    if final_test {
                        *slot = Some(cert.clone());
                        self.ratified = true;
                        return Some(cert.clone());
                    }
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn update_batch(
        &mut self,
        submissions: &[SignedSubmission],
        agg_mode: AggregationMode,
    ) -> Option<QuorumCertificate> {
        if self.ratified {
            return None;
        }

        if submissions.is_empty() {
            return None;
        }

        let step = submissions[0].step;
        let hash_value = submissions[0].hash_value;

        for sub in submissions {
            if sub.step != step || sub.hash_value != hash_value {
                return None; // inconsistent submissions
            }
        }

        match agg_mode {
            AggregationMode::Pessimistic => {
                if !submissions.iter().all(|s| s.almost_full_verify(&self.ca, &self.params)) {
                    return None;
                }
            }
            AggregationMode::Optimistic => {
                if !submissions.iter().all(|s| s.optimistic_partial_verify(&self.ca, &self.params))
                {
                    return None;
                }
            }
            AggregationMode::SuperOptimistic => {
                if !submissions.iter().all(|s| s.vrf_threshold_verify(&self.params)) {
                    return None;
                }
            }
        }

        let key = (step, hash_value);
        self.certificates
            .entry(key)
            .and_modify(|qc| qc.append_batch(submissions, &self.ca))
            .or_insert_with(|| {
                let mut qc = QuorumCertificate::new(&self.ca, &submissions[0]);
                qc.append_batch(&submissions[1..], &self.ca);
                qc
            });

        if let Some((expected_hash, slot)) = self.proposed.get_mut(&step) {
            if *expected_hash == hash_value {
                let cert = self.certificates.get(&key).unwrap();
                if cert.signers.len() >= self.params.quorum_threshold() {
                    match agg_mode {
                        AggregationMode::Pessimistic => {
                            *slot = Some(cert.clone());
                            self.ratified = true;
                            return Some(cert.clone());
                        }
                        AggregationMode::Optimistic => {
                            if cert.optimistic_verify_msig() {
                                *slot = Some(cert.clone());
                                self.ratified = true;
                                return Some(cert.clone());
                            }
                        }
                        AggregationMode::SuperOptimistic => {
                            if cert.optimistic_verify_msig() {
                                *slot = Some(cert.clone());
                                self.ratified = true;
                                return Some(cert.clone());
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

impl CertManager {
    //used by the propagator
    pub fn new(
        id: ProcessId,
        //engine: CryptoMaterial,
        ca: Arc<CertAuthority>,
        params: Arc<PublicParams>,
    ) -> Self {
        Self {
            id,
            //engine,
            ca,
            params,
            known_certificates: HashMap::new(),
        }
    }

    pub fn consider(&mut self, cert: &QuorumCertificate) -> Option<QuorumCertificate> {
        let key = (cert.step, cert.hash_value);

        if self.known_certificates.contains_key(&key) {
            return None;
        }

        //if !cert.verify(&self.ca, &self.params, VerificationMode::BLSOptimizedParallelized) {

        if !cert.verify(&self.ca, &self.params, VerificationMode::BLSOptimized) {
            return None;
        }

        self.known_certificates.insert(key, cert.clone());
        Some(cert.clone())
    }
}

///*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        engine::{CertAuthority, CryptoMaterial},
        public_params::PublicParams,
    };

    fn default_params() -> PublicParams {
        PublicParams {
            n: 1000,
            lambda: 50.0,
            epsilon: 0.1,
            delta: 0.2,
            kappa_hash: 256,
            kappa_msig: 256,
            kappa_vrf: 256,
        }
    }

    #[test]
    fn test_signed_submission_creation_and_verification() {
        let params = default_params();
        let id = ProcessId(1);
        let mut ca = CertAuthority::new();
        let material = CryptoMaterial::fresh();
        ca.register(id, &material);

        let hash_value = [42u8; 32];
        let submission =
            SignedSubmission::create_if_eligible(1, hash_value, id, &material, &params);

        if let Some(sub) = submission {
            assert!(sub.full_verify(&ca, &params));
        } else {
            // It's OK for the submission to be None if not elected
            println!("Process not elected in VRF sampling");
        }
    }

    #[test]
    fn test_quorum_certificate_creation_and_verification() {
        let params = default_params();
        let mut ca = CertAuthority::new();
        let mut submissions = vec![];
        let hash_value = [1u8; 32];
        let step = 42;

        // Generate enough eligible submissions
        for i in 0..params.n {
            let id = ProcessId(i as u32);
            let material = CryptoMaterial::fresh();
            ca.register(id, &material);

            if let Some(sub) =
                SignedSubmission::create_if_eligible(step, hash_value, id, &material, &params)
            {
                if sub.full_verify(&ca, &params) {
                    submissions.push((id, sub));
                }
            }

            if submissions.len() >= params.quorum_threshold() {
                break;
            }
        }

        assert!(submissions.len() >= params.quorum_threshold(), "Not enough eligible submissions");

        let (_, first) = &submissions[0];
        let mut qc = QuorumCertificate::new(&ca, first);

        for (_, sub) in &submissions[1..] {
            qc.append(sub, &ca);
        }

        assert!(
            qc.verify(&ca, &params, VerificationMode::Agnostic),
            "QuorumCertificate verification failed in Agnostic mode"
        );

        assert!(
            qc.verify(&ca, &params, VerificationMode::BLSOptimizedParallelized),
            "QuorumCertificate verification failed in BLSOptimizedParallelized mode"
        );

        assert!(
            qc.verify(&ca, &params, VerificationMode::BLSOptimized),
            "QuorumCertificate verification failed in BLSOptimized mode"
        );
    }

    #[test]
    fn test_quorum_certificate_reaches_threshold() {
        use std::sync::Arc;

        let params = Arc::new(PublicParams {
            n: 10,
            lambda: 10.0,
            epsilon: 0.2,
            delta: 0.2,
            kappa_hash: 256,
            kappa_msig: 256,
            kappa_vrf: 256,
        });

        let mut ca = CertAuthority::new();
        let mut materials = Vec::new();

        // Generate and register crypto material
        for i in 0..10 {
            let id = ProcessId(i);
            let material = Arc::new(CryptoMaterial::fresh());
            ca.register(id, &material);
            materials.push((id, material));
        }

        let ca = Arc::new(ca); // Wrap only after registration is complete

        let mut managers = Vec::new();
        let mut submissions = Vec::new();
        let step = 1;
        let hash_value = [42u8; 32];

        // Create managers and attempt submissions
        for (id, material) in &materials {
            let mut manager =
                SubmissionManager::new(*id, material.clone(), ca.clone(), params.clone());

            if let Some(submission) = manager.submit(step, hash_value) {
                submissions.push(submission);
            }

            managers.push(manager);
        }

        // Distribute submissions to all managers
        for sub in &submissions {
            for mgr in &mut managers {
                mgr.update(sub, AggregationMode::Optimistic);
            }
        }

        // Check for valid quorum certificate
        let mut certified = false;
        for mgr in &managers {
            if let Some((hash, Some(qc))) = mgr.proposed.get(&step) {
                assert_eq!(*hash, hash_value);
                assert!(qc.signers.len() >= params.quorum_threshold());
                certified = true;
            }
        }

        assert!(certified, "No manager formed a valid quorum certificate");
    }

    #[test]
    fn test_cert_manager_consider() {
        use std::{sync::Arc, time::Instant};

        use super::*;
        use crate::crypto::public_params::PublicParams;
        //use crate::crypto::engine::*;

        let params = Arc::new(PublicParams {
            n: 100,
            lambda: 30.0, // High enough to expect most to be elected
            epsilon: 0.1,
            delta: 0.2,
            kappa_hash: 256,
            kappa_msig: 256,
            kappa_vrf: 256,
        });

        let step = 42;
        let hash = [42u8; 32];

        let mut raw_ca = CertAuthority::new();
        let mut materials = Vec::new();

        // Create and register materials before Arc wrapping
        for i in 0..params.n {
            let id = ProcessId(i as u32);
            let material = Arc::new(CryptoMaterial::fresh());
            raw_ca.register(id, &material);
            materials.push((id, material));
        }

        let ca = Arc::new(raw_ca);
        let mut managers = Vec::new();
        let mut submissions = Vec::new();

        for (id, material) in &materials {
            let mut manager =
                SubmissionManager::new(*id, material.clone(), ca.clone(), params.clone());
            if let Some(sub) = manager.submit(step, hash) {
                submissions.push(sub);
            }

            managers.push(manager);
        }

        // Deliver submissions to all managers
        for sub in &submissions {
            for mgr in &mut managers {
                mgr.update(sub, AggregationMode::Optimistic);
            }
        }

        // Use the first manager that produced a certificate
        let mut found = false;
        for mgr in &managers {
            if let Some(qc) = mgr.get_certificate(step) {
                let mut cert_manager = CertManager::new(
                    mgr.id,
                    //mgr.engine.clone(),
                    ca.clone(),
                    params.clone(),
                );

                let start = Instant::now();
                let result = cert_manager.consider(&qc);
                let duration = start.elapsed();
                println!(
                    "Verification took: {:?} for a certificate of {:?} signers",
                    duration,
                    params.quorum_threshold()
                );

                assert!(result.is_some(), "Expected a valid certificate");

                let second = cert_manager.consider(&qc);
                assert!(second.is_none(), "Second consider call should be ignored");

                found = true;
                break;
            }
        }

        assert!(found, "No quorum certificate formed in any manager");
    }
}
//*/
