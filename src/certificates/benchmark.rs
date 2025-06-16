use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    certificates::{party::Party, quorum::SignedSubmission},
    crypto::{
        engine::{CertAuthority, CryptoMaterial},
        process_id::ProcessId,
        public_params::PublicParams,
    },
};

pub fn run_setup(n: usize) -> (Arc<CertAuthority>, Vec<CryptoMaterial>) {
    let mut ca = CertAuthority::new();
    let mut materials = Vec::new();
    for i in 0..n {
        let id = ProcessId(i as u32);
        let mat = Arc::new(CryptoMaterial::fresh());
        ca.register(id, &mat);
        materials.push(Arc::try_unwrap(mat).unwrap());
    }

    (Arc::new(ca), materials)
}

pub fn generate_parties_and_submissions(
    step: u64,
    hash_value: [u8; 32],
    ca: &Arc<CertAuthority>,
    params: &Arc<PublicParams>,
    materials: &[CryptoMaterial],
) -> (Vec<Party>, Vec<SignedSubmission>, Vec<ProcessId>) {
    let mut parties = Vec::new();
    let mut submissions = Vec::new();
    let mut eligible_ids = Vec::new();

    for (i, material) in materials.iter().enumerate() {
        let id = ProcessId(i as u32);
        let mat_arc = Arc::new(material.clone());
        let mut party = Party::new(id, Arc::clone(&mat_arc), Arc::clone(ca), Arc::clone(params));

        if let Some(submission) = party.submission_manager.submit(step, hash_value) {
            eligible_ids.push(id);
            submissions.push(submission);
        }

        parties.push(party);
    }

    (parties, submissions, eligible_ids)
}

use crate::certificates::quorum::AggregationMode;

pub fn run_ratification(
    parties: &mut [Party],
    submissions: &[SignedSubmission],
    mode: AggregationMode,
    n_eval: usize,
) -> (Duration, Duration) {
    let mut duration_max = Duration::ZERO;
    let mut duration_tot = Duration::ZERO;

    for i in 1..n_eval {
        let party = &mut parties[i];
        let clock = Instant::now();

        for sub in submissions {
            party.submission_manager.update(sub, mode);
        }

        let duration = clock.elapsed();
        duration_tot += duration;
        if duration > duration_max {
            duration_max = duration;
        }
    }

    (duration_max, duration_tot)
}

pub fn run_propagation(step: u64, parties: &mut [Party], n_eval: usize) -> (Duration, Duration) {
    let mut duration_max = Duration::ZERO;
    let mut duration_tot = Duration::ZERO;

    for i in 1..n_eval {
        if let Some(qc) = parties[i].submission_manager.get_certificate(step) {
            let clock = Instant::now();
            parties[i].cert_manager.consider(&qc);
            let duration = clock.elapsed();

            if duration > duration_max {
                duration_max = duration;
            }
            duration_tot += duration;
        }
    }

    (duration_max, duration_tot)
}
