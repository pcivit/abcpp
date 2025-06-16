use std::sync::Arc;

use crate::{
    certificates::quorum::{CertManager, SubmissionManager},
    crypto::{
        engine::{CertAuthority, CryptoMaterial},
        process_id::ProcessId,
        public_params::PublicParams,
    },
};

#[derive(Debug, Clone)]
pub struct Party {
    #[allow(dead_code)]
    pub id: ProcessId,
    #[allow(dead_code)]
    pub engine: Arc<CryptoMaterial>,
    pub submission_manager: SubmissionManager,
    pub cert_manager: CertManager,
}

impl Party {
    pub fn new(
        id: ProcessId,
        engine: Arc<CryptoMaterial>,
        ca: Arc<CertAuthority>,
        params: Arc<PublicParams>,
    ) -> Self {
        let submission_manager =
            SubmissionManager::new(id, Arc::clone(&engine), Arc::clone(&ca), Arc::clone(&params));
        let cert_manager = CertManager::new(id, Arc::clone(&ca), Arc::clone(&params));

        Party {
            id,
            engine,
            submission_manager,
            cert_manager,
        }
    }
}
