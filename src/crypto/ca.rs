use std::collections::HashMap;
use blst::min_sig::PublicKey;
use std::sync::{Arc, RwLock};
use crate::crypto::process_id::ProcessId;

/// Singleton Certification Authority
#[derive(Clone)]
pub struct CertAuthority {
    inner: Arc<RwLock<HashMap<ProcessId, PublicKey>>>,
}

impl CertAuthority {
    pub fn new() -> Self {
        CertAuthority {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn publish(&self, id: ProcessId, pk: PublicKey) {
        let mut map = self.inner.write().unwrap();
        map.insert(id, pk);
    }

    pub fn get(&self, id: &ProcessId) -> Option<PublicKey> {
        let map = self.inner.read().unwrap();
        map.get(id).cloned()
    }

    pub fn contains(&self, id: &ProcessId) -> bool {
        let map = self.inner.read().unwrap();
        map.contains_key(id)
    }

    pub fn all_ids(&self) -> Vec<ProcessId> {
        let map = self.inner.read().unwrap();
        map.keys().cloned().collect()
    }
}
