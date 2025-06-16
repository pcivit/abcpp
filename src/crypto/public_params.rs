use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicParams {
    pub n: usize,          // Total number of processes
    pub lambda: f64,       // Expected quorum size
    pub epsilon: f64,      // Overthreshold slack
    pub delta: f64,        // Fault tolerance margin (deviation from expectation in Chernoff bound)
    pub kappa_hash: usize, // size of hash values
    pub kappa_msig: usize, // size of multi-signatures
    pub kappa_vrf: usize,  // size of VRF
}

impl PublicParams {
    pub fn quorum_threshold(&self) -> usize {
        ((1.0 - self.delta) * ((2.0 / 3.0) + self.epsilon) * self.lambda).ceil() as usize
    }

    pub fn vrf_probability(&self) -> f64 { self.lambda / (self.n as f64) }
}
