use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct ProcessId(pub u32); // 32-bit integer wrapper

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "P{}", self.0) }
}

impl From<u32> for ProcessId {
    fn from(x: u32) -> Self { ProcessId(x) }
}

impl Into<u32> for ProcessId {
    fn into(self) -> u32 { self.0 }
}
