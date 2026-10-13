//! Types shared by the engine, the service and the UI. Phase 2 adds request/response enums.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Layer {
    Hash,
    Signature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reason {
    pub layer: Layer,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub path: String,
    pub sha256: String,
    pub status: Status,
    pub reasons: Vec<Reason>,
    pub error: Option<String>,
}
