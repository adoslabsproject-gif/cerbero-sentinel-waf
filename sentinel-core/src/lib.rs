//! # SENTINEL Core
//!
//! Core types and traits for the SENTINEL WAF system.
//! Security ENhanced Threat INtelligence for AI EL (Entities Layer)

pub mod error;
pub mod request;
pub mod response;
pub mod risk;
pub mod types;
pub mod config;
pub mod agent;
pub mod action;
pub mod text;
pub mod sharded_lru;

pub use error::{SentinelError, SentinelResult};
pub use request::{Request, RequestBody};
pub use response::{EnforcementResult, Response};
pub use risk::{RiskLevel, RiskScore, RiskFlag, UnifiedRiskScore, ChallengeType, LayerRiskScore};
// Re-export LayerRiskScore as RiskScore for layer compatibility (used by edge, neural, behavior layers)
pub type RiskScoreLayer = LayerRiskScore;
pub use types::{SentinelConfig, EdgeConfig, NeuralConfig, ResponseConfig};
pub use config::{BehaviorConfig};
pub use agent::AgentId;
pub use action::{Action, Challenge};
pub use text::{percent_decode_iterative, truncate_char_boundary};
