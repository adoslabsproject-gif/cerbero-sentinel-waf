//! Agent identity types

use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};

/// Agent identifier
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentId {
    /// Internal ID
    id: String,
}

impl AgentId {
    /// Create a new random agent ID
    pub fn new() -> Self {
        Self {
            id: uuid::Uuid::now_v7().to_string(),
        }
    }

    /// Create from a string
    pub fn new_from_string(s: &str) -> Self {
        Self { id: s.to_string() }
    }

    /// Create from a JWT token (hashed)
    pub fn from_token(token: &str) -> Self {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        token.hash(&mut hasher);
        Self {
            id: format!("token:{:x}", hasher.finish()),
        }
    }

    /// Get the ID as a string
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl Hash for AgentId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
