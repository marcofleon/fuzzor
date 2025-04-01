pub mod inmemory;
pub mod ondisk;
pub mod reporter;
pub mod stack_trace;

pub use stack_trace::*;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha1::{Digest, Sha1};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SolutionMetadata {
    /// Crashes come with stack trace
    Crash(String),
    /// Timeouts come with a flamegraph
    Timeout(String),

    Differential(String),
}

/// Solution holds information about an interesting fuzz input.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Solution {
    id: String,
    unique_id: String,

    #[serde_as(as = "Base64")]
    input_bytes: Vec<u8>,

    metadata: SolutionMetadata,
}

impl Solution {
    pub fn from_differential_solution(input_bytes: Vec<u8>, stderr: String) -> Self {
        let unique_id = Solution::create_unique_id(&input_bytes);
        Self {
            id: String::from("differential"),
            unique_id,
            input_bytes,
            metadata: SolutionMetadata::Differential(stderr),
        }
    }

    /// Create a new solution from a crashing fuzz input and the crash's stack trace.
    pub fn from_crash(input_bytes: Vec<u8>, stack_trace: String) -> Self {
        let unique_id = Solution::create_unique_id(&input_bytes);

        // Fallback to "crash" as deduplication id if the stack trace does not appear to be a
        // libFuzzer trace.
        let id = if let Some(trace) = LibFuzzerStackTrace::parse(&stack_trace) {
            trace.hash()
        } else {
            String::from("crash")
        };

        Self {
            id,
            unique_id,
            input_bytes,
            metadata: SolutionMetadata::Crash(stack_trace),
        }
    }

    /// Create a new solution from a fuzz input that times out.
    pub fn from_timeout(input_bytes: Vec<u8>, flamegraph: String) -> Self {
        Self {
            // Deduplicating timeouts is hard since there is no stack trace, so we'll just use
            // "timeout" as the deduplication identifier. This will mean that we will only track
            // one type of timeout per harness.
            id: String::from("timeout"),
            unique_id: Solution::create_unique_id(&input_bytes),
            input_bytes,
            metadata: SolutionMetadata::Timeout(flamegraph),
        }
    }

    /// Deduplication identifier for a solution.
    ///
    /// This identifier will be the same for solutions of the same kind. For example, there might
    /// be more than one fuzz input that triggers the same crash, in which case the identifier will
    /// be the same for deduplication purposes.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Unique identifier for a solution.
    ///
    /// This identifier is simply a hash of the input bytes and will therefore be unique to each
    /// fuzz input.
    pub fn unique_id(&self) -> &str {
        &self.unique_id
    }
    /// Input bytes that trigger the solution when passed to the corresponding harness.
    pub fn input_bytes(&self) -> &[u8] {
        &self.input_bytes
    }
    /// Metadata associated with solution (e.g. stack trace for crashes).
    pub fn metadata(&self) -> &SolutionMetadata {
        &self.metadata
    }

    /// Returns the input bytes as a base64 encoded string.
    pub fn input_base64(&self) -> String {
        STANDARD.encode(self.input_bytes())
    }

    fn create_unique_id(input_bytes: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(input_bytes);
        hex::encode(hasher.finalize())
    }
}

#[async_trait::async_trait]
pub trait SolutionTracker {
    /// Mark a solution as resolved (e.g. underlying bug was fixed).
    async fn mark_as_resolved(&mut self, id: &str) -> Option<Solution>;
    /// Submit a solution to the tracker. Returns whether or this was a new solution.
    async fn submit(&mut self, solution: Solution) -> bool;
    /// Retrieve an open solution from the tracker by its deduplication id.
    async fn get_open(&self, id: &str) -> Option<&Solution>;
    /// Get all solutions in the tracker
    async fn get_all(&self) -> Vec<Solution>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_ids() {
        {
            let input = vec![0u8];
            let crash = Solution::from_crash(input, String::from(""));
            // Malformed stack trace uses unique id as id
            assert_eq!(crash.id(), "crash");
        }

        {
            let input = vec![0u8];
            let crash0 = Solution::from_crash(input, String::from("==ERROR\n\nSUMMARY"));
            assert_ne!(crash0.id(), crash0.unique_id());

            let input = vec![0u8];
            let crash1 = Solution::from_crash(input, String::from("== ERROR\n\nSUMMARY"));
            assert_ne!(crash1.id(), crash1.unique_id());

            let input = vec![1u8];
            let crash2 = Solution::from_crash(input, String::from("===WARNING\n\nSUMMARY"));
            assert_eq!(crash1.id(), crash2.id());
        }
    }
}
