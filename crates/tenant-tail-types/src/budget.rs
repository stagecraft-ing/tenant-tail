//! `AssumptionBudget` -- per-project counter and cap for `ASSUMPTION`-tagged
//! and `ASSUMPTION-orphaned` claims (FR-028, FR-029).
//!
//! `cap` is configured per project via `factory-config.yaml`'s
//! `provenance.assumptionBudget` (default 10). `used` is the count of
//! slots already consumed by prior-run claims that persist in
//! `provenance.json`. The validator is pure -- it does not mutate `used`;
//! it returns the post-run count in the `ValidationReport.summary`.

use serde::{Deserialize, Serialize};

/// Per-project assumption budget. Both fields are `u32` to make the
/// arithmetic integer-only and the JSON shape obvious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssumptionBudget {
    /// Maximum number of `Assumption` + `AssumptionOrphaned` claims the
    /// gate admits. `0` is a valid cap (zero-tolerance / regulated
    /// workspace). Default 10 (FR-028).
    pub cap: u32,
    /// Slots already consumed by prior-run claims carried in
    /// `provenance.json`. The validator adds new admissions on top.
    pub used: u32,
}

impl Default for AssumptionBudget {
    fn default() -> Self {
        AssumptionBudget { cap: 10, used: 0 }
    }
}

impl AssumptionBudget {
    /// Remaining slots before the cap blocks further admissions. Saturates
    /// at zero -- over-consumption never produces a negative number.
    pub fn remaining(&self) -> u32 {
        self.cap.saturating_sub(self.used)
    }

    /// Whether one more admission would fit under the cap.
    pub fn has_capacity(&self) -> bool {
        self.used < self.cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ten_zero() {
        let b = AssumptionBudget::default();
        assert_eq!(b.cap, 10);
        assert_eq!(b.used, 0);
        assert!(b.has_capacity());
        assert_eq!(b.remaining(), 10);
    }

    #[test]
    fn has_capacity_false_at_cap() {
        let b = AssumptionBudget { cap: 2, used: 2 };
        assert!(!b.has_capacity());
        assert_eq!(b.remaining(), 0);
    }

    #[test]
    fn remaining_saturates_at_zero_when_over() {
        let b = AssumptionBudget { cap: 1, used: 5 };
        assert_eq!(b.remaining(), 0);
        assert!(!b.has_capacity());
    }

    #[test]
    fn round_trip_serde() {
        let b = AssumptionBudget { cap: 3, used: 1 };
        let j = serde_json::to_string(&b).unwrap();
        assert!(j.contains("\"cap\":3"));
        assert!(j.contains("\"used\":1"));
        let back: AssumptionBudget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
