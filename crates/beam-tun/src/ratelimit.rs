//! Small bounded-window rate limiter for diagnostic log sites.
//!
//! Used on failure paths only (never on the packet fast path) so a broken
//! upstream cannot flood the journal with identical warnings.

use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct LimiterState {
    window_start: Instant,
    events: u32,
    suppressed: u32,
}

/// Allows at most `max_events` log lines per `window`, and counts the lines it
/// suppresses so the next emitted line can report them.
#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    max_events: u32,
    state: Mutex<LimiterState>,
}

impl RateLimiter {
    /// Creates a limiter that allows `max_events` lines in every `window`.
    pub fn new(max_events: u32, window: Duration) -> Self {
        Self {
            window,
            max_events: max_events.max(1),
            state: Mutex::new(LimiterState {
                window_start: Instant::now(),
                events: 0,
                suppressed: 0,
            }),
        }
    }

    /// Returns `Some(suppressed)` when the caller may log now, where
    /// `suppressed` counts the lines dropped since the previous emitted line
    /// (always `0` for the first line in a window). Returns `None` when the
    /// caller must stay silent.
    pub fn allow(&self) -> Option<u32> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.window_start.elapsed() >= self.window {
            state.window_start = Instant::now();
            state.events = 0;
        }
        if state.events < self.max_events {
            state.events += 1;
            Some(std::mem::take(&mut state.suppressed))
        } else {
            state.suppressed = state.suppressed.saturating_add(1);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_budget_then_counts_suppressed_lines() {
        let limiter = RateLimiter::new(2, Duration::from_millis(50));
        assert_eq!(limiter.allow(), Some(0));
        assert_eq!(limiter.allow(), Some(0));
        assert_eq!(limiter.allow(), None);
        assert_eq!(limiter.allow(), None);

        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            limiter.allow(),
            Some(2),
            "a new window must report the two suppressed lines"
        );
        assert_eq!(limiter.allow(), Some(0));
    }
}
