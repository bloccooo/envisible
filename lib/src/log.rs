use std::sync::atomic::{AtomicBool, Ordering};

static WARNINGS_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable or disable the diagnostic `warn!` output below (silent by default).
/// Intended to be set once at startup from a CLI flag.
pub fn set_warnings_enabled(enabled: bool) {
    WARNINGS_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn warnings_enabled() -> bool {
    WARNINGS_ENABLED.load(Ordering::Relaxed)
}

/// Like `eprintln!`, but only prints when warnings are enabled (see `set_warnings_enabled`).
#[macro_export]
macro_rules! warn_log {
    ($($arg:tt)*) => {
        if $crate::log::warnings_enabled() {
            eprintln!($($arg)*);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Single test: WARNINGS_ENABLED is a process-wide static, so asserting the
    // default and then toggling must happen in one test to avoid racing other
    // tests in this file that run concurrently in the same process.
    #[test]
    fn default_is_silent_and_toggles() {
        assert!(!warnings_enabled(), "warnings must be silent by default");
        set_warnings_enabled(true);
        assert!(warnings_enabled());
        set_warnings_enabled(false);
        assert!(!warnings_enabled());
    }
}
