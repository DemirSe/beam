#![no_main]

use beam_core::config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(config) = Config::from_toml_str(input) {
        // Also exercise derived FD-budget checks at representative low and
        // deployment-floor limits once TOML + semantic validation succeeds.
        let _ = config.validate_fd_budget(1_024);
        let _ = config.validate_fd_budget(65_536);
    }
});
