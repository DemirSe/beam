use std::process::{Command, Output};

/// Runs git read-only. `GIT_OPTIONAL_LOCKS=0` keeps `git status` from
/// refreshing and rewriting `.git/index`, which this script also watches.
fn git(args: &[&str]) -> Option<Output> {
    Command::new("git")
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|output| output.status.success())
}

fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");
    // Staging a change rewrites the index without touching HEAD or a source
    // file, so the stamp must observe it.
    println!("cargo:rerun-if-changed=../../.git/index");
    // Cargo reruns a build script only for the paths it names. Watching the
    // compiled tree makes an unstaged source edit refresh the dirty marker
    // instead of leaving the stamp from an earlier run.
    println!("cargo:rerun-if-changed=../../crates");
    println!("cargo:rerun-if-changed=../../Cargo.toml");
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    println!("cargo:rerun-if-changed=../../rust-toolchain.toml");
    println!("cargo:rerun-if-env-changed=BEAM_BUILD_GIT_HASH");

    let hash = std::env::var("BEAM_BUILD_GIT_HASH")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let head = git(&["rev-parse", "--short=12", "HEAD"])?;
            let mut value = String::from_utf8(head.stdout).ok()?.trim().to_owned();
            if value.is_empty() {
                return None;
            }
            // One porcelain read covers staged, unstaged, and untracked files.
            // Ignored local files such as target/ do not mark the build dirty.
            let dirty = match git(&["status", "--porcelain", "--untracked-files=normal"]) {
                Some(output) => !String::from_utf8_lossy(&output.stdout).trim().is_empty(),
                // A checkout whose status cannot be read is not provably clean.
                None => true,
            };
            if dirty {
                value.push_str("-dirty");
            }
            Some(value)
        })
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=BEAM_GIT_HASH={hash}");
}
