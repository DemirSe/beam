use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");
    println!("cargo:rerun-if-env-changed=BEAM_BUILD_GIT_HASH");

    let hash = std::env::var("BEAM_BUILD_GIT_HASH")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let output = Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()
                .ok()
                .filter(|output| output.status.success())?;
            let mut value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
            if value.is_empty() {
                return None;
            }
            let dirty = Command::new("git")
                .args(["diff", "--quiet", "--"])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .status()
                .ok()
                .is_some_and(|status| !status.success());
            if dirty {
                value.push_str("-dirty");
            }
            Some(value)
        })
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=BEAM_GIT_HASH={hash}");
}
