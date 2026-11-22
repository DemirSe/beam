use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Repository paths that affect the compiled `beam` binary.
///
/// Both Cargo's `rerun-if-changed` directives and the dirty-tree check use this
/// exact list so out-of-scope edits (such as documentation or lab scripts)
/// never leave a cached `-dirty` or clean stamp inconsistent with Cargo's rerun
/// triggers.
const WATCHED_BUILD_PATHS: &[&str] = &["crates", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"];

/// Git environment overrides that could redirect metadata queries away from the
/// checkout containing `CARGO_MANIFEST_DIR`.
const IGNORED_GIT_ENV_VARS: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
];

/// Runs git read-only against `workspace_root` with inherited repo-redirecting
/// variables stripped. `GIT_OPTIONAL_LOCKS=0` keeps `git status` from
/// refreshing and rewriting the index watched by Cargo.
fn git(workspace_root: &Path, args: &[&str]) -> Option<Output> {
    let mut cmd = Command::new("git");
    cmd.args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .current_dir(workspace_root);
    for var in IGNORED_GIT_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.output().ok().filter(|output| output.status.success())
}

/// Validates an explicit `BEAM_BUILD_GIT_HASH` override.
///
/// Accepts a single lowercase/uppercase hexadecimal revision of 7..=40 digits
/// with an optional `-dirty` suffix, rejecting whitespace, control characters,
/// or Cargo directive injections.
fn is_valid_hash_override(value: &str) -> bool {
    let hex = value.strip_suffix("-dirty").unwrap_or(value);
    (7..=40).contains(&hex.len()) && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Resolves a Git metadata path (supporting both ordinary checkouts and linked
/// worktrees) to an absolute path.
fn git_path(workspace_root: &Path, rel: &str) -> Option<PathBuf> {
    let output = git(workspace_root, &["rev-parse", "--git-path", rel])?;
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains(['\n', '\r']) {
        return None;
    }
    Some(workspace_root.join(trimmed))
}

fn emit_git_watch_paths(workspace_root: &Path) {
    let mut watched = Vec::new();
    for rel in ["HEAD", "index", "packed-refs", "refs/heads"] {
        if let Some(path) = git_path(workspace_root, rel) {
            watched.push(path);
        }
    }
    if let Some(output) = git(workspace_root, &["symbolic-ref", "-q", "HEAD"])
        && let Ok(symref) = String::from_utf8(output.stdout)
    {
        let symref = symref.trim();
        if !symref.is_empty()
            && let Some(path) = git_path(workspace_root, symref)
        {
            watched.push(path);
        }
    }
    watched.sort();
    watched.dedup();
    for path in watched {
        // Only watch paths that exist on disk; Cargo treats nonexistent
        // `rerun-if-changed` entries (such as packed loose refs or an absent
        // `packed-refs`) as perpetually dirty.
        if path.exists()
            && let Some(text) = path.to_str()
        {
            println!("cargo:rerun-if-changed={text}");
        }
    }
}

fn resolve_git_hash(workspace_root: &Path) -> Option<String> {
    let head = git(workspace_root, &["rev-parse", "--short=12", "HEAD"])?;
    let mut value = String::from_utf8(head.stdout).ok()?.trim().to_owned();
    if !is_valid_hash_override(&value) {
        return None;
    }
    // Check dirty status on the exact paths watched by Cargo so the dirty
    // marker always agrees with rerun triggers.
    let mut status_args = vec!["status", "--porcelain", "--untracked-files=normal", "--"];
    status_args.extend_from_slice(WATCHED_BUILD_PATHS);
    let dirty = match git(workspace_root, &status_args) {
        Some(output) => !String::from_utf8_lossy(&output.stdout).trim().is_empty(),
        // A checkout whose status cannot be read is not provably clean.
        None => true,
    };
    if dirty {
        value.push_str("-dirty");
    }
    Some(value)
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(&manifest_dir)
        .to_path_buf();

    println!("cargo:rerun-if-env-changed=BEAM_BUILD_GIT_HASH");

    let hash = match std::env::var("BEAM_BUILD_GIT_HASH") {
        Ok(value) if !value.is_empty() => {
            if !is_valid_hash_override(&value) {
                eprintln!(
                    "invalid BEAM_BUILD_GIT_HASH: expected 7..=40 hexadecimal characters \
                     with an optional `-dirty` suffix"
                );
                std::process::exit(1);
            }
            value
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            eprintln!("invalid BEAM_BUILD_GIT_HASH: value is not valid UTF-8");
            std::process::exit(1);
        }
        _ => {
            emit_git_watch_paths(&workspace_root);
            // Cargo reruns a build script only for the paths it names. Watching
            // the compiled tree makes an unstaged source edit refresh the dirty
            // marker instead of leaving the stamp from an earlier run.
            for path in WATCHED_BUILD_PATHS {
                println!("cargo:rerun-if-changed=../../{path}");
            }
            resolve_git_hash(&workspace_root).unwrap_or_else(|| {
                println!(
                    "cargo:warning=could not read Git metadata for BEAM_GIT_HASH; \
                     stamping build as `unknown` (set BEAM_BUILD_GIT_HASH to override)"
                );
                "unknown".to_owned()
            })
        }
    };

    println!("cargo:rustc-env=BEAM_GIT_HASH={hash}");
}
