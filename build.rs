//! Stamp the build with the git commit it came from (`NTOSEYE_BUILD`), so a
//! long-lived interpreter can tell it is running a stale extension after a
//! rebuild. `<commit>`, `<commit>-dirty` with uncommitted tracked changes, or
//! `unknown` outside a git checkout (a crates.io or sdist build). With
//! `python-embed`, also point the binary at a macOS framework Python.

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn main() {
    // Sources and the index decide the dirty flag; HEAD and its ref decide
    // the commit. Directories are watched recursively.
    for path in [
        "src",
        "python/src",
        "python/ntoseye",
        ".git/HEAD",
        ".git/index",
    ] {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(reference) = std::fs::read_to_string(".git/HEAD")
        .ok()
        .and_then(|head| head.strip_prefix("ref: ").map(|r| r.trim().to_string()))
    {
        println!("cargo:rerun-if-changed=.git/{reference}");
    }

    let stamp = match git(&["rev-parse", "--short=12", "HEAD"]) {
        Some(commit) => {
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                .is_some_and(|status| !status.is_empty());
            if dirty {
                format!("{commit}-dirty")
            } else {
                commit
            }
        }
        None => "unknown".to_string(),
    };
    println!("cargo:rustc-env=NTOSEYE_BUILD={stamp}");

    // A macOS framework Python (Xcode's, python.org's, Homebrew's) is linked
    // as `@rpath/Python3.framework`; without an rpath to the framework, a
    // binary embedding the interpreter cannot start.
    #[cfg(feature = "python-embed")]
    pyo3_build_config::add_python_framework_link_args();
}
