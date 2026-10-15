//! Stamp the build with the git commit it came from (`NTOSEYE_BUILD`), so a
//! long-lived interpreter can tell it is running a stale extension after a
//! rebuild. `<commit>`, `<commit>-dirty` with uncommitted tracked changes, or
//! `unknown` outside a git checkout (a crates.io or sdist build). With
//! `python-embed`, also point the binary at a macOS framework Python.
//!
//! With `python`, also list the SDK's `#[record]` classes (see
//! `src/view/record.rs`) in `$OUT_DIR/record_classes.rs`.

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

    #[cfg(feature = "python")]
    records::write();
}

/// Finds every `#[record]` class by walking the crate's module tree from
/// `src/lib.rs`, as rustc does, and writes `with_record_classes!`, which
/// adds a `#[pymodule_export] use` of each to the SDK's module. A class is
/// exported under the `cfg`s of the modules on its path and its own; a
/// module whose `cfg` names `test` is skipped. Also checks that no two
/// classes (records or hand-written `#[pyclass]`es) share a Python name.
#[cfg(feature = "python")]
mod records {
    use std::collections::BTreeMap;
    use std::fmt::Write;
    use std::path::{Path, PathBuf};

    use quote::ToTokens;
    use syn::{Attribute, Item};

    struct Class {
        cfgs: Vec<String>,
        /// The class's Rust path, `crate::view::process::ZombiesPy`.
        path: String,
    }

    #[derive(Default)]
    struct Walk {
        classes: Vec<Class>,
        /// Python name -> where it is defined, for the duplicate check.
        names: BTreeMap<String, String>,
    }

    pub fn write() {
        let mut walk = Walk::default();
        walk.file(Path::new("src/lib.rs"), "crate", Path::new("src"), &[]);
        walk.classes.sort_by(|a, b| a.path.cmp(&b.path));
        let mut uses = String::new();
        for class in &walk.classes {
            for cfg in &class.cfgs {
                uses.push_str(cfg);
                uses.push(' ');
            }
            writeln!(uses, "#[pymodule_export] use {};", class.path).unwrap();
        }
        let source = format!(
            "/// `with_record_classes! {{ #[pymodule] mod m {{ ... }} }}`: the module, \
             exporting every `#[record]` class besides its own items. Written by build.rs.\n\
             macro_rules! with_record_classes {{\n\
             ($(#[$attr:meta])* $vis:vis mod $name:ident {{ $($body:tt)* }}) => {{\n\
             $(#[$attr])* $vis mod $name {{\n$($body)*\n{uses}}}\n}};\n}}\n"
        );
        let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("record_classes.rs");
        std::fs::write(out, source).unwrap();
    }

    fn cfgs(attrs: &[Attribute]) -> Vec<String> {
        attrs
            .iter()
            .filter(|attr| attr.path().is_ident("cfg"))
            .map(|attr| attr.to_token_stream().to_string())
            .collect()
    }

    fn names_test(cfgs: &[String]) -> bool {
        cfgs.iter().any(|cfg| {
            cfg.split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|word| word == "test")
        })
    }

    /// The `#[record(...)]` attribute's arguments, if the item has one.
    fn record(attrs: &[Attribute]) -> Option<String> {
        attrs
            .iter()
            .find(|attr| {
                attr.path()
                    .segments
                    .last()
                    .is_some_and(|last| last.ident == "record")
            })
            .map(|attr| match &attr.meta {
                syn::Meta::List(list) => list.tokens.to_string(),
                _ => String::new(),
            })
    }

    /// A hand-written `#[pyclass]`'s Python name.
    fn pyclass(attrs: &[Attribute], ident: &syn::Ident) -> Option<String> {
        let attr = attrs.iter().find(|attr| {
            attr.path()
                .segments
                .last()
                .is_some_and(|last| last.ident == "pyclass")
        })?;
        let mut name = ident.to_string();
        if let syn::Meta::List(list) = &attr.meta {
            let _ = list.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    name = meta.value()?.parse::<syn::LitStr>()?.value();
                } else if meta.input.peek(syn::Token![=]) {
                    meta.value()?.parse::<syn::Expr>()?;
                }
                Ok(())
            });
        }
        Some(name)
    }

    impl Walk {
        /// Walk `file`, module `module`, whose `mod x;` files are in `dir`.
        fn file(&mut self, file: &Path, module: &str, dir: &Path, cfgs: &[String]) {
            let source = std::fs::read_to_string(file)
                .unwrap_or_else(|error| panic!("{}: {error}", file.display()));
            let ast = syn::parse_file(&source)
                .unwrap_or_else(|error| panic!("{}: {error}", file.display()));
            self.items(&ast.items, file, module, dir, cfgs);
        }

        fn items(
            &mut self,
            items: &[Item],
            file: &Path,
            module: &str,
            dir: &Path,
            cfgs: &[String],
        ) {
            for item in items {
                let (attrs, ident, class) = match item {
                    Item::Mod(child) => {
                        let mut child_cfgs = cfgs.to_vec();
                        child_cfgs.extend(self::cfgs(&child.attrs));
                        if names_test(&child_cfgs) {
                            continue;
                        }
                        assert!(
                            !child.attrs.iter().any(|attr| attr.path().is_ident("path")),
                            "{}: build.rs does not follow #[path] modules",
                            file.display()
                        );
                        let name = child.ident.to_string();
                        let path = format!("{module}::{name}");
                        let child_dir = dir.join(&name);
                        match &child.content {
                            Some((_, items)) => {
                                self.items(items, file, &path, &child_dir, &child_cfgs)
                            }
                            None => {
                                let flat = dir.join(format!("{name}.rs"));
                                let nested = child_dir.join("mod.rs");
                                let child_file = if flat.exists() { flat } else { nested };
                                self.file(&child_file, &path, &child_dir, &child_cfgs);
                            }
                        }
                        continue;
                    }
                    Item::Struct(item) => (&item.attrs, &item.ident, true),
                    Item::Enum(item) => (&item.attrs, &item.ident, false),
                    _ => continue,
                };
                let mut item_cfgs = cfgs.to_vec();
                item_cfgs.extend(self::cfgs(attrs));
                if names_test(&item_cfgs) {
                    continue;
                }
                let python = if let Some(args) = record(attrs) {
                    // A struct, or a `tagged` enum, has a class.
                    if !class && !args.split([',', ' ']).any(|arg| arg == "tagged") {
                        continue;
                    }
                    let name = ident.to_string();
                    self.classes.push(Class {
                        cfgs: item_cfgs,
                        path: format!("{module}::{name}Py"),
                    });
                    name
                } else if let Some(name) = pyclass(attrs, ident) {
                    name
                } else {
                    continue;
                };
                let at = format!("{module}::{ident}");
                if let Some(earlier) = self.names.insert(python.clone(), at.clone()) {
                    panic!("two SDK classes are named `{python}`: {earlier} and {at}");
                }
            }
        }
    }
}
