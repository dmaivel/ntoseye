//! Stamp the build with the git commit it came from (`NTOSEYE_BUILD`), so a
//! long-lived interpreter can tell it is running a stale extension after a
//! rebuild. `<commit>`, `<commit>-dirty` with uncommitted tracked changes, or
//! `unknown` outside a git checkout (a crates.io or sdist build). With
//! `python-embed`, also point the binary at a macOS framework Python.
//!
//! With `python`, also list the SDK's classes (`#[record]`s, `#[handle]`s
//! and `#[pyclass]`es) in `$OUT_DIR/sdk_classes.rs`.

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
    classes::write();
}

/// Finds every SDK class (a `#[record]` struct or `tagged` enum, a
/// `#[handle]`, or a `#[pyclass]`) by walking the crate's module tree from
/// `src/lib.rs`, as rustc does (`#[path]` included), and writes
/// `with_sdk_classes!`, which adds a `#[pymodule_export] use` of each to the
/// SDK's module. A class is exported under the `cfg`s of the modules on its
/// path and its own; one that only exists under `cfg(test)` is not (but one
/// under `not(test)` is). A `tagged` enum with a `base` has no class of its
/// own (its variants subclass the base's, which nests them).
///
/// The walk reads the source, so it cannot see a class that a macro makes
/// (a `macro_rules!`, a `cfg_attr(..., record)`). It writes an
/// `ExportedClass` impl for each `#[record]` and `#[handle]` class it
/// exports, and those macros require one outside tests, so a class the
/// walk missed fails to compile at its name instead of being left out of
/// the module.
///
/// Also fails the build on a name clash, which PyO3 would resolve silently:
/// two classes with one Python name, or two members of one class with one
/// Python name (a record's properties, a handle's generated members, a
/// `#[collection]`'s protocol, `#[command(python = ...)]` methods and
/// hand-written `#[pymethods]`). A `#[handle] impl` item replaces the
/// generated property of its name; that is how it overrides one.
#[cfg(feature = "python")]
mod classes {
    use std::collections::BTreeMap;
    use std::fmt::Write;
    use std::path::{Path, PathBuf};

    use quote::ToTokens;
    use syn::{Attribute, Fields, ImplItem, Item, ItemImpl, LitStr};

    struct Class {
        cfgs: Vec<String>,
        /// The class's Rust path, `crate::target::zombies::ZombiesPy`
        /// (a record's) or `crate::python::process::Process`.
        path: String,
        /// A `#[record]`'s or `#[handle]`'s class, which requires its
        /// `ExportedClass` impl.
        checked: bool,
    }

    /// A Python member of a class, and where it is defined (for the clash
    /// message), under the `cfg`s of its item: two members are alternatives
    /// only when one's `cfg` is `not` of one of the other's.
    struct Member {
        name: String,
        at: String,
        cfgs: Vec<Cfg>,
    }

    /// One `#[cfg(predicate)]`: the predicate's text, and for `not(p)`,
    /// `p`'s.
    struct Cfg {
        text: String,
        negates: Option<String>,
    }

    /// The Python members the walk found, by the Rust name of their class
    /// (a record's own name, not its `<Name>Py` class's).
    #[derive(Default)]
    struct Members {
        /// A record struct's properties, or a `tagged` enum's `kind`.
        record: BTreeMap<String, Vec<Member>>,
        /// A `#[record] impl` block's computed properties, which a handle
        /// on the record has too.
        computed: BTreeMap<String, Vec<Member>>,
        /// Everything else: `#[record(python)]` methods, `#[pymethods]`,
        /// `#[collection]`s, `#[command]` methods.
        methods: BTreeMap<String, Vec<Member>>,
        /// A `#[handle] impl` block's items, which replace generated
        /// properties of their names.
        handle_items: BTreeMap<String, Vec<Member>>,
        /// Each `#[handle]`'s record, and where the handle is defined.
        handles: Vec<(String, String, String)>,
        /// The record classes, by record name, and where they are defined.
        records: Vec<(String, String)>,
    }

    #[derive(Default)]
    struct Walk {
        classes: Vec<Class>,
        /// Python name -> where it is defined, for the duplicate check.
        names: BTreeMap<String, String>,
        members: Members,
    }

    pub fn write() {
        let mut walk = Walk::default();
        walk.file(Path::new("src/lib.rs"), "crate", Path::new("src"), &[]);
        walk.members.check();
        walk.classes.sort_by(|a, b| a.path.cmp(&b.path));
        let mut uses = String::new();
        let mut checked = String::new();
        for class in &walk.classes {
            let cfgs: String = class.cfgs.iter().map(|cfg| format!("{cfg} ")).collect();
            writeln!(uses, "{cfgs}#[pymodule_export] use {};", class.path).unwrap();
            if class.checked {
                writeln!(
                    checked,
                    "{cfgs}impl crate::python::record::ExportedClass for {} {{}}",
                    class.path
                )
                .unwrap();
            }
        }
        let source = format!(
            "/// `with_sdk_classes! {{ #[pymodule] mod m {{ ... }} }}`: the module, \
             exporting every SDK class besides its own items. Written by build.rs.\n\
             macro_rules! with_sdk_classes {{\n\
             ($(#[$attr:meta])* $vis:vis mod $name:ident {{ $($body:tt)* }}) => {{\n\
             $(#[$attr])* $vis mod $name {{\n$($body)*\n{uses}}}\n}};\n}}\n\
             {checked}"
        );
        let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("sdk_classes.rs");
        std::fs::write(out, source).unwrap();
    }

    fn cfgs(attrs: &[Attribute]) -> Vec<String> {
        attrs
            .iter()
            .filter(|attr| attr.path().is_ident("cfg"))
            .map(|attr| attr.to_token_stream().to_string())
            .collect()
    }

    /// The predicates of the `#[cfg]`s in `attrs`.
    fn predicates(attrs: &[Attribute]) -> Vec<syn::Meta> {
        attrs
            .iter()
            .filter(|attr| attr.path().is_ident("cfg"))
            .map(|attr| {
                attr.parse_args::<syn::Meta>()
                    .unwrap_or_else(|error| panic!("#[cfg(...)]: {error}"))
            })
            .collect()
    }

    /// `attrs`' `#[cfg]`s, for comparing two members' conditions.
    fn conditions(attrs: &[Attribute]) -> Vec<Cfg> {
        predicates(attrs)
            .into_iter()
            .map(|predicate| {
                let negates = match &predicate {
                    syn::Meta::List(list) if list.path.is_ident("not") => list
                        .parse_args::<syn::Meta>()
                        .ok()
                        .map(|inner| inner.to_token_stream().to_string()),
                    _ => None,
                };
                Cfg {
                    text: predicate.to_token_stream().to_string(),
                    negates,
                }
            })
            .collect()
    }

    /// Whether `predicate` holds only in a test build: `test`, an `all`
    /// with such a part, or an `any` of only such parts. `not(test)` and
    /// `any(test, x)` hold outside tests too.
    fn requires_test(predicate: &syn::Meta) -> bool {
        let parts = |list: &syn::MetaList| {
            list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .unwrap_or_else(|error| panic!("#[cfg(...)]: {error}"))
        };
        match predicate {
            syn::Meta::Path(path) => path.is_ident("test"),
            syn::Meta::List(list) if list.path.is_ident("all") => {
                parts(list).iter().any(requires_test)
            }
            syn::Meta::List(list) if list.path.is_ident("any") => {
                let parts = parts(list);
                !parts.is_empty() && parts.iter().all(requires_test)
            }
            _ => false,
        }
    }

    /// Whether an item with `attrs` exists only in a test build.
    fn test_only(attrs: &[Attribute]) -> bool {
        predicates(attrs).iter().any(requires_test)
    }

    /// A module's `#[path = "..."]`.
    fn child_path(attrs: &[Attribute], file: &Path) -> Option<String> {
        let attr = attrs.iter().find(|attr| attr.path().is_ident("path"))?;
        match &attr.meta {
            syn::Meta::NameValue(syn::MetaNameValue {
                value:
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(path),
                        ..
                    }),
                ..
            }) => Some(path.value()),
            _ => panic!(
                "{}: #[path] takes a string, #[path = \"...\"]",
                file.display()
            ),
        }
    }

    /// The attribute named `name` (by its last path segment).
    fn attribute<'a>(attrs: &'a [Attribute], name: &str) -> Option<&'a Attribute> {
        attrs.iter().find(|attr| {
            attr.path()
                .segments
                .last()
                .is_some_and(|last| last.ident == name)
        })
    }

    /// The `#[record(...)]` attribute's arguments, if the item has one.
    fn record(attrs: &[Attribute]) -> Option<String> {
        attribute(attrs, "record").map(|attr| match &attr.meta {
            syn::Meta::List(list) => list.tokens.to_string(),
            _ => String::new(),
        })
    }

    /// The flags of a `#[record(...)]` (`tagged`, `skip`, `python`, ...),
    /// and its `rename` and `base`.
    #[derive(Default)]
    struct RecordArgs {
        flags: Vec<String>,
        rename: Option<String>,
        base: Option<String>,
    }

    fn record_args(attrs: &[Attribute]) -> Option<RecordArgs> {
        let attr = attribute(attrs, "record")?;
        let mut args = RecordArgs::default();
        if let syn::Meta::List(_) = &attr.meta {
            attr.parse_nested_meta(|meta| {
                let key = meta.path.to_token_stream().to_string();
                if meta.input.peek(syn::Token![=]) {
                    let value = meta.value()?;
                    match key.as_str() {
                        "rename" => args.rename = Some(value.parse::<LitStr>()?.value()),
                        "base" => args.base = Some(value.parse::<syn::Ident>()?.to_string()),
                        _ => {
                            value.parse::<syn::Expr>()?;
                        }
                    }
                } else {
                    args.flags.push(key);
                }
                Ok(())
            })
            .unwrap_or_else(|error| panic!("#[record(...)]: {error}"));
        }
        Some(args)
    }

    /// Python keywords and `BaseRecord.to_dict`: a record key that is one
    /// keeps the Rust name as its property, as `#[record]` does.
    const RESERVED: [&str; 36] = [
        "to_dict", "False", "None", "True", "and", "as", "assert", "async", "await", "break",
        "class", "continue", "def", "del", "elif", "else", "except", "finally", "for", "from",
        "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise",
        "return", "try", "while", "with", "yield",
    ];

    fn unraw(ident: &syn::Ident) -> String {
        let name = ident.to_string();
        name.strip_prefix("r#").map_or(name.clone(), str::to_string)
    }

    /// The property of a record field or getter named `ident`.
    fn property(ident: &syn::Ident, rename: Option<String>) -> String {
        match rename {
            Some(key) if !RESERVED.contains(&key.as_str()) => key,
            Some(_) => unraw(ident),
            None => unraw(ident),
        }
    }

    /// A hand-written class's Python name: a `#[pyclass]`'s, or a
    /// `#[handle]`'s, which is a pyclass named by its ident.
    fn pyclass(attrs: &[Attribute], ident: &syn::Ident) -> Option<String> {
        let mut name = ident.to_string();
        let attr = attrs.iter().find_map(|attr| {
            let last = &attr.path().segments.last()?.ident;
            (last == "pyclass" || last == "handle").then_some((last == "pyclass", attr))
        });
        let (true, attr) = attr? else {
            return Some(name);
        };
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

    /// A `#[handle(record = R, ...)]`'s record.
    fn handle_record(attrs: &[Attribute]) -> Option<String> {
        let attr = attribute(attrs, "handle")?;
        let mut record = None;
        if let syn::Meta::List(_) = &attr.meta {
            attr.parse_nested_meta(|meta| {
                if meta.input.peek(syn::Token![=]) {
                    let value = meta.value()?.parse::<syn::Expr>()?;
                    if meta.path.is_ident("record") {
                        record = Some(value.to_token_stream().to_string());
                    }
                }
                Ok(())
            })
            .unwrap_or_else(|error| panic!("#[handle(...)]: {error}"));
        }
        record.map(|path| path.rsplit(' ').next().unwrap_or(&path).to_string())
    }

    /// The `name = "..."` of a `#[pyo3(...)]`, whose other options (a
    /// `signature`) are not all expressions.
    fn pyo3_name(attr: &Attribute) -> Option<String> {
        attr.parse_args_with(|input: syn::parse::ParseStream<'_>| {
            let mut name = None;
            while !input.is_empty() {
                if input.peek(syn::Ident) && input.peek2(syn::Token![=]) && input.peek3(LitStr) {
                    let key: syn::Ident = input.parse()?;
                    input.parse::<syn::Token![=]>()?;
                    let value: LitStr = input.parse()?;
                    if key == "name" {
                        name = Some(value.value());
                    }
                } else {
                    // Skip one token tree.
                    input.step(|cursor| {
                        cursor
                            .token_tree()
                            .map(|(_, rest)| ((), rest))
                            .ok_or_else(|| cursor.error("end of input"))
                    })?;
                }
            }
            Ok(name)
        })
        .ok()
        .flatten()
    }

    /// The Python name a `#[pymethods]` item takes: `#[pyo3(name = ...)]`,
    /// `#[getter(name)]`, a getter's name less `get_`, or its own; `None`
    /// for a setter, which shares its property's name.
    fn method_name(attrs: &[Attribute], ident: &syn::Ident) -> Option<String> {
        let mut name = None;
        let mut getter = false;
        for attr in attrs {
            let path = attr.path();
            if path.is_ident("setter") {
                return None;
            }
            if path.is_ident("getter") {
                getter = true;
                if let syn::Meta::List(list) = &attr.meta {
                    name = Some(list.tokens.to_string().trim_matches('"').to_string());
                }
            } else if path.is_ident("pyo3") {
                name = pyo3_name(attr).or(name);
            }
        }
        let own = unraw(ident);
        Some(name.unwrap_or_else(|| match own.strip_prefix("get_") {
            Some(stripped) if getter => stripped.to_string(),
            _ => own,
        }))
    }

    /// The class an impl block is for: the last segment of its type.
    fn impl_class(item: &ItemImpl) -> Option<String> {
        match &*item.self_ty {
            syn::Type::Path(path) => Some(path.path.segments.last()?.ident.to_string()),
            _ => None,
        }
    }

    /// The methods of a `#[pymethods]` or `#[handle]` impl block.
    fn methods(item: &ItemImpl, at: &str) -> Vec<Member> {
        item.items
            .iter()
            .filter_map(|item| match item {
                ImplItem::Fn(method) => Some(Member {
                    name: method_name(&method.attrs, &method.sig.ident)?,
                    at: at.to_string(),
                    cfgs: conditions(&method.attrs),
                }),
                _ => None,
            })
            .collect()
    }

    /// The classes and names a `#[command(...)]` adds a method to:
    /// `python = X` or `[X, Y]` (not `none`), named `python_name` or the
    /// function.
    fn command(attr: &Attribute, function: &syn::Ident) -> (Vec<String>, String) {
        let mut classes = Vec::new();
        let mut name = unraw(function);
        attr.parse_nested_meta(|meta| {
            if !meta.input.peek(syn::Token![=]) {
                return Ok(());
            }
            let value = meta.value()?.parse::<syn::Expr>()?;
            if meta.path.is_ident("python_name") {
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(text),
                    ..
                }) = &value
                {
                    name = text.value();
                }
            } else if meta.path.is_ident("python") {
                let paths = match value {
                    syn::Expr::Array(array) => array.elems.into_iter().collect(),
                    other => vec![other],
                };
                for path in paths {
                    let path = path.to_token_stream().to_string();
                    if path != "none" {
                        classes.push(path);
                    }
                }
            }
            Ok(())
        })
        .unwrap_or_else(|error| panic!("#[command(...)] on {function}: {error}"));
        (classes, name)
    }

    impl Members {
        fn add(map: &mut BTreeMap<String, Vec<Member>>, class: &str, members: Vec<Member>) {
            map.entry(class.to_string()).or_default().extend(members);
        }

        /// Panic on two members of one class with one Python name.
        fn check(&self) {
            fn get<'a>(map: &'a BTreeMap<String, Vec<Member>>, class: &str) -> &'a [Member] {
                map.get(class).map_or(&[], Vec::as_slice)
            }
            let generated = |name: &str, at: &str| Member {
                name: name.to_string(),
                at: at.to_string(),
                cfgs: Vec::new(),
            };
            for (record, at) in &self.records {
                let mut all: Vec<&Member> = get(&self.record, record).iter().collect();
                all.extend(get(&self.computed, record));
                all.extend(get(&self.methods, record));
                let to_dict = generated("to_dict", "BaseRecord");
                all.push(&to_dict);
                unique(&format!("{record} ({at})"), &all);
            }
            for (handle, record, at) in &self.handles {
                let items = get(&self.handle_items, handle);
                let replaced =
                    |member: &&Member| !items.iter().any(|item| item.name == member.name);
                let info = generated("info", &format!("#[handle] {at}"));
                let to_dict = generated("to_dict", &format!("#[handle] {at}"));
                let mut all: Vec<&Member> = get(&self.record, record)
                    .iter()
                    .chain(get(&self.computed, record))
                    .chain([&info, &to_dict])
                    .filter(replaced)
                    .collect();
                all.extend(items);
                all.extend(get(&self.methods, handle));
                unique(&format!("{handle} ({at})"), &all);
            }
            for (class, members) in &self.methods {
                let known = self.records.iter().any(|(record, _)| record == class)
                    || self.handles.iter().any(|(handle, _, _)| handle == class);
                if !known {
                    unique(class, &members.iter().collect::<Vec<_>>());
                }
            }
        }
    }

    fn unique(class: &str, members: &[&Member]) {
        // Two `cfg`s exclude each other when one is `not` of the other.
        // Anything else (`feature = "a"` and `feature = "b"`) can hold at
        // once, so the two members can both exist.
        let excludes = |a: &Member, b: &Member| {
            a.cfgs.iter().any(|cfg| {
                b.cfgs
                    .iter()
                    .any(|other| cfg.negates.as_ref() == Some(&other.text))
            })
        };
        for (index, member) in members.iter().enumerate() {
            if let Some(earlier) = members[..index].iter().find(|earlier| {
                earlier.name == member.name
                    && !excludes(earlier, member)
                    && !excludes(member, earlier)
            }) {
                panic!(
                    "class {class} has two Python members named `{}`, which PyO3 would \
                     silently make one: {} and {}",
                    member.name, earlier.at, member.at
                );
            }
        }
    }

    impl Walk {
        /// Walk `file`, module `module`, whose `mod x;` files are in `dir`.
        fn file(&mut self, file: &Path, module: &str, dir: &Path, cfgs: &[String]) {
            let source = std::fs::read_to_string(file)
                .unwrap_or_else(|error| panic!("{}: {error}", file.display()));
            let ast = syn::parse_file(&source)
                .unwrap_or_else(|error| panic!("{}: {error}", file.display()));
            // A `#[path]` at a file's top level is relative to the file's
            // directory; in an inline module, to that module's directory.
            let path_base = file.parent().unwrap_or(Path::new(""));
            self.items(&ast.items, file, module, dir, cfgs, path_base);
        }

        /// The members an item outside a class's own definition adds to a
        /// class: an impl block's, or a `#[command]` function's method.
        fn members(&mut self, item: &Item, module: &str) {
            match item {
                Item::Impl(item) if item.trait_.is_none() => {
                    let Some(class) = impl_class(item) else {
                        return;
                    };
                    let at = format!("impl {class} in {module}");
                    let members = &mut self.members;
                    if record(&item.attrs).is_some() {
                        // `#[record] impl`: computed getters and Python methods.
                        for impl_item in &item.items {
                            let ImplItem::Fn(method) = impl_item else {
                                continue;
                            };
                            let Some(args) = record_args(&method.attrs) else {
                                continue;
                            };
                            let ident = &method.sig.ident;
                            let cfgs = conditions(&method.attrs);
                            if args.flags.iter().any(|flag| flag == "getter") {
                                let name = property(ident, args.rename);
                                let member = Member {
                                    name,
                                    at: at.clone(),
                                    cfgs,
                                };
                                Members::add(&mut members.computed, &class, vec![member]);
                            } else if args.flags.iter().any(|flag| flag == "python") {
                                let name = method_name(&method.attrs, ident)
                                    .unwrap_or_else(|| unraw(ident));
                                let member = Member {
                                    name,
                                    at: at.clone(),
                                    cfgs,
                                };
                                Members::add(&mut members.methods, &class, vec![member]);
                            }
                        }
                    } else if attribute(&item.attrs, "handle").is_some() {
                        Members::add(&mut members.handle_items, &class, methods(item, &at));
                    } else if attribute(&item.attrs, "collection").is_some() {
                        // The protocol every collection gets, and `find`/`at`.
                        let protocol = format!("#[collection] {at}");
                        let generated_member = |name: String| Member {
                            name,
                            at: protocol.clone(),
                            cfgs: Vec::new(),
                        };
                        let mut generated: Vec<Member> =
                            ["__len__", "__iter__", "__getitem__", "get", "__contains__"]
                                .into_iter()
                                .map(|name| generated_member(name.to_string()))
                                .collect();
                        for impl_item in &item.items {
                            let ImplItem::Fn(method) = impl_item else {
                                continue;
                            };
                            let ident = method.sig.ident.to_string();
                            let matcher = attribute(&method.attrs, "collection").map(|attr| {
                                attr.parse_args::<syn::Ident>()
                                    .map(|ident| ident.to_string())
                                    .unwrap_or_default()
                            });
                            match matcher {
                                Some(kind) => generated.push(generated_member(kind)),
                                None if ident == "enumerate" || ident == "lookup" => {}
                                None => generated.extend(
                                    method_name(&method.attrs, &method.sig.ident).map(|name| {
                                        Member {
                                            name,
                                            at: at.clone(),
                                            cfgs: conditions(&method.attrs),
                                        }
                                    }),
                                ),
                            }
                        }
                        Members::add(&mut members.methods, &class, generated);
                    } else if attribute(&item.attrs, "pymethods").is_some() {
                        Members::add(&mut members.methods, &class, methods(item, &at));
                    }
                }
                Item::Fn(function) => {
                    let Some(attr) = attribute(&function.attrs, "command") else {
                        return;
                    };
                    let (classes, name) = command(attr, &function.sig.ident);
                    for class in classes {
                        let member = Member {
                            name: name.clone(),
                            at: format!("#[command] {} in {module}", function.sig.ident),
                            cfgs: conditions(&function.attrs),
                        };
                        Members::add(&mut self.members.methods, &class, vec![member]);
                    }
                }
                _ => {}
            }
        }

        /// A record struct's properties.
        fn record_members(&mut self, item: &syn::ItemStruct, module: &str) {
            let Fields::Named(fields) = &item.fields else {
                return;
            };
            let name = item.ident.to_string();
            let at = format!("#[record] {name} in {module}");
            let members = fields
                .named
                .iter()
                .filter_map(|field| {
                    let args = record_args(&field.attrs).unwrap_or_default();
                    if args.flags.iter().any(|flag| flag == "skip") {
                        return None;
                    }
                    let ident = field.ident.as_ref()?;
                    Some(Member {
                        name: property(ident, args.rename),
                        at: at.clone(),
                        cfgs: conditions(&field.attrs),
                    })
                })
                .collect();
            Members::add(&mut self.members.record, &name, members);
            self.members.records.push((name, module.to_string()));
        }

        fn items(
            &mut self,
            items: &[Item],
            file: &Path,
            module: &str,
            dir: &Path,
            cfgs: &[String],
            path_base: &Path,
        ) {
            for item in items {
                let (attrs, ident, class) = match item {
                    Item::Mod(child) => {
                        if test_only(&child.attrs) {
                            continue;
                        }
                        let mut child_cfgs = cfgs.to_vec();
                        child_cfgs.extend(self::cfgs(&child.attrs));
                        let name = child.ident.to_string();
                        let path = format!("{module}::{name}");
                        let explicit =
                            child_path(&child.attrs, file).map(|explicit| path_base.join(explicit));
                        match &child.content {
                            Some((_, items)) => {
                                // An inline module's `#[path]` names its
                                // directory.
                                let child_dir = explicit.unwrap_or_else(|| dir.join(&name));
                                self.items(items, file, &path, &child_dir, &child_cfgs, &child_dir)
                            }
                            None => {
                                let (child_file, child_dir) = match explicit {
                                    // A `#[path]` file's own modules are
                                    // beside it, as a `mod.rs`'s are.
                                    Some(child_file) => {
                                        let child_dir = child_file
                                            .parent()
                                            .unwrap_or(Path::new(""))
                                            .to_path_buf();
                                        (child_file, child_dir)
                                    }
                                    None => {
                                        let child_dir = dir.join(&name);
                                        let flat = dir.join(format!("{name}.rs"));
                                        let nested = child_dir.join("mod.rs");
                                        (if flat.exists() { flat } else { nested }, child_dir)
                                    }
                                };
                                self.file(&child_file, &path, &child_dir, &child_cfgs);
                            }
                        }
                        continue;
                    }
                    Item::Struct(item) => (&item.attrs, &item.ident, true),
                    Item::Enum(item) => (&item.attrs, &item.ident, false),
                    Item::Impl(ItemImpl { attrs, .. }) | Item::Fn(syn::ItemFn { attrs, .. }) => {
                        if !test_only(attrs) {
                            self.members(item, module);
                        }
                        continue;
                    }
                    _ => continue,
                };
                if test_only(attrs) {
                    continue;
                }
                let mut item_cfgs = cfgs.to_vec();
                item_cfgs.extend(self::cfgs(attrs));
                let python = if let Some(args) = record_args(attrs) {
                    // A struct, or a `tagged` enum without a `base`, has a
                    // class.
                    let tagged = args.flags.iter().any(|flag| flag == "tagged");
                    if !class && (!tagged || args.base.is_some()) {
                        continue;
                    }
                    let name = ident.to_string();
                    self.classes.push(Class {
                        cfgs: item_cfgs,
                        path: format!("{module}::{name}Py"),
                        checked: true,
                    });
                    match item {
                        Item::Struct(item) => self.record_members(item, module),
                        _ => {
                            let member = Member {
                                name: "kind".to_string(),
                                at: format!("#[record] {name} in {module}"),
                                cfgs: Vec::new(),
                            };
                            Members::add(&mut self.members.record, &name, vec![member]);
                            self.members
                                .records
                                .push((name.clone(), module.to_string()));
                        }
                    }
                    name
                } else if let Some(name) = pyclass(attrs, ident) {
                    self.classes.push(Class {
                        cfgs: item_cfgs,
                        path: format!("{module}::{ident}"),
                        checked: attribute(attrs, "handle").is_some(),
                    });
                    if let Some(record) = handle_record(attrs) {
                        self.members
                            .handles
                            .push((ident.to_string(), record, module.to_string()));
                    }
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
