use super::cache::{ModuleIdentities, ModuleIdentity, PdbReference};
use super::download::local_source_candidates;
use super::index_build::{insert_symbol_rva, undecorate_x86};
use super::locals::live_range_contains;
use super::lookup::preferred_symbol_records;
use super::source::{SourceFileQuery, lookup_source_line, remap_source_file};
use super::*;
use crate::backend::MemoryOps;
use crate::error::Result;
use crate::types::{Arch, PhysAddr};
use std::io::Write;
use std::path::Path;

#[test]
fn symbol_path_parser_supports_local_http_and_srv_syntax() {
    let sources = parse_symbol_sources(&[
        "/private",
        "https://symbols.example.test/",
        "srv*/cache*https://backup.example.test",
    ]);
    assert_eq!(
        sources,
        vec![
            SymbolSource::LocalDirectory("/private".into()),
            SymbolSource::Http("https://symbols.example.test".to_string()),
            SymbolSource::LocalDirectory("/cache".into()),
            SymbolSource::Http("https://backup.example.test".to_string()),
        ]
    );
}

#[test]
fn source_path_parser_supports_roots_and_prefix_mappings() {
    assert_eq!(
        parse_source_paths(&[";a;;b=c=d;"]),
        vec![
            SourcePathMapping {
                recorded_prefix: None,
                local_root: "a".into(),
            },
            SourcePathMapping {
                recorded_prefix: Some("b".to_string()),
                local_root: "c=d".into(),
            },
        ]
    );
}

#[test]
fn local_locations_describe_negative_offsets_as_subtraction() {
    assert_eq!(
        LocalVariableLocation::RegisterRelative {
            register: "rsp".to_string(),
            offset: -0x20,
        }
        .describe(),
        "[rsp-0x20]"
    );
}

fn temp_root(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ntoseye-{name}-{nonce}"))
}

fn identity(name: &str) -> ModuleIdentity {
    ModuleIdentity {
        name: name.to_string(),
        time_date_stamp: 0x6600_0000,
        size_of_image: 0x7000,
    }
}

fn reference(age: u32) -> PdbReference {
    PdbReference {
        server_name: "driver.pdb".to_string(),
        guid: 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef,
        age,
    }
}

#[test]
fn module_identities_persist_across_reopen() {
    let root = temp_root("identities");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("identities");

    let identities = ModuleIdentities::open(Some(path.clone()));
    identities.insert(identity("a.sys"), reference(1));
    identities.insert(identity("b.sys"), reference(2));
    identities.insert(identity("a.sys"), reference(3));
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"garbage line\n")
        .unwrap();

    let reopened = ModuleIdentities::open(Some(path.clone()));
    assert_eq!(reopened.get(&identity("a.sys")), Some(reference(3)));
    assert_eq!(reopened.get(&identity("b.sys")), Some(reference(2)));
    assert_eq!(reopened.get(&identity("c.sys")), None);

    reopened.remove(&identity("a.sys"));
    let again = ModuleIdentities::open(Some(path));
    assert_eq!(again.get(&identity("a.sys")), None);
    assert_eq!(again.get(&identity("b.sys")), Some(reference(2)));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn remembered_module_is_discovered_without_reading_the_target() {
    struct NoReads;
    impl MemoryOps<PhysAddr> for NoReads {
        fn read_bytes(&self, addr: PhysAddr, _: &mut [u8]) -> Result<()> {
            panic!("read at {addr:#x} for a remembered module");
        }
        fn write_bytes(&self, _: PhysAddr, _: &[u8]) -> Result<()> {
            unreachable!()
        }
    }

    let root = temp_root("identity-discovery");
    std::fs::create_dir_all(&root).unwrap();
    let store = SymbolStore::new();
    let identities = ModuleIdentities::open(Some(root.join("identities")));
    identities.insert(identity("driver.sys"), reference(2));
    store.identities.set(identities).ok().unwrap();

    let mut module = ModuleInfo::new(
        "\\SystemRoot\\drivers\\Driver.sys".to_string(),
        VirtAddr(0xffff_f800_1000_0000),
        0x7000,
    );
    module = module.with_time_date_stamp(0x6600_0000);
    let discovery = store
        .extract_download_job(&NoReads, 0x1000, &module, Arch::Amd64)
        .unwrap();
    let ModuleSymbolDiscovery::Ready { job, guid, source } = discovery else {
        panic!("expected a ready job");
    };
    assert!(matches!(source, ModuleSymbolSource::Identity));
    assert_eq!(guid, reference(2).guid);
    assert_eq!(job.filename, "driver.pdb");
    assert!(
        job.urls[0].ends_with("/driver.pdb/0123456789ABCDEF0123456789ABCDEF2/driver.pdb"),
        "{}",
        job.urls[0]
    );
    assert!(
        job.path
            .ends_with("driver.pdb/0123456789ABCDEF0123456789ABCDEF2/driver.pdb"),
        "{}",
        job.path.display()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn local_source_paths_cover_direct_and_symbol_store_layouts() {
    let identity = PdbIdentity {
        guid: 0x00112233445566778899AABBCCDDEEFF,
        age: 2,
    };
    let root = Path::new("/symbols");

    assert_eq!(
        local_source_candidates(root, "private.pdb", identity),
        vec![
            root.join("private.pdb"),
            root.join("private.pdb")
                .join("00112233445566778899AABBCCDDEEFF2")
                .join("private.pdb")
        ]
    );
}

#[test]
fn pdb_identity_requires_guid_and_non_stale_age() {
    let expected = PdbIdentity {
        guid: 0x1234,
        age: 3,
    };
    assert!(expected.matches(expected).is_ok());
    assert!(
        expected
            .matches(PdbIdentity {
                guid: expected.guid,
                age: 4
            })
            .is_ok()
    );
    assert!(
        expected
            .matches(PdbIdentity {
                guid: 0x5678,
                age: 3
            })
            .unwrap_err()
            .contains("GUID mismatch")
    );
    assert!(
        expected
            .matches(PdbIdentity {
                guid: expected.guid,
                age: 2
            })
            .unwrap_err()
            .contains("age mismatch")
    );
}

#[test]
fn duplicate_private_symbols_remain_candidates_while_public_symbols_take_precedence() {
    let mut symbols = HashMap::new();
    insert_symbol_rva(
        &mut symbols,
        "duplicate".to_string(),
        0x100,
        SymbolVisibility::Private,
        Some("first.obj".to_string()),
    );
    insert_symbol_rva(
        &mut symbols,
        "duplicate".to_string(),
        0x200,
        SymbolVisibility::Private,
        Some("second.obj".to_string()),
    );
    assert_eq!(preferred_symbol_records(&symbols["duplicate"]).len(), 2);

    insert_symbol_rva(
        &mut symbols,
        "duplicate".to_string(),
        0x300,
        SymbolVisibility::Public,
        None,
    );
    let preferred = preferred_symbol_records(&symbols["duplicate"]);
    assert_eq!(preferred.len(), 1);
    assert_eq!(preferred[0].rva, 0x300);
    assert_eq!(symbols["duplicate"].len(), 3);
}

#[test]
fn symbol_resolution_reports_distinct_private_candidates() {
    let store = SymbolStore::new();
    let dtb = 0x1000_u64;
    let base = VirtAddr(0x0000_0001_8000_0000);
    store.modules.insert(
        SymbolStore::module_key(dtb, base),
        LoadedModule {
            name: "driver.sys".to_string(),
            short_name: "driver".to_string(),
            guid: 1,
            base_address: base,
            size: 0x1000,
            dtb,
        },
    );
    store.publish_symbol_rvas(
        1,
        HashMap::from([(
            "worker".to_string(),
            vec![
                IndexedSymbol {
                    rva: 0x100,
                    visibility: SymbolVisibility::Private,
                    compiland: Some("first.obj".to_string()),
                },
                IndexedSymbol {
                    rva: 0x200,
                    visibility: SymbolVisibility::Private,
                    compiland: Some("second.obj".to_string()),
                },
            ],
        )]),
    );

    let candidates = store.find_symbol_candidates(dtb, "driver!worker");
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].compiland.as_deref(), Some("first.obj"));
    assert_eq!(candidates[1].address, base + 0x200_u64);
    let error = store
        .find_symbol_with_module(dtb, "driver!worker")
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("driver!worker"));
    assert!(message.contains("first.obj"));
    assert!(message.contains("second.obj"));
}

#[test]
fn public_symbol_is_the_unique_resolution_for_a_duplicate_name() {
    let store = SymbolStore::new();
    let dtb = 0x1000_u64;
    let base = VirtAddr(0x0000_0001_8000_0000);
    store.modules.insert(
        SymbolStore::module_key(dtb, base),
        LoadedModule {
            name: "driver.sys".to_string(),
            short_name: "driver".to_string(),
            guid: 1,
            base_address: base,
            size: 0x1000,
            dtb,
        },
    );
    store.publish_symbol_rvas(
        1,
        HashMap::from([(
            "worker".to_string(),
            vec![
                IndexedSymbol {
                    rva: 0x100,
                    visibility: SymbolVisibility::Private,
                    compiland: Some("first.obj".to_string()),
                },
                IndexedSymbol {
                    rva: 0x300,
                    visibility: SymbolVisibility::Public,
                    compiland: None,
                },
            ],
        )]),
    );

    assert_eq!(
        store.find_symbol_with_module(dtb, "driver!worker").unwrap(),
        Some((base + 0x300_u64, "driver".to_string()))
    );
}

#[test]
fn closest_symbol_picks_nearest_lower_record_and_prefers_public_at_ties() {
    let store = SymbolStore::new();
    let base = VirtAddr(0x0000_0001_8000_0000);
    let mut rvas = HashMap::new();
    let mut insert = |name: &str, rva, visibility, compiland: Option<&str>| {
        insert_symbol_rva(
            &mut rvas,
            name.to_string(),
            rva,
            visibility,
            compiland.map(str::to_string),
        );
    };
    insert("zeta", 0x100, SymbolVisibility::Public, None);
    insert("alpha", 0x100, SymbolVisibility::Private, Some("a.obj"));
    insert("later", 0x200, SymbolVisibility::Private, Some("b.obj"));
    insert("far", 0x8000, SymbolVisibility::Public, None);
    store.publish_symbol_rvas(1, rvas);

    let closest = |rva: u64| store.closest_symbol(1, base, base + rva);
    assert_eq!(closest(0x0), None);
    assert_eq!(closest(0x100), Some(("zeta".to_string(), 0)));
    assert_eq!(closest(0x1ff), Some(("zeta".to_string(), 0xff)));
    assert_eq!(closest(0x200), Some(("later".to_string(), 0)));
    assert_eq!(closest(0x200 + 8192), Some(("later".to_string(), 8192)));
    assert_eq!(closest(0x200 + 8193), None);
    assert_eq!(closest(0x8010), Some(("far".to_string(), 0x10)));
}

#[test]
fn source_line_lookup_obeys_line_ranges() {
    let lines = vec![
        SourceLineEntry {
            rva: 0x100,
            length: Some(4),
            location: SourceLocation {
                file: "private.c".to_string(),
                line: 10,
                column: Some(2),
                local: None,
            },
        },
        SourceLineEntry {
            rva: 0x110,
            length: None,
            location: SourceLocation {
                file: "private.c".to_string(),
                line: 11,
                column: None,
                local: None,
            },
        },
        SourceLineEntry {
            rva: 0x120,
            length: Some(2),
            location: SourceLocation {
                file: "private.c".to_string(),
                line: 12,
                column: None,
                local: None,
            },
        },
    ];

    assert_eq!(
        lookup_source_line(&lines, 0x102).unwrap().0.location.line,
        10
    );
    assert!(lookup_source_line(&lines, 0x104).is_none());
    assert_eq!(
        lookup_source_line(&lines, 0x11f).unwrap().0.location.line,
        11
    );
    assert!(lookup_source_line(&lines, 0x122).is_none());
}

#[test]
fn source_line_extent_reports_explicit_next_and_missing_ends() {
    let store = SymbolStore::new();
    let dtb = 0x1000_u64;
    let base = VirtAddr(0x0000_0001_8000_0000);
    store.inject_source_lines_for_test(
        1,
        dtb,
        base,
        0x1000,
        "private.c",
        &[(0x100, Some(4), 10), (0x110, None, 11), (0x120, None, 12)],
    );

    let explicit = store.source_line_extent(dtb, base + 0x101_u64).unwrap();
    assert_eq!(explicit.end, Some(base + 0x104_u64));

    let next_entry = store.source_line_extent(dtb, base + 0x111_u64).unwrap();
    assert_eq!(next_entry.end, Some(base + 0x120_u64));

    let final_entry = store.source_line_extent(dtb, base + 0x120_u64).unwrap();
    assert_eq!(final_entry.end, None);
}

#[test]
fn definition_range_excludes_gaps() {
    let gaps = [(4, 2)];
    assert!(live_range_contains(0x100, 10, &gaps, 0x103));
    assert!(!live_range_contains(0x100, 10, &gaps, 0x104));
    assert!(!live_range_contains(0x100, 10, &gaps, 0x105));
    assert!(live_range_contains(0x100, 10, &gaps, 0x106));
    assert!(!live_range_contains(0x100, 10, &gaps, 0x10a));
}

#[test]
fn source_file_matching_supports_windows_paths_and_basenames() {
    let recorded = r"C:\agent\src\private.c";
    assert!(SourceFileQuery::new(r"c:\AGENT\src\PRIVATE.c").matches(recorded));
    assert!(SourceFileQuery::new("c:/agent/SRC/private.c").matches(recorded));
    assert!(SourceFileQuery::new("PRIVATE.c").matches(recorded));
    assert!(!SourceFileQuery::new("other.c").matches(recorded));
}

fn unverified(_: &Path) -> Option<bool> {
    None
}

fn local(path: PathBuf, state: LocalSourceState) -> Option<LocalSource> {
    Some(LocalSource { path, state })
}

#[test]
fn source_path_remapping_prefers_existing_ordered_candidate() {
    let root = temp_root("source-remap");
    let first = root.join("missing");
    let second = root.join("checkout");
    std::fs::create_dir_all(&second).unwrap();
    std::fs::write(second.join("private.c"), "int private;\n").unwrap();
    let mappings = vec![
        SourcePathMapping {
            recorded_prefix: Some(r"C:\agent\src".to_string()),
            local_root: first.clone(),
        },
        SourcePathMapping {
            recorded_prefix: Some(r"C:\agent\src".to_string()),
            local_root: second.clone(),
        },
    ];

    assert_eq!(
        remap_source_file(r"C:\agent\src\private.c", &mappings, &mut unverified),
        local(second.join("private.c"), LocalSourceState::Found)
    );
    assert_eq!(
        remap_source_file(r"C:\agent\src\gone.c", &mappings, &mut unverified),
        local(first.join("gone.c"), LocalSourceState::Missing)
    );

    let _ = std::fs::remove_dir_all(root);
}

/// A bare root holds the recorded path's trailing components: the longest
/// that names a file under it wins, exact case first, then ignoring case.
#[test]
fn a_bare_source_root_matches_the_longest_recorded_suffix() {
    let root = temp_root("source-suffix");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("Inc")).unwrap();
    std::fs::write(root.join("src/queue.c"), "queue\n").unwrap();
    std::fs::write(root.join("queue.c"), "other queue\n").unwrap();
    std::fs::write(root.join("Inc/Driver.h"), "driver\n").unwrap();
    let mappings = [SourcePathMapping {
        recorded_prefix: None,
        local_root: root.clone(),
    }];

    assert_eq!(
        remap_source_file(
            r"C:\Users\me\repos\MyDriver\src\queue.c",
            &mappings,
            &mut unverified
        ),
        local(root.join("src/queue.c"), LocalSourceState::Found)
    );
    assert_eq!(
        remap_source_file(r"C:\build\inc\driver.h", &mappings, &mut unverified),
        local(root.join("Inc/Driver.h"), LocalSourceState::Found)
    );
    assert_eq!(
        remap_source_file(r"C:\build\src\absent.c", &mappings, &mut unverified),
        local(root.join("absent.c"), LocalSourceState::Missing)
    );

    let _ = std::fs::remove_dir_all(root);
}

/// A file that is not the one compiled is passed over for one that is, and
/// reported only when no candidate is.
#[test]
fn source_remapping_passes_over_files_that_are_not_the_one_compiled() {
    let root = temp_root("source-verify");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/queue.c"), "edited\n").unwrap();
    std::fs::write(root.join("queue.c"), "compiled\n").unwrap();
    let mappings = [SourcePathMapping {
        recorded_prefix: None,
        local_root: root.clone(),
    }];
    let compiled = |path: &Path| Some(std::fs::read(path).unwrap() == b"compiled\n");

    assert_eq!(
        remap_source_file(r"C:\drv\src\queue.c", &mappings, &mut { compiled }),
        local(root.join("queue.c"), LocalSourceState::Found)
    );
    std::fs::remove_file(root.join("queue.c")).unwrap();
    assert_eq!(
        remap_source_file(r"C:\drv\src\queue.c", &mappings, &mut { compiled }),
        local(root.join("src/queue.c"), LocalSourceState::Differs)
    );

    let _ = std::fs::remove_dir_all(root);
}

/// The store checks a mapped file against the checksum the PDB records,
/// again after the file changes.
#[test]
fn source_lines_report_whether_the_local_file_is_the_one_compiled() {
    let root = temp_root("source-checksum");
    std::fs::create_dir_all(root.join("src")).unwrap();
    let file = root.join("src/driver.c");
    std::fs::write(&file, "int compiled;\n").unwrap();
    let store = SymbolStore::new();
    let (guid, dtb, base) = (0x77, 0x1000, VirtAddr(0xffff_f800_1000_0000));
    let recorded = r"C:\agent\src\driver.c";
    store.inject_source_lines_for_test(guid, dtb, base, 0x1000, recorded, &[(0x100, Some(4), 7)]);
    let checksum = source::source_digest(&SourceChecksum::Sha256([0; 32]), b"int compiled;\n");
    store
        .source_checksums
        .insert(guid, HashMap::from([(recorded.to_string(), checksum)]));
    store.set_source_paths(parse_source_paths(&[root.to_str().unwrap()]));
    let state = || {
        store
            .source_location(dtb, base + 0x100_u64)
            .and_then(|location| location.local)
            .map(|local| local.state)
    };

    assert_eq!(state(), Some(LocalSourceState::Found));
    std::fs::write(&file, "int edited since;\n").unwrap();
    assert_eq!(state(), Some(LocalSourceState::Differs));
    std::fs::write(&file, "int compiled;\n").unwrap();
    assert_eq!(state(), Some(LocalSourceState::Found));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn source_path_remapping_rejects_traversal_and_symlink_escape() {
    let root = temp_root("source-containment");
    let checkout = root.join("checkout");
    let outside = root.join("outside");
    std::fs::create_dir_all(&checkout).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.c"), "secret\n").unwrap();
    std::os::unix::fs::symlink(&outside, checkout.join("link")).unwrap();
    let mappings = [SourcePathMapping {
        recorded_prefix: Some(r"C:\agent\src".to_string()),
        local_root: checkout.clone(),
    }];

    assert_eq!(
        remap_source_file(
            r"C:\agent\src\..\outside\secret.c",
            &mappings,
            &mut unverified
        ),
        None
    );
    assert_eq!(
        remap_source_file(r"C:\agent\src\link\secret.c", &mappings, &mut unverified),
        local(checkout.join("link/secret.c"), LocalSourceState::Missing)
    );
    assert_eq!(remap_source_file("/etc/passwd", &[], &mut unverified), None);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn source_addresses_resolve_cached_file_and_line() {
    let store = SymbolStore::new();
    let guid = 0x55;
    let dtb = 0x1000;
    store.modules.insert(
        (dtb, 0x140000000),
        LoadedModule {
            name: "private.exe".to_string(),
            short_name: "private".to_string(),
            guid,
            base_address: VirtAddr(0x140000000),
            size: 0x1000,
            dtb,
        },
    );
    store.source_lines.insert(
        guid,
        vec![
            SourceLineEntry {
                rva: 0x120,
                length: Some(4),
                location: SourceLocation {
                    file: r"C:\agent\src\private.c".to_string(),
                    line: 42,
                    column: None,
                    local: None,
                },
            },
            SourceLineEntry {
                rva: 0x180,
                length: Some(4),
                location: SourceLocation {
                    file: r"C:\agent\src\private.c".to_string(),
                    line: 42,
                    column: None,
                    local: None,
                },
            },
        ],
    );
    store.set_source_paths(vec![SourcePathMapping {
        recorded_prefix: Some(r"C:\agent\src".to_string()),
        local_root: "/checkout".into(),
    }]);

    assert_eq!(
        store.source_addresses(dtb, "private.c", 42),
        vec![VirtAddr(0x140000120), VirtAddr(0x140000180)]
    );
    assert_eq!(
        store.source_addresses(dtb, "/checkout/private.c", 42),
        vec![VirtAddr(0x140000120), VirtAddr(0x140000180)]
    );
}

#[test]
fn invalidating_module_clears_registration_and_status() {
    let store = SymbolStore::new();
    let dtb = 0x1000;
    let base = VirtAddr(0x180000000);
    store.modules.insert(
        (dtb, base.0),
        LoadedModule {
            name: "reload.dll".to_string(),
            short_name: "reload".to_string(),
            guid: 0x99,
            base_address: base,
            size: 0x1000,
            dtb,
        },
    );
    store.set_module_symbol_status(dtb, base, ModuleSymbolStatus::Loaded);

    store.invalidate_modules(dtb, &[base]);

    assert!(store.find_module_for_address(dtb, base).is_none());
    assert!(store.module_symbol_status(dtb, base).is_none());
}

#[test]
fn kernel_modules_are_visible_from_user_address_spaces() {
    let store = SymbolStore::new();
    let user_dtb = 0x1000;
    let kernel_dtb = 0x2000;
    let base = VirtAddr(0x180000000);
    let module = |name: &str, guid, dtb| LoadedModule {
        name: name.to_string(),
        short_name: ModuleInfo::derive_short_name(name),
        guid,
        base_address: base,
        size: 0x1000,
        dtb,
    };
    store
        .modules
        .insert((kernel_dtb, base.0), module("kernel.sys", 0x22, kernel_dtb));

    assert!(store.find_module_for_address(user_dtb, base).is_none());
    assert!(store.module_base_by_name(user_dtb, "kernel").is_none());

    store.set_kernel(Some(0x22), kernel_dtb);
    let resolved = store.find_module_for_address(user_dtb, base).unwrap();
    assert_eq!(resolved.name, "kernel.sys");
    assert_eq!(store.module_base_by_name(user_dtb, "kernel"), Some(base));
}

#[test]
fn type_lookup_prefers_the_kernel_unless_qualified() {
    let store = SymbolStore::new();
    let (kernel_dtb, dtb) = (0x2000, 0x1000);
    let (kernel, ntdll32) = (0x22, 0x33);
    let layout = |name: &str, size| TypeInfo {
        name: name.to_string(),
        size,
        fields: HashMap::new(),
        pointer_size: 8,
    };
    store.inject_module_for_test(kernel, vec![layout("_PEB", 2008)], &[]);
    store.inject_module_for_test(ntdll32, vec![layout("_PEB", 1168)], &[]);
    for (name, guid, module_dtb, base) in [
        ("ntoskrnl.exe", kernel, kernel_dtb, 0xffff_f800_0000_0000),
        ("ntdll.dll", ntdll32, dtb, 0x7773_0000),
    ] {
        let mut module = ModuleInfo::new(name.to_string(), VirtAddr(base), 0x1000);
        if guid == ntdll32 {
            module.short_name.push_str("32");
        }
        store.modules.insert(
            (module_dtb, base),
            LoadedModule {
                name: module.name,
                short_name: module.short_name,
                guid,
                base_address: VirtAddr(base),
                size: 0x1000,
                dtb: module_dtb,
            },
        );
    }
    store.set_kernel(Some(kernel), kernel_dtb);

    let size = |name: &str| store.find_type_across_modules(dtb, name).map(|t| t.size);
    assert_eq!(size("_PEB"), Some(2008));
    assert_eq!(size("nt!_PEB"), Some(2008));
    assert_eq!(size("ntdll32!_PEB"), Some(1168));
    assert_eq!(size("ntdll!_PEB"), None);
}

#[test]
fn nested_types_name_the_module_that_defines_them() {
    let store = SymbolStore::new();
    let (kernel_dtb, user_dtb) = (0x2000, 0x1000);
    let (kernel, balloon, viorng, ntdll32) = (0x22, 0x44, 0x45, 0x55);
    let layout = |name: &str, size| TypeInfo {
        name: name.to_string(),
        size,
        fields: HashMap::new(),
        pointer_size: 8,
    };
    store.set_kernel(Some(kernel), kernel_dtb);
    store.register_module_for_test(balloon, "balloon", kernel_dtb);
    store.register_module_for_test(viorng, "viorng", kernel_dtb);
    store.register_module_for_test(ntdll32, "ntdll32", user_dtb);
    store.pdb_pointer_sizes.insert(ntdll32, 4);
    store.inject_module_for_test(balloon, vec![layout("DEVICE_CONTEXT", 0x40)], &[]);
    store.inject_module_for_test(viorng, vec![layout("DEVICE_CONTEXT", 0x20)], &[]);
    store.struct_defs.insert(
        balloon,
        HashMap::from([(
            "DEVICE_CONTEXT".to_string(),
            (0x40, pdb2::TypeIndex(0x1000)),
        )]),
    );
    store.index_enums.insert(
        balloon,
        SymbolIndex::from_names(vec!["BALLOON_STATE".to_string()]),
    );

    // A driver qualifies what its PDB defines; a forward reference resolves
    // in the kernel's.
    let driver = store.nested_type_prefix(balloon);
    let context = driver.aggregate(&store, "DEVICE_CONTEXT", Some(0x1000));
    assert_eq!(context, "balloon!DEVICE_CONTEXT");
    assert_eq!(driver.aggregate(&store, "_EPROCESS", None), "_EPROCESS");
    assert_eq!(
        driver.enumeration(&store, "BALLOON_STATE"),
        "balloon!BALLOON_STATE"
    );
    assert_eq!(driver.enumeration(&store, "_POOL_TYPE"), "_POOL_TYPE");
    assert_eq!(
        driver.aggregate(&store, "<unnamed-tag>", Some(0x1124)),
        "balloon!<unnamed-tag>#1124"
    );
    // The name resolves to the defining driver's layout, not another's.
    let size = |name: &str| {
        store
            .find_type_across_modules(kernel_dtb, name)
            .map(|t| t.size)
    };
    assert_eq!(size(&context), Some(0x40));

    let nt = store.nested_type_prefix(kernel);
    assert_eq!(nt.aggregate(&store, "_KPRCB", Some(0x10)), "_KPRCB");
    assert_eq!(
        nt.aggregate(&store, "<unnamed-tag>", Some(0x10)),
        "nt!<unnamed-tag>#10"
    );
    // A 32-bit module qualifies every named type, defined here or not.
    let wow = store.nested_type_prefix(ntdll32);
    assert_eq!(
        wow.aggregate(&store, "_LIST_ENTRY", None),
        "ntdll32!_LIST_ENTRY"
    );
}

#[test]
fn x86_public_names_lose_their_calling_convention_decoration() {
    assert_eq!(undecorate_x86("_RtlAllocateHeap@12"), "RtlAllocateHeap");
    assert_eq!(undecorate_x86("_RtlpLFHKey"), "RtlpLFHKey");
    assert_eq!(undecorate_x86("@RtlpFastCall@8"), "RtlpFastCall");
    assert_eq!(undecorate_x86("_wcslen"), "wcslen");
    assert_eq!(
        undecorate_x86("??_C@_0BA@HKDEHBAO@RtlAllocateHeap@"),
        "??_C@_0BA@HKDEHBAO@RtlAllocateHeap@"
    );
}

#[test]
fn merged_indexes_cover_the_selected_address_space_only() {
    let store = SymbolStore::new();
    let kernel_dtb = 0x2000;
    let selected_dtb = 0x1000;
    let other_dtb = 0x3000;
    let register = |name: &str, guid: u128, dtb, base: u64, symbol: &str, type_name: &str| {
        store.modules.insert(
            (dtb, base),
            LoadedModule {
                name: name.to_string(),
                short_name: ModuleInfo::derive_short_name(name),
                guid,
                base_address: VirtAddr(base),
                size: 0x1000,
                dtb,
            },
        );
        store
            .index
            .insert(guid, SymbolIndex::from_names(vec![symbol.to_string()]));
        store
            .index_types
            .insert(guid, SymbolIndex::from_names(vec![type_name.to_string()]));
    };
    register(
        "ntoskrnl.exe",
        0x22,
        kernel_dtb,
        0xffff_f800_0000_0000,
        "KeBugCheckEx",
        "_EPROCESS",
    );
    register(
        "user32.dll",
        0x33,
        selected_dtb,
        0x7ff0_0000_0000,
        "PostQuitMessage",
        "_WND",
    );
    register(
        "notepad.exe",
        0x44,
        other_dtb,
        0x7ff1_0000_0000,
        "WinMain",
        "_NOTEPAD",
    );
    store.set_kernel(Some(0x22), kernel_dtb);

    let symbols = store.merged_symbol_index(Some(selected_dtb));
    assert_eq!(
        symbols.names,
        vec![
            "nt!KeBugCheckEx".to_string(),
            "user32!PostQuitMessage".to_string()
        ]
    );
    assert_eq!(
        symbols.search("PostQuit", 10),
        vec!["user32!PostQuitMessage".to_string()]
    );

    let types = store.merged_types_index(Some(selected_dtb));
    assert_eq!(
        types.names,
        vec!["_EPROCESS".to_string(), "_WND".to_string()]
    );
}

#[test]
fn secure_roots_do_not_resolve_nt_symbols_at_colliding_addresses() {
    let store = SymbolStore::new();
    let base = VirtAddr(0xffff_f800_0000_0000);
    for (guid, dtb, name, symbol) in [
        (1, 0x1000, "nt", "NtOnly"),
        (2, 0x2000, "securekernel", "SkOnly"),
    ] {
        store.inject_module_for_test(guid, vec![], &[(symbol, 0x100)]);
        store.modules.insert(
            (dtb, base.0),
            LoadedModule {
                name: name.to_string(),
                short_name: name.to_string(),
                guid,
                base_address: base,
                size: 0x1000,
                dtb,
            },
        );
    }
    store.set_kernel(Some(1), 0x1000);
    store.set_secure_roots(0x2000, [0x3000]);
    assert_eq!(
        store
            .find_module_for_address(0x4000, base)
            .unwrap()
            .short_name,
        "nt"
    );
    assert_eq!(
        store
            .find_module_for_address(0x3000, base)
            .unwrap()
            .short_name,
        "securekernel"
    );
    assert!(
        store
            .find_symbol_across_modules(0x3000, "nt!NtOnly")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .find_symbol_across_modules(0x3000, "securekernel!SkOnly")
            .unwrap(),
        Some(base + 0x100u64)
    );
    assert!(
        store
            .find_symbol_across_modules(0x4000, "securekernel!SkOnly")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.find_closest_symbol_for_address(0x3000, base + 0x108u64),
        Some(("securekernel".into(), "SkOnly".into(), 8))
    );
    // Selecting system scope must not reclassify a saved trustlet selection
    // as NT; rebuilding the guest must discard that old classification.
    store.set_secure_roots(0x2000, []);
    assert!(
        store
            .find_symbol_across_modules(0x3000, "nt!NtOnly")
            .unwrap()
            .is_none()
    );
    store.set_kernel(Some(1), 0x1000);
    assert_eq!(
        store
            .find_symbol_across_modules(0x3000, "nt!NtOnly")
            .unwrap(),
        Some(base + 0x100u64)
    );
}

#[test]
fn qualified_index_search_matches_bare_names_unless_query_names_a_module() {
    let index = SymbolIndex::from_names(vec![
        "nt!KeBugCheckEx".to_string(),
        "nt!memcpy".to_string(),
        "ntdll!memcpy".to_string(),
    ]);
    assert_eq!(index.search("Ke*", 10), vec!["nt!KeBugCheckEx"]);
    assert_eq!(
        index.search("memcpy", 10),
        vec!["nt!memcpy", "ntdll!memcpy"]
    );
    assert_eq!(index.search("ntdll!*", 10), vec!["ntdll!memcpy"]);
    assert!(index.search("nt!*", 10).contains(&"nt!memcpy".to_string()));
    assert!(
        !index
            .search("nt!*", 10)
            .contains(&"ntdll!memcpy".to_string())
    );
}

#[test]
fn prefix_search_ranks_and_substring_search_falls_back() {
    let index = SymbolIndex::from_names(vec![
        "nt!PostQuitMessage".to_string(),
        "nt!PostThreadMessage".to_string(),
        "nt!XPostQuitMessage".to_string(),
    ]);

    assert_eq!(
        index.search("Post", 1),
        vec!["nt!PostQuitMessage".to_string()]
    );
    assert_eq!(
        index.search("Quit", 10),
        vec![
            "nt!PostQuitMessage".to_string(),
            "nt!XPostQuitMessage".to_string()
        ]
    );
}

#[test]
fn a_bare_module_qualifier_lists_that_module() {
    let index = SymbolIndex::from_names(vec![
        "nt!KeBugCheckEx".to_string(),
        "nt!memcpy".to_string(),
        "ntdll!memcpy".to_string(),
    ]);

    let hits = index.search("nt!", 10);
    assert_eq!(
        hits[..2],
        ["nt!KeBugCheckEx".to_string(), "nt!memcpy".to_string()]
    );
}
