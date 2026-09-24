//! Loaded-module [`View`] builders: module identity and symbol
//! load status.

use super::View;
use crate::guest::{ModuleInfo, ModuleSymbolLoadReport};
use crate::symbols::ModuleSymbolStatus;
use crate::target::Target;
use crate::types::Dtb;

pub fn module(module: &ModuleInfo) -> View {
    let mut fields = vec![
        ("name", View::Str(module.name.clone())),
        ("short_name", View::Str(module.short_name.clone())),
        ("path", View::OptStr(module.path.clone())),
        ("base", View::Hex(module.base_address.0)),
        ("end", View::Hex(module.end_address().0)),
        ("size", View::Num(module.size.into())),
    ];
    if let Some(timestamp) = module.time_date_stamp {
        fields.push(("time_date_stamp", View::Hex(timestamp.into())));
    }
    if let Some(checksum) = module.checksum {
        fields.push(("checksum", View::Hex(checksum.into())));
    }
    if let Some(version) = &module.file_version {
        fields.push(("file_version", View::Str(version.clone())));
    }
    if let Some(version) = &module.product_version {
        fields.push(("product_version", View::Str(version.clone())));
    }
    View::Object(fields)
}

/// The outcome of a symbol reload: how many modules loaded, lacked a PDB,
/// were skipped, or failed, plus the first diagnostics (bounded).
pub fn module_symbol_report(report: &ModuleSymbolLoadReport) -> View {
    View::Object(vec![
        ("total", View::Num(report.total as u64)),
        ("loaded", View::Num(report.loaded as u64)),
        ("unloaded", View::Num(report.unloaded as u64)),
        ("no_pdb", View::Num(report.no_pdb as u64)),
        ("skipped", View::Num(report.skipped as u64)),
        ("failed", View::Num(report.failed as u64)),
        (
            "diagnostic_count",
            View::Num(report.diagnostic_count as u64),
        ),
        (
            "diagnostics",
            View::List(
                report
                    .diagnostics
                    .iter()
                    .map(|diagnostic| {
                        View::Object(vec![
                            ("module", View::Str(diagnostic.module.clone())),
                            ("phase", View::Str(diagnostic.phase.to_string())),
                            ("compiland", View::OptStr(diagnostic.compiland.clone())),
                            ("message", View::Str(diagnostic.message.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// A module's symbol status and PDB identity (`lmv`).
pub fn module_symbols(target: &Target, info: &ModuleInfo, dtb: Dtb) -> View {
    let status = target.symbols.module_symbol_status(dtb, info.base_address);
    let identity = target.symbols.module_pdb_identity(dtb, info.base_address);
    let source = target.symbols.module_symbol_source(dtb, info.base_address);
    let status_name = match (&status, &identity) {
        (Some(status), _) => status.label().to_string(),
        (None, Some(_)) => "loaded".to_string(),
        (None, None) => "unknown".to_string(),
    };
    let failed = match &status {
        Some(ModuleSymbolStatus::Failed(error)) => Some(error.clone()),
        _ => None,
    };
    View::Object(vec![
        ("status", View::Str(status_name)),
        (
            "source",
            View::OptStr(source.as_ref().map(|source| source.label().to_string())),
        ),
        (
            "pdb_guid",
            View::OptStr(
                identity
                    .as_ref()
                    .map(|identity| format!("{:032X}", identity.guid)),
            ),
        ),
        (
            "pdb_age",
            View::OptNum(identity.map(|identity| u64::from(identity.age))),
        ),
        ("error", View::OptStr(failed)),
    ])
}
