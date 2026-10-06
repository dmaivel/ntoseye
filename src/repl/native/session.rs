//! The card a session opens with: which Windows the target runs and where
//! its kernel is.

use tern_sdk::View;
use tern_sdk::ui::{self, Tone};

use super::{MUTED, NUMBER, STRONG, addr, span};

/// What the session found of the target's kernel.
pub struct Target {
    /// `NtBuildNumber`, when the kernel was found.
    pub build: Option<u16>,
    pub base: Option<u64>,
    /// `PsLoadedModuleList`; zero when unavailable.
    pub modules: Option<u64>,
}

pub fn target_card(target: &Target) -> View {
    let head = match target.build {
        Some(build) => vec![span("Windows", STRONG), span(format!(" {build}"), NUMBER)],
        None => vec![span("target", STRONG)],
    };
    let base = match target.base {
        Some(base) => vec![addr(base)],
        None => vec![span("unknown (ntoskrnl not found in dump)", MUTED)],
    };
    let mut details = ui::kv().item("kernel base", base);
    if let Some(modules) = target.modules {
        details = details.item(
            "module list",
            if modules == 0 {
                span("unavailable", MUTED)
            } else {
                addr(modules)
            },
        );
    }
    View::new().main([ui::card()
        .head(head)
        .tone(Tone::Neutral)
        .role("ntoseye.target")
        .child(details)])
}
