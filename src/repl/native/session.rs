//! The card a session opens with: which Windows the target runs and where
//! its kernel is, or, for a user-mode minidump, which process it captured.

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

/// What a user-mode minidump captured, as the session opens with it.
pub struct UserDump {
    /// `charmap.exe (pid 1234)`.
    pub process: String,
    /// `Windows 10.0.26100 AMD64`, with the build string when recorded.
    pub system: String,
    /// When the dump was written (`MINIDUMP_HEADER.TimeDateStamp`).
    pub written: Option<String>,
    pub threads: usize,
    pub modules: usize,
    /// Captured memory: how many ranges, how many bytes.
    pub memory: String,
    /// The exception the dump was written for, described.
    pub exception: Option<String>,
}

pub fn user_dump_card(dump: &UserDump) -> View {
    let mut details = ui::kv()
        .item("system", vec![span(dump.system.clone(), "")])
        .item("threads", vec![span(dump.threads.to_string(), NUMBER)])
        .item("modules", vec![span(dump.modules.to_string(), NUMBER)])
        .item("memory", vec![span(dump.memory.clone(), "")]);
    if let Some(written) = &dump.written {
        details = details.item("written", vec![span(written.clone(), MUTED)]);
    }
    if let Some(exception) = &dump.exception {
        details = details.item("exception", vec![span(exception.clone(), "")]);
    }
    View::new().main([ui::card()
        .head(vec![span(dump.process.clone(), STRONG)])
        .tone(Tone::Neutral)
        .role("ntoseye.target")
        .child(details)])
}
