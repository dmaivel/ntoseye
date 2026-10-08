//! What the debugger tells the operator beside a command's output: a status
//! line, such as a background symbol fetch finishing, or a warning that
//! something did not work as it should. Core code queues notices and each
//! host shows them its own way at its next output boundary.

use std::fmt;

/// How much a notice matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NoticeLevel {
    /// Status: something happened that the operator may want to know.
    Info,
    /// Something did not work, or works less well than it should.
    Warning,
}

impl NoticeLevel {
    /// The level's name in structured output and the SDK.
    pub fn name(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Notice {
    pub level: NoticeLevel,
    pub text: String,
}

impl Notice {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            level: NoticeLevel::Info,
            text: text.into(),
        }
    }

    pub fn warning(text: impl Into<String>) -> Self {
        Self {
            level: NoticeLevel::Warning,
            text: text.into(),
        }
    }
}

impl fmt::Display for Notice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}
