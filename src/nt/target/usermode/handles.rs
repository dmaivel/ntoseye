//! `!handle` on a user-mode minidump: the handles its `HandleDataStream`
//! records. The stream holds what `NtQueryObject` reported when the dump
//! was written (type, name, access, attributes, counts), not the objects;
//! nothing here reads or names an object's address.

use crate::base::error::{Error, Result};
use crate::nt::target::Target;
use crate::nt::userdump::UserHandle;

/// Handle attribute bits (`OBJ_*`) as `NtQueryObject` reports them.
const HANDLE_ATTRIBUTES: [(u32, &str); 5] = [
    (0x01, "OBJ_PROTECT_CLOSE"),
    (0x02, "OBJ_INHERIT"),
    (0x04, "OBJ_AUDIT_OBJECT_CLOSE"),
    (0x10, "OBJ_PERMANENT"),
    (0x20, "OBJ_EXCLUSIVE"),
];

/// The names of `attributes`' bits, with any bit Windows does not define
/// kept as its value.
pub fn handle_attribute_names(attributes: u32) -> Vec<String> {
    let mut names: Vec<String> = HANDLE_ATTRIBUTES
        .iter()
        .filter(|(bit, _)| attributes & bit != 0)
        .map(|(_, name)| (*name).to_string())
        .collect();
    let known = HANDLE_ATTRIBUTES
        .iter()
        .fold(0, |mask, (bit, _)| mask | bit);
    if attributes & !known != 0 {
        names.push(format!("{:#x}", attributes & !known));
    }
    names
}

/// The type a handle's stream entry names, or `-` when it names none.
pub fn handle_type_label(handle: &UserHandle) -> &str {
    handle.type_name.as_deref().unwrap_or("-")
}

/// Handles per type, most numerous first.
pub fn handle_type_counts<'a>(
    handles: impl IntoIterator<Item = &'a UserHandle>,
) -> Vec<(String, usize)> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for handle in handles {
        let label = handle_type_label(handle);
        match counts.iter_mut().find(|(name, _)| name == label) {
            Some((_, count)) => *count += 1,
            None => counts.push((label.to_string(), 1)),
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    counts
}

impl Target {
    /// The handles a user-mode minidump records. Fails, naming the missing
    /// stream, when the dump has no handle data.
    pub fn user_handles(&self) -> Result<&[UserHandle]> {
        let info = self
            .user_dump_info()
            .ok_or_else(|| Error::DebugInfo("this target is not a user-mode minidump".into()))?;
        info.handles.as_deref().ok_or_else(|| {
            Error::DebugInfo("the minidump records no handle data (HandleDataStream)".into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(handle: u64, type_name: Option<&str>) -> UserHandle {
        UserHandle {
            handle,
            type_name: type_name.map(str::to_string),
            object_name: None,
            attributes: 0,
            granted_access: 0,
            handle_count: 1,
            pointer_count: 1,
        }
    }

    #[test]
    fn attribute_bits_are_named_and_undefined_ones_kept() {
        assert!(handle_attribute_names(0).is_empty());
        assert_eq!(
            handle_attribute_names(0x03),
            ["OBJ_PROTECT_CLOSE", "OBJ_INHERIT"]
        );
        assert_eq!(handle_attribute_names(0x142), ["OBJ_INHERIT", "0x140"]);
    }

    #[test]
    fn types_are_counted_most_numerous_first_with_untyped_handles_grouped() {
        let handles = [
            handle(4, Some("Event")),
            handle(8, Some("File")),
            handle(0xc, Some("Event")),
            handle(0x10, None),
            handle(0x14, Some("ALPC Port")),
            handle(0x18, None),
        ];
        assert_eq!(
            handle_type_counts(&handles),
            [
                ("-".to_string(), 2),
                ("Event".to_string(), 2),
                ("ALPC Port".to_string(), 1),
                ("File".to_string(), 1),
            ]
        );
    }
}
