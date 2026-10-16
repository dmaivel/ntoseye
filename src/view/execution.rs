//! The evaluated-expression record (`?`).

use ntoseye_macros::record;

use crate::types::VirtAddr;

/// An evaluated debugger expression (`?`).
#[record]
pub struct ExpressionValue {
    pub expression: String,
    pub value: VirtAddr,
}
