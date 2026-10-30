//! Readers of Rust syntax that several macros share.

use syn::{Error, GenericArgument, Ident, ItemImpl, PathArguments, Result, Type};

/// The name of the type that impl block `item` is for, which must be a
/// plain identifier (`Name`, not `a::Name`); `message` is the error
/// otherwise.
pub fn self_name(item: &ItemImpl, message: &str) -> Result<Ident> {
    match &*item.self_ty {
        Type::Path(path) if path.qself.is_none() && path.path.segments.len() == 1 => {
            Ok(path.path.segments[0].ident.clone())
        }
        other => Err(Error::new_spanned(other, message)),
    }
}

/// The last segment of path type `ty` and its first type argument: `Vec`
/// and `T` for `std::vec::Vec<T>`.
pub fn first_type_argument(ty: &Type) -> Option<(&Ident, &Type)> {
    let Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    arguments.args.iter().find_map(|argument| match argument {
        GenericArgument::Type(inner) => Some((&segment.ident, inner)),
        _ => None,
    })
}
