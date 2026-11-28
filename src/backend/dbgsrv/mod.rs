mod backend;
mod client;
mod events;
mod layout;
mod service;
mod transport;
mod wire;

#[cfg(test)]
pub(crate) mod tests;

pub use self::backend::{DbgsrvBackend, DbgsrvTarget};
pub use client::{DbgsrvClient, DbgsrvUserMemory};
pub use transport::{DbgsrvEndpoint, parse_endpoint};
#[cfg(test)]
pub(crate) use wire::{Method, stub_index};
