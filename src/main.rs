// On MSVC, link.exe prints "Creating library ..." for a target that exports
// symbols, which this one does through mimalloc's C objects; rustc reports
// that as `linker_messages`. The line says nothing about the build.
#![allow(linker_messages)]

/// Indexing PDBs allocates and frees millions of small blocks from many
/// threads at once, which glibc's allocator serves slowly.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    ntoseye::hosts::cli::main();
}
