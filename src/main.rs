/// Indexing PDBs allocates and frees millions of small blocks from many
/// threads at once, which glibc's allocator serves slowly.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    ntoseye::hosts::cli::main();
}
