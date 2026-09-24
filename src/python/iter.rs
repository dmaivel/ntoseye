//! Typed iterators for the SDK's collections. A collection's `__iter__`
//! walks a fresh snapshot; iterating through one of these (rather than a
//! plain list iterator) lets the generated stubs give `for p in
//! dbg.processes` its element type.

use pyo3::exceptions::PyStopIteration;
use pyo3::prelude::*;

use super::breakpoints::Breakpoint;
use super::memory::MemoryRegion;
use super::module::{Driver, Module};
use super::process::{Heap, Process};
use super::record::Record;
use super::thread::{Cpu, Thread};

macro_rules! typed_iterator {
    ($(#[$doc:meta])* $name:ident($item:ty)) => {
        $(#[$doc])*
        #[pyclass(module = "ntoseye")]
        pub struct $name(std::vec::IntoIter<$item>);

        impl $name {
            pub fn new(items: Vec<$item>) -> Self {
                $name(items.into_iter())
            }
        }

        #[pymethods]
        impl $name {
            fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
                slf
            }

            // `PyResult<T>` rather than `Option<T>`: the stub then types
            // the element as `T`, not `T | None`.
            fn __next__(&mut self) -> PyResult<$item> {
                self.0.next().ok_or_else(|| PyStopIteration::new_err(()))
            }
        }
    };
}

typed_iterator! {
    /// Iterator over `dbg.processes`.
    ProcessIterator(Process)
}
typed_iterator! {
    /// Iterator over `dbg.threads` / `proc.threads`.
    ThreadIterator(Py<Thread>)
}
typed_iterator! {
    /// Iterator over `dbg.modules` / `proc.modules`.
    ModuleIterator(Module)
}
typed_iterator! {
    /// Iterator over `dbg.drivers`.
    DriverIterator(Driver)
}
typed_iterator! {
    /// Iterator over `dbg.cpus`.
    CpuIterator(Py<Cpu>)
}
typed_iterator! {
    /// Iterator over `dbg.breakpoints`.
    BreakpointIterator(Py<Breakpoint>)
}
typed_iterator! {
    /// Iterator over `proc.regions`.
    MemoryRegionIterator(MemoryRegion)
}
typed_iterator! {
    /// Iterator over `proc.heaps`.
    HeapIterator(Heap)
}
typed_iterator! {
    /// Iterator over records, such as `dbg.exceptions`.
    RecordIterator(Py<Record>)
}
typed_iterator! {
    /// Iterator over names: a record's fields, a register file's registers.
    NameIterator(String)
}
