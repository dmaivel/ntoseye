use pyo3::prelude::*;

#[pymodule]
fn _ntoseye(m: &Bound<'_, PyModule>) -> PyResult<()> {
    ntoseye_core::python::register_module(m)
}
