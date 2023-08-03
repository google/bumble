use bumble::wrapper::{self, core::Uuid16};
use pyo3::{intern, prelude::*, types::PyDict};
use std::collections;

#[pyo3_asyncio::tokio::test]
async fn company_ids_matches_python() -> PyResult<()> {
    let ids_from_python = Python::with_gil(|py| {
        PyModule::import(py, intern!(py, "bumble.company_ids"))?
            .getattr(intern!(py, "COMPANY_IDENTIFIERS"))?
            .downcast::<PyDict>()?
            .into_iter()
            .map(|(k, v)| {
                Ok((
                    Uuid16::from_be_bytes(k.extract::<u16>()?.to_be_bytes()),
                    v.str()?.to_str()?.to_string(),
                ))
            })
            .collect::<PyResult<collections::HashMap<_, _>>>()
    })?;

    assert_eq!(
        wrapper::assigned_numbers::COMPANY_IDS
            .iter()
            .map(|(id, name)| (*id, name.to_string()))
            .collect::<collections::HashMap<_, _>>(),
        ids_from_python,
        "Company ids do not match -- re-run gen_assigned_numbers?"
    );
    Ok(())
}
