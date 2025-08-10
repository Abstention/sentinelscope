use pyo3::prelude::*;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use futures::stream::{FuturesUnordered, StreamExt};

#[pyfunction]
fn scan_ports(py: Python<'_>, host: String, ports: Vec<u16>, timeout_ms: u64, concurrency: usize) -> PyResult<Vec<(u16, bool)>> {
    pyo3_asyncio::tokio::run(py, async move {
        let sem = tokio::sync::Semaphore::new(concurrency);
        let mut tasks = FuturesUnordered::new();

        for port in ports {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let h = host.clone();
            tasks.push(async move {
                let res = timeout(Duration::from_millis(timeout_ms), TcpStream::connect((h.as_str(), port))).await;
                drop(permit);
                match res {
                    Ok(Ok(_stream)) => (port, true),
                    _ => (port, false),
                }
            });
        }

        let mut out: Vec<(u16, bool)> = Vec::new();
        while let Some(r) = tasks.next().await {
            out.push(r);
        }
        Ok(out)
    })
}

#[pymodule]
fn sentinelscope_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_ports, m)?)?;
    Ok(())
}

