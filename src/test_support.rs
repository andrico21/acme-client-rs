//! Shared `#[cfg(test)]` fixtures.
//!
//! An inline HTTP/1.1 mock server, used by any test that needs a live endpoint
//! to point an [`crate::client::AcmeClient`] at. Extracted here so the ACME
//! protocol tests and the renewal-decision tests drive the same implementation
//! instead of maintaining two.

use anyhow::{Context, Result, anyhow, bail};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub(crate) struct CapturedRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) body: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct Route {
    pub(crate) method: &'static str,
    pub(crate) path_prefix: &'static str,
    pub(crate) status_line: &'static str,
    pub(crate) extra_headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

fn build_response(route: &Route, nonce: &str) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut headers = String::new();
    headers.push_str(route.status_line);
    headers.push_str("\r\n");
    let _ = writeln!(headers, "Replay-Nonce: {nonce}\r");
    headers.push_str("connection: close\r\n");
    for (k, v) in &route.extra_headers {
        let _ = writeln!(headers, "{k}: {v}\r");
    }
    let _ = writeln!(headers, "content-length: {}\r", route.body.len());
    headers.push_str("\r\n");
    let mut out = headers.into_bytes();
    out.extend_from_slice(&route.body);
    out
}

/// Serve `routes` on `listener`, matching by method + path-prefix.
///
/// Returns the shared capture log so a test can assert on what was requested.
pub(crate) fn spawn_mock(
    listener: TcpListener,
    routes: Vec<Route>,
) -> Arc<Mutex<Vec<CapturedRequest>>> {
    let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = Arc::clone(&captured);
    let routes = Arc::new(routes);
    let nonce_counter = Arc::new(Mutex::new(0u64));

    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let captured = Arc::clone(&captured_clone);
            let routes = Arc::clone(&routes);
            let nonce_counter = Arc::clone(&nonce_counter);
            tokio::spawn(async move {
                // Fire-and-forget: any I/O failure simply drops the
                // connection. The test will fail loudly via missing
                // captured requests if the mock can't talk.
                let _ = handle_connection(socket, &captured, &routes, &nonce_counter).await;
            });
        }
    });

    captured
}

// NOT cancel-safe: runs in a detached task that the runtime drops at test
// teardown, and a cancellation between recording the request and writing
// the response leaves the peer without a reply. Harmless here — the mock
// owns no state beyond the capture log, and an abandoned connection can
// only make an already-finished test's assertions fail loudly.
async fn handle_connection(
    mut socket: tokio::net::TcpStream,
    captured: &Mutex<Vec<CapturedRequest>>,
    routes: &[Route],
    nonce_counter: &Mutex<u64>,
) -> Result<()> {
    // Read until we have full headers (\r\n\r\n), then body by Content-Length.
    let mut buf = Vec::with_capacity(4096);
    let header_end = loop {
        let mut chunk = [0u8; 1024];
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            bail!("client closed before headers");
        }
        buf.extend_from_slice(chunk.get(..n).ok_or_else(|| anyhow!("range"))?);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            bail!("headers too large");
        }
    };

    let header_slice = buf
        .get(..header_end.saturating_sub(4))
        .ok_or_else(|| anyhow!("header range"))?;
    let header_text = std::str::from_utf8(header_slice).context("headers not UTF-8")?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| anyhow!("no request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let path = parts.next().unwrap_or("").to_owned();

    let mut content_length: usize = 0;
    for line in lines {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    let body_slice = buf.get(header_end..).ok_or_else(|| anyhow!("body range"))?;
    let mut body = body_slice.to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 4096];
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(chunk.get(..n).ok_or_else(|| anyhow!("range"))?);
    }
    body.truncate(content_length);

    {
        let mut lock = captured.lock().map_err(|_| anyhow!("poisoned"))?;
        lock.push(CapturedRequest {
            method: method.clone(),
            path: path.clone(),
            body: body.clone(),
        });
    }

    let route = routes
        .iter()
        .find(|r| r.method.eq_ignore_ascii_case(&method) && path.starts_with(r.path_prefix));
    let response = match route {
        Some(r) => {
            let counter_value = {
                let mut ctr = nonce_counter.lock().map_err(|_| anyhow!("poisoned"))?;
                *ctr += 1;
                *ctr
            };
            let nonce = format!("nonce-{counter_value:08}");
            build_response(r, &nonce)
        }
        None => {
            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec()
        }
    };
    socket.write_all(&response).await?;
    socket.shutdown().await?;
    Ok(())
}

pub(crate) fn collect_captured(
    captured: &Mutex<Vec<CapturedRequest>>,
) -> Result<Vec<CapturedRequest>> {
    Ok(captured.lock().map_err(|_| anyhow!("poisoned"))?.clone())
}
