//! Same-origin UI for owned account processes. No arbitrary-host forwarding,
//! redirects, ambient proxies/cookies or credential persistence in the parent.
use crate::{daemon::AppState, ui::ApiError};
use axum::{
    body::{to_bytes, Body},
    extract::{Path, Request, State},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
};
use std::{sync::Arc, time::Duration};
const MAX_BODY: usize = 2 * 1024 * 1024;
pub fn client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(30))
        .build()
}
fn allowed(method: &Method, path: &str) -> bool {
    if path.contains(['?', '#', '%', '\\']) || path.contains("..") || path.len() > 256 {
        return false;
    }
    match method.as_str() {
        "GET" => matches!(
            path,
            "state"
                | "account"
                | "config"
                | "settings"
                | "diagnostics"
                | "peers"
                | "server/admission"
                | "server/blacklist"
                | "server/max-clients"
                | "server/pending"
                | "tunnel/status"
                | "tunnel/clients"
        ),
        "POST" => {
            matches!(
                path,
                "auth/start"
                    | "auth/verify"
                    | "auth/signup"
                    | "connect"
                    | "disconnect"
                    | "logout"
                    | "settings"
                    | "config"
                    | "tunnel/config"
                    | "tunnel/disconnect"
                    | "client/auto-reconnect"
                    | "peers/refresh"
                    | "contacts/search"
                    | "server/call-privacy"
                    | "server/max-clients"
                    | "server/admission"
                    | "server/blacklist"
            ) || dynamic(path, "server/pending/", &["/accept", "/reject"])
                || dynamic(path, "tunnel/clients/", &["/disconnect"])
        }
        "DELETE" => {
            dynamic(path, "server/admission/", &[""]) || dynamic(path, "server/blacklist/", &[""])
        }
        _ => false,
    }
}
fn dynamic(path: &str, prefix: &str, suffixes: &[&str]) -> bool {
    let Some(tail) = path.strip_prefix(prefix) else {
        return false;
    };
    suffixes.iter().any(|suffix| {
        tail.strip_suffix(suffix).is_some_and(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-:".contains(&b))
        })
    })
}
async fn owned_endpoint(state: &AppState, slot: usize) -> Result<String, ApiError> {
    let (port, pid) = state
        .aggregate
        .workers
        .endpoint(slot)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let base = format!("http://127.0.0.1:{port}");
    let response = state
        .profile_http
        .get(format!("{base}/instance"))
        .send()
        .await
        .map_err(|_| ApiError::Internal("Account profile is unavailable".into()))?;
    let bytes = bounded(response, 1024).await?;
    let instance: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::Internal("Account process identity check failed".into()))?;
    if instance["pid"].as_u64() != Some(pid as u64) {
        return Err(ApiError::Internal(
            "Account process identity check failed".into(),
        ));
    }
    Ok(base)
}
async fn bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, ApiError> {
    let mut output = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ApiError::Internal("Account profile response was interrupted".into()))?
    {
        if output.len().saturating_add(chunk.len()) > limit {
            return Err(ApiError::Internal(
                "Account profile response is too large".into(),
            ));
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}
pub async fn view(
    State(state): State<Arc<AppState>>,
    Path(slot): Path<usize>,
) -> Result<Response, ApiError> {
    owned_endpoint(&state, slot).await?;
    Ok(([(header::CONTENT_TYPE,"text/html; charset=utf-8"),(header::X_FRAME_OPTIONS,"SAMEORIGIN"),(header::CONTENT_SECURITY_POLICY,"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'")],crate::ui::INDEX_HTML).into_response())
}
pub async fn forward(
    State(state): State<Arc<AppState>>,
    Path((slot, path)): Path<(usize, String)>,
    request: Request,
) -> Result<Response, ApiError> {
    let method = request.method().clone();
    if !allowed(&method, &path) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let base = owned_endpoint(&state, slot).await?;
    let body = to_bytes(request.into_body(), MAX_BODY)
        .await
        .map_err(|_| ApiError::Internal("Account request is too large".into()))?;
    let response = state
        .profile_http
        .request(method, format!("{base}/{path}"))
        .header("Origin", &base)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| ApiError::Internal("Account profile is unavailable".into()))?;
    let status = response.status();
    if !response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"))
    {
        return Err(ApiError::Internal("Account request was rejected".into()));
    }
    let body = bounded(response, MAX_BODY).await?;
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_forwarding_is_an_explicit_method_and_path_allowlist() {
        for path in ["state", "settings", "peers", "diagnostics"] {
            assert!(allowed(&Method::GET, path));
        }
        for path in [
            "auth/start",
            "auth/verify",
            "tunnel/config",
            "server/pending/123/accept",
        ] {
            assert!(allowed(&Method::POST, path));
        }
        for path in [
            "shutdown",
            "instance",
            "aggregate/worker",
            "aggregate/start",
            "../state",
            "auth/%2fstart",
            "http://evil.test/state",
            "server/pending/../accept",
            "server/pending/123/accept/extra",
        ] {
            assert!(!allowed(&Method::POST, path), "{path}");
        }
        assert!(!allowed(&Method::GET, "auth/start"));
        assert!(!allowed(&Method::PUT, "settings"));
    }
}
