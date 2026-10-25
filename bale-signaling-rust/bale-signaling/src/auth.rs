//! BaleAuth — the Bale-shaped sign-in flow. Doesn't fit a generic
//! trait (phone + OTP + conditional signup), so it lives
//! outside `lk_signaling::Signaling` and is consumed directly by
//! the app's auth UI.
//!
//! Ports `BaleAuthClient.kt` and the Node `http-server.js`
//! `/auth/*` endpoints into a single async API.
//!
//! Flow:
//! 1. `start_phone_auth(phone)` → server selects a code delivery channel, returns
//!    a `transaction_hash` and an `is_registered` flag.
//! 2. `submit_otp(tx, code)` → either
//!      - [`AuthOutcome::Authenticated { access_token }`] for known
//!        users, OR
//!      - [`AuthOutcome::NeedsSignupName`] for unknown users
//!        (covers both the legacy `PHONE_NUMBER_UNOCCUPIED` gRPC
//!        error and the new empty-JWT response shape Bale's API
//!        switched to in early 2026).
//! 3. `submit_signup_name(tx, name)` → completes signup, returns
//!    `Authenticated { access_token }`.
//!
//! After `Authenticated`, the caller persists the access token
//! through a `TokenStore` (managed by `BaleSignaling`).

use crate::grpc_web::{self, GrpcError};
use crate::proto::{ProtoError, ProtoReader, ProtoWriter};
use rand::RngCore;
use std::sync::Arc;
use std::time::{Duration, Instant};
use reqwest::cookie::{CookieStore, Jar};

pub const AUTH_HOST:     &str = "next-ws.bale.ai";
const AUTH_APP_ID:       i32  = 4;
const AUTH_API_KEY:      &str = "C28D46DC4C3A7A26564BFCC48B929086A95C93C98E789A19847BEE8627DE4E7D";
const SENDCODE_DEFAULT:  i32  = 1;
const DEFAULT_LANGUAGE:  &str = "fa";
const CLIENT_LABEL:      &str = "BaleVPN";

/// Outcome of `start_phone_auth`.
#[derive(Debug, Clone)]
pub struct StartResult {
    pub transaction_hash: String,
    pub is_registered:    bool,
    /// Bale's AuthSendCodeType: 2 = Bale, 3 = SMS, 9/12 = Telegram.
    pub sent_code_type: i32,
    pub next_send_code_wait_time: Option<u64>,
}

/// Outcome of `submit_otp` / `submit_signup_name`.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    /// Caller is signed in. The `access_token` is the cookie value
    /// to persist + send on the WS upgrade.
    Authenticated { access_token: String },

    /// Unknown phone. The caller should collect a display name and
    /// hand it back via `submit_signup_name(transaction_hash, name)`.
    /// Carries the same `transaction_hash` that started this flow.
    NeedsSignupName { transaction_hash: String },
}

#[derive(Debug)]
pub enum AuthError {
    Grpc(GrpcError),
    Proto(ProtoError),
    /// Server returned 2xx but the response shape didn't include
    /// a JWT and we couldn't classify it as `NeedsSignupName`.
    Malformed(&'static str),
    InvalidPhone,
    Http(reqwest::Error),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Grpc(e)              => write!(f, "auth gRPC: {e}"),
            Self::Proto(e)             => write!(f, "auth proto: {e}"),
            Self::Malformed(s)         => write!(f, "auth malformed: {s}"),
            Self::InvalidPhone         => f.write_str("Enter a valid international phone number, including country code (for example +98912...)."),
            Self::Http(e)              => write!(f, "auth HTTP: {e}"),
        }
    }
}
impl std::error::Error for AuthError {}

impl From<GrpcError>     for AuthError { fn from(e: GrpcError)     -> Self { Self::Grpc(e) } }
impl From<ProtoError>    for AuthError { fn from(e: ProtoError)    -> Self { Self::Proto(e) } }
impl From<reqwest::Error> for AuthError { fn from(e: reqwest::Error) -> Self { Self::Http(e) } }

/// Bale auth client. Holds a `reqwest::Client` and runs the three
/// auth RPCs against `next-ws.bale.ai`. The shared `jar` captures
/// HttpOnly cookies from the auth RPC responses, just as the web
/// client's `credentials: "include"` transport does.
pub struct BaleAuth {
    http: reqwest::Client,
    jar:  Arc<Jar>,
    endpoint: String,
    device_hash: Vec<u8>,
    device_label: String,
    device_override:std::sync::Mutex<Option<(Vec<u8>,String)>>,
    // Serialize auth attempts and retain one successful result briefly so a
    // repeated Verify click cannot consume the same one-time code twice.
    completed: tokio::sync::Mutex<Option<(String, String, Instant)>>,
    login_phone: std::sync::Mutex<Option<(String, String)>>,
}

impl BaleAuth {
    pub fn new() -> Self {
        let jar = Arc::new(Jar::default());
        Self::with_client(grpc_web::build_client_with_jar(jar.clone()), jar)
    }

    /// Construct with a caller-supplied client. The caller is
    /// responsible for attaching the same `jar` as its
    /// `cookie_provider`, or the authentication RPCs won't
    /// capture the `access_token`.
    pub fn with_client(http: reqwest::Client, jar: Arc<Jar>) -> Self {
        // The web client sends the UTF-8 bytes of a UUID, reused on retries.
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let uuid = format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]);
        Self { http, jar, endpoint: format!("https://{AUTH_HOST}"), device_hash: uuid.into_bytes(), device_label: CLIENT_LABEL.into(), device_override:std::sync::Mutex::new(None), completed: tokio::sync::Mutex::new(None), login_phone: std::sync::Mutex::new(None) }
    }
    /// Reuse the account installation identity on restart and session import.
    /// This does not create or refresh a server session.
    pub fn for_device(hash: &str, label: &str) -> Result<Self, AuthError> {
        if hash.len()!=36 || !hash.bytes().enumerate().all(|(i,b)|if [8,13,18,23].contains(&i){b==b'-'}else{b.is_ascii_hexdigit()}) || label.is_empty() || label.len()>64 || label.chars().any(char::is_control) {return Err(AuthError::Malformed("Invalid device identity"));}
        let mut client=Self::new();client.device_hash=hash.as_bytes().to_vec();client.device_label=label.into();Ok(client)
    }
    pub fn use_device(&self,hash:&str,label:&str)->Result<(),AuthError>{
        if hash.len()!=36 || !hash.bytes().enumerate().all(|(i,b)|if [8,13,18,23].contains(&i){b==b'-'}else{b.is_ascii_hexdigit()}) || label.is_empty()||label.len()>64||label.chars().any(char::is_control){return Err(AuthError::Malformed("Invalid device identity"));}
        *self.device_override.lock().unwrap_or_else(|e|e.into_inner())=Some((hash.as_bytes().to_vec(),label.into()));Ok(())
    }

    /// Step 1: request a code using Bale's default delivery channel.
    /// Accepts international numbers and Iranian local mobile numbers.
    /// Returns the transaction hash to be threaded
    /// through `submit_otp` / `submit_signup_name`, and a hint
    /// whether the phone is already registered.
    pub async fn start_phone_auth(&self, phone: &str) -> Result<StartResult, AuthError> {
        let mut completed = self.completed.lock().await;
        *self.login_phone.lock().unwrap_or_else(|e|e.into_inner())=None;
        let normalized=normalize_phone(phone)?;
        let device=self.device_override.lock().unwrap_or_else(|e|e.into_inner()).clone();
        let(hash,label)=device.as_ref().map(|(h,l)|(h.as_slice(),l.as_str())).unwrap_or((&self.device_hash,&self.device_label));
        let payload = encode_start_phone_auth_named(normalized, hash, label);
        let resp = self.rpc("StartPhoneAuth", &payload).await?;
        let result = decode_start_phone_auth(&resp)?;
        *completed = None;
        *self.login_phone.lock().unwrap_or_else(|e|e.into_inner())=Some((result.transaction_hash.clone(),format!("+{normalized}")));
        Ok(result)
    }

    /// Only return the phone whose transaction actually authenticated. Never
    /// expose a pending phone or associate one account's number with another token.
    pub async fn verified_login_phone(&self, transaction: &str) -> Option<String> {
        let completed=self.completed.lock().await;
        if !completed.as_ref().is_some_and(|(hash,_,_)|hash==transaction) { return None; }
        self.login_phone.lock().unwrap_or_else(|e|e.into_inner()).as_ref()
            .filter(|(hash,_)|hash==transaction).map(|(_,phone)|phone.clone())
    }

    async fn rpc(&self, method: &str, payload: &[u8]) -> Result<Vec<u8>, GrpcError> {
        grpc_web::call_endpoint(&self.http,
            &format!("{}/bale.auth.v1.Auth/{method}", self.endpoint), payload, None).await
    }

    /// Step 2: submit the verification code. For unknown phones Bale used to
    /// return a `PHONE_NUMBER_UNOCCUPIED` gRPC error; current API
    /// behaviour is to succeed with an empty `jwt` field. Both
    /// shapes resolve to `AuthOutcome::NeedsSignupName`.
    pub async fn submit_otp(
        &self,
        transaction_hash: &str,
        code:             &str,
    ) -> Result<AuthOutcome, AuthError> {
        let mut completed = self.completed.lock().await;
        if let Some(outcome) = cached_auth(&completed, transaction_hash) { return Ok(outcome); }
        let previous_cookie = self.access_token_cookie();
        let is_jwt = ProtoWriter::new().bool_(1, true).build();
        let payload = ProtoWriter::new()
            .string(1, transaction_hash)
            .string(2, code)
            .bytes (3, &is_jwt)
            .build();

        let buf = match self.rpc("ValidateCode", &payload).await {
            Ok(b)  => b,
            Err(GrpcError::Status { code: _, message: Some(m) })
                    if m.contains("PHONE_NUMBER_UNOCCUPIED") => {
                return Ok(AuthOutcome::NeedsSignupName {
                    transaction_hash: transaction_hash.to_string(),
                });
            }
            Err(e) => return Err(e.into()),
        };

        match self.response_token(&buf, previous_cookie.as_deref())? {
            Some(token) => {
                *completed = Some((transaction_hash.to_owned(), token.clone(), Instant::now()));
                Ok(AuthOutcome::Authenticated { access_token: token })
            }
            None => Ok(AuthOutcome::NeedsSignupName {
                transaction_hash: transaction_hash.to_string(),
            }),
        }
    }

    /// Step 3 (signup branch only): submit a display name. Returns
    /// `Authenticated`.
    pub async fn submit_signup_name(
        &self,
        transaction_hash: &str,
        name:             &str,
    ) -> Result<AuthOutcome, AuthError> {
        let mut completed = self.completed.lock().await;
        if let Some(outcome) = cached_auth(&completed, transaction_hash) { return Ok(outcome); }
        let previous_cookie = self.access_token_cookie();
        let payload = ProtoWriter::new()
            .string(1, transaction_hash)
            .string(2, name)
            .build();

        let buf = self.rpc("SignUp", &payload).await?;

        match self.response_token(&buf, previous_cookie.as_deref())? {
            Some(token) => {
                *completed = Some((transaction_hash.to_owned(), token.clone(), Instant::now()));
                Ok(AuthOutcome::Authenticated { access_token: token })
            }
            None => Err(AuthError::Malformed("SignUp returned no authentication token")),
        }
    }

    /// Manual token refresh (paste-cookie path): accept an
    /// `access_token` cookie value that the user pulled from
    /// `web.bale.ai` in their browser. Stored as if it had come
    /// from a fresh sign-in.
    pub fn refresh_with_cookie(&self, _access_token: &str) {
        // Plain setter at the BaleSignaling level — BaleAuth itself
        // is stateless. The caller is expected to persist via the
        // `TokenStore` injected into `BaleSignaling`. Kept as a
        // method on `BaleAuth` so the API surface is symmetric
        // with the SMS flow.
    }

    /// Drop the short-lived verification result when the user logs out or
    /// replaces credentials, so an old transaction cannot restore that login.
    pub async fn clear_completed_auth(&self) {
        *self.completed.lock().await = None;
        *self.login_phone.lock().unwrap_or_else(|e|e.into_inner())=None;
    }

    // Authentication completes in the RPC itself. Never require an extra
    // /set-cookie/ GET: that endpoint can reject a valid login with HTTP 403
    // after its OTP has already been consumed. A newly issued HttpOnly cookie
    // takes precedence; otherwise the RPC's JWT is the native client's token.
    fn response_token(&self, body: &[u8], previous_cookie: Option<&str>) -> Result<Option<String>, AuthError> {
        let jwt = decode_auth_response_jwt(body)?;
        let cookie = self.access_token_cookie().filter(|c| Some(c.as_str()) != previous_cookie);
        Ok(cookie.or(jwt))
    }

    fn access_token_cookie(&self) -> Option<String> {
        format!("{}/ws/", self.endpoint).parse::<reqwest::Url>().ok().as_ref()
            .and_then(|u| self.jar.cookies(u))
            .and_then(|hv| hv.to_str().ok().and_then(extract_access_token_from_cookie_header))
    }
}

fn cached_auth(completed: &Option<(String, String, Instant)>, transaction_hash: &str) -> Option<AuthOutcome> {
    completed.as_ref().filter(|(tx, _, at)| tx == transaction_hash && at.elapsed() < Duration::from_secs(300))
        .map(|(_, token, _)| AuthOutcome::Authenticated { access_token: token.clone() })
}

impl Default for BaleAuth {
    fn default() -> Self { Self::new() }
}

// ─── Response decoders ──────────────────────────────────────────────────

fn decode_start_phone_auth(buf: &[u8]) -> Result<StartResult, AuthError> {
    let mut r = ProtoReader::new(buf);
    let mut hash       = String::new();
    let mut registered = false;
    let mut sent_code_type = 0;
    let mut next_send_code_wait_time = None;
    while r.has_more() {
        let (f, w) = r.tag()?;
        match f {
            1 if w == 2 => hash = r.string()?.to_string(),
            2 if w == 0 => registered = r.varint()? != 0,
            5 if w == 0 => sent_code_type = r.varint()? as i32,
            8 if w == 2 => {
                let mut wrapped = ProtoReader::new(r.bytes()?);
                let mut wait = 0;
                while wrapped.has_more() {
                    let (field, wire) = wrapped.tag()?;
                    if field == 1 && wire == 0 { wait = wrapped.varint()?; }
                    else { wrapped.skip(wire)?; }
                }
                // Reject negative int64 values encoded as unsigned varints.
                if wait <= i64::MAX as u64 { next_send_code_wait_time = Some(wait); }
            }
            _ => r.skip(w)?,
        }
    }
    if hash.trim().is_empty() {
        return Err(AuthError::Malformed("StartPhoneAuth returned no transaction hash; code delivery was not confirmed"));
    }
    Ok(StartResult { transaction_hash: hash, is_registered: registered, sent_code_type, next_send_code_wait_time })
}

#[cfg(test)]
fn encode_start_phone_auth(phone: i64, device_hash: &[u8]) -> Vec<u8> {
    encode_start_phone_auth_named(phone, device_hash, CLIENT_LABEL)
}
fn encode_start_phone_auth_named(phone: i64, device_hash: &[u8], label: &str) -> Vec<u8> {
    // Official web client: DEFAULT delivery lets Bale choose the channel;
    // packed field 10 advertises Telegram Gateway (0) and six-digit OTP (1).
    ProtoWriter::new().int64(1, phone).int32(2, AUTH_APP_ID)
        .string(3, AUTH_API_KEY).bytes(4, device_hash).string(5, label)
        .string(7, DEFAULT_LANGUAGE).int32(9, SENDCODE_DEFAULT)
        .bytes(10, &[0, 1]).build()
}

fn normalize_phone(phone: &str) -> Result<i64, AuthError> {
    let mut digits = String::new();
    for (index, c) in phone.trim().chars().enumerate() {
        match c {
            '0'..='9' => digits.push(c),
            '\u{06f0}'..='\u{06f9}' => digits.push(char::from(b'0' + (c as u32 - 0x06f0) as u8)),
            '\u{0660}'..='\u{0669}' => digits.push(char::from(b'0' + (c as u32 - 0x0660) as u8)),
            '+' if index == 0 => {},
            ' ' | '-' | '(' | ')' => {},
            _ => return Err(AuthError::InvalidPhone),
        }
    }
    if let Some(international) = digits.strip_prefix("00") { digits = international.to_string(); }
    // Accept the common Iranian local mobile format as well as E.164.
    if digits.len() == 11 && digits.starts_with("09") { digits = format!("98{}", &digits[1..]); }
    if !(7..=15).contains(&digits.len()) || digits.starts_with('0') { return Err(AuthError::InvalidPhone); }
    digits.parse().map_err(|_| AuthError::InvalidPhone)
}

/// Returns the JWT string from `AuthResponse { 2: user, 4: jwt-wrapped }`.
/// `None` if field 4 is absent or holds an empty string — the
/// "needs signup" signal Bale's API uses now.
fn decode_auth_response_jwt(buf: &[u8]) -> Result<Option<String>, ProtoError> {
    let mut r = ProtoReader::new(buf);
    let mut jwt: Option<String> = None;
    while r.has_more() {
        let (f, w) = r.tag()?;
        match f {
            2 => { let _ = r.bytes()?; }                      // user — opaque to us
            4 => jwt = Some(decode_wrapped_string(r.bytes()?)?),
            _ => r.skip(w)?,
        }
    }
    Ok(jwt.filter(|s| !s.is_empty()))
}

/// Bale wraps nullable strings as `Wrapped { 1: string }`. Empty
/// inner string → empty outer string; we collapse that to "".
fn decode_wrapped_string(buf: &[u8]) -> Result<String, ProtoError> {
    let mut r = ProtoReader::new(buf);
    let mut s = String::new();
    while r.has_more() {
        let (f, w) = r.tag()?;
        if f == 1 { s = r.string()?.to_string(); } else { r.skip(w)?; }
    }
    Ok(s)
}

/// Pull `access_token=…` out of a `Cookie`-style header value as
/// produced by [`reqwest::cookie::Jar::cookies`] — a `; `-joined
/// list of `name=value` pairs (no attributes; the jar already
/// stripped `Path`/`HttpOnly`/etc.).
fn extract_access_token_from_cookie_header(header: &str) -> Option<String> {
    for part in header.split(';') {
        if let Some(value) = part.trim().strip_prefix("access_token=") {
            return (!value.is_empty()).then(|| value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "Live Bale health check; sends only invalid phone 0, never a real number"]
    async fn live_auth_endpoint_rejects_invalid_phone() {
        let auth = BaleAuth::new();
        let payload = encode_start_phone_auth(0, &auth.device_hash);
        let response = auth.rpc("StartPhoneAuth", &payload).await;
        assert!(matches!(&response, Err(GrpcError::Status { message: Some(message), .. })
            if message.contains("PHONE_NUMBER_INVALID")),
            "Expected PHONE_NUMBER_INVALID for phone 0, got {response:?}");
    }

    // HTTP fixtures exercise the real request framing and transport, without
    // sending a code to a real phone number. The field numbers and enums are
    // checked against the official web client (see docs/auth-protocol.md).
    fn mock_auth(headers: &str, body: Vec<u8>) -> (BaleAuth, std::thread::JoinHandle<Vec<u8>>) {
        mock_auth_method("StartPhoneAuth", headers, body)
    }

    fn mock_auth_method(method: &str, headers: &str, body: Vec<u8>) -> (BaleAuth, std::thread::JoinHandle<Vec<u8>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let headers = headers.to_owned();
        let method = method.to_ascii_lowercase();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            let mut request = Vec::new();
            let body_start;
            loop {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
                if let Some(index) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    body_start = index + 4;
                    break;
                }
            }
            let head = String::from_utf8_lossy(&request[..body_start]).to_ascii_lowercase();
            assert!(head.starts_with(&format!("post /bale.auth.v1.auth/{method} http/1.1")));
            assert!(head.contains("content-type: application/grpc-web+proto"));
            assert!(head.contains("origin: https://web.bale.ai"));
            let length: usize = head.lines().find_map(|line| line.strip_prefix("content-length: ")).unwrap().parse().unwrap();
            while request.len() < body_start + length {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
            }
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/grpc-web+proto\r\nConnection: close\r\n{}\r\n", body.len(), headers).unwrap();
            socket.write_all(&body).unwrap();
            request[body_start..].to_vec()
        });
        let jar = Arc::new(Jar::default());
        let mut auth = BaleAuth::with_client(reqwest::Client::builder().no_proxy().cookie_provider(jar.clone()).timeout(std::time::Duration::from_secs(10)).build().unwrap(), jar);
        auth.endpoint = format!("http://{address}");
        (auth, server)
    }

    fn jwt_response(token: &str) -> Vec<u8> {
        grpc_web::encode_frame(&ProtoWriter::new().bytes(4, &ProtoWriter::new().string(1, token).build()).build())
    }

    fn assert_authenticated(outcome: AuthOutcome, expected: &str) {
        assert!(matches!(outcome, AuthOutcome::Authenticated { access_token } if access_token == expected));
    }

    #[tokio::test]
    async fn otp_jwt_completes_without_cookie_exchange_and_duplicate_rpc() {
        let (auth, server) = mock_auth_method("ValidateCode", "", jwt_response("fixture.jwt.token"));
        let (first, duplicate) = tokio::join!(auth.submit_otp("fixture-tx", "123456"), auth.submit_otp("fixture-tx", "123456"));
        assert_authenticated(first.unwrap(), "fixture.jwt.token");
        assert_authenticated(duplicate.unwrap(), "fixture.jwt.token");
        server.join().unwrap();
        // The one-request server is now closed. A UI retry must still succeed
        // without submitting the already-consumed OTP or making a GET request.
        assert_authenticated(auth.submit_otp("fixture-tx", "123456").await.unwrap(), "fixture.jwt.token");
        assert!(auth.submit_otp("different-tx", "123456").await.is_err());
    }

    #[tokio::test]
    async fn login_phone_requires_the_matching_successful_transaction_and_clears_on_logout() {
        let (auth,server)=mock_auth_method("ValidateCode","",jwt_response("fixture.jwt.token"));
        *auth.login_phone.lock().unwrap()=Some(("fixture-tx".into(),"+10000000001".into()));
        assert!(auth.verified_login_phone("fixture-tx").await.is_none());
        auth.submit_otp("fixture-tx","123456").await.unwrap();server.join().unwrap();
        assert_eq!(auth.verified_login_phone("fixture-tx").await.as_deref(),Some("+10000000001"));
        assert!(auth.verified_login_phone("other-tx").await.is_none());
        auth.clear_completed_auth().await;
        assert!(auth.verified_login_phone("fixture-tx").await.is_none());
        assert!(auth.login_phone.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn otp_accepts_httponly_rpc_cookie_without_jwt() {
        let (auth, server) = mock_auth_method("ValidateCode", "Set-Cookie: access_token=fixture-cookie; Path=/; HttpOnly\r\n", grpc_web::encode_frame(&[]));
        assert_authenticated(auth.submit_otp("fixture-tx", "123456").await.unwrap(), "fixture-cookie");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn new_cookie_takes_precedence_over_rpc_jwt() {
        let (auth, server) = mock_auth_method("ValidateCode", "Set-Cookie: access_token=new-cookie; Path=/; HttpOnly\r\n", jwt_response("fixture.jwt.token"));
        auth.jar.add_cookie_str("access_token=stale-cookie; Path=/", &auth.endpoint.parse().unwrap());
        assert_authenticated(auth.submit_otp("fixture-tx", "123456").await.unwrap(), "new-cookie");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn stale_cookie_is_not_a_successful_verification() {
        let (auth, server) = mock_auth_method("ValidateCode", "", grpc_web::encode_frame(&[]));
        auth.jar.add_cookie_str("access_token=stale-cookie; Path=/", &auth.endpoint.parse().unwrap());
        assert!(matches!(auth.submit_otp("fixture-tx", "123456").await.unwrap(), AuthOutcome::NeedsSignupName { .. }));
        assert!(auth.completed.lock().await.is_none());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn signup_accepts_jwt_or_fresh_cookie_and_preserves_completed_result() {
        for (headers, body, expected) in [
            ("", jwt_response("signup.jwt.token"), "signup.jwt.token"),
            ("Set-Cookie: access_token=signup-cookie; Path=/; HttpOnly\r\n", grpc_web::encode_frame(&[]), "signup-cookie"),
        ] {
            let (auth, server) = mock_auth_method("SignUp", headers, body);
            assert_authenticated(auth.submit_signup_name("signup-tx", "Fixture").await.unwrap(), expected);
            server.join().unwrap();
            assert_authenticated(auth.submit_signup_name("signup-tx", "Fixture").await.unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn expired_otp_is_an_error_without_cached_credentials() {
        let (auth, server) = mock_auth_method("ValidateCode", "grpc-status: 3\r\ngrpc-message: PHONE_CODE_EXPIRED\r\n", vec![]);
        assert!(auth.submit_otp("expired-tx", "123456").await.unwrap_err().to_string().contains("PHONE_CODE_EXPIRED"));
        assert!(auth.completed.lock().await.is_none());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn new_phone_attempt_clears_completed_verification() {
        let (auth, server) = mock_auth("", grpc_web::encode_frame(&ProtoWriter::new().string(1, "new-tx").build()));
        *auth.completed.lock().await = Some(("old-tx".into(), "old-token".into(), Instant::now()));
        auth.start_phone_auth("+989121234567").await.unwrap();
        assert!(auth.completed.lock().await.is_none());
        server.join().unwrap();
    }

    #[test]
    fn completed_verification_expires() {
        let completed = Some(("fixture-tx".into(), "fixture-token".into(), Instant::now() - Duration::from_secs(301)));
        assert!(cached_auth(&completed, "fixture-tx").is_none());
    }

    #[tokio::test]
    async fn logout_discards_completed_verification() {
        let auth = BaleAuth::new();
        *auth.completed.lock().await = Some(("fixture-tx".into(), "fixture-token".into(), Instant::now()));
        auth.clear_completed_auth().await;
        assert!(cached_auth(&*auth.completed.lock().await, "fixture-tx").is_none());
    }

    #[tokio::test]
    async fn start_auth_advertises_telegram_and_decodes_delivery_over_http() {
        let wait = ProtoWriter::new().int64(1, 60).build();
        let response = ProtoWriter::new().string(1, "test-transaction").bool_(2, true)
            .int32(5, 12).bytes(8, &wait).build();
        let (auth, server) = mock_auth("", grpc_web::encode_frame(&response));
        let result = auth.start_phone_auth("+98 912 123 4567").await.unwrap();
        assert_eq!(result.transaction_hash, "test-transaction");
        assert!(result.is_registered);
        assert_eq!(result.sent_code_type, 12);
        assert_eq!(result.next_send_code_wait_time, Some(60));
        let frame = server.join().unwrap();
        let payload = grpc_web::decode_response(&frame).unwrap();
        let mut r = ProtoReader::new(&payload);
        let mut delivery = None;
        let mut options = None;
        while r.has_more() {
            let (field, wire) = r.tag().unwrap();
            match field {
                1 => assert_eq!(r.varint().unwrap(), 989121234567),
                4 => assert_eq!(r.bytes().unwrap(), auth.device_hash),
                9 => delivery = Some(r.varint().unwrap()),
                10 => options = Some(r.bytes().unwrap().to_vec()),
                _ => r.skip(wire).unwrap(),
            }
        }
        assert_eq!(delivery, Some(1)); // DEFAULT, never force SMS
        assert_eq!(options, Some(vec![0, 1])); // packed Telegram Gateway + six-digit OTP
        assert_eq!(auth.device_hash.len(), 36); // UUID text, same value on retries
    }

    #[tokio::test]
    async fn header_only_auth_errors_are_not_success() {
        for (status, expected) in [("7", "PHONE_NUMBER_NOT_IN_TELEGRAM"), ("8", "phone auth limit exceeded"), ("invalid", "invalid grpc-status header")] {
            let headers = format!("grpc-status: {status}\r\ngrpc-message: {expected}\r\n");
            let (auth, server) = mock_auth(&headers, vec![]);
            let error = auth.start_phone_auth("+989121234567").await.unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            server.join().unwrap();
        }
    }

    #[tokio::test]
    async fn empty_success_is_not_a_sent_code() {
        for body in [vec![], grpc_web::encode_frame(&[]), grpc_web::encode_frame(&ProtoWriter::new().bool_(2, true).build())] {
            let (auth, server) = mock_auth("grpc-status: 0\r\n", body);
            assert!(matches!(auth.start_phone_auth("+989121234567").await, Err(AuthError::Malformed(_))));
            server.join().unwrap();
        }
    }

    #[test]
    fn phone_numbers_are_normalized_without_silently_dropping_characters() {
        for phone in ["+98 912-123-4567", "00989121234567", "09121234567", "+۹۸۹۱۲۱۲۳۴۵۶۷", "٠٩١٢١٢٣٤٥٦٧"] {
            assert_eq!(normalize_phone(phone).unwrap(), 989121234567);
        }
        assert_eq!(normalize_phone("+44 (7700) 900123").unwrap(), 447700900123);
        for phone in ["", "abc989121234567", "0", "++989121234567", "+0123456789", "9999999999999999", "0912x1234567"] {
            assert!(matches!(normalize_phone(phone), Err(AuthError::InvalidPhone)), "{phone}");
        }
    }

    #[test]
    fn decode_start_phone_auth_full() {
        let buf = ProtoWriter::new()
            .string(1, "abc-tx-hash")
            .int32 (2, 1)
            .build();
        let r = decode_start_phone_auth(&buf).unwrap();
        assert_eq!(r.transaction_hash, "abc-tx-hash");
        assert!(r.is_registered);
    }

    #[test]
    fn decode_auth_response_jwt_present() {
        let wrapped = ProtoWriter::new().string(1, "header.payload.sig").build();
        let buf     = ProtoWriter::new().bytes(4, &wrapped).build();
        let jwt = decode_auth_response_jwt(&buf).unwrap();
        assert_eq!(jwt.as_deref(), Some("header.payload.sig"));
    }

    #[test]
    fn decode_auth_response_jwt_missing_means_needs_signup() {
        // No field 4 — empty buffer
        let jwt = decode_auth_response_jwt(&[]).unwrap();
        assert!(jwt.is_none(), "missing field 4 = needs signup");
    }

    #[test]
    fn decode_auth_response_jwt_empty_means_needs_signup() {
        // Field 4 wrapped empty string — the new Bale behaviour
        let wrapped = ProtoWriter::new().string(1, "").build();
        let buf     = ProtoWriter::new().bytes(4, &wrapped).build();
        let jwt = decode_auth_response_jwt(&buf).unwrap();
        assert!(jwt.is_none(), "empty JWT = needs signup");
    }

    #[test]
    fn decode_auth_response_jwt_ignores_user_field() {
        let user_payload = b"opaque user blob".as_slice();
        let wrapped      = ProtoWriter::new().string(1, "valid.jwt.here").build();
        let buf          = ProtoWriter::new()
            .bytes(2, user_payload)   // field 2 user — should be skipped
            .bytes(4, &wrapped)
            .build();
        let jwt = decode_auth_response_jwt(&buf).unwrap();
        assert_eq!(jwt.as_deref(), Some("valid.jwt.here"));
    }

    #[test]
    fn decode_wrapped_string_handles_unknown_inner_fields() {
        // Inner f1=string, plus garbage at f2 — skip should keep us going
        let inner = ProtoWriter::new()
            .string(1, "outer")
            .int32 (2, 99)
            .build();
        assert_eq!(decode_wrapped_string(&inner).unwrap(), "outer");
    }
}
