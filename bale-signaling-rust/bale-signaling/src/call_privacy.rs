//! Bale Web's account setting: `bale.v1.Configs`, `privacy.call = always`.
//! EditParameter.value is a wrapped string, unlike GetParameters' plain value.
//! See docs/call-privacy.md for the inspected official protocol source.

use crate::grpc_web::{self, GrpcError};
use crate::proto::{ProtoReader, ProtoWriter};

const KEY: &str = "privacy.call";
const EVERYONE: &str = "always";
const ENDPOINT: &str = "https://next-ws.bale.ai/bale.v1.Configs";

pub(crate) async fn allow_incoming_calls(http: &reqwest::Client, token: &str) -> Result<(), GrpcError> {
    allow_at(http, token, ENDPOINT).await
}

async fn read_at(http: &reqwest::Client, token: &str, endpoint: &str) -> Result<Option<String>, GrpcError> {
    let response = grpc_web::call_endpoint(http, &format!("{endpoint}/GetParameters"), &[], Some(token)).await?;
    decode_call_privacy(&response)
}

async fn allow_at(http: &reqwest::Client, token: &str, endpoint: &str) -> Result<(), GrpcError> {
    if read_at(http, token, endpoint).await?.as_deref() == Some(EVERYONE) {
        return Ok(());
    }
    // Edit only this key; never send the entire account settings object back.
    let wrapped = ProtoWriter::new().string(1, EVERYONE).build();
    let edit = ProtoWriter::new().string(1, KEY).bytes(2, &wrapped).build();
    grpc_web::call_endpoint(http, &format!("{endpoint}/EditParameter"), &edit, Some(token)).await?;
    // A successful write response alone is not proof the account permits calls.
    if read_at(http, token, endpoint).await?.as_deref() != Some(EVERYONE) {
        return Err(GrpcError::Malformed("Bale call privacy could not be verified as Everyone".into()));
    }
    Ok(())
}

fn decode_call_privacy(buf: &[u8]) -> Result<Option<String>, GrpcError> {
    let mut reader = ProtoReader::new(buf);
    let mut result = None;
    while reader.has_more() {
        let (field, wire) = reader.tag()?;
        if (field, wire) == (1, 2) {
            let mut parameter = ProtoReader::new(reader.bytes()?);
            let (mut key, mut value) = (String::new(), String::new());
            while parameter.has_more() {
                match parameter.tag()? {
                    (1, 2) => key = parameter.string()?.to_owned(),
                    (2, 2) => value = parameter.string()?.to_owned(),
                    (_, wire) => parameter.skip(wire)?,
                }
            }
            if key == KEY { result = Some(value); }
        } else {
            reader.skip(wire)?;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn parameters(value: Option<&str>) -> Vec<u8> {
        let unrelated = ProtoWriter::new().string(1, "privacy.last_seen").string(2, "nobody").build();
        let mut response = ProtoWriter::new().bytes(1, &unrelated);
        if let Some(value) = value {
            let setting = ProtoWriter::new().string(1, KEY).string(2, value).build();
            response = response.bytes(1, &setting);
        }
        response.build()
    }

    // Real loopback HTTP + gRPC framing; fake credentials only. Exact request
    // assertions protect the account setting key and its nested value encoding.
    async fn exercise(replies: Vec<(&'static str, Vec<u8>, bool)>) -> Result<(), GrpcError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/bale.v1.Configs", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for (method, payload, error) in replies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let (end, length) = loop {
                    let mut block = [0; 4096];
                    let read = socket.read(&mut block).await.unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&block[..read]);
                    if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..pos]).to_lowercase();
                        let length: usize = headers.lines().find_map(|line| line.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                        if request.len() >= pos + 4 + length { break (pos + 4, length); }
                    }
                };
                let headers = String::from_utf8_lossy(&request[..end]);
                assert!(headers.starts_with(&format!("POST /bale.v1.Configs/{method} ")));
                let body = grpc_web::decode_response(&request[end..end + length]).unwrap();
                if method == "EditParameter" {
                    let wrapped = ProtoWriter::new().string(1, EVERYONE).build();
                    assert_eq!(body, ProtoWriter::new().string(1, KEY).bytes(2, &wrapped).build());
                } else { assert!(body.is_empty()); }
                let body = grpc_web::encode_frame(&payload);
                let status = if error { "grpc-status: 7\r\ngrpc-message: PermissionDenied\r\n" } else { "grpc-status: 0\r\n" };
                let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: {}\r\n{status}Connection: close\r\n\r\n", body.len());
                socket.write_all(head.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });
        let http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(2)).build().unwrap();
        let result = allow_at(&http, "fixture-token", &endpoint).await;
        tokio::time::timeout(std::time::Duration::from_secs(3), server).await.unwrap().unwrap();
        result
    }

    #[tokio::test]
    async fn restricted_or_missing_setting_is_changed_and_read_back() {
        for before in [Some("nobody"), Some("contacts"), None] {
            exercise(vec![("GetParameters", parameters(before), false),
                ("EditParameter", vec![], false),
                ("GetParameters", parameters(Some(EVERYONE)), false)]).await.unwrap();
        }
    }

    #[tokio::test]
    async fn already_everyone_does_not_write() {
        exercise(vec![("GetParameters", parameters(Some(EVERYONE)), false)]).await.unwrap();
    }

    #[tokio::test]
    async fn read_or_write_denial_is_not_success() {
        assert!(exercise(vec![("GetParameters", vec![], true)]).await.is_err());
        assert!(exercise(vec![("GetParameters", parameters(Some("nobody")), false),
            ("EditParameter", vec![], true)]).await.is_err());
    }

    #[tokio::test]
    async fn unchanged_or_malformed_readback_is_not_success() {
        for after in [parameters(Some("nobody")), parameters(None), vec![10, 255]] {
            assert!(exercise(vec![("GetParameters", parameters(Some("nobody")), false),
                ("EditParameter", vec![], false), ("GetParameters", after, false)]).await.is_err());
        }
    }

    #[tokio::test]
    async fn malformed_initial_response_does_not_write() {
        assert!(exercise(vec![("GetParameters", vec![10, 255], false)]).await.is_err());
    }
}
