//! Mutually authenticated TLS 1.3. Pair public certificates out of band.
//! There is no extra payload cipher or per-packet authentication wrapper.
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct TunnelOptions {
    pub client: Option<quinn::ClientConfig>,
    pub server: Option<quinn::ServerConfig>,
    pub(crate) authenticated: bool,
}

pub struct Identity {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Result<Self, String> {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["lktunnel".into()])
                .map_err(|e| e.to_string())?;
        Ok(Self {
            certificate: cert.der().to_vec(),
            private_key: key_pair.serialize_der(),
        })
    }

    pub fn options(
        &self,
        trusted: &[Vec<u8>],
        server: bool,
        throughput: bool,
    ) -> Result<TunnelOptions, String> {
        let mut roots = rustls::RootCertStore::empty();
        // With no paired clients, trust only our own private identity: nobody
        // else can authenticate. Never disable client authentication to boot.
        let anchors = if trusted.is_empty() && server {
            vec![self.certificate.clone()]
        } else {
            trusted.to_vec()
        };
        if anchors.is_empty() {
            return Err("Pair the server's public code before connecting".into());
        }
        for certificate in anchors {
            roots
                .add(CertificateDer::from(certificate))
                .map_err(|e| e.to_string())?;
        }
        let certs = vec![CertificateDer::from(self.certificate.clone())];
        let key = PrivatePkcs8KeyDer::from(self.private_key.clone());
        let transport = crate::quic_tunnel::transport_config_for(throughput);
        if server {
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| e.to_string())?;
            let mut tls = rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key.into())
                .map_err(|e| e.to_string())?;
            tls.alpn_protocols = vec![b"balevpn-auth-v1".to_vec()];
            tls.max_early_data_size = 0;
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
                .map_err(|e| e.to_string())?;
            let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            config.transport_config(transport);
            Ok(TunnelOptions {
                server: Some(config),
                authenticated: true,
                ..Default::default()
            })
        } else {
            let mut tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_client_auth_cert(certs, key.into())
                .map_err(|e| e.to_string())?;
            tls.alpn_protocols = vec![b"balevpn-auth-v1".to_vec()];
            tls.enable_early_data = false;
            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|e| e.to_string())?;
            let mut config = quinn::ClientConfig::new(Arc::new(crypto));
            config.transport_config(transport);
            Ok(TunnelOptions {
                client: Some(config),
                authenticated: true,
                ..Default::default()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn authenticated_mode_drops_raw_ip_before_user_callbacks() {
        let server = Identity::generate().unwrap();
        let client = Identity::generate().unwrap();
        let (a, b) = crate::connect_loopback_with_options(
            client
                .options(&[server.certificate.clone()], false, false)
                .unwrap(),
            server
                .options(&[client.certificate.clone()], true, false)
                .unwrap(),
        );
        assert!(a.send_ip(&[0x45, 0, 0, 20]).is_err());
        assert!(a
            .send_raw_frame(vec![crate::FRAME_TYPE_IP, 0x45, 0, 0, 20], 4)
            .is_err());
        a.disconnect();
        b.disconnect();
        // A legacy/malicious sender also cannot inject clear IP into a secure
        // receiver, even with a caller-provided raw-IP callback installed.
        let (a, b) = crate::connect_loopback_with_options(
            Default::default(),
            server
                .options(&[client.certificate.clone()], true, false)
                .unwrap(),
        );
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = called.clone();
        b.set_on_ip(Some(Arc::new(move |_| {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        })));
        a.send_raw_frame(vec![crate::FRAME_TYPE_IP, 0x45, 0, 0, 20], 4)
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!called.load(std::sync::atomic::Ordering::Relaxed));
        a.disconnect();
        b.disconnect();
    }
}
