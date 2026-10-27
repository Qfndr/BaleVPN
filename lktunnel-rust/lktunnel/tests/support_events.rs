use lktunnel::security::Identity;
#[tokio::test]
async fn rejected_client_on_a_multi_pin_server_produces_redacted_tls_evidence() {
    let server_id=Identity::generate().unwrap();
    let allowed_a=Identity::generate().unwrap();let allowed_b=Identity::generate().unwrap();
    let outsider=Identity::generate().unwrap();
    let before=lktunnel::diagnostics::snapshot().last().and_then(|e|e["sequence"].as_u64()).unwrap_or(0);
    let (client,server)=lktunnel::connect_loopback_with_options(
        outsider.options(&[server_id.certificate.clone()],false,false).unwrap(),
        server_id.options(&[allowed_a.certificate,allowed_b.certificate],true,false).unwrap());
    server.start_server().unwrap();
    let _=tokio::time::timeout(std::time::Duration::from_secs(5),client.ensure_quic_client()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            if lktunnel::diagnostics::snapshot().iter().any(|e|e["sequence"].as_u64().unwrap_or(0)>before&&e["stage"]=="server_setup"&&e["code"].as_u64().is_some_and(|c|(0x100..0x200).contains(&c))) {break;}
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("Missing structured server TLS rejection");
    let evidence=serde_json::to_string(&lktunnel::diagnostics::snapshot()).unwrap();
    for key in ["token=","private_key","access_token","bvp1:"] {assert!(!evidence.contains(key));}
    client.disconnect();server.disconnect();
}
