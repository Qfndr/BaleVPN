//! Explicit anonymous protocol probe. No registration, login, token or calls.
use igap_signaling::rpc::{Connection, Rpc};
#[tokio::main]
async fn main() {
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--connect"] {
        println!("{{\"networkRequested\":false,\"authenticated\":false}}");
        return;
    }
    let result = async {
        let (connection, _pushes) = Connection::open().await?;
        let response = connection.request(506, vec![]).await;
        connection.close();
        let response = response?;
        if response.action != 30506 {
            return Err(igap_signaling::Error::InvalidResponse);
        }
        Ok::<_, igap_signaling::Error>(response.action)
    }
    .await;
    match result{Ok(action)=>println!("{{\"networkRequested\":true,\"encryptedRoundTrip\":true,\"action\":{action},\"authenticated\":false}}"),Err(_)=>{println!("{{\"networkRequested\":true,\"encryptedRoundTrip\":false,\"authenticated\":false}}");std::process::exit(1);}}
}
