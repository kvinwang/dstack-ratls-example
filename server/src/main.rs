use anyhow::{Context, Result};
use dstack_guest_agent_rpc::GetTlsKeyArgs;

use dstack_guest_agent_rpc::dstack_guest_client::DstackGuestClient;
use http_client::prpc::PrpcClient;
use ra_tls::attestation::Attestation;
use rocket::{get, mtls::Certificate, routes};

fn dstack_client() -> DstackGuestClient<PrpcClient> {
    DstackGuestClient::new(PrpcClient::new(dstack_types::dstack_agent_address()))
}

#[get("/")]
async fn index(peer_cert: Certificate<'_>) -> Result<String, String> {
    index_innner(peer_cert).await.map_err(|err| err.to_string())
}

async fn index_innner(peer_cert: Certificate<'_>) -> anyhow::Result<String> {
    let attestation = Attestation::from_der(peer_cert.as_bytes())
        .context("Failed to parse attestation")?
        .context("No attestation")?;
    let verified = attestation
        .verify_with_ra_pubkey(peer_cert.public_key().raw, None)
        .await
        .context("Failed to verify the attestation report")?;
    Ok(format!("Client info: {:?}", verified.report))
}

async fn prepare_cert() -> Result<()> {
    let dstack = dstack_client();
    let response = dstack
        .get_tls_key(GetTlsKeyArgs {
            subject: "demo-server".to_string(),
            alt_names: vec![std::env::var("DEMO_DOMAIN").context("Failed to get hostname")?],
            usage_ra_tls: true,
            usage_server_auth: true,
            usage_client_auth: false,
        })
        .await
        .context("Failed to get TLS key")?;
    std::fs::write("./certs/server.crt", &response.certificate_chain.join(""))?;
    std::fs::write("./certs/server.key", &response.key)?;
    Ok(())
}

#[rocket::main]
async fn main() -> Result<()> {
    prepare_cert().await?;

    let server = rocket::Rocket::build().mount("/", routes![index]);
    server
        .launch()
        .await
        .map_err(|err| anyhow::anyhow!("Failed to launch server: {err}"))?;
    Ok(())
}
