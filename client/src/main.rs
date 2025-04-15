use anyhow::{Context, Result, bail};
use clap::Parser;
use dstack_guest_agent_rpc::RawQuoteArgs;
use dstack_guest_agent_rpc::dstack_guest_client::DstackGuestClient;
use http_client::prpc::PrpcClient;
use ra_tls::{
    attestation::{Attestation, QuoteContentType, VerifiedAttestation},
    cert::{CaCert, CertRequest},
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};
use reqwest::tls::TlsInfo;
use reqwest::{Client, Identity, Response};

#[derive(Parser)]
#[command(name = "ratls-client", about = "RATLS client", long_about = None)]
struct Args {
    url: String,
}

fn dstack_client() -> DstackGuestClient<PrpcClient> {
    DstackGuestClient::new(PrpcClient::new(dstack_types::dstack_agent_address()))
}

async fn gen_ra_cert(ca_cert_pem: String, ca_key_pem: String) -> Result<(String, String)> {
    let ca = CaCert::new(ca_cert_pem, ca_key_pem)?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let quote_res = dstack_client()
        .get_quote(RawQuoteArgs {
            report_data: report_data.to_vec(),
        })
        .await
        .context("Failed to get quote")?;
    let quote = quote_res.quote;
    let event_log: Vec<u8> = quote_res.event_log.into();
    let req = CertRequest::builder()
        .subject("RA-TLS TEMP Cert")
        .quote(&quote)
        .usage_client_auth(true)
        .event_log(&event_log)
        .key(&key)
        .build();
    let cert = ca.sign(req).context("Failed to sign certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}

async fn ra_verify(response: &Response) -> Result<VerifiedAttestation> {
    let Some(tls_info) = response.extensions().get::<TlsInfo>() else {
        bail!("No TLS info in response");
    };
    let Some(cert_der) = tls_info.peer_certificate() else {
        bail!("No peer certificate");
    };
    let (_, cert) =
        x509_parser::parse_x509_certificate(cert_der).context("Failed to parse certificate")?;
    let attestation = Attestation::from_der(cert_der)
        .context("Failed to parse attestation")?
        .context("No attestation")?;
    attestation
        .verify_with_ra_pubkey(cert.public_key().raw, None)
        .await
        .context("Failed to verify the attestation report")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let ca_cert_pem = include_str!("../certs/tmp-ca.crt").to_string();
    let ca_key_pem = include_str!("../certs/tmp-ca.key").to_string();

    // Because an HTTP server typically requires a CA-signed certificate to establish mutual TLS,
    // we utilize a shared public temporary CA recognized by both client and server to sign the RA certificate.
    // The security is guaranteed through attestation rather than the CA itself.
    let (ra_client_cert, ra_client_key) = gen_ra_cert(ca_cert_pem, ca_key_pem).await?;
    let identity_pem = format!("{ra_client_cert}\n{ra_client_key}");
    let identity =
        Identity::from_pem(identity_pem.as_bytes()).context("Failed to parse identity")?;

    let client = Client::builder()
        .tls_info(true)
        .danger_accept_invalid_certs(true)
        .identity(identity)
        .build()
        .context("failed to create client")?;

    let response = client.get(args.url).send().await?;
    let verified = ra_verify(&response).await?;
    println!("Server Info: {:?}", verified.report);

    let body = response.text().await?;
    println!("Response: {body}");
    Ok(())
}
