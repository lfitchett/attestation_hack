use futures::TryStreamExt;
use guid_create::GUID;
use jsonwebtoken::*;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = "c92dd71d-c78b-49e0-8c86-1f6b5301a825";
    let client_id = "7b69073c-ca57-403d-b649-dc1ee28bdb16";

    let login_url = format!("https://login.windows-ppe.net/{}/oauth2/v2.0/token", tenant);
    // ========================== Make Cert JWT ================================================
    // https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
    // https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials

    // TODO: use better exp values
    let my_claims = Claims {
        aud: login_url.clone(),
        exp: 10000000000,
        iss: client_id.to_owned(),
        jti: GUID::rand().to_string(),
        nbf: 0,
        sub: client_id.to_owned(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.x5t = Some("2YcP/RtHg9MI002scO6552MBLaQ=".to_owned());

    let cert_token = encode(
        &header,
        &my_claims,
        &EncodingKey::from_rsa_pem(include_bytes!(r#"C:\Users\Lee\Downloads\device-id.key.pem"#))?,
    )?;
    // println!("Cert JWT: {}", cert_token);

    // ========================== Get token ================================================
    let client = reqwest::Client::new();

    let body = &[
        ("client_id", client_id),
        ("scope", "https://management.azure.com/.default"),
        ("grant_type", "client_credentials"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", &cert_token),
    ];

    // let body = &[
    //     ("client_id", client_id),
    //     ("client_secret", "ngB0~Cu~FUH4um1R_HhA-gfXA638IAULS8"),
    //     ("scope", "https://management.azure.com/.default"),
    //     ("grant_type", "client_credentials"),
    // ];

    let get_token = client.post(&login_url).form(body).send().await?;

    // println!("AAD Token: {:#?}", get_token.text().await);

    let token: TokenResponse = get_token.json().await?;
    println!("AAD Token: {}", token.access_token);

    Ok(())
}

#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    token_type: String,
    expires_in: u64,
    // ext_expires_in: u64,
    access_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct AcrTokenResponse {
    refresh_token: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Claims {
    aud: String,
    exp: usize,
    iss: String,
    jti: String,
    nbf: usize,
    sub: String,
}
