use guid_create::GUID;
use jsonwebtoken::*;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    let client_id = "1acd55d3-138b-4538-8521-63215c58e9df";

    let login_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant
    );

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
        &EncodingKey::from_rsa_pem(include_bytes!(
            r#"C:\Users\Lee\Downloads\device-id.key.pem"#
        ))?,
    )?;
    // println!("Cert JWT: {}", cert_token);

    // ========================== Get token ================================================
    let client = reqwest::Client::new();

    let scope = "https://management.azure.com/.default";
    // let scope = "https://hackprovider.wus.attest.azure.net";

    let body = &[
        ("client_id", client_id),
        ("scope", scope),
        ("grant_type", "client_credentials"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", &cert_token),
    ];

    let get_token = client.post(&login_url).form(body).send().await?;
    // println!("AAD Token: {:#?}", get_token.text().await);

    let token: TokenResponse = get_token.json().await?;
    // println!("AAD Token: {}", token.access_token);

    // ========================== Attest Token ================================================
    let quote_hex = b"";
    let enclave_held_data_hex = b"";

    let quote_base64 = base64::encode_config(quote_hex, base64::URL_SAFE);
    let enclave_held_data_base64 = base64::encode_config(enclave_held_data_hex, base64::URL_SAFE);

    let body = json! {
        {
            "RuntimeData " : {
                "Data": enclave_held_data_base64,
                "DataType": "Binary"
            },
            "Report": quote_base64,
        }
    };

    let enclave_request = client.post("https://hackprovider.wus.attest.azure.net:443/attest/OpenEnclave?api-version=2020-10-01")
        .header("Authorization", format!("Bearer {}", token.access_token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body)?)
        .send().await?;

    println!("Enclave Request: {:#?}", enclave_request);
    // println!("Enclave Request: {:#?}", enclave_request.text().await);

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
