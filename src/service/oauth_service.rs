use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::anyhow;
use reqwest::StatusCode;
use rocket::serde::json::serde_json::json;
use rocket::serde::json::Value;
use rocket::serde::Deserialize;
use serde::Serialize;

use crate::config::config;
use crate::service::jwt_service;

#[derive(Deserialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub scope: String,
    pub expires_in: u32,
    pub token_type: String,
}

#[derive(Deserialize, Debug)]
pub struct OAuthTokensError {
    error: String,
    error_description: String,
}

impl Display for OAuthTokensError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OAuth token error: {}. More details: {}",
            self.error, self.error_description
        )
    }
}

impl std::error::Error for OAuthTokensError {}

pub async fn login(
    username: &str,
    password: &str,
    http_client: Arc<reqwest::Client>,
) -> anyhow::Result<OAuthTokens> {
    let endpoint = &config().OAUTH.SERVER;
    let res = http_client
        .post(endpoint)
        .json(&json!({
                "grant_type": "password",
                "scope": "offline_access",
                "username": username,
                "password": password,
                "audience": config().OAUTH.AUDIENCE,
                "client_id": config().OAUTH.CLIENT_ID,
                "client_secret": config().OAUTH.CLIENT_SECRET}))
        .send()
        .await?;

    Ok(ok_or_error(res).await?)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub email: String,
    pub nickname: String,
    pub name: String,
}

pub async fn get_user_by_token(access_token: &str) -> anyhow::Result<User> {
    let user_id = get_user_id_from_token(&access_token)?;
    let mut endpoint = PathBuf::from(&config().OAUTH.AUDIENCE);
    endpoint.push("users");
    endpoint.push(&user_id);
    let endpoint = endpoint.to_str().unwrap();
    println!("{endpoint}");

    let client = reqwest::Client::new();
    let res = client
        .get(endpoint)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await?;

    if res.status() != StatusCode::OK {
        Err(anyhow!(res.text().await?))?
    } else {
        let user: User = res.json().await?;
        Ok(user)
    }
}

fn get_user_id_from_token(token: &str) -> anyhow::Result<String> {
    let payload_json: Value = jwt_service::decode_token_payload(token)?;
    let user_id = payload_json
        .get("sub")
        .ok_or(anyhow!("There isn't user id in token"))?
        .to_owned();

    match user_id {
        Value::String(sub) => Ok(sub),
        _ => Err(anyhow!("User id in token is not a string")),
    }
}

pub async fn refresh(
    refresh_token: &str,
    http_client: Arc<reqwest::Client>,
) -> anyhow::Result<OAuthTokens> {
    let endpoint = &config().OAUTH.SERVER;
    let res = http_client
        .post(endpoint)
        .json(&json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            
                "client_id": config().OAUTH.CLIENT_ID,
                "client_secret": config().OAUTH.CLIENT_SECRET}))
        .send()
        .await?;
    Ok(ok_or_error(res).await?)
}

async fn ok_or_error(res: reqwest::Response) -> anyhow::Result<OAuthTokens> {
    if res.status() != StatusCode::OK {
        let err = res.json::<OAuthTokensError>().await?;
        Err(err)?
    } else {
        let tokens: OAuthTokens = res.json().await?;
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use rocket::tokio;

    use crate::service::oauth_service::{get_user_by_token, get_user_id_from_token};

    #[test]
    fn test_function() {
        let id = get_user_id_from_token("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRLWXJ6RHJCbm81QUpYdzRwY0NQQiJ9.eyJpc3MiOiJodHRwczovL2Rldi1peHloMDJqMWNkdzZ0cWpwLnVzLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHw2NWYwNzg1N2ExM2E2NmI5OTFkODExNmUiLCJhdWQiOiJodHRwczovL2Rldi1peHloMDJqMWNkdzZ0cWpwLnVzLmF1dGgwLmNvbS9hcGkvdjIvIiwiaWF0IjoxNzEwMjg0NDUxLCJleHAiOjE3MTAzNzA4NTEsImF6cCI6IkZacVI4V2dXM25PeWkwTkVMTXFPd0VKaUNudnpwdU0zIiwic2NvcGUiOiJyZWFkOmN1cnJlbnRfdXNlciB1cGRhdGU6Y3VycmVudF91c2VyX21ldGFkYXRhIGRlbGV0ZTpjdXJyZW50X3VzZXJfbWV0YWRhdGEgY3JlYXRlOmN1cnJlbnRfdXNlcl9tZXRhZGF0YSBjcmVhdGU6Y3VycmVudF91c2VyX2RldmljZV9jcmVkZW50aWFscyBkZWxldGU6Y3VycmVudF91c2VyX2RldmljZV9jcmVkZW50aWFscyB1cGRhdGU6Y3VycmVudF91c2VyX2lkZW50aXRpZXMgb2ZmbGluZV9hY2Nlc3MiLCJndHkiOiJwYXNzd29yZCJ9.fLfOwDC8_jUptCYTRSXpopaHrVnKzbuZ5yOsbjc8irFlDtRzND5bbeMF4IFQTe75jgNIDfgCqOO61Jpvu7jH_bIDb1C1RVN6QUYvGihyib3W2Be-4NLj8Fqg0CmGXziwoCQlyByFJXnEo8xj43mpG1TPnAWWPp0ND6-U2RXtB8NACCe7uIkSIGFA4g734R5sF2kuPf7XCSFKTuUM_UzG7496h1QfxgPibi3gUdYCwf_Xag88IA21NVZ0s5ULYnclXUm3y-g5vifv-0vyyduiNP33nuZ8HtOFi6sMlthg_xak4X_HSwW7Z_3AFkc_UMOURkeiYn4RArnnuthbZiOErw");
        match id {
            Ok(id) => {
                println!("{id}")
            }
            Err(error) => {
                println!("{error}")
            }
        }
    }

    #[tokio::test]
    async fn test2() {
        let user = get_user_by_token("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRLWXJ6RHJCbm81QUpYdzRwY0NQQiJ9.eyJpc3MiOiJodHRwczovL2Rldi1peHloMDJqMWNkdzZ0cWpwLnVzLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHw2NWYwNzg1N2ExM2E2NmI5OTFkODExNmUiLCJhdWQiOiJodHRwczovL2Rldi1peHloMDJqMWNkdzZ0cWpwLnVzLmF1dGgwLmNvbS9hcGkvdjIvIiwiaWF0IjoxNzEwMjg0NDUxLCJleHAiOjE3MTAzNzA4NTEsImF6cCI6IkZacVI4V2dXM25PeWkwTkVMTXFPd0VKaUNudnpwdU0zIiwic2NvcGUiOiJyZWFkOmN1cnJlbnRfdXNlciB1cGRhdGU6Y3VycmVudF91c2VyX21ldGFkYXRhIGRlbGV0ZTpjdXJyZW50X3VzZXJfbWV0YWRhdGEgY3JlYXRlOmN1cnJlbnRfdXNlcl9tZXRhZGF0YSBjcmVhdGU6Y3VycmVudF91c2VyX2RldmljZV9jcmVkZW50aWFscyBkZWxldGU6Y3VycmVudF91c2VyX2RldmljZV9jcmVkZW50aWFscyB1cGRhdGU6Y3VycmVudF91c2VyX2lkZW50aXRpZXMgb2ZmbGluZV9hY2Nlc3MiLCJndHkiOiJwYXNzd29yZCJ9.fLfOwDC8_jUptCYTRSXpopaHrVnKzbuZ5yOsbjc8irFlDtRzND5bbeMF4IFQTe75jgNIDfgCqOO61Jpvu7jH_bIDb1C1RVN6QUYvGihyib3W2Be-4NLj8Fqg0CmGXziwoCQlyByFJXnEo8xj43mpG1TPnAWWPp0ND6-U2RXtB8NACCe7uIkSIGFA4g734R5sF2kuPf7XCSFKTuUM_UzG7496h1QfxgPibi3gUdYCwf_Xag88IA21NVZ0s5ULYnclXUm3y-g5vifv-0vyyduiNP33nuZ8HtOFi6sMlthg_xak4X_HSwW7Z_3AFkc_UMOURkeiYn4RArnnuthbZiOErw").await;
        println!("{user:?}")
    }
}
