use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::service::oauth_service::{OAuthTokens, User};

use super::oauth_service;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn login(
    username: &str,
    password: &str,
    http_client: Arc<reqwest::Client>,
) -> anyhow::Result<AuthTokens> {
    let OAuthTokens {
        access_token,
        refresh_token,
        ..
    } = oauth_service::login(username, password, http_client).await?;

    Ok(AuthTokens {
        access_token,
        refresh_token: refresh_token.unwrap(),
    })
}

pub async fn refresh(
    auth_tokens: AuthTokens,
    http_client: Arc<reqwest::Client>,
) -> anyhow::Result<AuthTokens> {
    let OAuthTokens { access_token, .. } =
        oauth_service::refresh(&auth_tokens.refresh_token, http_client).await?;

    Ok(AuthTokens {
        access_token,
        refresh_token: auth_tokens.refresh_token,
    })
}

pub async fn get_user(access_token: &str) -> anyhow::Result<User> {
    oauth_service::get_user_by_token(&access_token).await
}
