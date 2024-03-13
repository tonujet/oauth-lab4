use anyhow::anyhow;
use base64::decode;
use rocket::serde::json::{serde_json, Value};

pub fn get_token_from_header(header: &str) -> anyhow::Result<&str> {
    let split: Vec<&str> = header.split_whitespace().collect();
    if split.len() != 2 {
        Err(anyhow!("Wrong header"))?
    }
    let token_type = split[0];

    if token_type != "Bearer" {
        Err(anyhow!("Wrong token type"))?
    }

    let token = split[1];
    Ok(token)
}

pub fn decode_token_payload(token: &str) -> anyhow::Result<Value> {
    let parts: Vec<&str> = token.split('.').collect();
    let payload_bytes = decode(parts[1])?;
    let payload_json: Value = serde_json::from_slice(&payload_bytes)?;
    Ok(payload_json)
}
