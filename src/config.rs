use std::env;
use std::sync::OnceLock;

use anyhow::anyhow;

pub fn config() -> &'static Config {
    static INSTANCE: OnceLock<Config> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        Config::load().unwrap_or_else(|ex| panic!("ERROR WHILE LOADING CONF: {ex:?}"))
    })
}

trait ConfigLoader {
    fn load() -> anyhow::Result<Self>
    where
        Self: Sized;
}

#[allow(non_snake_case)]
pub struct Config {
    pub OAUTH: OauthConfig,
    pub SERVER: ServerConfig,
}

impl ConfigLoader for Config {
    fn load() -> anyhow::Result<Config> {
        Ok(Config {
            OAUTH: OauthConfig::load()?,
            SERVER: ServerConfig::load()?,
        })
    }
}

#[allow(non_snake_case)]
pub struct OauthConfig {
    pub SERVER: String,
    pub AUDIENCE: String,
    pub CLIENT_ID: String,
    pub CLIENT_SECRET: String,
}

impl ConfigLoader for OauthConfig {
    fn load() -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(OauthConfig {
            SERVER: get_env("OAUTH_SERVER")?,
            AUDIENCE: get_env("OAUTH_AUDIENCE")?,
            CLIENT_ID: get_env("OAUTH_CLIENT_ID")?,
            CLIENT_SECRET: get_env("OAUTH_CLIENT_SECRET")?,
        })
    }
}

#[allow(non_snake_case)]
pub struct ServerConfig {
    pub PORT: u16,
}

impl ConfigLoader for ServerConfig {
    fn load() -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let port: u16 = get_env("SERVER_PORT")?
            .parse()
            .map_err(|_| anyhow!("Can not parse port to u16"))?;
        Ok(ServerConfig {
            PORT: port,
        })
    }
}

fn get_env(name: &'static str) -> anyhow::Result<String> {
    Ok(env::var(name)?)
}
