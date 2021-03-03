use std::str::FromStr;

use log::trace;
use serde::Serialize;
use serde_json;
use structopt::StructOpt;
use url::Url;

use crate::{BoxedError, Result};

#[derive(Debug, Clone)]
pub struct BaseUrl {
    inner: Url,
}

impl BaseUrl {
    pub fn is_prefix_of(&self, url: &Url) -> bool {
        url.host() == self.inner.host() && url.port() == self.inner.port()
    }

    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }
}

impl FromStr for BaseUrl {
    type Err = BoxedError;

    fn from_str(s: &str) -> Result<Self> {
        let mut url = s.parse::<Url>()?;
        url.set_path(url.path().trim_end_matches('/').to_owned().as_str());
        Ok(BaseUrl { inner: url })
    }
}

impl Serialize for BaseUrl {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.inner.as_str())
    }
}

#[derive(StructOpt, Debug, Serialize, Clone)]
#[structopt(name = "hydepark")]
pub struct Config {
    #[structopt(long, name = "Server bind address", default_value = "0.0.0.0:1965")]
    pub listen_address: String,

    #[structopt(long, name = "Server base URL", default_value = "gemini://localhost")]
    pub base_url: BaseUrl,

    #[structopt(
        long,
        name = "Path to .pfx certificate file",
        default_value = "cert.pfx"
    )]
    pub cert_path: String,

    #[structopt(
        long,
        name = "Password for decryption of .pfx certificate file",
        default_value = ""
    )]
    pub cert_pass: String,

    #[structopt(long, name = "Storage connection string", default_value = "sqlite://")]
    pub db_conn: String,

    #[structopt(long, name = "Topics to show in one page", default_value = "10")]
    pub topics_per_page: u8,

    #[structopt(long, name = "Messages to show in one page", default_value = "10")]
    pub messages_per_page: u8,
}

impl Config {
    pub fn read() -> Config {
        let config = Config::from_args();
        trace!(
            "Using configuration: {}",
            serde_json::to_string_pretty(&config).unwrap()
        );
        config
    }
}
