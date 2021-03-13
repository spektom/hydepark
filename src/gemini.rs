use std::collections::HashMap;

use async_std::io::{prelude::WriteExt, ReadExt};
use async_trait::async_trait;
use chrono::Utc;
use percent_encoding::percent_decode_str;
use url::Url;

use crate::{
    config::Config,
    server::{ClientCertificate, SessionContext},
    BoxedError, Result,
};

pub struct Request {
    pub resource: String,
    pub input: Option<HashMap<String, String>>,
    pub context: SessionContext,
}

impl Request {
    fn parse(
        buf: &[u8],
        config: &Config,
        context: SessionContext,
    ) -> std::result::Result<Request, RequestError> {
        if !buf.ends_with(b"\r\n") {
            return Err(RequestError::Incomplete);
        }

        let uri = std::str::from_utf8(&buf[..buf.len() - 2]).or(Err(RequestError::NotUtf8))?;
        let uri = Url::parse(uri).or(Err(RequestError::InvalidUrl))?;

        if !config.base_url.is_prefix_of(&uri) {
            return Err(RequestError::ProxyUnsupported);
        }

        let resource = percent_decode_str(uri.path())
            .decode_utf8()
            .or(Err(RequestError::NotUtf8))?;
        let resource = if resource.len() == 0 {
            "/"
        } else {
            resource.as_ref()
        };

        let input = uri.query().map(|_| {
            uri.query_pairs()
                .fold(HashMap::new(), |mut pairs, query_pair| {
                    let (name, value) = query_pair;
                    pairs.insert(name.into_owned(), value.into_owned());
                    pairs
                })
        });

        Ok(Request {
            resource: resource.to_owned(),
            input,
            context,
        })
    }

    pub async fn read_from<S>(
        stream: &mut S,
        config: &Config,
        context: SessionContext,
    ) -> std::result::Result<Request, RequestError>
    where
        S: ReadExt + Unpin,
    {
        let mut request = [0u8; 1026];
        let mut len = 0;
        let mut buf = &mut request[..];
        loop {
            let bytes_read = stream.read(buf).await.map_err(RequestError::Io)?;
            len += bytes_read;
            if bytes_read == 0 || buf[..len].ends_with(b"\r\n") {
                break;
            }
            buf = &mut request[len..];
        }

        Request::parse(&request[..len], config, context)
    }

    pub fn param_i64(&self, name: &str) -> Option<i64> {
        self.input
            .as_ref()
            .and_then(|h| h.get(name))
            .and_then(|p| p.parse::<i64>().ok())
    }

    pub fn input_as_str(&self) -> Option<&String> {
        self.input
            .as_ref()
            .and_then(|h| h.iter().next())
            .and_then(|e| if e.0.len() > 0 { Some(e.0) } else { None })
    }

    /// Returns client SSL certificate if exists in current session.
    pub fn client_certificate_opt(&self) -> Option<ClientCertificate> {
        match self.context.peer_certificate() {
            Ok(cert) => cert,
            _ => None,
        }
    }

    /// Return client SSL certificate, or issue relevant Gemini error if client SSL certificate
    /// is not used or if it's invalid.
    pub fn client_certificate(&self) -> std::result::Result<ClientCertificate, RequestError> {
        self.context
            .peer_certificate()
            .map_err(|_| RequestError::InvalidCertificate)?
            .ok_or(RequestError::MissingCertificate)
            .and_then(|cert| {
                let now = Utc::now();
                if cert.valid_from > now || cert.valid_until < now {
                    Err(RequestError::InvalidCertificate)
                } else {
                    Ok(cert)
                }
            })
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ResponseStatus {
    Input,
    SensitiveInput,
    Success,
    TemporaryRedirect,
    PermanentRedirect,
    TemporaryFailure,
    ServerUnavailable,
    CgiError,
    ProxyError,
    SlowDown,
    PermanentFailure,
    NotFound,
    Gone,
    ProxyRefused,
    BadRequest,
    ClientCertificateRequired,
    CertificateNotAuthorized,
    CertificateNotValid,
}

impl ResponseStatus {
    pub fn code(&self) -> &str {
        match *self {
            ResponseStatus::Input => "10",
            ResponseStatus::SensitiveInput => "11",
            ResponseStatus::Success => "20",
            ResponseStatus::TemporaryRedirect => "30",
            ResponseStatus::PermanentRedirect => "31",
            ResponseStatus::TemporaryFailure => "40",
            ResponseStatus::ServerUnavailable => "41",
            ResponseStatus::CgiError => "42",
            ResponseStatus::ProxyError => "43",
            ResponseStatus::SlowDown => "44",
            ResponseStatus::PermanentFailure => "50",
            ResponseStatus::NotFound => "51",
            ResponseStatus::Gone => "52",
            ResponseStatus::ProxyRefused => "53",
            ResponseStatus::BadRequest => "59",
            ResponseStatus::ClientCertificateRequired => "60",
            ResponseStatus::CertificateNotAuthorized => "61",
            ResponseStatus::CertificateNotValid => "63",
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: ResponseStatus,
    meta: String,
    body: Option<String>,
}

impl Response {
    fn new(status: ResponseStatus, meta: &str, body: Option<&str>) -> Response {
        Response {
            status,
            meta: meta.to_string(),
            body: body.map(|b| b.to_string()),
        }
    }

    pub fn header(status: ResponseStatus, meta: &str) -> Response {
        Response::new(status, meta, None)
    }

    pub fn text(body: &str) -> Response {
        Response::new(
            ResponseStatus::Success,
            "text/gemini; charset=utf-8",
            Some(body),
        )
    }
}

impl Response {
    pub async fn send_to<S>(&self, stream: &mut S) -> Result<()>
    where
        S: WriteExt + Unpin,
    {
        stream.write_all(self.status.code().as_bytes()).await?;
        stream.write_all(b" ").await?;
        stream.write_all(self.meta.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        if let Some(body) = self.body.as_ref() {
            stream.write_all(body.as_bytes()).await?;
        }
        Ok(())
    }
}

#[async_trait]
pub trait RequestMapper {
    async fn map_request(&self, request: &Request) -> std::result::Result<Response, RequestError>;
}

#[derive(Debug)]
pub enum RequestError {
    Io(std::io::Error),
    ServerError(BoxedError),
    Incomplete,
    InvalidCertificate,
    MissingCertificate,
    InvalidUrl,
    NotUtf8,
    ProxyUnsupported,
    UserError(ResponseStatus, &'static str),
}

impl std::error::Error for RequestError {}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            RequestError::Io(ref e) => write!(f, "I/O error reading request: {}", e),
            RequestError::Incomplete => write!(f, "Incomplete request (missing CRLF)"),
            RequestError::InvalidCertificate => write!(f, "Invalid client certificate"),
            RequestError::MissingCertificate => write!(f, "Client certificate is required"),
            RequestError::InvalidUrl => write!(f, "Invalid URL"),
            RequestError::NotUtf8 => write!(f, "Not a valid UTF-8 string"),
            RequestError::ProxyUnsupported => write!(f, "Proxy requests are not supported"),
            RequestError::UserError(ref status, message) => {
                write!(f, "User error {}: {}", status.code(), message)
            }
            RequestError::ServerError(ref e) => write!(f, "Internal server error: {}", e),
        }
    }
}

impl From<BoxedError> for RequestError {
    fn from(error: BoxedError) -> Self {
        RequestError::ServerError(error)
    }
}

impl RequestError {
    pub fn into_response(&self) -> Response {
        if let RequestError::UserError(ref status, message) = self {
            Response::header(status.clone(), message)
        } else {
            let status = match self {
                RequestError::Io(_) => ResponseStatus::TemporaryFailure,
                RequestError::ServerError(_) => ResponseStatus::PermanentFailure,
                RequestError::InvalidCertificate => ResponseStatus::CertificateNotValid,
                RequestError::MissingCertificate => ResponseStatus::ClientCertificateRequired,
                RequestError::ProxyUnsupported => ResponseStatus::ProxyRefused,
                _ => ResponseStatus::BadRequest,
            };
            Response::header(status, self.to_string().as_str())
        }
    }
}
