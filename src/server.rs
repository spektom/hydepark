use std::net::SocketAddr;

use async_native_tls::{Certificate, TlsAcceptor, TlsStream};
use async_std::{fs::File, net::TcpStream};
use async_std::{net::TcpListener, prelude::*};
use chrono::{DateTime, TimeZone, Utc};
use crypto::{digest::Digest, sha1::Sha1};
use log::{error, info};
use x509_parser::prelude::X509Certificate;

use crate::config::Config;
use crate::Result;
use crate::{gemini::*, hydepark::Hydepark};

pub struct Server {
    config: Config,
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    hydepark: Hydepark,
}

impl Server {
    /// Creates new server and starts listening.
    pub async fn new(config: Config, hydepark: Hydepark) -> Result<Server> {
        let cert_file = File::open(config.cert_path.as_str()).await.or_else(|e| {
            Err(format!(
                "Error reading certificate file '{}': {}",
                config.cert_path, e
            ))
        })?;

        let tls_acceptor = TlsAcceptor::new(cert_file, config.cert_pass.as_str())
            .await
            .or_else(|e| {
                Err(format!(
                    "Error decrypting certificate file '{}': {}",
                    config.cert_path, e
                ))
            })?;

        let listener = TcpListener::bind(config.listen_address.as_str())
            .await
            .or_else(|e| {
                Err(format!(
                    "Error listening on '{}': {}",
                    config.listen_address, e
                ))
            })?;

        info!("Started listening on {}", config.listen_address);
        Ok(Server {
            config,
            listener,
            tls_acceptor,
            hydepark,
        })
    }

    /// Serves incoming requests.
    pub async fn serve(&mut self) -> Result<()> {
        let mut incoming = self.listener.incoming();
        while let Some(tcp_stream) = incoming.next().await {
            if let Ok(mut stream) = self.tls_acceptor.clone().accept(tcp_stream?).await {
                if let Err(ref error) = self.process_request(&mut stream).await {
                    error!("Error processing request: {}", error);
                }
            }
        }
        Ok(())
    }

    async fn process_request(&self, stream: &mut TlsStream<TcpStream>) -> Result<()> {
        let request = Request::read_from(
            stream,
            &self.config,
            SessionContext {
                certificate: stream.peer_certificate()?,
                remote_addr: stream.get_ref().peer_addr()?,
            },
        )
        .await;

        let response = match request {
            Ok(ref request) => match self.hydepark.map_request(request).await {
                Ok(response) => response,
                Err(ref error) => {
                    if let RequestError::ServerError(err) = error {
                        error!("Server error: {}", err);
                    }
                    error.into_response()
                }
            },
            Err(ref error) => error.into_response(),
        };

        response.send_to(stream).await?;

        Self::log_request(stream, request, response);

        Ok(())
    }

    fn log_request(
        stream: &TlsStream<TcpStream>,
        request: std::result::Result<Request, RequestError>,
        response: Response,
    ) {
        let remote_addr = stream.get_ref().peer_addr().unwrap().to_string();
        info!(
            "{} {} {}",
            remote_addr,
            request
                .as_ref()
                .map_or_else(|_| "-", |r| r.resource.as_ref()),
            response.status.code()
        );
    }
}

#[derive(Debug)]
pub struct ClientCertificate {
    pub subject: String,
    pub fingerprint: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Clone)]
pub struct SessionContext {
    certificate: Option<Certificate>,
    pub remote_addr: SocketAddr,
}

impl SessionContext {
    pub fn peer_certificate(&self) -> Result<Option<ClientCertificate>> {
        if let Some(certificate) = &self.certificate {
            let der = certificate.to_der()?;
            let res = X509Certificate::from_der(der.as_slice())?;
            let certificate = res.1;

            certificate.verify_signature(None)?;

            let mut sha1 = Sha1::new();
            sha1.input(der.as_slice());

            Ok(Some(ClientCertificate {
                subject: certificate.subject().to_string(),
                fingerprint: sha1.result_str(),
                valid_from: Utc.timestamp(certificate.validity().not_before.timestamp(), 0),
                valid_until: Utc.timestamp(certificate.validity().not_after.timestamp(), 0),
            }))
        } else {
            Ok(None)
        }
    }
}
