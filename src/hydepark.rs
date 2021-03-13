use async_std::sync::Mutex;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use chrono_humanize::{Accuracy, HumanTime, Humanize, Tense};
use fomat_macros::fomat;
use lazy_static::{__Deref, lazy_static};
use lru::LruCache;
use rand::Rng;
use std::collections::HashMap;

use crate::{
    config::Config,
    gemini::{Request, RequestError, RequestMapper, Response, ResponseStatus},
    storage::{Storage, Topic, User},
};

#[derive(Debug, Clone)]
struct UserContext {
    current_topic: Option<Topic>,
}

impl UserContext {
    pub fn new() -> UserContext {
        UserContext {
            current_topic: None,
        }
    }
}

lazy_static! {
    // Holds temporary session data per authenticated user.
    static ref CONTEXTS: Mutex<HashMap<i64, UserContext>> = Mutex::new(HashMap::new());

    // Number of requests made from an IP address at the specified minute.
    static ref REQ_COUNT: Mutex<LruCache<(String, u32), u64>> = Mutex::new(LruCache::new(1000));
}

pub struct Hydepark {
    config: Config,
    storage: Box<dyn Storage>,
}

impl Hydepark {
    pub fn new(config: Config, storage: Box<dyn Storage>) -> Hydepark {
        Hydepark { config, storage }
    }

    /// Returns a user according to the client certificate used in current session, or issues
    /// relevant Gemini error if certificate doesn't exist or invalid. If current certificate
    /// is not linked to any user account, redirect to a "new user" page is returned.
    async fn current_user(&self, request: &Request) -> std::result::Result<User, RequestError> {
        let certificate = request.client_certificate()?;
        self.storage
            .user_by_certificate(certificate.fingerprint.as_str())
            .await?
            .ok_or(RequestError::UserError(
                ResponseStatus::TemporaryRedirect,
                "/new-user",
            ))
    }

    /// Returns a user according to the client certificate used in current session.
    /// If there's a problem with a certificate (not used or invalid), or there's no user
    /// account linked to it - None is returned.
    async fn current_user_opt(&self, request: &Request) -> Option<User> {
        if let Some(cert) = request.client_certificate_opt() {
            if let Ok(user) = self
                .storage
                .user_by_certificate(cert.fingerprint.as_str())
                .await
            {
                return user;
            }
        }
        None
    }

    /// Simple request limiter that looks at how many requests came from current IP
    /// at this minute. If the number of requests is greater than the limit,
    /// Gemini response "slowdown" will be sent to the client.
    async fn limit_rate(&self, request: &Request) -> std::result::Result<(), RequestError> {
        if let Some(limit) = self.config.max_reqs_per_min {
            let mut req_count = REQ_COUNT.lock().await;
            let ip = request.context.remote_addr.ip().to_string();
            let mins_since_epoch = Utc::now().timestamp() as u32 / 60;
            let key = (ip, mins_since_epoch);
            if let Some(count) = req_count.get_mut(&key) {
                *count += 1;
                if count.deref() > &limit {
                    return Err(RequestError::UserError(
                        ResponseStatus::SlowDown,
                        "Too many requests",
                    ));
                }
            } else {
                req_count.put(key, 1);
            }
        }
        Ok(())
    }

    /// Access a session context stored for current user using callback `f`.
    async fn with_user_context<F, R>(&self, user: &User, f: F) -> R
    where
        F: FnOnce(&mut UserContext) -> R,
    {
        f(CONTEXTS
            .lock()
            .await
            .entry(user.id)
            .or_insert(UserContext::new()))
    }

    async fn param_topic(&self, request: &Request) -> std::result::Result<Topic, RequestError> {
        let topic_id = request.param_i64("t").unwrap_or(-1);
        self.storage
            .topic_by_id(topic_id as i64)
            .await?
            .ok_or(RequestError::UserError(
                ResponseStatus::NotFound,
                "Topic not found",
            ))
    }

    async fn new_user(&self, request: &Request) -> std::result::Result<Response, RequestError> {
        let certificate = request.client_certificate()?;
        if let Some(username) = request.input_as_str() {
            if self
                .storage
                .user_by_name(username.as_str())
                .await?
                .is_some()
            {
                return Ok(Response::header(
                    ResponseStatus::PermanentFailure,
                    "User with such name is already registered",
                ));
            }

            self.storage
                .user_insert(
                    username.as_str(),
                    certificate.fingerprint.as_str(),
                    certificate.subject.as_str(),
                    certificate.valid_from,
                    certificate.valid_until,
                )
                .await?;

            Ok(Response::header(ResponseStatus::TemporaryRedirect, "/"))
        } else {
            Ok(Response::header(
                ResponseStatus::Input,
                "Please register with Hydepark. Choose your username:",
            ))
        }
    }

    /// Reqest to link a new client certificate with an existing account.
    /// The method generates a new token, which is valid for 3 hours, and stores
    /// it in current account. This token is used for authorization when
    /// a request to /update-cert is made with the new client certificate.
    async fn update_cert_req(
        &self,
        request: &Request,
    ) -> std::result::Result<Response, RequestError> {
        let user = self.current_user(request).await?;

        let token: String = rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        let expires_on = Utc::now() + Duration::hours(3);

        self.storage
            .cert_update_token_insert(&user, token.as_str(), &expires_on)
            .await?;

        let body = fomat!(
            "# Client certificate update procedure"
            "\n\n1. Set up new client certificate with your browser."
            "\n\n2. Navigate to " (self.config.base_url.as_str()) "/update-cert, and enter token: " (token)
            "\n\nPlease note, the token will be valid until " (expires_on.to_rfc3339()) "."
            "\nTo request a new token, simply re-enter this page."
        );
        Ok(Response::text(body.as_str()))
    }

    /// Link a new client certificate with an existing account. The method receives
    /// a token generated in `update_cert_req`, and uses it for authorization.
    async fn update_cert(&self, request: &Request) -> std::result::Result<Response, RequestError> {
        let certificate = request.client_certificate()?;
        if self
            .storage
            .user_by_certificate(certificate.fingerprint.as_str())
            .await?
            .is_some()
        {
            return Ok(Response::header(
                ResponseStatus::PermanentFailure,
                "The certificate is already linked to a username",
            ));
        }

        let token = match request.input_as_str() {
            Some(token) => token,
            None => {
                return Ok(Response::header(
                    ResponseStatus::Input,
                    "Please enter your certificate update token:",
                ))
            }
        };

        let token = self
            .storage
            .cert_update_token(token)
            .await?
            .ok_or(RequestError::UserError(
                ResponseStatus::PermanentFailure,
                "Unrecognized certificate update token",
            ))?;

        if token.expires_on < Utc::now() {
            return Ok(Response::header(
                ResponseStatus::PermanentFailure,
                "The certificate update token is expired, please request a new one.",
            ));
        }

        self.storage
            .user_update_cert(
                token.user_id,
                certificate.fingerprint.as_str(),
                certificate.subject.as_str(),
                certificate.valid_from,
                certificate.valid_until,
            )
            .await?;

        Ok(Response::header(ResponseStatus::TemporaryRedirect, "/"))
    }

    async fn cert_update_link_user(&self, user: &User) -> Option<String> {
        if user.cert_valid_until < Utc::now() + Duration::weeks(2) {
            Some(fomat!(
                "\n\n=> " (self.config.base_url.as_str())
                "/update-cert-req Your certificate will be expired in "
                (HumanTime::from(user.cert_valid_until).to_text_en(Accuracy::Precise, Tense::Future))))
        } else {
            None
        }
    }

    async fn cert_update_link_req(&self, request: &Request) -> Option<String> {
        if let Some(user) = self.current_user_opt(request).await {
            self.cert_update_link_user(&user).await
        } else {
            None
        }
    }

    async fn new_topic(&self, request: &Request) -> std::result::Result<Response, RequestError> {
        let user = self.current_user(request).await?;
        if let Some(topic) = request.input_as_str() {
            let topic_id = self.storage.topic_insert(&user, topic).await?;
            Ok(Response::header(
                ResponseStatus::TemporaryRedirect,
                fomat!("/view-topic?t="(topic_id)).as_str(),
            ))
        } else {
            Ok(Response::header(ResponseStatus::Input, "New topic title:"))
        }
    }

    async fn view_topic(&self, request: &Request) -> std::result::Result<Response, RequestError> {
        let topic = self.param_topic(request).await?;
        let page = request.param_i64("p").unwrap_or(0) as u64;
        let messages = self
            .storage
            .messages_by_topic(
                topic.id as i64,
                page * self.config.messages_per_page as u64,
                self.config.messages_per_page,
            )
            .await?;
        let cert_update_link = self.cert_update_link_req(request).await;
        let body = fomat!("# " (topic.title) "\nLast updated " (topic.update_time.humanize())
            for message in &messages {
                "\n\n### " (message.user_name) " wrote " (message.create_time.humanize()) "\n" (message.content)
            }
            "\n\n~~~"
            if messages.len() as u8 == self.config.messages_per_page {
                "\n\n=> " (self.config.base_url.as_str()) "/view-topic?t=" (topic.id) "&p=" (page + 1) " Next page"
            }
            if page > 0 {
                "\n\n=> " (self.config.base_url.as_str()) "/view-topic?t=" (topic.id) "&p=" (page - 1) " Previous page"
            }
            "\n\n=> " (self.config.base_url.as_str()) "/new-message?t=" (topic.id) " New message"
            "\n\n=> " (self.config.base_url.as_str()) " Home"
            if let Some(cert_update_link) = cert_update_link { (cert_update_link) }
        );
        Ok(Response::text(body.as_str()))
    }

    async fn new_message(&self, request: &Request) -> std::result::Result<Response, RequestError> {
        let user = self.current_user(request).await?;
        if request.param_i64("t").is_some() {
            let topic = self.param_topic(request).await?;
            self.with_user_context(&user, |ctx| ctx.current_topic = Some(topic))
                .await;
            return Ok(Response::header(
                ResponseStatus::Input,
                "Enter your message:",
            ));
        }

        let topic = self
            .with_user_context(&user, |ctx| ctx.current_topic.clone())
            .await
            .ok_or(RequestError::UserError(
                ResponseStatus::PermanentFailure,
                "Current topic is unknown",
            ))?;

        if let Some(message) = request.input_as_str() {
            self.storage.message_insert(&user, &topic, message).await?;
            Ok(Response::header(
                ResponseStatus::TemporaryRedirect,
                fomat!("/view-topic?t="(topic.id)).as_str(),
            ))
        } else {
            Ok(Response::header(
                ResponseStatus::TemporaryRedirect,
                fomat!("/new-message?t="(topic.id)).as_str(),
            ))
        }
    }

    async fn index(&self, request: &Request) -> std::result::Result<Response, RequestError> {
        let page = request.param_i64("p").unwrap_or(0) as u64;
        let topics = self
            .storage
            .recent_topics(
                page * self.config.topics_per_page as u64,
                self.config.topics_per_page,
            )
            .await?;
        let cert_update_link = self.cert_update_link_req(request).await;
        let body = fomat!(
            "# Welcome to Hydepark!\n\n"
            "This is a place for discussions, please be kind to each other.\n\n"
            "## Latest topics\n"
            for topic in &topics {
                "\n=> " (self.config.base_url.as_str()) "/view-topic?t=" (topic.id) " " (topic.title)
            }
            "\n\n~~~"
            if topics.len() as u8 == self.config.topics_per_page {
                "\n\n=> "(self.config.base_url.as_str()) "?p=" (page + 1) " Next page"
            }
            if page > 0 {
                "\n\n=> " (self.config.base_url.as_str()) "?p=" (page - 1) " Previous page"
            }
            "\n\n=> " (self.config.base_url.as_str()) "/new-topic New topic"
            if let Some(cert_update_link) = cert_update_link { (cert_update_link) }
        );
        Ok(Response::text(body.as_str()))
    }
}

#[async_trait]
impl RequestMapper for Hydepark {
    async fn map_request(&self, request: &Request) -> std::result::Result<Response, RequestError> {
        self.limit_rate(request).await?;
        match request.resource.as_str() {
            "/" => self.index(request).await,
            "/new-user" => self.new_user(request).await,
            "/new-topic" => self.new_topic(request).await,
            "/view-topic" => self.view_topic(request).await,
            "/new-message" => self.new_message(request).await,
            "/update-cert-req" => self.update_cert_req(request).await,
            "/update-cert" => self.update_cert(request).await,
            _ => Ok(Response::header(
                ResponseStatus::TemporaryRedirect,
                self.config.base_url.as_str(),
            )),
        }
    }
}
