use askama::Template;
use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};

use axum_extra::extract::cookie::{Cookie, Key as CookieKey, PrivateCookieJar};
use reqwest;
use serde::{Deserialize, Serialize};

pub fn build() -> axum::Router {
    let key = match std::env::var("GRAMBERRY_SECRET") {
        Ok(secret) => CookieKey::from(secret[..].as_bytes()),
        _ => CookieKey::generate(),
    };
    Router::new()
        .route("/", get(index))
        .route("/calls", get(calls_index))
        .route("/session", post(session_create))
        .route("/log_out", get(session_destroy))
        .route("/health_check", get(health_check))
        .layer(axum::Extension(key))
        // an HTTP client for reuse across requests, for connection pooling :sparkles:
        .layer(axum::Extension(reqwest::Client::new()))
}

async fn session_create(
    Form(payload): Form<TwilioAuth>,
    jar: PrivateCookieJar,
) -> (PrivateCookieJar, Redirect) {
    let updated_jar = jar.add(
        Cookie::build(
            "twauth",
            format!("{},{}", payload.account_sid, payload.secret_token),
        )
        .secure(true)
        .http_only(true)
        .finish(),
    );
    (updated_jar, Redirect::to("/"))
}

#[derive(Deserialize, Serialize)]
struct TwilioAuth {
    account_sid: String,
    secret_token: String,
}

struct TwilioAuthRedirect;
impl IntoResponse for TwilioAuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/").into_response()
    }
}

#[async_trait]
impl<B> FromRequest<B> for TwilioAuth
where
    B: Send,
{
    type Rejection = TwilioAuthRedirect;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        match req.extract::<PrivateCookieJar>().await {
            Ok(jar) => match jar.get("twauth") {
                Some(cookie) => {
                    let auth_string = cookie.value();
                    let split: Vec<&str> = auth_string.split(",").collect();
                    Ok(TwilioAuth {
                        account_sid: split.get(0).unwrap().to_string(),
                        secret_token: split.get(1).unwrap().to_string(),
                    })
                }
                _ => Err(TwilioAuthRedirect),
            },
            _ => Err(TwilioAuthRedirect),
        }
    }
}

async fn session_destroy(jar: PrivateCookieJar) -> (PrivateCookieJar, Redirect) {
    let updated_jar = jar.remove(Cookie::named("twauth"));
    (updated_jar, Redirect::to("/"))
}

async fn health_check() -> &'static str {
    "WE GOOD"
}

async fn index(maybe_auth: Option<TwilioAuth>) -> impl IntoResponse {
    HtmlTemplate(IndexTemplate {
        logged_in: maybe_auth.is_some(),
        maybe_auth,
    })
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    logged_in: bool,
    maybe_auth: Option<TwilioAuth>,
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {}", err),
            )
                .into_response(),
        }
    }
}

// --- BEGIN TWILIO LIST ROUTES ---

use twilio_api::apis::{configuration::Configuration as TwilioConfig, default_api as Twilio};
use twilio_api::models::ApiV2010AccountCall as TwilioCall;

async fn calls_index(
    twilio_auth: TwilioAuth,
    axum::Extension(http_client): axum::Extension<reqwest::Client>,
) -> impl IntoResponse {
    let account_sid = twilio_auth.account_sid;
    let twilio_config = TwilioConfig {
        basic_auth: Some((account_sid.clone(), Some(twilio_auth.secret_token))),
        // this piece will let us pool + reuse http connections to twilio :sparkles:
        client: http_client,
        ..Default::default()
    };
    let resp = Twilio::list_call(
        &twilio_config,
        &account_sid,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    let call_list: Vec<TwilioCall> = resp.unwrap().calls.unwrap();
    HtmlTemplate(CallsIndexTemplate {
        calls: call_list,
        logged_in: true,
    })
}

#[derive(Template)]
#[template(path = "calls_index.html")]
struct CallsIndexTemplate {
    calls: Vec<TwilioCall>,
    logged_in: bool,
}

mod filters {
    pub fn unwrapstring(s: &Option<String>) -> ::askama::Result<String> {
        Ok(s.clone().expect("option was None :("))
    }
    pub fn is_inbound_string(s: &Option<String>) -> ::askama::Result<bool> {
        match s.clone() {
            Some(val) => Ok(val == "inbound".to_string()),
            _ => Ok(false),
        }
    }
}
