use askama::Template;
use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Form, Router,
};

use axum_extra::extract::cookie::{Cookie, Key as CookieKey, PrivateCookieJar};
use serde::{Deserialize, Serialize};

pub fn router() -> Router {
    let key = match std::env::var("GRAMBERRY_SECRET") {
        Ok(secret) => CookieKey::from(secret[..].as_bytes()),
        _ => CookieKey::generate(),
    };
    Router::new()
        .route("/", get(index))
        // TODO: nest a twilio section for calls/sms? guard on private cookie existing
        .route("/session", post(session_create))
        .route("/log_out", get(session_destroy))
        .route("/health_check", get(health_check))
        .layer(Extension(key))
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
                        secret_token: split.get(0).unwrap().to_string(),
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
    HtmlTemplate(IndexTemplate { maybe_auth })
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
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
