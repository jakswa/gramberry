use axum::{
    async_trait,
    extract::{FromRequest, Path, RequestParts},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};

use crate::templates::*;
use axum_extra::extract::cookie::{Cookie, Key as CookieKey, PrivateCookieJar, SameSite};
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
        .route("/sms", get(sms_index))
        .route("/sms/:msg_sid/media", get(sms_media))
        .route("/sms/:msg_sid/media/:media_sid", get(sms_media_redirect))
        .route("/session", post(session_create))
        .route("/log_out", get(session_destroy))
        .route("/health_check", get(health_check))
        .layer(axum::Extension(key))
        // an HTTP client for reuse across requests, for connection pooling :sparkles:
        .layer(axum::Extension(
            reqwest::ClientBuilder::new()
                // this is so SMS media redirects are not followed automatically
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        ))
}

async fn session_create(
    Form(payload): Form<TwilioAuth>,
    axum::Extension(http_client): axum::Extension<reqwest::Client>,
    jar: PrivateCookieJar,
) -> impl IntoResponse {
    // verify the auth is valid first.
    let account_sid = payload.account_sid;
    let secret_token = payload.secret_token;
    let twilio_config = TwilioConfig {
        basic_auth: Some((account_sid.clone(), Some(secret_token.clone()))),
        client: http_client,
        ..Default::default()
    };
    let resp = Twilio::fetch_account(&twilio_config, &account_sid).await;
    if resp.is_err() {
        return Redirect::to("/").into_response();
    }

    let friendly_name = resp.unwrap().friendly_name.unwrap();
    let updated_jar = jar.add(
        Cookie::build(
            "twauth",
            format!("{account_sid},{secret_token},{friendly_name}",),
        )
        .same_site(SameSite::Strict)
        .secure(true)
        .http_only(true)
        .finish(),
    );
    (updated_jar, Redirect::to("/")).into_response()
}

#[derive(Deserialize, Serialize, Default)]
pub struct TwilioAuth {
    pub account_sid: String,
    pub secret_token: String,
    pub friendly_name: Option<String>,
}

pub struct TwilioAuthRedirect;
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
                        friendly_name: Some(split.get(2).unwrap().to_string()),
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

// --- BEGIN TWILIO LIST ROUTES ---

use twilio_api::models::{
    ApiV2010AccountCall as TwilioCall, ApiV2010AccountMessage as TwilioMessage,
    ApiV2010AccountMessageMedia as MessageMedia,
};
use twilio_api::{
    apis::{configuration::Configuration as TwilioConfig, default_api as Twilio},
    models::MessageEnumDirection,
};

fn contact_for(msg: &TwilioMessage) -> String {
    match msg.direction {
        Some(MessageEnumDirection::Inbound) => msg.from.clone().unwrap(),
        _ => msg.to.clone().unwrap(),
    }
}

async fn sms_index(
    twilio_auth: TwilioAuth,
    axum::Extension(http_client): axum::Extension<reqwest::Client>,
) -> impl IntoResponse {
    let account_sid = twilio_auth.account_sid.clone();
    let twilio_config = TwilioConfig {
        basic_auth: Some((account_sid.clone(), Some(twilio_auth.secret_token.clone()))),
        client: http_client,
        ..Default::default()
    };
    let resp = Twilio::list_message(
        &twilio_config,
        &account_sid,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    // sorted + grouped for easy reading in UI.
    // still a single page of msgs, just grouping them
    let mut sorted_contacts: Vec<(String, Vec<TwilioMessage>)> = Vec::new();
    resp.unwrap().messages.unwrap().iter().for_each(|msg| {
        let contact = contact_for(msg);
        match sorted_contacts.iter_mut().find(|i| i.0 == contact) {
            Some(grp) => grp.1.push(msg.clone()),
            _ => {
                let mut sms_list: Vec<TwilioMessage> = Vec::new();
                sms_list.push(msg.clone());
                sorted_contacts.push((contact, sms_list));
            }
        }
    });

    HtmlTemplate(SmsIndexTemplate {
        sorted_contacts,
        maybe_auth: Some(twilio_auth),
    })
}

async fn sms_media(
    Path(msg_sid): Path<String>,
    twilio_auth: TwilioAuth,
    axum::Extension(http_client): axum::Extension<reqwest::Client>,
) -> impl IntoResponse {
    let account_sid = twilio_auth.account_sid.clone();
    let twilio_config = TwilioConfig {
        basic_auth: Some((account_sid.clone(), Some(twilio_auth.secret_token.clone()))),
        client: http_client,
        ..Default::default()
    };
    let resp = Twilio::list_media(
        &twilio_config,
        &account_sid,
        &msg_sid,
        None,
        None,
        None,
        None,
    )
    .await;
    let media_list: Vec<MessageMedia> = resp.unwrap().media_list.unwrap();
    HtmlTemplate(SmsMediaTemplate {
        media_list: media_list,
        maybe_auth: Some(twilio_auth),
    })
}

async fn sms_media_redirect(
    Path(sids): Path<(String, String)>,
    twilio_auth: TwilioAuth,
    axum::Extension(http_client): axum::Extension<reqwest::Client>,
) -> impl IntoResponse {
    let base_path = TwilioConfig::default().base_path;
    let account_sid = twilio_auth.account_sid;
    let uri = format!(
        "{base_path}/2010-04-01/Accounts/{account_sid}/Messages/{msg_sid}/Media/{media_sid}",
        msg_sid = sids.0,
        media_sid = sids.1,
    );
    let req_builder = http_client
        .request(reqwest::Method::GET, uri)
        .basic_auth(account_sid, Some(twilio_auth.secret_token));
    let resp = http_client
        .execute(req_builder.build().unwrap())
        .await
        .unwrap();
    Redirect::temporary(resp.headers().get("Location").unwrap().to_str().unwrap())
}

async fn calls_index(
    twilio_auth: TwilioAuth,
    axum::Extension(http_client): axum::Extension<reqwest::Client>,
) -> impl IntoResponse {
    let account_sid = twilio_auth.account_sid.clone();
    let twilio_config = TwilioConfig {
        basic_auth: Some((account_sid.clone(), Some(twilio_auth.secret_token.clone()))),
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
        maybe_auth: Some(twilio_auth),
    })
}
