use crate::routes::TwilioAuth;
use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use twilio_api::models::{
    ApiV2010AccountCall as TwilioCall, ApiV2010AccountMessage as TwilioMessage,
    ApiV2010AccountMessageMedia as MessageMedia,
};

pub struct HtmlTemplate<T>(pub T);

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

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub maybe_auth: Option<TwilioAuth>,
}

#[derive(Template)]
#[template(path = "calls_index.html")]
pub struct CallsIndexTemplate {
    pub calls: Vec<TwilioCall>,
    pub maybe_auth: Option<TwilioAuth>,
}

#[derive(Template)]
#[template(path = "sms_index.html")]
pub struct SmsIndexTemplate {
    pub sorted_contacts: Vec<(String, Vec<TwilioMessage>)>,
    pub maybe_auth: Option<TwilioAuth>,
}

#[derive(Template)]
#[template(path = "sms_media.html")]
pub struct SmsMediaTemplate {
    pub media_list: Vec<MessageMedia>,
    pub maybe_auth: Option<TwilioAuth>,
}

mod filters {
    use twilio_api::models::MessageEnumDirection;

    pub fn unwrapstring(s: &Option<String>) -> ::askama::Result<String> {
        Ok(s.clone().expect("option was None :("))
    }
    pub fn is_present_string(s: &Option<String>) -> ::askama::Result<bool> {
        match s.clone() {
            Some(str) => Ok(str.len() > 0),
            _ => Ok(false),
        }
    }
    pub fn is_inbound_string(s: &Option<String>) -> ::askama::Result<bool> {
        match s.clone() {
            Some(val) => Ok(&val == "inbound"),
            _ => Ok(false),
        }
    }
    pub fn is_inbound_msg(s: &Option<MessageEnumDirection>) -> ::askama::Result<bool> {
        match s {
            Some(MessageEnumDirection::Inbound) => Ok(true),
            _ => Ok(false),
        }
    }
}
