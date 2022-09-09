// routes dedicated to rendering Twilio's XML format, TwiML
use crate::templates::{HangupTwiml, RejectTwiml, VoicemailTwiml, XmlTemplate};
use axum::{
    response::IntoResponse,
    routing::{get, post},
    Form,
};
use serde::Deserialize;

pub fn build() -> axum::Router {
    axum::Router::new()
        .route("/twilio/calls", post(twilio_call_create))
        .route("/twilio/hangup", get(twilio_call_hangup))
}

#[derive(Deserialize)]
#[serde(rename_all(deserialize = "PascalCase"))]
struct TwilioCallForm {
    stir_verstat: Option<String>,
}

// we will route the call if the Stir-Shaken validation seems good (that's mysterious/new).
async fn twilio_call_create(Form(payload): Form<TwilioCallForm>) -> impl IntoResponse {
    if let Some(stir_verstat) = payload.stir_verstat {
        if stir_verstat.starts_with("TN-Validation-Passed-A") {
            return XmlTemplate(VoicemailTwiml {}).into_response();
        }
    }

    XmlTemplate(RejectTwiml {}).into_response()
}

async fn twilio_call_hangup() -> impl IntoResponse {
    XmlTemplate(HangupTwiml {}).into_response()
}
