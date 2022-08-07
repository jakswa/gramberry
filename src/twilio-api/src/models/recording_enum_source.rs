/*
 * Twilio - Api
 *
 * This is the public Twilio REST API.
 *
 * The version of the OpenAPI document: 1.32.0
 * Contact: support@twilio.com
 * Generated by: https://openapi-generator.tech
 */


/// 
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum RecordingEnumSource {
    #[serde(rename = "DialVerb")]
    DialVerb,
    #[serde(rename = "Conference")]
    Conference,
    #[serde(rename = "OutboundAPI")]
    OutboundAPI,
    #[serde(rename = "Trunking")]
    Trunking,
    #[serde(rename = "RecordVerb")]
    RecordVerb,
    #[serde(rename = "StartCallRecordingAPI")]
    StartCallRecordingAPI,
    #[serde(rename = "StartConferenceRecordingAPI")]
    StartConferenceRecordingAPI,

}

impl ToString for RecordingEnumSource {
    fn to_string(&self) -> String {
        match self {
            Self::DialVerb => String::from("DialVerb"),
            Self::Conference => String::from("Conference"),
            Self::OutboundAPI => String::from("OutboundAPI"),
            Self::Trunking => String::from("Trunking"),
            Self::RecordVerb => String::from("RecordVerb"),
            Self::StartCallRecordingAPI => String::from("StartCallRecordingAPI"),
            Self::StartConferenceRecordingAPI => String::from("StartConferenceRecordingAPI"),
        }
    }
}

impl Default for RecordingEnumSource {
    fn default() -> RecordingEnumSource {
        Self::DialVerb
    }
}




