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
pub enum IncomingPhoneNumberLocalEnumVoiceReceiveMode {
    #[serde(rename = "voice")]
    Voice,
    #[serde(rename = "fax")]
    Fax,

}

impl ToString for IncomingPhoneNumberLocalEnumVoiceReceiveMode {
    fn to_string(&self) -> String {
        match self {
            Self::Voice => String::from("voice"),
            Self::Fax => String::from("fax"),
        }
    }
}

impl Default for IncomingPhoneNumberLocalEnumVoiceReceiveMode {
    fn default() -> IncomingPhoneNumberLocalEnumVoiceReceiveMode {
        Self::Voice
    }
}




