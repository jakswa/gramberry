/*
 * Twilio - Api
 *
 * This is the public Twilio REST API.
 *
 * The version of the OpenAPI document: 1.32.0
 * Contact: support@twilio.com
 * Generated by: https://openapi-generator.tech
 */




#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct ApiV2010AccountValidationRequest {
    /// The SID of the Account that created the resource
    #[serde(rename = "account_sid", skip_serializing_if = "Option::is_none")]
    pub account_sid: Option<String>,
    /// The SID of the Call the resource is associated with
    #[serde(rename = "call_sid", skip_serializing_if = "Option::is_none")]
    pub call_sid: Option<String>,
    /// The string that you assigned to describe the resource
    #[serde(rename = "friendly_name", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    /// The phone number to verify in E.164 format
    #[serde(rename = "phone_number", skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// The 6 digit validation code that someone must enter to validate the Caller ID  when `phone_number` is called
    #[serde(rename = "validation_code", skip_serializing_if = "Option::is_none")]
    pub validation_code: Option<String>,
}

impl ApiV2010AccountValidationRequest {
    pub fn new() -> ApiV2010AccountValidationRequest {
        ApiV2010AccountValidationRequest {
            account_sid: None,
            call_sid: None,
            friendly_name: None,
            phone_number: None,
            validation_code: None,
        }
    }
}


