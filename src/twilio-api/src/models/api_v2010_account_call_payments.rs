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
pub struct ApiV2010AccountCallPayments {
    /// The SID of the Account that created the Payments resource.
    #[serde(rename = "account_sid", skip_serializing_if = "Option::is_none")]
    pub account_sid: Option<String>,
    /// The SID of the Call the resource is associated with.
    #[serde(rename = "call_sid", skip_serializing_if = "Option::is_none")]
    pub call_sid: Option<String>,
    /// The SID of the Payments resource.
    #[serde(rename = "sid", skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// The RFC 2822 date and time in GMT that the resource was created
    #[serde(rename = "date_created", skip_serializing_if = "Option::is_none")]
    pub date_created: Option<String>,
    /// The RFC 2822 date and time in GMT that the resource was last updated
    #[serde(rename = "date_updated", skip_serializing_if = "Option::is_none")]
    pub date_updated: Option<String>,
    /// The URI of the resource, relative to `https://api.twilio.com`
    #[serde(rename = "uri", skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

impl ApiV2010AccountCallPayments {
    pub fn new() -> ApiV2010AccountCallPayments {
        ApiV2010AccountCallPayments {
            account_sid: None,
            call_sid: None,
            sid: None,
            date_created: None,
            date_updated: None,
            uri: None,
        }
    }
}


