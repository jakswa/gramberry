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
pub struct ApiV2010AccountMessageMedia {
    /// The SID of the Account that created this resource
    #[serde(rename = "account_sid", skip_serializing_if = "Option::is_none")]
    pub account_sid: Option<String>,
    /// The default mime-type of the media
    #[serde(rename = "content_type", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// The RFC 2822 date and time in GMT that this resource was created
    #[serde(rename = "date_created", skip_serializing_if = "Option::is_none")]
    pub date_created: Option<String>,
    /// The RFC 2822 date and time in GMT that this resource was last updated
    #[serde(rename = "date_updated", skip_serializing_if = "Option::is_none")]
    pub date_updated: Option<String>,
    /// The SID of the resource that created the media
    #[serde(rename = "parent_sid", skip_serializing_if = "Option::is_none")]
    pub parent_sid: Option<String>,
    /// The unique string that identifies this resource
    #[serde(rename = "sid", skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// The URI of this resource, relative to `https://api.twilio.com`
    #[serde(rename = "uri", skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

impl ApiV2010AccountMessageMedia {
    pub fn new() -> ApiV2010AccountMessageMedia {
        ApiV2010AccountMessageMedia {
            account_sid: None,
            content_type: None,
            date_created: None,
            date_updated: None,
            parent_sid: None,
            sid: None,
            uri: None,
        }
    }
}


