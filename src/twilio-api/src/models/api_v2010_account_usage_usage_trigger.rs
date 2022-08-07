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
pub struct ApiV2010AccountUsageUsageTrigger {
    /// The SID of the Account that this trigger monitors
    #[serde(rename = "account_sid", skip_serializing_if = "Option::is_none")]
    pub account_sid: Option<String>,
    /// The API version used to create the resource
    #[serde(rename = "api_version", skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
    /// The HTTP method we use to call callback_url
    #[serde(rename = "callback_method", skip_serializing_if = "Option::is_none")]
    pub callback_method: Option<CallbackMethod>,
    /// he URL we call when the trigger fires
    #[serde(rename = "callback_url", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    /// The current value of the field the trigger is watching
    #[serde(rename = "current_value", skip_serializing_if = "Option::is_none")]
    pub current_value: Option<String>,
    /// The RFC 2822 date and time in GMT that the resource was created
    #[serde(rename = "date_created", skip_serializing_if = "Option::is_none")]
    pub date_created: Option<String>,
    /// The RFC 2822 date and time in GMT that the trigger was last fired
    #[serde(rename = "date_fired", skip_serializing_if = "Option::is_none")]
    pub date_fired: Option<String>,
    /// The RFC 2822 date and time in GMT that the resource was last updated
    #[serde(rename = "date_updated", skip_serializing_if = "Option::is_none")]
    pub date_updated: Option<String>,
    /// The string that you assigned to describe the trigger
    #[serde(rename = "friendly_name", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "recurring", skip_serializing_if = "Option::is_none")]
    pub recurring: Option<crate::models::UsageTriggerEnumRecurring>,
    /// The unique string that identifies the resource
    #[serde(rename = "sid", skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(rename = "trigger_by", skip_serializing_if = "Option::is_none")]
    pub trigger_by: Option<crate::models::UsageTriggerEnumTriggerField>,
    /// The value at which the trigger will fire
    #[serde(rename = "trigger_value", skip_serializing_if = "Option::is_none")]
    pub trigger_value: Option<String>,
    /// The URI of the resource, relative to `https://api.twilio.com`
    #[serde(rename = "uri", skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(rename = "usage_category", skip_serializing_if = "Option::is_none")]
    pub usage_category: Option<crate::models::UsageTriggerEnumUsageCategory>,
    /// The URI of the UsageRecord resource this trigger watches
    #[serde(rename = "usage_record_uri", skip_serializing_if = "Option::is_none")]
    pub usage_record_uri: Option<String>,
}

impl ApiV2010AccountUsageUsageTrigger {
    pub fn new() -> ApiV2010AccountUsageUsageTrigger {
        ApiV2010AccountUsageUsageTrigger {
            account_sid: None,
            api_version: None,
            callback_method: None,
            callback_url: None,
            current_value: None,
            date_created: None,
            date_fired: None,
            date_updated: None,
            friendly_name: None,
            recurring: None,
            sid: None,
            trigger_by: None,
            trigger_value: None,
            uri: None,
            usage_category: None,
            usage_record_uri: None,
        }
    }
}

/// The HTTP method we use to call callback_url
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum CallbackMethod {
    #[serde(rename = "HEAD")]
    HEAD,
    #[serde(rename = "GET")]
    GET,
    #[serde(rename = "POST")]
    POST,
    #[serde(rename = "PATCH")]
    PATCH,
    #[serde(rename = "PUT")]
    PUT,
    #[serde(rename = "DELETE")]
    DELETE,
}

impl Default for CallbackMethod {
    fn default() -> CallbackMethod {
        Self::HEAD
    }
}

