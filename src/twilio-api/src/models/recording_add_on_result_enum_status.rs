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
pub enum RecordingAddOnResultEnumStatus {
    #[serde(rename = "canceled")]
    Canceled,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "deleted")]
    Deleted,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "in-progress")]
    InProgress,
    #[serde(rename = "init")]
    Init,
    #[serde(rename = "processing")]
    Processing,
    #[serde(rename = "queued")]
    Queued,

}

impl ToString for RecordingAddOnResultEnumStatus {
    fn to_string(&self) -> String {
        match self {
            Self::Canceled => String::from("canceled"),
            Self::Completed => String::from("completed"),
            Self::Deleted => String::from("deleted"),
            Self::Failed => String::from("failed"),
            Self::InProgress => String::from("in-progress"),
            Self::Init => String::from("init"),
            Self::Processing => String::from("processing"),
            Self::Queued => String::from("queued"),
        }
    }
}

impl Default for RecordingAddOnResultEnumStatus {
    fn default() -> RecordingAddOnResultEnumStatus {
        Self::Canceled
    }
}




