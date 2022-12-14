# ApiV2010AccountRecording

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**account_sid** | Option<**String**> | The SID of the Account that created the resource | [optional]
**api_version** | Option<**String**> | The API version used during the recording. | [optional]
**call_sid** | Option<**String**> | The SID of the Call the resource is associated with | [optional]
**conference_sid** | Option<**String**> | The unique ID for the conference associated with the recording. | [optional]
**date_created** | Option<**String**> | The RFC 2822 date and time in GMT that the resource was created | [optional]
**date_updated** | Option<**String**> | The RFC 2822 date and time in GMT that the resource was last updated | [optional]
**start_time** | Option<**String**> | The start time of the recording, given in RFC 2822 format | [optional]
**duration** | Option<**String**> | The length of the recording in seconds. | [optional]
**sid** | Option<**String**> | The unique string that identifies the resource | [optional]
**price** | Option<**String**> | The one-time cost of creating the recording. | [optional]
**price_unit** | Option<**String**> | The currency used in the price property. | [optional]
**status** | Option<[**crate::models::RecordingEnumStatus**](recording_enum_status.md)> |  | [optional]
**channels** | Option<**i32**> | The number of channels in the final recording file as an integer. | [optional]
**source** | Option<[**crate::models::RecordingEnumSource**](recording_enum_source.md)> |  | [optional]
**error_code** | Option<**i32**> | More information about why the recording is missing, if status is `absent`. | [optional]
**uri** | Option<**String**> | The URI of the resource, relative to `https://api.twilio.com` | [optional]
**encryption_details** | Option<[**serde_json::Value**](.md)> | How to decrypt the recording. | [optional]
**subresource_uris** | Option<[**serde_json::Value**](.md)> | A list of related resources identified by their relative URIs | [optional]
**media_url** | Option<**String**> | The URL of the media file. | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


