use common::content::VideoDetailsSummary;
use http::StatusCode;
use log::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

///
/// Maximum number of seconds a video may be. If a user attempts to upload a video longer than this,
/// Cloudflare is configured to reject it.
/// This should be checked client side before the upload is started however, so it should never be
/// actually needed, but is kept as a backup/redundant check
///
pub const VIDEO_MAX_SECONDS: u32 = 90;

///
/// After initializing the upload URL in Cloudflare, how long should it be available?
/// Default (if not otherwise set) in Cloudflare is 30 minutes
/// Here, we're setting it to 1hr
///
pub const CLOUDFLARE_UPLOAD_URL_EXPIRY_MS: u64 = 3_600_000;

/// Default jpg thumbnail height
pub const THUMBNAIL_JPG_HEIGHT: u32 = 1024;

/// Default gif thumbnail height
pub const THUMBNAIL_GIF_HEIGHT: u32 = 512;

/// Default gif thumbnail frames per second (FPS)
pub const THUMBNAIL_GIF_FPS: u32 = 8;

/// Default gif thumbnail gif length (seconds)
pub const THUMBNAIL_GIF_LENGTH_SEC: u32 = 10;

///
/// Details for a direct upload
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectUploadDetails {
    pub uid: String,
    pub url: String,
    /// Expiry timestamp, UTC epoch milliseconds
    pub expiry_timestamp: u64,
}

///
/// Response for listing videos
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListVideosResponse {
    pub success: bool,
    pub errors: Vec<String>,
    pub messages: Vec<String>,
    pub result: Vec<VideoDetails>,
    pub total: Option<String>,
    pub range: Option<String>,
}

///
/// Response from Cloudflare Stream -- details of a single video
///
/// Format: https://api.cloudflare.com/#stream-videos-list-videos
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoDetails {
    #[serde(alias = "allowedOrigins")]
    pub allowed_origins: Option<Vec<String>>,
    pub created: Option<String>,
    /// Duration of the video, in seconds (if known/available)
    pub duration: Option<f32>,
    pub input: Option<VideoInput>,
    #[serde(alias = "maxDurationSeconds")]
    pub max_duration_seconds: Option<u32>,
    pub meta: Option<HashMap<String, String>>,
    pub modified: Option<String>,
    pub playback: Option<VideoPlayback>,
    pub preview: Option<String>,
    #[serde(alias = "readyToStream")]
    pub ready_to_stream: bool,
    #[serde(alias = "requireSignedURLs")]
    pub require_signed_urls: bool,
    pub size: u32,
    pub status: VideoStatus,
    pub thumbnail: String,
    #[serde(alias = "thumbnailTimestampPct")]
    pub thumbnail_ts_pct: f32,
    pub uid: String,
    #[serde(alias = "maxSizeBytes")]
    pub max_size_bytes: Option<u64>,
    pub uploaded: Option<String>,
    #[serde(alias = "uploadExpiry")]
    pub upload_expiry: Option<String>,
    pub watermark: Option<Watermark>,
    pub nft: Option<NFT>,
}

///
/// VideoDetails instance wrapped in a result (returned by Cloudflare)
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoDetailsResult {
    result: VideoDetails,
}

///
/// Details for the original input video (height and width resolution)
/// Note Cloudflare Stream may return -1 for these if it is not yet known
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoInput {
    pub height: i32,
    pub width: i32,
}

///
/// URLs for playback - HLS (for Apple devices) and DASH formats
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoPlayback {
    pub hls: String,
    pub dash: String,
}

///
/// Status for the video
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VideoStatus {
    state: String,
    #[serde(alias = "pctComplete")]
    pct_complete: Option<String>,
}

///
/// Details of the watermark applied to the video.
/// Not currently used in the Platform
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Watermark {
    uid: String,
    size: u32,
    height: u32,
    width: u32,
    created: String,
    #[serde(alias = "downloadedFrom")]
    downloaded_from: String,
    name: String,
    opacity: f32,
    padding: f32,
    scale: f32,
    position: String,
}

///
/// NFT details. Not currently used in the Platform
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NFT {
    pub contract: String,
    pub token: u64,
}

///
/// ID of the watermark applied to the video. Not currently used in the Platform
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatermarkID {
    uid: String,
}

///
/// Direct creator upload request: https://developers.cloudflare.com/stream/uploading-videos/direct-creator-uploads
/// Only maxDurationSeconds is required by cloudflare, all other arguments are optional: https://api.cloudflare.com/#stream-videos-create-a-video-and-get-authenticated-direct-upload-url
/// However we'll enforce requireSignedURLS for hotlink protection (should always be set to true)
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectUploadRequest {
    #[serde(rename = "maxDurationSeconds")]
    pub max_duration_seconds: u32,
    /// Upload endpoint expiry, in UTC RFC3339 format - "2020-04-06T02:20:00Z"
    /// Cloudflare's default expiry if not set: 30 minutes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(rename = "requireSignedURLs")]
    pub require_signed_urls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origins: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_timestamp_pct: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watermark: Option<WatermarkID>,
    /// Metadata - can include arbitrary keys
    pub meta: Option<HashMap<String, String>>,
}

///
/// Response to a request to create a direct upload endpoint
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectUploadResponse {
    pub success: bool,
    pub errors: Vec<String>,
    pub messages: Vec<String>,
    result: Option<DirectUploadResponseResult>,
}

///
/// Response to a request to create a direct upload endpoint
///
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectUploadResponseResult {
    #[serde(rename = "uploadURL")]
    pub upload_url: String,
    pub uid: String,
    pub watermark: Option<Watermark>,
}

///
/// Error from Cloudflare Stream client
///
#[derive(Debug, thiserror::Error)]
pub enum CloudflareError {
    #[error("Request error: {0:?}")]
    RequestError(reqwest::Error),
    #[error("Response error: {0:?}")]
    ResponseError(StatusCode, Option<String>),
    #[error("JSON deserialization error: {0:?}")]
    JsonError(reqwest::Error),
    #[error("JSON deserialization error: {0:?}")]
    JsonError2(serde_json::Error),
    #[error("Response error: {0:?}")]
    DirectUploadInit(DirectUploadResponse),
    #[error("Error: {0:?}")]
    Error(String),
}

///
/// Cloudflare Stream client instance
///
#[derive(Debug)]
pub struct CloudflareStreamClient {
    pub client: Arc<reqwest::Client>,
    account_id: String,
    key: String,
}

impl CloudflareStreamClient {
    pub fn new(account_id: String, key: String) -> CloudflareStreamClient {
        CloudflareStreamClient {
            client: Arc::new(reqwest::Client::new()),
            account_id,
            key,
        }
    }

    ///
    /// List all videos on the account
    /// TODO expand this to support pagination!
    ///
    pub async fn list_videos(&self) -> Result<ListVideosResponse, CloudflareError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/stream",
            self.account_id
        );
        let result = self
            .client
            .get(url)
            .header("Authorization", &format!("Bearer {}", self.key))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .send()
            .await?;

        let status = result.status();
        if !status.is_success() {
            let body = result.text().await;
            let body = body.map(|s| Some(s)).unwrap_or(None);
            warn!(
                "Cloudflare Stream video listing request failed: {:?} {:?}",
                status, body
            );
            Err(CloudflareError::ResponseError(status, body))
        } else {
            // let temp = result.text().await.unwrap();
            // info!("==========\n{}\n==========", temp);
            // let json_result: Result<ListVideosResponse, serde_json::Error> = serde_json::from_str(&temp);
            let json_result: Result<ListVideosResponse, reqwest::Error> = result.json().await;
            if let Err(e) = json_result {
                warn!(
                    "Error deserializing response from Cloudflare list_videos request: {:?}",
                    e
                );
                return Err(CloudflareError::JsonError(e));
                // panic!();
            }
            Ok(json_result.unwrap())
        }
    }

    ///
    /// Initialize a direct upload endpoint.
    /// NOTE: This uses the TUS protocol option (i.e., split, resumable, etc), not the simple direct
    /// upload option that doesn't support splitting uploads, resuming, etc.
    ///
    /// # Arguments
    /// * `upload_bytes`: the number of bytes of the file to be uploaded
    ///
    pub async fn init_direct_upload(
        &self,
        upload_bytes: u32,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<DirectUploadDetails, CloudflareError> {
        // https://developers.cloudflare.com/stream/uploading-videos/direct-creator-uploads

        use chrono::{DateTime, Utc};
        let now: DateTime<Utc> = Utc::now();
        let expiry = now + chrono::Duration::milliseconds(CLOUDFLARE_UPLOAD_URL_EXPIRY_MS as i64);
        let expiry_timestamp = expiry.timestamp_millis() as u64;
        let expiry_rfc3339 = expiry.to_rfc3339();

        let body = DirectUploadRequest {
            max_duration_seconds: VIDEO_MAX_SECONDS,
            // Default in Cloudflare if not set: 30 minutes
            expiry: Some(expiry_rfc3339),
            // Require signed URLs: i.e., don't allow hot-linking or viewing outside of the Platform
            require_signed_urls: true,
            allowed_origins: None,
            thumbnail_timestamp_pct: None,
            watermark: None,
            meta: metadata,
        };

        // https://developers.cloudflare.com/stream/uploading-videos/direct-creator-uploads#using-tus-recommended-for-videos-over-200mb
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/stream?direct_user=true",
            self.account_id
        );
        let result = self
            .client
            .post(url)
            .header("Authorization", &format!("Bearer {}", self.key))
            .header("Tus-Resumable", "1.0.0")
            .header("Upload-Length", upload_bytes)
            .json(&body)
            .send()
            .await?;

        let status = result.status();
        if !status.is_success() {
            let body = result.text().await;
            let body = body.map(|s| Some(s)).unwrap_or(None);
            warn!(
                "Cloudflare Stream - initializing direct upload failed: {:?} {:?}",
                status, body
            );
            Err(CloudflareError::ResponseError(status, body))
        } else {
            // With TUS uploads, the details are in the HEADERS - not the body
            let headers = result.headers();

            let url: String = if let Some(l) = headers.get("location") {
                l.to_str().unwrap().to_string()
            } else {
                return Err(CloudflareError::Error(
                    "Response is missing required 'location' header".to_string(),
                ));
            };
            let uid: String = if let Some(s) = headers.get("stream-media-id") {
                s.to_str().unwrap().to_string()
            } else {
                return Err(CloudflareError::Error(
                    "Response is missing required 'stream-media-id' header".to_string(),
                ));
            };

            Ok(DirectUploadDetails {
                uid,
                url,
                expiry_timestamp, //TODO expiry isn't actually passed to cloudflare!
            })
        }
    }

    pub async fn delete_video(&self, cf_video_id: &str) -> Result<(), CloudflareError> {
        // https://api.cloudflare.com/#stream-videos-delete-video

        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/stream/{}",
            self.account_id, cf_video_id
        );
        let result = self
            .client
            .delete(url)
            .header("Authorization", &format!("Bearer {}", self.key))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .send()
            .await?;

        let status = result.status();
        if !status.is_success() {
            let body = result.text().await;
            let body = body.map(|s| Some(s)).unwrap_or(None);
            warn!(
                "Cloudflare Stream video deletion request failed: {:?} {:?}",
                status, body
            );
            Err(CloudflareError::ResponseError(status, body))
        } else {
            Ok(())
        }
    }

    pub async fn get_video_status(
        &self,
        cf_video_id: &str,
    ) -> Result<VideoDetails, CloudflareError> {
        // https://developers.cloudflare.com/stream/#step-2-wait-until-the-video-is-ready-to-stream
        // https://api.cloudflare.com/#stream-videos-video-details

        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/stream/{}",
            self.account_id, cf_video_id
        );
        let result = self
            .client
            .get(url)
            .header("Authorization", &format!("Bearer {}", self.key))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .send()
            .await?;

        let status = result.status();
        if !status.is_success() {
            let body = result.text().await;
            let body = body.map(|s| Some(s)).unwrap_or(None);
            warn!(
                "Cloudflare Stream video status request failed: {} {:?} {:?}",
                cf_video_id, status, body
            );
            Err(CloudflareError::ResponseError(status, body))
        } else {
            let txt = result.text().await;
            if let Err(e) = txt {
                warn!(
                    "Cloudflare Stream video status request: could not get body: {:?}",
                    e
                );
                return Err(CloudflareError::RequestError(e));
            }
            let txt = txt.unwrap();

            let vd_result: Result<VideoDetailsResult, serde_json::Error> =
                serde_json::from_str(&txt);
            if let Err(e) = vd_result {
                warn!(
                    "Cloudflare Stream video status deserialization failed: {} {:?}",
                    cf_video_id, e
                );
                debug!("Cloudflare Stream video status JSON: {}", txt);
                return Err(CloudflareError::JsonError2(e));
            }

            Ok(vd_result.unwrap().result)
        }
    }

    ///
    /// Get the animated GIF thumbnail URL, given the .jpg thumbnail URL
    ///
    pub fn thumbnail_gif_from_jpg_url(jpg_url: String) -> String {
        jpg_url.replace(
            ".jpg",
            &format!(
                ".gif?height={}&duration={}s&fps={}",
                THUMBNAIL_GIF_HEIGHT, THUMBNAIL_GIF_LENGTH_SEC, THUMBNAIL_GIF_FPS
            ),
        )
    }

    ///
    /// Get the jpg thumbnail URL with the default image height, given the .jpg thumbnail URL
    ///
    pub fn thumbnail_jpg_with_size(jpg_url: String) -> String {
        jpg_url + &format!("?height={}", THUMBNAIL_JPG_HEIGHT)
    }
}

impl CloudflareStreamClient {
    pub fn clone(&self) -> CloudflareStreamClient {
        CloudflareStreamClient::new(self.account_id.clone(), self.key.clone())
    }
}

impl From<reqwest::Error> for CloudflareError {
    fn from(e: reqwest::Error) -> Self {
        CloudflareError::RequestError(e)
    }
}

impl From<VideoDetails> for VideoDetailsSummary {
    fn from(vd: VideoDetails) -> Self {
        (&vd).into()
    }
}

impl From<&VideoDetails> for VideoDetailsSummary {
    fn from(vd: &VideoDetails) -> Self {
        VideoDetailsSummary {
            uid: vd.uid.clone(),
            duration: vd.duration.clone().map(|f| f.round() as u32).unwrap_or(0),
            hls_url: vd
                .playback
                .as_ref()
                .map(|p| p.hls.clone())
                .unwrap_or_else(|| "".to_string()),
            dash_url: vd
                .playback
                .as_ref()
                .map(|p| p.dash.clone())
                .unwrap_or_else(|| "".to_string()),
            thumbnail_static: vd.thumbnail.clone(),
            thumbnail_dynamic: vd.thumbnail.clone().replace(".jpg", ".gif"),
        }
    }
}
