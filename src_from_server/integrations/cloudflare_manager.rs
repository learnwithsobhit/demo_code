use crate::config::ServerConfig;
use crate::database::Database;
use crate::integrations::cloudflare_client::{CloudflareStreamClient, VideoDetails};
use common::{common::TimeUuid, errors::Error, timestamp};
use futures::future::{AbortHandle, Abortable};
use log::*;
use std::collections::{BinaryHeap, HashSet, VecDeque};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

///
/// How frequently we should poll Cloudflare Stream API to see if the conversion of a given video is complete
///
pub const POLLING_INTERVAL_MS: u64 = 10_000;

///
/// If polling a video fails this many times in a row, declare it failed and stop polling
///
pub const MAX_CONSECUTIVE_FAILURES: u32 = 15;

///
/// VideoStatusPoller -- used to poll the Cloudflare Stream API to determine the status of a video,
/// i.e., uploading, transcoding, or completed and ready for playback.
///
/// Note that Cloudflare Stream also supports Webhooks -- but we can't easily use them here as they
/// only support a single subscription, which won't be easy to use when we have multiple backend servers
///
/// Internally, the VideoStatusPoller uses a single thread to perform scheduling, but uses the provided
/// Tokio runtime to execute the polling/checks asynchronously; i.e., we hand off items to Tokio; the
/// tasks will re-add themselves to the queue for future polling when necessary (if not complete, or if check fails)
///
pub struct CloudflareStreamManager {
    state: ThreadState,
}

///
/// Details for one video that should be polled
///
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VideoPollingDetails {
    pub video_id: TimeUuid,
    pub cloudflare_id: String,
    pub next_poll_ms: u64,
    pub failure_count: u32,
}

///
/// Queue for processing videos
/// BinaryHeap contains all videos to be polled, ordered by next polling timestamp (next first)
/// HashSet provides O(1) existence lookup, by UUID
///
struct VideoQueue {
    set: HashSet<TimeUuid>,
    queue: BinaryHeap<VideoPollingDetails>,
}

/// State for the poller
#[derive(Clone)]
pub struct ThreadState {
    node_id: String,
    queue: Arc<RwLock<VideoQueue>>,
    db: Arc<Database>,
    csc: Arc<CloudflareStreamClient>,
    _http_client: Arc<reqwest::Client>,
    shutdown: Arc<AtomicBool>,
    /// Abort handle. Used to wake the thread when a new video is added to the poller - otherwise
    /// the thread will sleep until the next polling time
    sleep_abort_handle: Arc<Mutex<Option<AbortHandle>>>,
}

impl CloudflareStreamManager {
    ///
    /// Get a reference to the Cloudflare Stream client
    ///
    pub async fn get_cloudflare_client(&self) -> Arc<CloudflareStreamClient> {
        self.state.csc.clone()
    }

    ///
    /// Initialize the VideoStatusPoller
    /// NOTE:
    ///
    /// # Arguments
    /// * `rt`: reference to the Tokio runtime instance to use
    /// * `db`: Database instance
    /// * `csc`: Cloudflare Stream client instance
    /// * `http_client`: Reqwest HTTP client
    ///
    pub async fn new(
        node_id: String,
        db: Arc<Database>,
        config: &ServerConfig,
    ) -> Result<CloudflareStreamManager, Error> {
        debug!("Initializing CloudflareStreamManager");
        //, csc: Arc<CloudflareStreamClient>, http_client: Arc<reqwest::Client>
        let csc = Arc::new(CloudflareStreamClient::new(
            config.cloudflare_stream_acct_id.clone(),
            config.cloudflare_stream_key.clone(),
        ));
        let http_client = Arc::new(reqwest::Client::new());

        let shutdown = Arc::new(AtomicBool::new(false));

        let state = ThreadState {
            node_id,
            queue: Default::default(),
            db,
            csc,
            _http_client: http_client,
            shutdown,
            sleep_abort_handle: Default::default(),
        };

        let vsp = CloudflareStreamManager { state };
        vsp.start_thread().await;

        // Query the database to discover any in-progress videos that this node is responsible for
        // This is designed to handle the case where the server is restarted - i.e., the CloudflareStreamManager
        // should continue polling the videos it was handling before it restarted
        let uploads = vsp
            .state
            .db
            .video_uploads_list_in_progress_for_node(&vsp.state.node_id)
            .await?;
        if !uploads.is_empty() {
            info!(
                "CloudflareStreamManager: adding {} videos to polling queue on initialization",
                uploads.len()
            );
        }
        for u in uploads {
            vsp.add(u.id.unwrap()).await;
        }

        Ok(vsp)
    }

    ///
    /// Add a video to the poller
    /// Note: if the video is already being polled, this will be a no-op (i.e., we don't poll the
    /// same video multiple times in parallel)
    ///
    /// # Arguments
    /// * `video_id`: Platform Id of the video content to be polled
    ///
    pub async fn add(&self, video_id: TimeUuid) {
        let data = self.state.queue.clone();
        let sleep_abort_handle = self.state.sleep_abort_handle.clone();

        let db = self.state.db.clone();

        tokio::spawn(async move {
            // TODO error handling
            let cloudflare_id = db
                .video_upload_cloudflare_id(&video_id)
                .await
                .unwrap()
                .unwrap();
            let mut guard = data.write().await;
            let vpd = VideoPollingDetails::new(video_id, cloudflare_id);
            guard.add(vpd, false);

            // Wake up thread for polling
            let mut guard = sleep_abort_handle.lock().await;
            if guard.is_some() {
                let ah = guard.take().unwrap();
                ah.abort();
            }
        });
    }

    ///
    /// Start thread that will handle polling of Cloudflare Stream
    ///
    async fn start_thread(&self) {
        let state = self.state.clone();

        tokio::spawn(async move {
            while !state.shutdown.load(Ordering::SeqCst) {
                // Get set of videos to process, this iteration
                let mut write_guard = state.queue.write().await;
                let to_process = write_guard.next_all(timestamp());

                if to_process.is_some() {
                    // Process each pending video - asynchronously
                    for vpd in to_process.unwrap() {
                        info!("Processing (polling) video: {:?}", vpd);
                        let state2 = state.clone();
                        tokio::spawn(async move {
                            // Record in database that this node will be polling the video
                            // This mechanism is used for high availability / fault tolerance - i.e., if
                            // this node goes down, other nodes can take over polling for this video
                            let update_ts_result = state2
                                .db
                                .video_upload_update_polled_timestamp(
                                    &vpd.video_id,
                                    &state2.node_id,
                                )
                                .await;
                            if let Err(e) = update_ts_result {
                                warn!(
                                    "Failed to update 'last polled' timestamp for video: {:?} {:?}",
                                    vpd.video_id, e
                                )
                            }

                            // Query Cloudflare Stream API to see if video has been uploaded + transcoded (ready to stream) yet
                            let mut vpd = vpd;
                            let state = state2;
                            let status_result =
                                state.csc.get_video_status(&vpd.cloudflare_id).await;

                            if let Err(e) = status_result {
                                warn!(
                                    "Poller failed to get video status for video {}: {:?}",
                                    vpd.video_id, e
                                );
                                // Push back to queue for re-processing
                                push_to_queue(
                                    true,
                                    vpd,
                                    state.queue,
                                    &state.sleep_abort_handle,
                                    state.db.deref(),
                                )
                                .await;
                                return;
                            } else {
                                let vd = status_result.unwrap();
                                if vd.ready_to_stream {
                                    info!("Video is ready to stream: video={:?}", vpd.video_id);
                                    process_completed_video(
                                        vpd,
                                        vd,
                                        state.db.as_ref(),
                                        state.queue.as_ref(),
                                    )
                                    .await;
                                } else {
                                    info!("Video is NOT ready to stream: {}", vpd.video_id);
                                    // Not ready yet. Push back to queue for checking again in future
                                    vpd.next_poll_ms = timestamp() + POLLING_INTERVAL_MS;
                                    vpd.failure_count = 0;
                                    push_to_queue(
                                        false,
                                        vpd,
                                        state.queue,
                                        &state.sleep_abort_handle,
                                        state.db.deref(),
                                    )
                                    .await;
                                }
                            }
                        });
                    }
                }

                // Work out how long to sleep until next iteration
                if let Some(next_poll_ms) = write_guard.next_polling_timestamp() {
                    // Sleep until the next processing time. We can exit sleep in either of 2 ways:
                    // (a) Time is up
                    // (b) Interrupted because of posting a new item
                    let now = timestamp();
                    let sleep_time = &next_poll_ms - now;
                    drop(write_guard);
                    if sleep_time > 0 {
                        trace!("Sleeping for {} milliseconds...", sleep_time);
                        let sleep_future = tokio::time::sleep(Duration::from_millis(sleep_time));
                        let (abort_handle, reg) = AbortHandle::new_pair();
                        let abortable_sleep = Abortable::new(sleep_future, reg);
                        *state.sleep_abort_handle.lock().await = Some(abort_handle);
                        // Sleep until interrupted, or until time runs out
                        let _result = abortable_sleep.await;
                    } else {
                        trace!(
                            "Next polling time: {}, now={}, sleep time={}",
                            next_poll_ms,
                            now,
                            sleep_time
                        );
                    }
                } else {
                    // No data at all
                    drop(write_guard);
                    trace!("Sleeping for {} ms seconds (no data)", POLLING_INTERVAL_MS);
                    let sleep_future =
                        tokio::time::sleep(Duration::from_millis(POLLING_INTERVAL_MS));
                    let (abort_handle, reg) = AbortHandle::new_pair();
                    let abortable_sleep = Abortable::new(sleep_future, reg);
                    *state.sleep_abort_handle.lock().await = Some(abort_handle);
                    // Sleep until interrupted, or until time runs out
                    let _result = abortable_sleep.await;
                }
            }
        });
    }

    pub async fn upload_cancelled(&self, uuid: &TimeUuid) {
        self.state.queue.write().await.on_cancel(uuid);
    }
}

impl Default for VideoQueue {
    fn default() -> Self {
        VideoQueue::new()
    }
}

impl VideoQueue {
    pub fn new() -> VideoQueue {
        VideoQueue {
            set: Default::default(),
            queue: Default::default(),
        }
    }

    ///
    /// Add - or re-add - an item to the queue
    ///
    /// # Arguments
    /// * 'vpd`: Video polling details
    /// * `resubmit`: If false, this is a new task that hasn't previosuly been in the queue.
    ///   If true, we are re-adding to the queue after polling. In this case, we expect the set
    ///   to still contain the reference to the item - unless it has been cancelled (at which point
    ///   we should ignore the re-add request
    ///
    pub fn add(&mut self, vpd: VideoPollingDetails, resubmit: bool) {
        if !resubmit {
            // New item
            if !self.set.contains(&vpd.video_id) {
                // Only add if not already in the processing queue
                debug!(
                    "Added video to VideoStatusPoller: video={}, cloudflare_id={}",
                    vpd.video_id, vpd.cloudflare_id
                );
                self.set.insert(vpd.video_id.clone());
                self.queue.push(vpd);
            }
        } else {
            // Re-add existing item
            if !self.set.contains(&vpd.video_id) {
                // No-op - the item was cancelled while it was being polled
                return;
            } else {
                self.queue.push(vpd);
            }
        }
    }

    ///
    /// Determine the timestamp when the next video should be polled (if any videos are present
    /// in the queue)
    ///
    pub fn next_polling_timestamp(&self) -> Option<u64> {
        if let Some(vpd) = self.queue.peek() {
            Some(vpd.next_poll_ms)
        } else {
            None
        }
    }

    ///
    /// Get the next video to poll
    ///
    pub fn next(&mut self, now: u64) -> Option<VideoPollingDetails> {
        self.remove_cancelled();

        if let Some(v) = self.queue.peek() {
            if v.next_poll_ms <= now {
                Some(self.queue.pop().unwrap())
            } else {
                None
            }
        } else {
            None
        }
    }

    ///
    /// Get all of the videos that should be polled now
    ///
    pub fn next_all(&mut self, now: u64) -> Option<VecDeque<VideoPollingDetails>> {
        let mut out = VecDeque::new();

        while let Some(v) = self.next(now) {
            out.push_back(v);
        }

        if !out.is_empty() {
            Some(out)
        } else {
            None
        }
    }

    ///
    /// To be called when a polling task has been processed successfully, or has failed enough
    /// times to be removed from queue
    ///
    pub fn on_completion_or_failure(&mut self, uuid: &TimeUuid) {
        // On completion or failure, the task in only in the set - just remove it from there
        self.set.remove(uuid);
    }

    ///
    /// To be called when a polling task is to be cancelled
    ///
    pub fn on_cancel(&mut self, uuid: &TimeUuid) {
        // On cancellation, the queue may, or may not contain the video
        // Contains if: not currently being polled
        // Does not contain if: being polled concurrently by another task

        // Remove from the set, but if present in the BinaryHeap leave it there.
        // Next time it comes up in the binary heap we'll ignore it
        self.set.remove(uuid);
    }

    ///
    /// Remove cancelled videos from the queue (Binary Heap)
    /// If a video has been cancelled, it won't be in the set - but it will be in the queue
    /// This function returns any cancelled videos from the top of the queue (heap) before returning.
    /// It does not return _all_ cancelled items
    ///
    fn remove_cancelled(&mut self) {
        // Note - &mut self means we don't need to worry about race conditions for queue

        while !self.queue.is_empty() {
            if let Some(v) = self.queue.peek() {
                if !self.set.contains(&v.video_id) {
                    self.queue.pop();
                } else {
                    break;
                }
            }
        }
    }
}

async fn process_completed_video(
    vpd: VideoPollingDetails,
    vd: VideoDetails,
    db: &Database,
    queue: &RwLock<VideoQueue>,
) {
    queue.write().await.on_completion_or_failure(&vpd.video_id);

    let summary_details = (&vd).into();
    let result = db
        .video_upload_finalize(&vpd.video_id, summary_details)
        .await;

    // TODO error handling
    if let Err(e) = result {
        warn!("Failed to finalize video: {:?} - {:?}", vpd, e);
    }
}

async fn push_to_queue(
    failure: bool,
    mut vpd: VideoPollingDetails,
    queue: Arc<RwLock<VideoQueue>>,
    sleep_abort_handle: &Mutex<Option<AbortHandle>>,
    db: &Database,
) {
    if vpd.failure_count >= MAX_CONSECUTIVE_FAILURES {
        warn!(
            "Video failed to poll/post {} times - removing video from polling queue: video={}",
            vpd.failure_count, vpd.video_id
        );
        if let Err(e) = db.video_upload_failed(&vpd.video_id).await {
            warn!(
                "Failed to mark video as failed in database: {:?}: {:?}",
                vpd, e
            );
        }
        queue.write().await.on_completion_or_failure(&vpd.video_id);
        return;
    }

    if failure {
        vpd.failure_count += 1;
    } else {
        vpd.failure_count = 0;
    }
    vpd.next_poll_ms = timestamp() + POLLING_INTERVAL_MS;

    let mut guard = queue.write().await;
    guard.add(vpd, true);

    // Wake thread to wake it up, so it knows that it needs to process the item
    let mut guard = sleep_abort_handle.lock().await;
    if guard.is_some() {
        let ah = guard.take().unwrap();
        ah.abort();
    }
}

impl VideoPollingDetails {
    pub fn new(video_id: TimeUuid, cloudflare_id: String) -> VideoPollingDetails {
        VideoPollingDetails {
            video_id,
            cloudflare_id,
            next_poll_ms: 0,
            failure_count: 0,
        }
    }
}

impl PartialOrd for VideoPollingDetails {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VideoPollingDetails {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Smallest first
        other.next_poll_ms.cmp(&self.next_poll_ms)
    }
}
