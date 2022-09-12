# Cloudflare Stream Integration - Developer Notes

Cloudflare Stream is a video hosting and transcoding service that we use for user video uploads, and
making videos available for streaming to users.  

This document provides some details regarding the Cloudflare Stream integration.  
The integration with Cloudflare Stream is sufficiently complex to warrant a written description/overview.


Our implementation has 2 components:
1. `CloudflareStreamClient` - an client used to interact with the Cloudflare Stream REST API
2. `CloudflareStreamManager` - a management service that handles processing of videos uploaded by users.
   Specifically, it polls Cloudflare Stream (every 10 seconds) to check if the user has finished uploading the video or 
   not, and whether transcoding is complete. Once the video is ready to stream, it removes the video from the 'in progress
   video uploads' table (`video_uploads`) and makes the video available in the content repository.
   
### Uploads

Uploads work as follows:
1. Client requests to perform a video upload to a specified content repository
2. Backend uses the CloudflareStreamClient to create an endpoint that the user can upload the video to, using the TUS protocol.
   This is via the 'direct creator uploads' feature: https://developers.cloudflare.com/stream/uploading-videos/direct-creator-uploads
3. The in-progress upload is added to the CloudflareStreamManager, and polling begins
4. The upload endpoint is returned to the client; they use it to upload the video (resumably) via TUS
5. Once the upload is complete, and the video is ready for streaming, CloudflareStreamManager will:
   - Remove the video from the `video_uploads` table (which stores in-progress video uploads)
   - Add to the content repository (`contents` table)


If the video upload is not completed, eventually it will time out.

If Cloudflare Stream is offline for an extended period of time, or another error occurs, eventually `CloudflareStreamManager`
will abandon polling the video, and will mark it as failed in the database (specifically, setting `video_uploads.upload_failed = true`).

As of 2022/02/23, these  `upload_failed` videos need to be checked and (if necessary) deleted from Cloudflare Stream manually,
to avoid paying for storage costs for a video that is no longer accessible.

Note that users can explicitly cancel uploads before completion.

### Deletion

Video deletion: when a video is deleted (i.e., the content repository item is deleted) it will also be deleted from
Cloudflare Stream. If deletion of the video from Cloudflare Stream fails (for example, due to an outage in Cloudflare Stream)
an entry is added to the `cloudflare_pending_video_deletions` table, so that it can be processed later.

App deletion: when an app deletion request is received, all of its content is deleted first. All videos for the app referenced
in the `contents` or `video_uploads` tables will be added to the `cloudflare_pending_video_deletions` table. We don't try to
delete all of the videos for the app in Cloudflare Stream synchronously, as this could take an unreasonable amount of time. 

Again, as of 2022/02/23, checking and deletion of videos added to the `cloudflare_pending_video_deletions` table needs to
be done manually.

### Database metadata

Because we want to support streaming videos from multiple locations (from Cloudflare Stream, from our own servers, or from
a cheaper video streaming CDN such as BunnyCDN) we don't hardcode the video URLs, thumbnail URLs etc in the `contents.data`
database field. Instead, we store the Cloudflare Stream metadata in the `contents.video_cfs_metadata` field, and fill in
the Protobuf/gRPC `Video` struct fields from this. In the future, we'll dynamically fill the Video URLs etc from the most
appropriate hosting location (i.e., the cheapest location such as our servers, unless our servers can't serve the required
bandwidth). 