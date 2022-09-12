use crate::database::common_types::RepoType;
use crate::integrations::cloudflare_client::CloudflareStreamClient;
use crate::integrations::cloudflare_manager::CloudflareStreamManager;
use crate::{config::ServerConfig, database::Database, Error};
use common::content::list_contents_request::SearchField;
use common::files::{DeleteFilesRequest, DeleteRepositoriesRequest};
use common::utils::{log_req, log_resp, validate_user_claims};
use common::uuid::generator::TimeUuidGenerator;
use common::{
    client_pool::SimpleInterceptor,
    common::{
        GetPropertyRequest, GetPropertyResponse, RemovePropertyRequest, RemovePropertyResponse,
        SetPropertyRequest, SetPropertyResponse, TimeUuid,
    },
    content::{
        content_service_server::{ContentService, ContentServiceServer},
        list_repositories_request::Order,
        *,
    },
    files::files_service_client::FilesServiceClient,
    user::UserClaims,
};
use log::warn;
use std::collections::HashMap;
use std::sync::Arc;
use tonic::{codegen::InterceptedService, transport::Channel, Response, Status};

// Type helper for gRPC client-side files download/upload interfaces
pub type FilesGrpcClient = FilesServiceClient<InterceptedService<Channel, SimpleInterceptor>>;

pub const CLOUDFLARE_STREAM_TUS_CHUNK_SIZE: u32 = 20_971_520;

pub struct ContentEndpoints {
    node_id: String,
    db: Arc<Database>,
    jwt_secret: String,
    /// File server client
    pool: Arc<common::client_pool::Pool<FilesGrpcClient>>,
    cloudflare_client: CloudflareStreamClient,
    cloudflare_mgr: Arc<CloudflareStreamManager>,
}

impl ContentEndpoints {
    ///
    ///
    /// # Arguments
    /// * `node_id`: Unique identifier for this server instance
    /// * `db`: Database reference
    /// * `config`: Server config
    /// * `cs_account_id`: Cloudflare Stream account ID
    /// * `cs_key`: Cloudflare Stream access/authorization key
    /// * `pool`: Files server client pool
    ///
    pub fn create(
        node_id: String,
        db: Arc<Database>,
        config: &ServerConfig,
        cs_account_id: &str,
        cs_key: &str,
        cloudflare_mgr: Arc<CloudflareStreamManager>,
        pool: Arc<common::client_pool::Pool<FilesGrpcClient>>,
    ) -> Result<ContentServiceServer<ContentEndpoints>, Error> {
        let ce = ContentEndpoints {
            node_id,
            db,
            jwt_secret: config.jwt_secret.to_string(),
            pool,
            cloudflare_client: CloudflareStreamClient::new(
                cs_account_id.to_string(),
                cs_key.to_string(),
            ),
            cloudflare_mgr,
        };

        Ok(ContentServiceServer::new(ce))
    }

    async fn check_add_content_permission(
        &self,
        req: &AddContentRequest,
        claims: &UserClaims,
    ) -> Result<(), Error> {
        // app id is used only if not platform_admin anyway
        let app_id = claims.app_id.unwrap_or(0);

        let repo_type_filter = if claims.is_platform_admin() {
            None
        } else {
            Some(RepoType::Normal)
        };

        let content = req.content.as_ref().unwrap();
        let repository = self
            .db
            .get_content_repository(content.repository_id, repo_type_filter)
            .await?
            .ok_or_else(|| {
                Error::content_repository_not_found(content.repository_id, "Repository not found")
            })?;

        // Adding may be performed atm by: repository owner or app admin only
        if claims.user_id != repository.creator_id && !claims.is_platform_admin() {
            if claims.is_app_admin() {
                let creator = self
                    .db
                    .get_user_by_id(repository.creator_id)
                    .await?
                    .expect("Creator exists");
                if creator.app_id.expect("App is set for creators") != app_id {
                    return Err(Error::not_authorized(
                        "User not permitted to add content to repository",
                    )
                    .into());
                }
            } else {
                return Err(Error::not_authorized(
                    "User not permitted to add content to repository",
                )
                .into());
            }
        }

        // Content creator must be set.
        // User is allowed to add contents in his own name.
        // Platfomr admin is allowed to confirm other user content is uploaded to file server.
        if content.creator_id == 0
            || (claims.user_id != content.creator_id && !claims.is_platform_admin())
        {
            return Err(Error::bad_request("Creator id invalid").into());
        }

        Ok(())
    }

    async fn get_content_creator_id(&self, repo_id: u64) -> Result<u64, Error> {
        let repo_data = self
            .db
            .get_content_repository(repo_id, None)
            .await?
            .ok_or_else(|| {
                Error::content_repository_not_found(repo_id, "Content repository not found")
            })?;

        let creator_id = repo_data.creator_id;
        Ok(creator_id)
    }
}

impl ContentEndpoints {}

#[tonic::async_trait]
impl ContentService for ContentEndpoints {
    async fn create_repository(
        &self,
        req: tonic::Request<CreateRepositoryRequest>,
    ) -> Result<Response<CreateRepositoryResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::create_repository", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let user_id = claims.user_id;

        let app_id = claims
            .app_id
            .ok_or_else(|| Error::bad_request("App id missing"))?; // TODO platform admin

        let repo = ContentRepository {
            name: req.get_ref().name.clone(),
            creator_id: user_id,
            ..Default::default()
        };

        let id = self
            .db
            .create_content_repository(repo, app_id, RepoType::Normal)
            .await?;

        let repository = self
            .db
            .get_content_repository(id, Some(RepoType::Normal))
            .await?
            .expect("Repository exists");

        let response = tonic::Response::new(CreateRepositoryResponse {
            repository: Some(repository),
        });

        log_resp(endpoint, &req, &start, user_id);

        Ok(response)
    }

    async fn delete_repository(
        &self,
        req: tonic::Request<DeleteRepositoryRequest>,
    ) -> Result<Response<DeleteRepositoryResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::delete_repository", &req);

        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;

        let repository = self
            .db
            .get_content_repository(req.get_ref().id, Some(RepoType::Normal))
            .await?
            .ok_or_else(|| {
                Error::content_repository_not_found(
                    req.get_ref().id,
                    "Content repository not found",
                )
            })?;

        if claims.user_id != repository.creator_id && !claims.is_platform_admin() {
            if claims.is_app_admin() {
                let creator = self
                    .db
                    .get_user_by_id(repository.creator_id)
                    .await?
                    .expect("Creator exists");
                if creator.app_id != claims.app_id {
                    return Err(Error::not_authorized(
                        "User not permitted to delete content repository",
                    )
                    .into());
                }
            } else {
                return Err(Error::not_authorized(
                    "User not permitted to delete content repository",
                )
                .into());
            }
        }

        let delete_req = tonic::Request::new(DeleteRepositoriesRequest {
            repository_ids: vec![req.get_ref().id],
        });
        if let Err(e) = self.pool.get().await?.delete_repositories(delete_req).await {
            let err: Error = e.into();
            let error = err.err.as_ref().unwrap();
            match error {
                common::errors::error::Err::ContentNotFound { .. }
                | common::errors::error::Err::RepositoryNotFound { .. } => {
                    // Nothing to delete
                }
                _ => {
                    // Propagate error
                    return Err(err.into());
                }
            }
        }

        self.db.delete_content_repository(req.get_ref().id).await?;

        let response = tonic::Response::new(DeleteRepositoryResponse {});

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }

    async fn list_repositories(
        &self,
        req: tonic::Request<ListRepositoriesRequest>,
    ) -> Result<Response<ListRepositoriesResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::list_repositories", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;

        let (creator_id, app_id) = if let Some(id) = req.get_ref().user_id {
            let creator = self
                .db
                .get_user_by_id(id)
                .await?
                .ok_or_else(|| Error::user_not_found(id, "User not found"))?;

            if creator.app_id != claims.app_id {
                return Err(Error::not_authorized("Cross app content browsing not allowed").into());
            }

            (Some(id), None)
        } else {
            if let Some(app_id) = claims.app_id {
                (None, Some(app_id))
            } else {
                // TODO - platform admin
                unimplemented!()
            }
        };
        let order_by = Order::from_i32(req.get_ref().order_by).unwrap_or(Order::Created);

        let list = self
            .db
            .list_content_repository(
                creator_id,
                app_id,
                order_by,
                req.get_ref().desc,
                Some(RepoType::Normal),
            )
            .await?;

        let response = tonic::Response::new(ListRepositoriesResponse { list });

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }

    async fn add_content(
        &self,
        req: tonic::Request<AddContentRequest>,
    ) -> Result<Response<AddContentResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::add_content", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;

        self.check_add_content_permission(req.get_ref(), &claims)
            .await?;

        // app id is used only if not platform_admin anyway
        let app_id = match claims.app_id {
            Some(v) => v,
            None => {
                let repo = self
                    .db
                    .get_content_repository(
                        req.get_ref().content.as_ref().unwrap().repository_id,
                        None,
                    )
                    .await?
                    .expect("Already checked in check_add_content_permission above");

                self.db
                    .get_user_by_id(repo.creator_id)
                    .await?
                    .expect("Creator exists")
                    .app_id
                    .unwrap()
            }
        };

        let content = req.get_ref().content.as_ref().unwrap();

        self.db.add_content(app_id, content).await?;

        let response = tonic::Response::new(AddContentResponse {});

        log_resp(endpoint, &req, &start, claims.user_id);
        Ok(response)
    }

    async fn delete_content(
        &self,
        req: tonic::Request<DeleteContentRequest>,
    ) -> Result<Response<DeleteContentResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::delete_content", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;

        let app_id = claims
            .app_id
            .ok_or_else(|| Error::bad_request("App id missing"))?; // TODO platform admin

        let repository_id = req.get_ref().repository_id;
        let uuid = req.get_ref().uuid.as_ref().unwrap();
        let repository = self
            .db
            .get_content_repository(repository_id, Some(RepoType::Normal))
            .await?
            .ok_or_else(|| {
                Error::content_repository_not_found(repository_id, "Repository not found")
            })?;
        let content = self
            .db
            .get_content(repository_id, uuid)
            .await?
            .ok_or_else(|| {
                Error::content_not_found(repository_id, uuid.to_string(), "Content not found")
            })?;

        // Delete may be performed by: content creator, repository owner, app admin and platform admin only
        if claims.user_id != content.creator_id
            && repository.creator_id != claims.user_id
            && !claims.is_platform_admin()
        {
            if claims.is_app_admin() {
                let creator = self
                    .db
                    .get_user_by_id(repository.creator_id)
                    .await?
                    .expect("Creator exists");
                if creator.app_id.expect("App is set for creators") != app_id {
                    return Err(Error::not_authorized(
                        "User not permitted to delete content repository",
                    )
                    .into());
                }
            } else {
                return Err(Error::not_authorized(
                    "User not permitted to delete content repository",
                )
                .into());
            }
        }

        match content.metadata {
            // Need to delete from file server
            Some(common::content::content::Metadata::F(_))
            | Some(common::content::content::Metadata::I(_)) => {
                let file_req = tonic::Request::new(DeleteFilesRequest {
                    repository_ids: vec![repository_id],
                    uuids: vec![req.get_ref().uuid.as_ref().unwrap().clone()],
                });
                if let Err(e) = self.pool.get().await?.delete_files(file_req).await {
                    let err: Error = e.into();
                    let error = err.err.as_ref().unwrap();
                    match error {
                        common::errors::error::Err::ContentNotFound { .. }
                        | common::errors::error::Err::RepositoryNotFound { .. } => {
                            // Nothing to delete
                        }
                        _ => {
                            // Propagate error
                            return Err(err.into());
                        }
                    }
                }
            }
            _ => (),
        }

        // If content is a video that is hosted in Cloudflare Stream, it should also be deleted there
        match content.metadata.as_ref().unwrap() {
            common::content::content::Metadata::V(_v) => {
                if let Some(details) = self.db.get_content_cloudflare_metadata(uuid).await? {
                    if let Err(e) = self.cloudflare_client.delete_video(&details.uid).await {
                        // In case the deletion fails, store details in the database so we can manually delete it later,
                        // or try again (in case this was just a temporary issue). Otherwise, we keep paying the storage
                        // for a video nobody can view
                        warn!(
                            "Failed to delete video from Cloudflare Stream: {} - {:?}, {:?}",
                            uuid, details, e
                        );
                        let last_error = format!("{:?}", e);
                        let r = self
                            .db
                            .video_cfs_deletion_failed(uuid, &details.uid, Some(last_error))
                            .await;
                        if let Err(e) = r {
                            warn!("Failed to insert Cloudflare Stream video deletion failure into database for later processing: {:?}", e);
                        }
                    }
                }
            }
            _ => {}
        }

        // Delete from database after cloudflare stream (need cloudflare stream metadata from database for videos)
        self.db.delete_content(repository_id, uuid).await?;

        let response = tonic::Response::new(DeleteContentResponse {});

        log_resp(endpoint, &req, &start, claims.user_id);
        Ok(response)
    }

    async fn list_contents(
        &self,
        req: tonic::Request<ListContentsRequest>,
    ) -> Result<Response<ListContentsResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::list_contents", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;

        let app_id = claims.app_id;

        let fields: Vec<SearchField> = req
            .get_ref()
            .fields
            .iter()
            .map(|t| SearchField::from_i32(*t).unwrap_or(SearchField::Undefined))
            .collect();

        if (req.get_ref().search_phrase.is_some() && fields.is_empty())
            || (req.get_ref().search_phrase.is_none() && !fields.is_empty())
        {
            return Err(Error::bad_request(
                format!("search_phrase and fields must both be provided, or both be absent. Got: search_phrase={:?}, fields={:?}",req.get_ref().search_phrase,fields ))
                .into());
        }

        // Contents for repository
        let (repository_id, creator_id) = if let Some(id) = req.get_ref().repository_id {
            let repo = self
                .db
                .get_content_repository(id, Some(RepoType::Normal))
                .await?
                .ok_or_else(|| {
                    Error::content_repository_not_found(id, "Content repository not found")
                })?;
            let creator = self
                .db
                .get_user_by_id(repo.creator_id)
                .await?
                .ok_or_else(|| Error::user_not_found(repo.creator_id, "User not found"))?;

            if creator.app_id != claims.app_id {
                return Err(Error::not_authorized("Cross app content browsing not allowed").into());
            }

            (Some(id), None)

        // Contents for repository user
        } else if let Some(id) = req.get_ref().user_id {
            let creator = self
                .db
                .get_user_by_id(id)
                .await?
                .ok_or_else(|| Error::user_not_found(id, "User not found"))?;

            if let Some(_app_id) = claims.app_id {
                if creator.app_id != claims.app_id {
                    return Err(
                        Error::not_authorized("Cross app content browsing not allowed").into(),
                    );
                }
                (None, Some(id))
            } else {
                // TODO - platform admin
                unimplemented!()
            }
        // Contents for app - supported for content search
        } else {
            (None, None)
        };

        let ctype = req
            .get_ref()
            .ctype
            .map(|t| ContentType::from_i32(t).unwrap_or(ContentType::Undefined));

        let order_by = list_contents_request::Order::from_i32(req.get_ref().order_by)
            .unwrap_or(list_contents_request::Order::Created);

        let contents = self
            .db
            .list_contents(
                repository_id,
                creator_id,
                ctype,
                order_by,
                req.get_ref().desc,
                req.get_ref().offset.as_ref(),
                req.get_ref().forward,
                req.get_ref().limit,
                req.get_ref().search_phrase.as_ref(),
                fields,
                app_id,
            )
            .await?;

        let response = tonic::Response::new(ListContentsResponse { contents });

        log_resp(endpoint, &req, &start, claims.user_id);
        Ok(response)
    }

    async fn get_content(
        &self,
        req: tonic::Request<GetContentRequest>,
    ) -> Result<Response<GetContentResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::get_content", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;

        let repository_id = req.get_ref().repository_id;

        let content = self
            .db
            .get_content(repository_id, req.get_ref().uuid.as_ref().unwrap())
            .await?;

        if content.is_none() {
            return Err(Error::content_not_found(
                repository_id,
                req.get_ref().uuid.as_ref().unwrap().to_string(),
                "Content not found",
            )
            .into());
        }

        let response = tonic::Response::new(GetContentResponse { content });

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }

    async fn check_permissions(
        &self,
        req: tonic::Request<CheckPermissionsRequest>,
    ) -> Result<tonic::Response<CheckPermissionsResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::get_content", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let request = req.get_ref();

        match request.request.as_ref().unwrap() {
            common::content::check_permissions_request::Request::AddContent(r) => {
                self.check_add_content_permission(r, &claims).await?;
            }
        };

        let response = tonic::Response::new(CheckPermissionsResponse {});

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }

    async fn video_upload(
        &self,
        r: tonic::Request<VideoUploadInitRequest>,
    ) -> Result<tonic::Response<VideoUploadInitResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::video_upload", &r);
        let claims = validate_user_claims(&self.jwt_secret, &r, false, false)?;

        // Check that user has write access to the specified content repository
        let req = r.get_ref();
        let repository = self
            .db
            .get_content_repository(req.repository_id, Some(RepoType::Normal))
            .await?
            .ok_or_else(|| {
                Error::content_repository_not_found(
                    req.repository_id,
                    "Content repository not found",
                )
            })?;

        // TODO update this once we allow people other than creator to upload to content repository
        // TODO add app_id to ContentRepository so we don't have to look this up every time -- and can still cheif user account no longer exists
        let creator = self.db.get_user_by_id(repository.creator_id).await?;
        if creator.is_none() || creator.unwrap().id as u64 != claims.user_id {
            return Err(Error::not_authorized(format!(
                "User is not authorized to upload to content repository {}",
                req.repository_id
            ))
            .into());
        }

        // TODO check video length, and reject those that are too long

        // TODO Handle metadata better?
        let uuid = TimeUuidGenerator::generate();
        let mut meta = HashMap::new();
        meta.insert("uuid".to_string(), uuid.to_string());
        // meta.insert("app_id".to_string(), repository.app_id.to_string());        // TODO
        meta.insert("uploader_id".to_string(), claims.user_id.to_string());
        meta.insert("title".to_string(), req.title.clone());
        meta.insert("description".to_string(), req.description.clone());

        let du_result = self
            .cloudflare_client
            .init_direct_upload(req.file_length as u32, Some(meta))
            .await;
        if let Err(e) = du_result {
            warn!(
                "Failed to initialize video upload (direct user upload - Cloudflare Stream): {:?}",
                e
            );
            return Err(Error::internal_server_error_unknown(
                "Failed to create upload endpoint for video upload",
            )
            .into());
        }

        let du = du_result.unwrap();

        // Record details in database
        self.db
            .video_upload_insert(
                &uuid,
                claims.app_id.unwrap(),
                claims.user_id,
                repository.id,
                &req.title,
                &req.description,
                &du.uid,
                &du.url,
                &self.node_id,
            )
            .await?;

        // Submit to video status poller, which will periodically check status, and move to content repository once ready to stream
        self.cloudflare_mgr.add(uuid.clone()).await;

        let resp = VideoUploadInitResponse::new(uuid, du.url, CLOUDFLARE_STREAM_TUS_CHUNK_SIZE);

        log_resp(endpoint, &r, &start, claims.user_id);
        Ok(resp)
    }

    async fn video_upload_cancel(
        &self,
        r: tonic::Request<TimeUuid>,
    ) -> Result<tonic::Response<()>, Status> {
        let (endpoint, start) = log_req("ContentService::video_upload_cancel", &r);

        let claims = validate_user_claims(&self.jwt_secret, &r, false, false)?;
        let video_uuid = r.get_ref();

        // Check that the video upload exists, and that the requesting user uploaded it (is authorized to cancel)
        let x = self.db.video_upload_get(video_uuid).await?;
        let _details = if x.is_none() {
            return Err(Error::content_not_found(
                0,
                video_uuid.clone().to_string(),
                "Video upload not found or upload already complete",
            )
            .into());
        } else {
            let (details, app_id) = x.unwrap();
            if !claims.is_platform_admin() && app_id != claims.app_id.clone().unwrap() {
                return Err(Error::not_authorized(
                    "User is not authorized to cancel this video upload",
                )
                .into());
            }
            details
        };

        // Now, we need to do 3 things
        // 1. Remove it from the CloudflareManager -- which polls Cloudflare until the video is ready, and
        // 2. Remove it from the database
        // 3. Delete the video from Cloudflare Stream

        self.cloudflare_mgr.upload_cancelled(video_uuid).await;

        let cloudflare_id = self.db.video_upload_cloudflare_id(video_uuid).await?;
        self.db.video_upload_delete(video_uuid).await?;

        if let Some(cf_id) = cloudflare_id {
            if let Err(e) = self.cloudflare_client.delete_video(&cf_id).await {
                warn!(
                    "Failed to delete video from Cloudflare Stream: {} {} - {:?}",
                    video_uuid, cf_id, e
                );
            }
        }

        log_resp(endpoint, &r, &start, claims.user_id);
        Ok(Response::new(()))
    }

    async fn video_in_progress_uploads(
        &self,
        r: tonic::Request<()>,
    ) -> Result<tonic::Response<VideoInProgressUploadsResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::video_upload", &r);
        let claims = validate_user_claims(&self.jwt_secret, &r, false, false)?;

        let uploads = self
            .db
            .video_uploads_list_in_progress(claims.user_id)
            .await?;

        let resp = tonic::Response::new(VideoInProgressUploadsResponse { uploads });
        log_resp(endpoint, &r, &start, claims.user_id);
        Ok(resp)
    }

    async fn set_content_repo_property(
        &self,
        req: tonic::Request<SetPropertyRequest>,
    ) -> Result<Response<SetPropertyResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::set_content_repo_property", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let user_id = claims.user_id;
        let app_id = claims
            .app_id
            .ok_or_else(|| Error::bad_request("App id missing"))?; // TODO platform admin
        let repo_id = req.get_ref().id as u64;
        let property_data = req.get_ref().property_data.clone();
        self.db
            .upsert_content_repo_properties(app_id, repo_id, property_data)
            .await?;
        let response = tonic::Response::new(SetPropertyResponse {});
        log_resp(endpoint, &req, &start, user_id);
        Ok(response)
    }

    async fn get_content_repo_property(
        &self,
        req: tonic::Request<GetPropertyRequest>,
    ) -> Result<Response<GetPropertyResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::get_content_repo_property", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let user_id = claims.user_id;
        let app_id = claims.app_id.unwrap();
        let repo_id = req.get_ref().id;

        let creator_id = self.get_content_creator_id(repo_id.into()).await?;

        let include_private_properties = creator_id == user_id;

        let property_names_list = req.get_ref().property_names.clone();
        let property_data = if !property_names_list.is_empty() {
            self.db
                .get_content_repo_properties_by_names(
                    app_id,
                    repo_id,
                    include_private_properties,
                    property_names_list,
                )
                .await?
        } else {
            self.db
                .get_all_content_repo_properties(app_id, repo_id, include_private_properties)
                .await?
        };
        let response = tonic::Response::new(GetPropertyResponse { property_data });

        log_resp(endpoint, &req, &start, repo_id as u64);

        Ok(response)
    }

    async fn remove_content_repo_property(
        &self,
        req: tonic::Request<RemovePropertyRequest>,
    ) -> Result<Response<RemovePropertyResponse>, Status> {
        let (endpoint, start) = log_req("ContentService::remove_content_repo_property", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let user_id = claims.user_id;
        let app_id = claims.app_id.unwrap();
        let property_name = req.get_ref().property_name.clone();
        let repo_id = req.get_ref().id as u64;
        let creator_id = self.get_content_creator_id(repo_id).await?;

        if user_id == creator_id {
            self.db
                .delete_content_repo_property(property_name, repo_id, app_id)
                .await?;

            let response = tonic::Response::new(RemovePropertyResponse {});

            log_resp(endpoint, &req, &start, repo_id);

            Ok(response)
        } else {
            Err(Error::not_authorized(
                "User is not authorized to remove content repository properties",
            )
            .into())
        }
    }
}
