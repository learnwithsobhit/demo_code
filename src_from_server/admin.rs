use crate::{config::ServerConfig, content::FilesGrpcClient, Error};

use common::{
    admin::{
        admin_service_server::{AdminService, AdminServiceServer},
        *,
    },
    user::{AccountStatus, UserClaims, UserProfileData, UserType},
    utils::generate_jwt,
};

use crate::database::common_types::User;
use crate::database::Database;
use common::files::DeleteRepositoriesRequest;
use common::utils::{log_req, log_resp, validate_user_claims};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tonic::{Response, Status};

pub struct AdminEndpoints {
    db: Arc<Database>,
    jwt_secret: String,
    pool: Arc<common::client_pool::Pool<FilesGrpcClient>>,
}

impl AdminEndpoints {
    pub fn create(
        db: Arc<Database>,
        config: &ServerConfig,
        pool: Arc<common::client_pool::Pool<FilesGrpcClient>>,
    ) -> Result<AdminServiceServer<AdminEndpoints>, Error> {
        let ae = AdminEndpoints {
            db,
            jwt_secret: config.jwt_secret.to_string(),
            pool,
        };

        Ok(AdminServiceServer::new(ae))
    }
}

impl AdminEndpoints {}

#[tonic::async_trait]
impl AdminService for AdminEndpoints {
    async fn register_admin_account(
        &self,
        req: tonic::Request<AdminAccountRegisterRequest>,
    ) -> Result<Response<AdminAccountRegisterResponse>, Status> {
        let (endpoint, start) = log_req("AdminService::register_admin_account", &req);

        let _claims = validate_user_claims(&self.jwt_secret, &req, true, false)?;

        // Create
        let r = req.get_ref();

        let user = User {
            id: 0, //Auto-filled
            sso_id: None,
            username: r.username.clone(),
            password: None,
            salt: None,
            email: None,
            phone: None,
            app_id: None,
            account_status: AccountStatus::Registered,
            user_type: UserType::Admin,
            profile: UserProfileData::default(),
        };

        let user_id = self.db.create_user(user, None, Some(&r.password)).await?;

        let claims = UserClaims {
            user_id,
            username: r.username.clone(),
            app_id: None,
            role: UserType::Admin,
            login_step: AccountStatus::Registered,
            exp: Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or(Duration::MAX)
                    .as_secs()
                    + 24 * 3600,
            ), //TODO proper exp policy
            login_stage: None,
            register_stage: None,
        };

        let jwt = generate_jwt(&self.jwt_secret, claims).expect("Failed to generate JWT");
        let resp = Ok(AdminAccountRegisterResponse::ok(jwt));

        log_resp(endpoint, &req, &start, user_id);
        resp
    }

    async fn create_app(
        &self,
        req: tonic::Request<CreateAppRequest>,
    ) -> Result<Response<CreateAppResponse>, Status> {
        let (endpoint, start) = log_req("AdminService::create_app", &req);

        let claims = validate_user_claims(&self.jwt_secret, &req, true, false)?;
        let user_id = claims.user_id;

        let details = self.db.admin_create_app(req.get_ref()).await?;
        let resp = Ok(CreateAppResponse::ok(details));

        log_resp(endpoint, &req, &start, user_id);
        resp
    }

    async fn delete_app(
        &self,
        req: tonic::Request<DeleteAppRequest>,
    ) -> Result<Response<DeleteAppResponse>, Status> {
        let (endpoint, start) = log_req("AdminService::delete_app", &req);

        let claims = validate_user_claims(&self.jwt_secret, &req, true, false)?;
        let user_id = claims.user_id;

        let repositories: Vec<u64> = self
            .db
            .list_content_repository(
                None,
                Some(req.get_ref().app_id),
                common::content::list_repositories_request::Order::Created,
                false,
                None,
            )
            .await?
            .iter()
            .map(|r| r.id)
            .collect();

        if !repositories.is_empty() {
            let delete_req = tonic::Request::new(DeleteRepositoriesRequest {
                repository_ids: repositories,
            });
            self.pool
                .get()
                .await?
                .delete_repositories(delete_req)
                .await?;
        }

        self.db.admin_delete_app(req.get_ref()).await?;

        let resp = Ok(DeleteAppResponse::ok());

        log_resp(endpoint, &req, &start, user_id);
        resp
    }

    async fn list_apps(
        &self,
        req: tonic::Request<()>,
    ) -> Result<Response<ListAppsResponse>, Status> {
        let (endpoint, start) = log_req("AdminService::list_apps", &req);

        let claims = validate_user_claims(&self.jwt_secret, &req, true, false)?;
        let user_id = claims.user_id;

        let apps = self.db.admin_list_apps().await?;
        let resp = Ok(ListAppsResponse::ok(apps));

        log_resp(endpoint, &req, &start, user_id);
        resp
    }

    async fn list_events(
        &self,
        req: tonic::Request<ListEventsRequest>,
    ) -> Result<Response<ListEventsResponse>, Status> {
        let (endpoint, start) = log_req("AdminService::list_events", &req);
        let user_id = req.get_ref().user_id;
        let app_id = req.get_ref().id;
        let events_data = self.db.admin_list_events(app_id, user_id).await?;
        let response = tonic::Response::new(ListEventsResponse {
            events: events_data,
        });
        log_resp(endpoint, &req, &start, user_id);
        Ok(response)
    }
}
