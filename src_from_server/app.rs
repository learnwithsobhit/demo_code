use crate::{config::ServerConfig, Error};
use common::user::UserClaims;

use common::{
    app::app_service_server::{AppService, AppServiceServer},
    common::{
        GetPropertyRequest, GetPropertyResponse, RemovePropertyRequest, RemovePropertyResponse,
        SetPropertyRequest, SetPropertyResponse,
    },
    user::UserType,
};

use crate::database::Database;
use common::utils::{log_req, log_resp, validate_user_claims};
use std::sync::Arc;
use tonic::{Response, Status};

pub struct AppEndpoints {
    db: Arc<Database>,
    jwt_secret: String,
}

impl AppEndpoints {
    pub fn create(
        db: Arc<Database>,
        config: &ServerConfig,
    ) -> Result<AppServiceServer<AppEndpoints>, Error> {
        let ae = AppEndpoints {
            db,
            jwt_secret: config.jwt_secret.to_string(),
        };

        Ok(AppServiceServer::new(ae))
    }
}

fn validate_admin<T>(jwt_secret: &str, request: &tonic::Request<T>) -> Result<UserClaims, Error> {
    let claims = validate_user_claims(jwt_secret, request, false, false)?;
    if claims.role != UserType::Admin {
        Err(Error::not_authorized("User not permitted to perform app admin actions").into())
    } else {
        Ok(claims)
    }
}

impl AppEndpoints {}

#[tonic::async_trait]
impl AppService for AppEndpoints {
    async fn set_app_property(
        &self,
        req: tonic::Request<SetPropertyRequest>,
    ) -> Result<Response<SetPropertyResponse>, Status> {
        let (endpoint, start) = log_req("AppService::set_app_property", &req);
        let claims = validate_admin(&self.jwt_secret, &req)?;
        let app_id = req.get_ref().id;

        let property_data = req.get_ref().property_data.clone();
        self.db
            .upsert_app_properties(app_id as u64, property_data)
            .await?;
        let response = tonic::Response::new(SetPropertyResponse {});
        log_resp(endpoint, &req, &start, claims.user_id);
        Ok(response)
    }

    async fn get_app_property(
        &self,
        req: tonic::Request<GetPropertyRequest>,
    ) -> Result<Response<GetPropertyResponse>, Status> {
        let (endpoint, start) = log_req("AppService::get_app_property", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;

        let is_admin = claims.role == UserType::Admin;
        if !is_admin && claims.app_id.is_none() {
            Err(Error::bad_request("No app found for the user!").into())
        } else {
            let request_app_id = req.get_ref().id.try_into().unwrap();
            let app_id = match claims.app_id {
                Some(id) => id,
                None => request_app_id,
            };
            if app_id != request_app_id {
                Err(Error::bad_request("Requested app is not valid!").into())
            } else {
                let property_names_list = req.get_ref().property_names.clone();
                let property_data = if !property_names_list.is_empty() {
                    self.db
                        .get_app_properties_by_names(app_id, property_names_list)
                        .await?
                } else {
                    self.db.get_all_app_properties(app_id).await?
                };
                let response = tonic::Response::new(GetPropertyResponse { property_data });

                log_resp(endpoint, &req, &start, claims.user_id);

                Ok(response)
            }
        }
    }

    async fn remove_app_property(
        &self,
        req: tonic::Request<RemovePropertyRequest>,
    ) -> Result<Response<RemovePropertyResponse>, Status> {
        let (endpoint, start) = log_req("AppService::remove_app_property", &req);
        let claims = validate_admin(&self.jwt_secret, &req)?;
        let app_id = req.get_ref().id as u64;
        let property_names = req.get_ref().property_name.clone();
        self.db.delete_app_property(property_names, app_id).await?;

        let response = tonic::Response::new(RemovePropertyResponse {});

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }
}
