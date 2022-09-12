use crate::content::FilesGrpcClient;
use crate::database::common_types::{RepoType, User};
use common::common::{
    EventRequest, EventResponse, GetPropertyRequest, GetPropertyResponse, RemovePropertyRequest,
    RemovePropertyResponse, SetPropertyRequest, SetPropertyResponse, TimeUuid,
};

use common::content::{list_repositories_request, Content, Image};
use common::errors::{Error, JwtErrorType};
use common::files::{CopyFileRequest, UploadFileRequest};
use common::user::list_users_request::{self, SearchField};
use common::user::{
    get_user_request, AccountStatus, FlowStage, ListUsersRequest, ListUsersResponse, LoginStep,
    RegisterStep, UserClaims, UserType,
};
use common::user::{
    login_step_data, register_step_data,
    user_service_server::{UserService, UserServiceServer},
    AuthProvider, GetUserRequest, GetUserResponse, LoginCredentials, LoginStepData,
    LoginUserRequest, LoginUserResponse, RegisterStepData, RegisterUserRequest,
    RegisterUserResponse, UpdateProfileRequest, UserData, UserProfileData,
};
use common::utils::{get_app_id_from_claim, parse_pf_url, validate_user_claims, verify_argon2};
use id_tree::{NodeId, Tree};
use log::warn;
use tokio::sync::RwLock;

use crate::database::common_types::App;
use crate::database::Database;
use common::utils::{log_req, log_resp};
use common::JWT_METADATA_HEADER;
use jsonwebtoken::{DecodingKey, EncodingKey, Validation};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tonic::{metadata::MetadataValue, Response, Status};

use self::sso::{GoogleKeyCache, KeyCache};
// use log::*;

mod sso;

/// Login transitions tree with hash of config string it was parsed from
struct LoginCfgWrapper {
    config: Tree<LoginStep>,
    /// Hash of config string used to parse config from
    hash: u64,
}

/// Register transitions tree with hash of config string it was parsed from
struct RegisterCfgWrapper {
    config: Tree<RegisterStep>,
    /// Hash of config string used to parse config from
    hash: u64,
}

pub struct UserEndpoints {
    pub db: Arc<Database>,
    pub jwt_secret: String,
    keys_cache_map: HashMap<AuthProvider, Box<dyn KeyCache>>,
    /// Set of register configs for different app ids
    register_cfg: RwLock<HashMap<u32, RwLock<RegisterCfgWrapper>>>,
    /// Set of login configs for different app ids
    login_cfg: RwLock<HashMap<u32, RwLock<LoginCfgWrapper>>>,
    /// File server client
    pool: Arc<common::client_pool::Pool<FilesGrpcClient>>,
}

impl UserEndpoints {
    pub fn create(
        db: Arc<Database>,
        jwt_secret: &str,
        integration_tests: bool,
        pool: Arc<common::client_pool::Pool<FilesGrpcClient>>,
    ) -> Result<UserServiceServer<UserEndpoints>, Error> {
        let mut map = HashMap::new();

        let google = Box::new(GoogleKeyCache::new(integration_tests));

        map.insert(AuthProvider::Google, google as Box<dyn KeyCache>);

        let ue = UserEndpoints {
            db,
            jwt_secret: jwt_secret.to_string(),
            keys_cache_map: map,
            register_cfg: RwLock::new(HashMap::new()),
            login_cfg: RwLock::new(HashMap::new()),
            pool,
        };

        Ok(UserServiceServer::new(ue))
    }

    async fn process_register_step(
        &self,
        data: &RegisterStepData,
        claims: UserClaims,
        app: App,
    ) -> Result<(Vec<RegisterStep>, UserClaims), Error> {
        let mut hasher = DefaultHasher::new();
        app.register_config.hash(&mut hasher);
        let hash = hasher.finish();

        if let Some(stage) = &claims.register_stage {
            if stage.hash != hash {
                return Err(Error::internal_server_error_internal(
                    "Register config has changed. Try again",
                ));
            }
        } else {
            match data.data.as_ref() {
                Some(register_step_data::Data::Init(_)) => {}
                _ => return Err(Error::bad_request("Missing Register step id")),
            }
        }

        {
            let read_guard = self.register_cfg.read().await;
            if let Some(cfg) = read_guard.get(&app.id) {
                if cfg.read().await.hash != hash {
                    // Cfg had changed
                    let config: Tree<RegisterStep> = serde_json::from_str(&app.register_config)?;
                    *cfg.write().await = RegisterCfgWrapper { config, hash };
                }
            } else {
                // First use of this app
                drop(read_guard);
                let mut guard = self.register_cfg.write().await;
                let config: Tree<RegisterStep> = serde_json::from_str(&app.register_config)?;
                guard.insert(app.id, RwLock::new(RegisterCfgWrapper { config, hash }));
            }
        }

        let app_register_cfg_guard = self.register_cfg.read().await;
        let cfg = app_register_cfg_guard.get(&app.id).unwrap();

        let (new_step_id, next_possible_steps) =
            Self::process_register_transition(&claims, data, &cfg.read().await.config)?;

        let mut claims = match data.data.as_ref() {
            Some(register_step_data::Data::UserData(data)) => {
                self.process_register_step_name_pass(data, claims, app)
                    .await?
            }
            Some(register_step_data::Data::SsoData(data)) => {
                self.process_register_step_sso(data, claims, app).await?
            }
            _ => claims,
        };
        if claims.register_stage.is_none() {
            claims.register_stage = Some(FlowStage {
                step_id: new_step_id,
                hash,
            });
        } else {
            claims.register_stage.as_mut().unwrap().step_id = new_step_id;
        }

        Ok((next_possible_steps, claims))
    }

    /// Validates transition and returns new node id after transition and its next possible actions
    fn process_register_transition(
        claims: &UserClaims,
        data: &RegisterStepData,
        cfg: &Tree<RegisterStep>,
    ) -> Result<(String, Vec<RegisterStep>), Error> {
        let next_step = data.get_register_step();
        let new_current = match &claims.register_stage {
            None => {
                if next_step != RegisterStep::Init {
                    return Err(Error::internal_server_error_unknown(
                        "Invalid register step",
                    ));
                } else {
                    cfg.root_node_id().expect("Cfg tree empty")
                }
            }
            Some(stage) => {
                let deserialized: NodeId = serde_json::from_str(&stage.step_id)?;
                let current = cfg
                    .get(&deserialized)
                    .map_err(|_e| Error::internal_server_error_unknown("Invalid register step"))?;

                let possible_steps = current.children();

                if let Some(next) = possible_steps
                    .iter()
                    .find(|step| *cfg.get(*step).unwrap().data() == next_step)
                {
                    next
                } else {
                    return Err(Error::bad_request("Invalid register step"));
                }
            }
        };

        let id_str = serde_json::to_string(new_current).unwrap();
        let next_steps: Vec<RegisterStep> = cfg
            .children(new_current)
            .unwrap()
            .map(|child| *child.data())
            .collect();
        Ok((id_str, next_steps))
    }

    /// Validates transition and returns new node id after transition and its next possible actions
    fn process_login_transition(
        claims: &UserClaims,
        data: &LoginStepData,
        cfg: &Tree<LoginStep>,
    ) -> Result<(String, Vec<LoginStep>), Error> {
        let next_step = data.get_login_step();
        let new_current = match &claims.login_stage {
            None => {
                if next_step != LoginStep::Init {
                    return Err(Error::internal_server_error_unknown("Invalid login step"));
                } else {
                    cfg.root_node_id().expect("Cfg tree empty")
                }
            }
            Some(stage) => {
                let deserialized: NodeId = serde_json::from_str(&stage.step_id)?;
                let current = cfg
                    .get(&deserialized)
                    .map_err(|_e| Error::internal_server_error_unknown("Invalid login step"))?;

                let possible_steps = current.children();

                if let Some(next) = possible_steps
                    .iter()
                    .find(|step| *cfg.get(*step).unwrap().data() == next_step)
                {
                    next
                } else {
                    return Err(Error::bad_request("Invalid login step"));
                }
            }
        };

        let id_str = serde_json::to_string(new_current).unwrap();
        let next_steps: Vec<LoginStep> = cfg
            .children(new_current)
            .unwrap()
            .map(|child| *child.data())
            .collect();
        Ok((id_str, next_steps))
    }

    async fn process_login_step(
        &self,
        data: &LoginStepData,
        claims: UserClaims,
        app: Option<App>,
    ) -> Result<(Vec<LoginStep>, UserClaims), Error> {
        if let Some(app) = app {
            let mut hasher = DefaultHasher::new();
            app.login_config.hash(&mut hasher);
            let hash = hasher.finish();

            if let Some(stage) = &claims.login_stage {
                if stage.hash != hash {
                    return Err(Error::internal_server_error_internal(
                        "Login config has changed. Try again",
                    ));
                }
            } else {
                match data.data.as_ref() {
                    Some(login_step_data::Data::Init(_)) => {}
                    _ => return Err(Error::bad_request("Missing Login step id")),
                }
            }

            // First use of this app or cfg have changed
            if self.login_cfg.read().await.get(&app.id).is_none()
                || self
                    .login_cfg
                    .read()
                    .await
                    .get(&app.id)
                    .as_ref()
                    .unwrap()
                    .read()
                    .await
                    .hash
                    != hash
            {
                let mut guard = self.login_cfg.write().await;
                let config: Tree<LoginStep> = serde_json::from_str(&app.login_config)?;
                guard.insert(app.id, RwLock::new(LoginCfgWrapper { config, hash }));
            }

            let app_login_cfg_guard = self.login_cfg.read().await;
            let cfg = app_login_cfg_guard.get(&app.id).unwrap();

            let (new_step_id, next_possible_steps) =
                Self::process_login_transition(&claims, data, &cfg.read().await.config)?;

            let mut claims = match data.data.as_ref() {
                Some(login_step_data::Data::Credentials(data)) => {
                    self.process_login_step_name_pass(data, claims, Some(app))
                        .await?
                }
                Some(login_step_data::Data::SsoData(data)) => {
                    self.process_login_step_sso(data, claims, &app).await?
                }
                _ => claims,
            };

            if claims.login_stage.is_none() {
                claims.login_stage = Some(FlowStage {
                    step_id: new_step_id,
                    hash,
                });
            } else {
                claims.login_stage.as_mut().unwrap().step_id = new_step_id;
            }

            Ok((next_possible_steps, claims))
        } else {
            let (steps, claims) = match data.data.as_ref() {
                Some(login_step_data::Data::Init(_)) => {
                    let steps = vec![LoginStep::Credentials];
                    (steps, claims)
                }
                Some(login_step_data::Data::Credentials(credentials)) => {
                    let claims = self
                        .process_login_step_name_pass(credentials, claims, None)
                        .await?;
                    let steps = vec![LoginStep::Finished];
                    (steps, claims)
                }
                _ => {
                    return Err(Error::bad_request("Invalid login step"));
                }
            };

            Ok((steps, claims))
        }
    }

    /// Resister flow state machine for init -> username/password -> finish
    async fn process_register_step_name_pass(
        &self,
        user_data: &UserData,
        claims: UserClaims,
        app: App,
    ) -> Result<UserClaims, Error> {
        // check if username is free
        if self
            .db
            .get_user(&user_data.username, Some(app.id))
            .await?
            .is_some()
        {
            return Err(Error::id_in_use("username", "Username already exists"));
        }
        // TODO check email

        let user = User {
            id: 0, // ingored, autoincrement
            sso_id: None,
            username: user_data.username.clone(),
            password: None,
            salt: None,
            email: user_data.email.clone(),
            phone: user_data.phone.clone(),
            app_id: Some(app.id),
            account_status: AccountStatus::Registered,
            user_type: UserType::User,
            profile: UserProfileData::default(), // Basic data like ids will be filled in db entry generation
        };
        let id = self
            .db
            .create_user(user.clone(), None, user_data.password.as_ref())
            .await?;

        self.generate_and_upload_user_avatar(id).await?;

        let new_claims = UserClaims {
            login_step: AccountStatus::Registered,
            user_id: id,
            username: user_data.username.clone(),
            role: user.user_type,
            ..claims
        };

        Ok(new_claims)
    }

    /// Login flow state machine for init -> username/password -> finish
    async fn process_login_step_name_pass(
        &self,
        data: &LoginCredentials,
        claims: UserClaims,
        app: Option<App>,
    ) -> Result<UserClaims, Error> {
        let app_id = app.as_ref().map(|a| a.id);
        let user = self
            .db
            .get_user(&data.username, app_id)
            .await?
            .ok_or_else(|| Error::user_not_found(0, ""))?; //TODO

        verify_argon2(
            &data.password,
            user.password.as_ref().unwrap(),
            user.salt.as_ref().unwrap(),
        )?;

        let new_claims = UserClaims {
            user_id: user.id as u64,
            username: user.username.clone(),
            role: user.user_type,
            login_step: AccountStatus::Registered,
            ..claims
        };

        Ok(new_claims)
    }

    ///
    /// Generates Identicon with default parameters and uploads to file server as png image. Finally updates users profile avatar url.
    ///
    pub async fn generate_and_upload_user_avatar(&self, user_id: u64) -> Result<(), Error> {
        let user = self.db.get_user_by_id(user_id).await?.unwrap();
        let repos = self
            .db
            .list_content_repository(
                Some(user_id),
                user.app_id,
                list_repositories_request::Order::Created,
                true,
                Some(RepoType::User),
            )
            .await?;
        assert_eq!(repos.len(), 1);
        let repository_id = repos[0].id;

        let bytes = identicon_rs::Identicon::new(&user.username)
            .border(50)
            .scale(500)?
            .size(5)?
            .background_color((240, 240, 240))
            .mirrored(true)
            .export_png_data()?;

        // scale + 2*border
        let width = 500 + 2 * 50;

        let mut content = Content {
            uuid: None,
            repository_id,
            creator_id: user.id,
            title: "avatar".into(),
            description: "".into(),
            filename: "avatar.png".into(),
            size: bytes.len() as u64,
            metadata: Some(common::content::content::Metadata::I(Image {
                height: width,
                width,
            })),
        };

        let req = tonic::Request::new(UploadFileRequest {
            content: Some(content.clone()),
            bytes,
        });

        let response = self.pool.get().await?.upload_admin(req).await?;

        content.uuid = Some(response.into_inner().uuid.unwrap());

        let mut profile = user.profile.clone();
        profile.avatar_url = Some(format!(
            "pf://{}/{}",
            repository_id,
            content.uuid.as_ref().unwrap().to_string()
        ));
        self.db
            .add_content(
                *user
                    .app_id
                    .as_ref()
                    .expect("Function not used by platform admins"),
                &content,
            )
            .await?;
        self.db.update_user_profile(&profile).await?;

        Ok(())
    }
}

#[tonic::async_trait]
impl UserService for UserEndpoints {
    ///
    /// Grpc server implementation for perforing registration step
    ///
    async fn register_user(
        &self,
        req: tonic::Request<RegisterUserRequest>,
    ) -> Result<Response<RegisterUserResponse>, Status> {
        let (endpoint, start) = log_req("UserService::register_user", &req);

        let step = req
            .get_ref()
            .step
            .as_ref()
            .ok_or_else(|| Error::bad_request("Missing step data"))?;

        let (claims, app) = if let register_step_data::Data::Init(init) =
            step.data.as_ref().expect("data is required")
        {
            let app = self
                .db
                .admin_get_app_by_token(&init.app_token)
                .await?
                .ok_or_else(|| Error::app_not_found(init.app_token.as_str(), "App not found"))?;

            (
                UserClaims {
                    user_id: 0,
                    username: "".to_string(),
                    app_id: Some(app.id),
                    role: UserType::User,
                    login_step: AccountStatus::Init,
                    exp: Some(
                        SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or(Duration::MAX)
                            .as_secs()
                            + 24 * 3600,
                    ), //TODO proper exp policy
                    login_stage: None,
                    register_stage: None,
                },
                app,
            )
        } else {
            let jwt = req.metadata().get(JWT_METADATA_HEADER).ok_or_else(|| {
                Error::jwt(JwtErrorType::MissingJwt, "JWT was not provided in request")
            })?;
            match jwt.to_str() {
                Ok(jwt_str) => {
                    let mut v = Validation::new(jsonwebtoken::Algorithm::HS256);
                    v.validate_exp = false;

                    let dk = DecodingKey::from_secret(self.jwt_secret.as_bytes());
                    let claims = jsonwebtoken::decode::<UserClaims>(jwt_str, &dk, &v)
                        .map_err(|e| Error::jwt(JwtErrorType::InvalidJwt, format!("{:?}", e)))?
                        .claims;

                    let app = self
                        .db
                        .admin_get_app_by_id(
                            *claims
                                .app_id
                                .as_ref()
                                .expect("App id is set for not init register steps"),
                        )
                        .await?
                        .ok_or_else(|| {
                            Error::app_not_found(
                                claims.app_id.as_ref().unwrap().to_string().as_str(),
                                "App not found",
                            )
                        })?;

                    (claims, app)
                }
                Err(e) => {
                    return Err(Error::jwt(JwtErrorType::InvalidJwt, e.to_string()).into());
                }
            }
        };

        let (next_data, claims) = self.process_register_step(step, claims, app).await?;

        let jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .unwrap();
        let mut response = tonic::Response::new(RegisterUserResponse {
            possible_steps: next_data.into_iter().map(|s| s as i32).collect(),
        });

        response
            .metadata_mut()
            .insert(JWT_METADATA_HEADER, MetadataValue::from_str(&jwt).unwrap());

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }

    ///
    /// Grpc server implementation for performing login step
    ///
    async fn login(
        &self,
        req: tonic::Request<LoginUserRequest>,
    ) -> Result<Response<LoginUserResponse>, Status> {
        let (endpoint, start) = log_req("UserService::login", &req);

        let step = req
            .get_ref()
            .step
            .as_ref()
            .ok_or_else(|| Error::bad_request("Missing step data"))?;

        let (claims, app) = if let login_step_data::Data::Init(init) =
            step.data.as_ref().expect("data is required")
        {
            let app = if !init.app_token.is_empty() {
                Some(
                    self.db
                        .admin_get_app_by_token(&init.app_token)
                        .await?
                        .ok_or_else(|| {
                            Error::app_not_found(init.app_token.as_str(), "App not found")
                        })?,
                )
            } else {
                None
            };

            (
                UserClaims {
                    user_id: 0,               // user identity not known yet
                    username: "".to_string(), // user identity not known yet
                    app_id: app.as_ref().map(|a| a.id),
                    role: UserType::User, // default role at init
                    login_step: AccountStatus::Init,
                    exp: Some(
                        SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or(Duration::MAX)
                            .as_secs()
                            + 24 * 3600,
                    ), //TODO proper exp policy
                    login_stage: None,
                    register_stage: None,
                },
                app,
            )
        } else {
            let jwt = req
                .metadata()
                .get(JWT_METADATA_HEADER)
                .ok_or_else(|| Error::jwt(JwtErrorType::MissingJwt, "Missing JWT"))?;
            match jwt.to_str() {
                Ok(jwt_str) => {
                    let mut v = Validation::new(jsonwebtoken::Algorithm::HS256);
                    v.validate_exp = false;

                    let dk = DecodingKey::from_secret(self.jwt_secret.as_bytes());
                    let claims = jsonwebtoken::decode::<UserClaims>(jwt_str, &dk, &v)
                        .map_err(|e| {
                            Error::jwt(
                                JwtErrorType::InvalidJwt,
                                format!("JWT is not valid: {:?}", e),
                            )
                        })?
                        .claims;

                    let app = if let Some(id) = claims.app_id {
                        Some(self.db.admin_get_app_by_id(id).await?.ok_or_else(|| {
                            Error::app_not_found(
                                claims.app_id.as_ref().unwrap().to_string().as_str(),
                                "App not found",
                            )
                        })?)
                    } else {
                        None
                    };

                    (claims, app)
                }
                Err(e) => {
                    return Err(Error::jwt(JwtErrorType::InvalidJwt, e.to_string()).into());
                }
            }
        };

        let (next_data, claims) = self.process_login_step(step, claims, app).await?;

        let jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .unwrap();
        let mut response = tonic::Response::new(LoginUserResponse {
            possible_steps: next_data.into_iter().map(|s| s as i32).collect(),
        });

        response
            .metadata_mut()
            .insert(JWT_METADATA_HEADER, MetadataValue::from_str(&jwt).unwrap());

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }

    async fn record_events(
        &self,
        req: tonic::Request<EventRequest>,
    ) -> Result<Response<EventResponse>, Status> {
        let (endpoint, start) = log_req("UserService::record_events", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let user_id = claims.user_id;
        let request_content_id = req.get_ref().content_id.clone();
        let request_app_id = req.get_ref().app_id;
        let app_id = get_app_id_from_claim(&claims, request_app_id)?;
        let event_data = req.get_ref().event.clone();
        let uuid = TimeUuid::new();
        self.db
            .set_user_actions(
                app_id,
                user_id,
                &uuid,
                request_content_id.as_ref(),
                event_data,
            )
            .await?;
        let response = tonic::Response::new(EventResponse {});
        log_resp(endpoint, &req, &start, user_id);
        Ok(response)
    }

    async fn set_user_property(
        &self,
        req: tonic::Request<SetPropertyRequest>,
    ) -> Result<Response<SetPropertyResponse>, Status> {
        let (endpoint, start) = log_req("UserService::set_user_property", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let user_id = claims.user_id;
        let app_id = claims
            .app_id
            .ok_or_else(|| Error::bad_request("App id missing"))?; // TODO platform admin

        let property_data = req.get_ref().property_data.clone();
        self.db
            .upsert_user_properties(app_id, user_id, property_data)
            .await?;
        let response = tonic::Response::new(SetPropertyResponse {});
        log_resp(endpoint, &req, &start, user_id);
        Ok(response)
    }

    async fn get_user_property(
        &self,
        req: tonic::Request<GetPropertyRequest>,
    ) -> Result<Response<GetPropertyResponse>, Status> {
        let (endpoint, start) = log_req("UserService::get_user_property", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let user_id = claims.user_id;
        let app_id = claims.app_id.unwrap();
        let request_id = req.get_ref().id as u64;
        let include_private_properties = claims.user_id == request_id;

        let property_names_list = req.get_ref().property_names.clone();
        let property_data = if !property_names_list.is_empty() {
            self.db
                .get_user_properties_by_names(
                    app_id,
                    user_id,
                    include_private_properties,
                    property_names_list,
                )
                .await?
        } else {
            self.db
                .get_all_user_properties(app_id, user_id, include_private_properties)
                .await?
        };
        let response = tonic::Response::new(GetPropertyResponse { property_data });

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }

    async fn remove_user_property(
        &self,
        req: tonic::Request<RemovePropertyRequest>,
    ) -> Result<Response<RemovePropertyResponse>, Status> {
        let (endpoint, start) = log_req("UserService::remove_user_property", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let user_id = claims.user_id;
        let app_id = claims.app_id.unwrap();
        let property_names = req.get_ref().property_name.clone();
        self.db
            .delete_user_property(property_names, user_id, app_id.into())
            .await?;

        let response = tonic::Response::new(RemovePropertyResponse {});

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }

    ///
    /// Grpc server implementation for getting user profile data
    ///
    async fn get_user(
        &self,
        req: tonic::Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let (endpoint, start) = log_req("UserService::get_user", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let request = req.get_ref();

        let mut user = match &request.query {
            Some(get_user_request::Query::Id(id)) => {
                if let Some(u) = self.db.get_user_by_id(*id).await? {
                    if u.app_id != claims.app_id {
                        return Err(Error::bad_request("User not found").into());
                    }
                    Some(u)
                } else {
                    None
                }
            }
            Some(get_user_request::Query::Email(email)) => {
                self.db.get_user_by_email(email, claims.app_id).await?
            }
            Some(get_user_request::Query::Username(username)) => {
                self.db.get_user(username, claims.app_id).await?
            }
            None => return Err(Error::bad_request("Search user criteria missing").into()),
        };

        if let Some(u) = &user {
            if u.account_status != AccountStatus::Registered && u.id != claims.user_id {
                user = None;
            }
        }

        let response = tonic::Response::new(GetUserResponse {
            profile: user.map(|u| u.profile),
        });

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }

    ///
    /// Grpc server implementation for setting user profile data
    ///
    async fn update_user_profile(
        &self,
        mut req: tonic::Request<UpdateProfileRequest>,
    ) -> Result<Response<()>, Status> {
        let (endpoint, start) = log_req("UserService::update_user_profile", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;

        let request = req.get_mut();
        let req_profile = request.profile.as_mut().unwrap();

        if claims.user_id != req_profile.user_id {
            return Err(Error::not_authorized("Forbidden to update others profiles").into());
        }

        if claims.username != req_profile.username {
            return Err(Error::bad_request("Forbidden to change username in profile").into());
        }

        if let Some(u) = self.db.get_user_by_id(req_profile.user_id).await? {
            // Update avarar. Ignore avatar_url field in request profile struct
            if let Some(bytes) = &request.avatar_bytes {
                if let Some(url) = &u.profile.avatar_url {
                    let (repository_id, uuid) = parse_pf_url(url)?;
                    let upload_req = UploadFileRequest {
                        content: Some(Content {
                            uuid: Some(uuid),
                            repository_id,
                            ..Default::default()
                        }),
                        bytes: bytes.clone(),
                    };
                    self.pool.get().await?.upload_admin(upload_req).await?;
                    req_profile.avatar_url = u.profile.avatar_url.clone();
                } else {
                    // Platform admin account. No private repository defined.
                    return Err(Error::bad_request("Can't upload avatar").into());
                }
            // Overwrite avatar file
            } else if req_profile.avatar_url.is_some()
                && u.profile.avatar_url.is_some()
                && u.profile.avatar_url != req_profile.avatar_url
            {
                let (src_repository_id, src_uuid) =
                    parse_pf_url(req_profile.avatar_url.as_ref().unwrap())?;
                let (dest_repository_id, dest_uuid) =
                    parse_pf_url(u.profile.avatar_url.as_ref().unwrap())?;
                let cpy_req = CopyFileRequest {
                    src_repository_id,
                    src_uuid: Some(src_uuid),
                    dest_repository_id,
                    dest_uuid: Some(dest_uuid),
                };
                // Update avatar file
                self.pool.get().await?.copy_file(cpy_req).await?;
                // Keep old url
                req_profile.avatar_url = u.profile.avatar_url.clone();
            } else if req_profile.avatar_url.is_none() && u.profile.avatar_url.is_some() {
                return Err(Error::bad_request("Forbidden to unset avatar once it was set").into());
            }
            // Update db only if something changed
            if u.profile != *req_profile {
                if u.email != req_profile.email {
                    warn!("Updating user's profile with no validation");
                }
                self.db.update_user_profile(req_profile).await?;
            }
        } else {
            return Err(Error::user_not_found(req_profile.user_id, "User already deleted").into());
        }

        let response = tonic::Response::new(());

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }

    ///
    /// Grpc server implementation for user search
    ///
    async fn list_users(
        &self,
        req: tonic::Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let (endpoint, start) = log_req("UserService::list_users", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;

        let app_id = claims
            .app_id
            .ok_or(Error::bad_request("App id unspecified"))?;
        let request = req.get_ref();

        let fields: Vec<SearchField> = request
            .fields
            .iter()
            .map(|t| SearchField::from_i32(*t).unwrap_or(SearchField::Undefined))
            .collect();

        if (request.search_phrase.is_some() && fields.is_empty())
            || (request.search_phrase.is_none() && !fields.is_empty())
        {
            return Err(Error::bad_request(
                format!("search_phrase and fields must both be provided, or both be absent. Got: search_phrase={:?}, fields={:?}",request.search_phrase,fields ))
                .into());
        }

        let order = list_users_request::Order::from_i32(request.order_by)
            .ok_or(Error::bad_request("Unknown order"))?;

        let users = self
            .db
            .list_users(
                app_id,
                request.search_phrase.clone(),
                order,
                fields,
                request.desc,
                request.offset.as_ref(),
                request.forward,
                request.limit,
            )
            .await?;

        let response = tonic::Response::new(ListUsersResponse { users });

        log_resp(endpoint, &req, &start, claims.user_id);

        Ok(response)
    }
}
