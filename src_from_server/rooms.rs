use crate::{config::ServerConfig, Error};
use common::common::{room_identifier, RemovePropertyRequest, SetPropertyRequest};

use common::{
    content::ListRepositoriesResponse,
    rooms::{
        room_service_server::{RoomService, RoomServiceServer},
        *,
    },
};

use crate::database::Database;
use common::rooms::list_room_request::SearchField;
use common::utils::{log_req, log_resp, validate_user_claims};
use std::sync::Arc;
use tonic::{Response, Status};

pub struct RoomsEndpoints {
    db: Arc<Database>,
    jwt_secret: String,
}

///
/// Rooms Endpoint which implement Room services
///
impl RoomsEndpoints {
    pub fn create(
        db: Arc<Database>,
        config: &ServerConfig,
    ) -> Result<RoomServiceServer<RoomsEndpoints>, Error> {
        let re = RoomsEndpoints {
            db,
            jwt_secret: config.jwt_secret.to_string(),
        };

        Ok(RoomServiceServer::new(re))
    }
}

#[tonic::async_trait]
impl RoomService for RoomsEndpoints {
    ///
    /// create rooms based on provided list of room informations
    ///  
    async fn create_rooms(
        &self,
        req: tonic::Request<CreateRoomRequest>,
    ) -> Result<Response<()>, Status> {
        let (endpoint, start) = log_req("RoomService::create_rooms", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let app_id = claims
            .app_id
            .ok_or(Error::bad_request("Invalid application!"))?;

        let creator_id = claims.user_id;
        let room_data = req.get_ref().rooms_data.as_ref();
        let resp_message = self.db.create_rooms(app_id, creator_id, room_data).await?;
        let response = tonic::Response::new(resp_message);
        log_resp(endpoint, &req, &start, creator_id);
        Ok(response)
    }

    ///
    /// update a room if it is already created
    ///
    async fn update_room(
        &self,
        req: tonic::Request<UpdateRoomRequest>,
    ) -> Result<Response<()>, Status> {
        let (endpoint, start) = log_req("RoomService::update_room", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let app_id = claims
            .app_id
            .ok_or(Error::bad_request("Invalid application!"))?;

        let room_update_key = req
            .get_ref()
            .update_room_key
            .as_ref()
            .ok_or(Error::bad_request(
                "room update require room id or room unique name!",
            ))?
            .key
            .as_ref()
            .ok_or(Error::bad_request("update key is missing!"))?;

        let room_data = req
            .get_ref()
            .rooms_data
            .as_ref()
            .ok_or(Error::bad_request("room update information not provided!"))?;

        match room_update_key {
            update_room_key::Key::RoomId(id) => {
                self.db
                    .update_room_by_room_id(app_id, *id, room_data)
                    .await?;
            }
            update_room_key::Key::RoomUniqueId(unique_name) => {
                self.db
                    .update_room_by_unique_id(app_id, unique_name, room_data)
                    .await?;
            }
        };

        let response = tonic::Response::new(());
        log_resp(endpoint, &req, &start, claims.user_id);
        Ok(response)
    }

    ///
    /// remove rooms based on list of room id or name or unique id or room type
    ///
    async fn delete_rooms(
        &self,
        req: tonic::Request<DeleteRoomRequest>,
    ) -> Result<Response<()>, Status> {
        let (endpoint, start) = log_req("RoomService::delete_rooms", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let app_id = claims
            .app_id
            .ok_or(Error::bad_request("Invalid application!"))?;

        if let Some(room_identifier) = req.get_ref().remove.clone() {
            let keys = room_identifier
                .key
                .ok_or(Error::bad_request("Invalid application!"))?;
            match keys {
                room_identifier::Key::RoomId(room_id) => {
                    self.db.delete_rooms_by_id(app_id, room_id).await?
                }
                room_identifier::Key::RoomName(room_name) => {
                    self.db.delete_rooms_by_names(app_id, room_name).await?
                }
                room_identifier::Key::RoomUniqueName(room_unique_name) => {
                    self.db
                        .delete_rooms_by_unique_ids(app_id, room_unique_name)
                        .await?
                }
            };
        } else {
            if let Some(room_type) = req.get_ref().room_type {
                self.db.delete_rooms_by_room_type(app_id, room_type).await?
            }
        }

        log_resp(endpoint, &req, &start, claims.user_id);
        Ok(tonic::Response::new(()))
    }

    ///
    /// list out all rooms based on app id and pagination parameters
    ///
    async fn list_rooms(
        &self,
        req: tonic::Request<ListRoomRequest>,
    ) -> Result<Response<ListRoomResponse>, Status> {
        let (endpoint, start) = log_req("RoomService::list_rooms", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let app_id = claims
            .app_id
            .ok_or(Error::bad_request("Invalid application!"))?;
        let order = list_room_request::Order::from_i32(req.get_ref().order_by)
            .ok_or(Error::bad_request("Unknown order"))?;
        //provide default pagination information
        let mut page_info = PaginationInfo {
            offset: None,
            limit: Some(MAX_ROOMS_PAGE_SIZE),
            forward: Some(true),
        };

        //if pagination exist in request
        if let Some(p_info) = req.get_ref().page_info.as_ref() {
            page_info.offset = p_info.offset.clone();
            page_info.limit = p_info.limit;
            page_info.forward = p_info.forward;
        }

        let request = req.get_ref();
        let fields: Vec<SearchField> = request
            .fields
            .iter()
            .map(|t| SearchField::from_i32(*t).unwrap_or(SearchField::Name))
            .collect();

        if (request.search_phrase.is_some() && fields.is_empty())
            || (request.search_phrase.is_none() && !fields.is_empty())
        {
            return Err(Error::bad_request(
                format!("search_phrase and fields must both be provided, or both be absent. Got: search_phrase={:?}, fields={:?}",request.search_phrase,fields ))
                .into());
        }

        let resp_message = self
            .db
            .list_rooms(
                app_id,
                order,
                false,
                request.search_phrase.to_owned(),
                fields,
                page_info,
            )
            .await?;
        let response = tonic::Response::new(ListRoomResponse {
            rooms_info: resp_message,
        });

        log_resp(endpoint, &req, &start, claims.user_id);
        Ok(response)
    }

    async fn join_room(
        &self,
        req: tonic::Request<JoinRoomRequest>,
    ) -> Result<Response<JoinRoomResponse>, Status> {
        let (endpoint, start) = log_req("RoomService::join_rooms", &req);
        let claims = validate_user_claims(&self.jwt_secret, &req, false, false)?;
        let app_id = claims
            .app_id
            .ok_or(Error::bad_request("Invalid application!"))?;

        let member_id = claims.user_id;
        let room_id = req.get_ref().room_id;
        let resp_message = self.db.join_room(app_id, member_id, room_id).await?;
        let response = tonic::Response::new(resp_message);
        log_resp(endpoint, &req, &start, member_id);
        Ok(response)
    }

    async fn leave_rooms(
        &self,
        _req: tonic::Request<LeaveRoomRequest>,
    ) -> Result<Response<()>, Status> {
        todo!()
    }

    async fn list_invitations_received(
        &self,
        _req: tonic::Request<ListInvitationRequest>,
    ) -> Result<Response<ListInvitationResponse>, Status> {
        todo!()
    }

    async fn list_invitations_sent(
        &self,
        _req: tonic::Request<ListInvitationRequest>,
    ) -> Result<Response<ListInvitationResponse>, Status> {
        todo!()
    }

    async fn search_room_members(
        &self,
        _req: tonic::Request<RoomMembersRequest>,
    ) -> Result<Response<RoomMembersResponse>, Status> {
        todo!()
    }

    async fn room_members_count(
        &self,
        _req: tonic::Request<RoomMembersCountRequest>,
    ) -> Result<Response<RoomMembersCountResponse>, Status> {
        todo!()
    }

    async fn get_room_properties(
        &self,
        _req: tonic::Request<GetRoomPropertiesRequest>,
    ) -> Result<Response<GetRoomPropertiesResponse>, Status> {
        todo!()
    }

    async fn get_room_feeds(
        &self,
        _req: tonic::Request<GetRoomFeedsRequest>,
    ) -> Result<Response<GetRoomFeedsResponse>, Status> {
        todo!()
    }

    async fn get_room_repos(
        &self,
        _req: tonic::Request<GetRoomReposRequest>,
    ) -> Result<Response<ListRepositoriesResponse>, Status> {
        todo!()
    }

    async fn remove_members(
        &self,
        _req: tonic::Request<RemoveUserRequest>,
    ) -> Result<Response<()>, Status> {
        todo!()
    }

    async fn ban_users(
        &self,
        _req: tonic::Request<BanUsersRequest>,
    ) -> Result<Response<()>, Status> {
        todo!()
    }

    async fn invite_room_members(
        &self,
        _req: tonic::Request<InviteRoomMembersRequest>,
    ) -> Result<Response<InviteRoomMembersResponse>, Status> {
        todo!()
    }

    async fn promote_admins(
        &self,
        _req: tonic::Request<PromoteAdminsRequest>,
    ) -> Result<Response<PromoteAdminsResponse>, Status> {
        todo!()
    }

    async fn add_users_in_room(
        &self,
        _req: tonic::Request<InviteRoomMembersRequest>,
    ) -> Result<Response<InviteRoomMembersResponse>, Status> {
        todo!()
    }

    async fn upsert_room_properties(
        &self,
        _req: tonic::Request<SetPropertyRequest>,
    ) -> Result<Response<()>, Status> {
        todo!()
    }

    async fn remove_room_properties(
        &self,
        _req: tonic::Request<RemovePropertyRequest>,
    ) -> Result<Response<()>, Status> {
        todo!()
    }

    async fn upsert_room_content_repositories(
        &self,
        _req: tonic::Request<CreateRoomRepositoryRequest>,
    ) -> Result<Response<()>, Status> {
        todo!()
    }

    async fn remove_room_content_repositories(
        &self,
        _req: tonic::Request<RemoveRepositoryRequest>,
    ) -> Result<Response<()>, Status> {
        todo!()
    }

    async fn set_content_repository_access(
        &self,
        _req: tonic::Request<ContentRepoAccessRequest>,
    ) -> Result<Response<()>, Status> {
        todo!()
    }
}
