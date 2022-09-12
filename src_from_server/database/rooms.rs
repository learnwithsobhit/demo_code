use crate::database::{Database, ROOMS_TABLE, ROOM_BANNED_MEMBERS_TABLE, ROOM_MEMBERS_TABLE};
use crate::utils::add_sql_like_clause;
use common::errors::Error;
use common::rooms::*;
use common::utils::get_comma_seperated_string_of_characters;
use const_format::formatcp;
use mysql_async::prelude::Queryable;
use mysql_async::Params;
use mysql_async::Value;

const ROOMS_FIELDS_SQL: &str =
    formatcp!("unique_id,app_id,creator_id, name, description, avatar_url, room_type,custom_data,search_indexing,
    content_access,join_rule,invite_rule,add_rule,last_changed_timestamp");

const ROOM_MEMBERS_FIELDS_SQL: &str =
    formatcp!("app_id,member_id, room_id, member_type, join_status");

const ROOM_MEMBERS_BANNED_FIELDS_SQL: &str =
    formatcp!("app_id,member_id, room_id, banned_by_user_id");

impl Database {
    pub async fn create_rooms(
        &self,
        app_id: u32,
        creator_id: u64,
        room: CreateRoomRequest,
    ) -> Result<(), Error> {
        let sql_value_string = get_comma_seperated_string_of_characters(
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP())",
            number_of_rooms,
        );

        let sql_room_create = formatcp!("INSERT INTO {ROOMS_TABLE} ({ROOMS_FIELDS_SQL}) VALUES ")
            .to_owned()
            + &sql_value_string;

        let number_of_params: Vec<&str> = ROOMS_FIELDS_SQL.split(',').collect();
        /* build a param vector and execute it in signle shot */
        let mut params = Vec::with_capacity(number_of_rooms * (number_of_params.len() - 1));
        for room in rooms {
            let custom_data = serde_json::to_string(&room.custom_data)?;
            let room_info = room
                .room_info
                .as_ref()
                .ok_or(Error::bad_request("no room info provided!"))?;
            let room_config = room
                .room_config
                .as_ref()
                .ok_or(Error::bad_request("no room configuration provided!"))?;
            let join_rules = room
                .join_rule
                .as_ref()
                .ok_or(Error::bad_request("no join rules provided!"))?;

            params.push(Value::from(room_info.unique_id.as_ref()));
            params.push(Value::from(app_id));
            params.push(Value::from(creator_id));
            params.push(Value::from(room_info.name.to_string()));
            params.push(Value::from(room_info.description.as_ref()));
            params.push(Value::from(room_info.avatar_url.as_ref()));
            params.push(Value::from(room_config.room_type));
            params.push(Value::from(custom_data));
            params.push(Value::from(room_config.search_indexing));
            params.push(Value::from(room_config.content_access));
            params.push(Value::from(join_rules.join_rule));
            params.push(Value::from(join_rules.invite_rule));
            params.push(Value::from(join_rules.add_rule));
        }

        let mut conn = self.conn().await?;
        let statement_room_create = conn.prep(sql_room_create).await?;
        conn.exec_drop(statement_room_create, Params::Positional(params))
            .await?;
        Ok(())
    }

    pub async fn update_room_by_room_id(
        &self,
        app_id: u32,
        room_id: u64,
        room: &AddRoomData,
    ) -> Result<(), Error> {
        let sql_room_update = formatcp!(
            "UPDATE {ROOMS_TABLE} SET name=?, description=?, avatar_url=?,
            room_type=?, custom_data=?, search_indexing=?, content_access=?, join_rule=?, invite_rule=?,
            add_rule=?, last_changed_timestamp=CURRENT_TIMESTAMP() WHERE app_id=? AND id=?;");

        /* build a param vector and execute it */
        let mut params = Vec::new();
        let custom_data = serde_json::to_string(&room.custom_data)?;
        let room_info = room
            .room_info
            .as_ref()
            .ok_or(Error::bad_request("no room info provided!"))?;
        let room_config = room
            .room_config
            .as_ref()
            .ok_or(Error::bad_request("no room configuration provided!"))?;
        let join_rules = room
            .join_rule
            .as_ref()
            .ok_or(Error::bad_request("no join rules provided!"))?;

        params.push(Value::from(room_info.name.to_string()));
        params.push(Value::from(room_info.description.as_ref()));
        params.push(Value::from(room_info.avatar_url.as_ref()));
        params.push(Value::from(room_config.room_type));
        params.push(Value::from(custom_data));
        params.push(Value::from(room_config.search_indexing));
        params.push(Value::from(room_config.content_access));
        params.push(Value::from(join_rules.join_rule));
        params.push(Value::from(join_rules.invite_rule));
        params.push(Value::from(join_rules.add_rule));
        params.push(Value::from(app_id));
        params.push(Value::from(room_id));

        let mut conn = self.conn().await?;
        let statement_room_update = conn.prep(sql_room_update).await?;
        conn.exec_drop(statement_room_update.clone(), Params::Positional(params))
            .await?;
        Ok(())
    }

    pub async fn update_room_by_unique_id(
        &self,
        app_id: u32,
        unique_name: &String,
        room: &AddRoomData,
    ) -> Result<(), Error> {
        let sql_room_update = formatcp!(
            "UPDATE {ROOMS_TABLE} SET name=?, description=?, avatar_url=?,
            room_type=?, custom_data=?, search_indexing=?, content_access=?, join_rule=?, invite_rule=?,
            add_rule=?, last_changed_timestamp= CURRENT_TIMESTAMP() WHERE app_id=? AND unique_id=?;");

        let number_of_params = 12;
        /* build a param vector and execute it in single shot */
        let mut params = Vec::with_capacity(number_of_params);

        let custom_data = serde_json::to_string(&room.custom_data)?;
        let room_info = room
            .room_info
            .as_ref()
            .ok_or(Error::bad_request("no room info provided!"))?;
        let room_config = room
            .room_config
            .as_ref()
            .ok_or(Error::bad_request("no room configuration provided!"))?;
        let join_rules = room
            .join_rule
            .as_ref()
            .ok_or(Error::bad_request("no join rules provided!"))?;

        params.push(Value::from(room_info.name.to_string()));
        params.push(Value::from(room_info.description.as_ref()));
        params.push(Value::from(room_info.avatar_url.as_ref()));
        params.push(Value::from(room_config.room_type));
        params.push(Value::from(custom_data));
        params.push(Value::from(room_config.search_indexing));
        params.push(Value::from(room_config.content_access));
        params.push(Value::from(join_rules.join_rule));
        params.push(Value::from(join_rules.invite_rule));
        params.push(Value::from(join_rules.add_rule));
        params.push(Value::from(app_id));
        params.push(Value::from(unique_name));

        let mut conn = self.conn().await?;
        let statement_room_update = conn.prep(sql_room_update).await?;
        conn.exec_drop(statement_room_update.clone(), Params::Positional(params))
            .await?;
        Ok(())
    }

    pub async fn delete_rooms_by_id(&self, app_id: u32, room_id: u64) -> Result<(), Error> {
        let sql = String::from(formatcp!(
            "DELETE FROM {ROOMS_TABLE} WHERE app_id = ? AND id = ?;"
        ));

        let mut values = vec![app_id.into()];
        values.push(Value::from(room_id));
        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;
        conn.exec_drop(stmt, Params::Positional(values)).await?;
        Ok(())
    }

    pub async fn delete_rooms_by_names(&self, app_id: u32, room_name: String) -> Result<(), Error> {
        let sql = String::from(formatcp!(
            "DELETE FROM {ROOMS_TABLE} WHERE app_id = ? AND unique_id =?;"
        ));

        let mut values = vec![app_id.into()];
        values.push(Value::from(room_name));
        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;
        conn.exec_drop(stmt, Params::Positional(values)).await?;
        Ok(())
    }

    pub async fn delete_rooms_by_unique_ids(
        &self,
        app_id: u32,
        unique_id: String,
    ) -> Result<(), Error> {
        let sql = String::from(formatcp!(
            "DELETE FROM {ROOMS_TABLE} WHERE app_id = ? AND unique_id =?;"
        ));

        let mut values = vec![app_id.into()];

        values.push(Value::from(unique_id));
        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;
        conn.exec_drop(stmt, Params::Positional(values)).await?;
        Ok(())
    }

    pub async fn delete_rooms_by_room_type(
        &self,
        app_id: u32,
        room_types: i32,
    ) -> Result<(), Error> {
        let sql = formatcp!("DELETE FROM {ROOMS_TABLE} WHERE app_id = ? AND room_type = ?;");
        let mut params = Vec::with_capacity(2);
        params.push(Value::from(app_id));
        params.push(Value::from(room_types));
        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;
        conn.exec_drop(stmt, Params::Positional(params)).await?;
        Ok(())
    }

    pub async fn list_rooms(
        &self,
        app_id: u32,
        order_by: list_room_request::Order,
        desc: bool,
        search_phrase: Option<String>,
        fields: Vec<list_room_request::SearchField>,
        page_info: PaginationInfo,
    ) -> Result<Vec<ListRoomInfo>, Error> {
        let (order, cmp_sign) =
            common::utils::calc_order_by_args(desc, page_info.forward.unwrap_or(true));
        let mut sql = format!(
            "SELECT id, name, unique_id, description, avatar_url FROM {} WHERE app_id = ?",
            ROOMS_TABLE,
        );

        let mut params = vec![Value::from(app_id)];

        if !fields.is_empty() {
            let phrase = search_phrase.ok_or(Error::bad_request("Missing search phrase"))?;
            let fields: Result<Vec<&str>, Error> =
                fields.iter().map(|f| f.to_column_str()).collect();
            sql.push_str(" AND (");
            add_sql_like_clause(&mut sql, &mut params, &phrase, fields?);
            sql.push_str(")");
        }

        if let Some(r) = page_info.offset {
            if order_by == list_room_request::Order::Id {
                sql.push_str(&format!(" AND id {} ?", cmp_sign));
                params.push(r.room_id.into());
            } else {
                sql.push_str(&format!(
                    " AND ({} {} ? OR ({} = ? AND id {} ?))",
                    order_by.to_column_str()?,
                    cmp_sign,
                    order_by.to_column_str()?,
                    cmp_sign
                ));
                params.push(r.room_unique_name);
                params.push(r.room_unique_name);
                params.push(r.room_id.into());
            }
        }

        sql.push_str(" ORDER BY ");
        if order_by == list_room_request::Order::Id {
            sql.push_str(&format!("{} {}", order_by.to_column_str()?, order));
        } else {
            sql.push_str(&format!(
                "{} {}, {} {}",
                order_by.to_column_str()?,
                order,
                list_room_request::Order::Id.to_column_str()?,
                order
            ));
        }

        if let Some(limit) = page_info.limit {
            sql.push_str(&format!(" LIMIT ?"));
            params.push(limit.min(MAX_ROOMS_PAGE_SIZE).into());
        }

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;
        let list = conn
            .exec_map(
                stmt,
                Params::Positional(params),
                |(id, name, unique_id, description, avatar_url)| ListRoomInfo {
                    room_id: id,
                    room_info: Some(RoomInfo {
                        name,
                        unique_id,
                        description,
                        avatar_url,
                    }),
                },
            )
            .await
            .map_err(|e| Error::database(format!("Connection error: {:?}", e)))?;

        Ok(list)
    }

    async fn is_member_banned(
        &self,
        app_id: u32,
        member_id: u64,
        room_id: u64,
    ) -> Result<bool, Error> {
        let sql = formatcp!(
            "SELECT user_id FROM {ROOM_BANNED_MEMBERS_TABLE} WHERE app_id = ? AND room_id =? AND user_id = ?",
        );

        let mut is_banned = false;
        let params: Vec<Value> = vec![app_id.into(), room_id.into(), member_id.into()];

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;
        let list = conn
            .exec_map(stmt, Params::Positional(params), |user_id: u64| user_id)
            .await
            .map_err(|e| Error::database(format!("Connection error: {:?}", e)))?;

        if list.len() > 0 {
            is_banned = true;
        }
        Ok(is_banned)
    }

    pub async fn join_room(
        &self,
        app_id: u32,
        member_id: u64,
        room_id: u64,
    ) -> Result<JoinRoomResponse, Error> {
        if self.is_member_banned(app_id, member_id, room_id).await? {
            return Ok(JoinRoomResponse {
                joined_status: "banned".into(),
            });
        }
        let sql_join_room = formatcp!(
            "INSERT INTO {ROOM_MEMBERS_TABLE} ({ROOM_MEMBERS_FIELDS_SQL}) VALUES (?,?,?,?,?)"
        );

        let number_of_params: Vec<&str> = ROOM_MEMBERS_FIELDS_SQL.split(',').collect();
        let mut params = Vec::with_capacity(number_of_params.len());

        params.push(Value::from(app_id));
        params.push(Value::from(member_id));
        params.push(Value::from(room_id));
        params.push(Value::from("Member"));
        params.push(Value::from("Request Pending"));

        let mut conn = self.conn().await?;
        let statement_join_room = conn.prep(sql_join_room).await?;
        conn.exec_drop(statement_join_room, Params::Positional(params))
            .await?;

        Ok(JoinRoomResponse {
            joined_status: "requested sent".into(),
        })
    }
}
