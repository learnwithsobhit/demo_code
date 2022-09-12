use crate::database::{Database, USER_ACTIONS_TABLE};
use common::common::{Event, TimeUuid};
use common::errors::Error;
use common::utils::get_comma_seperated_string_of_characters;
use const_format::formatcp;
use mysql_async::prelude::Queryable;
use mysql_async::Params;
use mysql_async::Value;

const USER_ACTIONS_FIELDS_SQL: &str =
    formatcp!("app_id, user_id, event_id, event_type, event_data, content_id, event_timestamp");

impl Database {
    pub async fn set_user_actions(
        &self,
        app_id: u32,
        user_id: u64,
        event_id: &TimeUuid,
        content_id: Option<&TimeUuid>,
        events: Vec<Event>,
    ) -> Result<(), Error> {
        let event_len = events.len();
        let sql_value_string = get_comma_seperated_string_of_characters(
            "(?,?,?,?,?,?,FROM_UNIXTIME(? * 0.001))",
            event_len,
        );

        let set_user_action_sql = String::from(formatcp!(
            "INSERT INTO {USER_ACTIONS_TABLE} ({USER_ACTIONS_FIELDS_SQL}) VALUES "
        )) + &sql_value_string;

        /* build a param vector and execute it in signle shot */
        let mut params = Vec::new();
        for event in events {
            // let bin_data = bincode::serialize(&event.data).unwrap();
            let meta_data = serde_json::to_string(&event.data)?;
            params.push(Value::from(app_id));
            params.push(Value::from(user_id));
            params.push(Value::from(event_id.to_uuid_v6().to_vec()));
            params.push(Value::from(event.event_type));
            params.push(Value::from(meta_data));
            match content_id {
                Some(id) => params.push(Value::from(id.to_uuid_v6().to_vec())),
                None => params.push(Value::NULL),
            };
            params.push(Value::UInt(event_id.timestamp_ms()));
        }

        let mut conn = self.conn().await?;
        let statement_user_actions = conn.prep(set_user_action_sql.as_str()).await?;
        conn.exec_drop(statement_user_actions.clone(), Params::Positional(params))
            .await?;

        Ok(())
    }
}
