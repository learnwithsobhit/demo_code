use const_format::formatcp;
use mysql_async::prelude::Queryable;
use mysql_async::{Params, Row, TxOpts};
use std::collections::HashMap;

use crate::database::common_types::*;
use crate::database::content::FAILED_VIDEO_DELETION_FIELDS;
use crate::database::Database;
use crate::database::{
    APPS_TABLE, APP_PROPERTIES_TABLE, CFS_PENDING_DELETION_TABLE, CONTENTS_TABLE,
    CONTENT_REPOS_TABLE, CONTENT_REPO_PROPERTIES_TABLE, ROOMS_TABLE, SSO_DATA_TABLE, USERS_TABLE,
    USER_ACTIONS_TABLE, USER_PROPERTIES_TABLE, VIDEO_UPLOADS_TABLE,
};

use common::admin::{CreateAppRequest, DeleteAppRequest};
use common::common::{AppDetails, Event};
use common::errors::Error;

const APP_FIELDS_SQL: &str = formatcp!("id, {APP_FIELDS_SQL_EX_ID}");
const APP_FIELDS_SQL_EX_ID: &str =
    "name, token, description, login_config, register_config, sso_config";

impl Database {
    pub async fn admin_create_app(&self, req: &CreateAppRequest) -> Result<AppDetails, Error> {
        let mut c = self.conn().await?;

        // Ensure that app name and token are unique
        // While the database will guarantee uniqueness, better to check and provide a proper error
        let sql = "SELECT id FROM apps WHERE name = ?;";
        if let Some(id) = c
            .exec_first(sql, Params::Positional(vec![req.app_name.clone().into()]))
            .await?
        {
            let _id: u32 = id;
            return Err(Error::id_in_use("App ID", "App ID already in use"));
        }

        let sql = "SELECT id FROM apps WHERE token = ?;";
        if let Some(id) = c
            .exec_first(sql, Params::Positional(vec![req.app_token.clone().into()]))
            .await?
        {
            let _id: u32 = id;
            return Err(Error::id_in_use("App Token", "App token already in use"));
        }

        // Create app
        let sql = formatcp!(
            "INSERT INTO {} ({APP_FIELDS_SQL_EX_ID}) VALUES (?,?,?,?,?,?);",
            APPS_TABLE
        );
        let sql2 = "SELECT LAST_INSERT_ID();";

        let s = c.prep(sql).await?;
        let s2 = c.prep(sql2).await?;

        let sso_config =
            serde_json::to_string(&req.sso_cfg).expect("Failed to serialize sso config");

        let values = vec![
            req.app_name.as_str().into(),
            req.app_token.as_str().into(),
            "".into(),
            req.login_config.clone().into(),
            req.register_config.clone().into(),
            sso_config.into(),
        ];

        let mut tr = c.start_transaction(TxOpts::default()).await?;
        tr.exec_drop(s, Params::Positional(values)).await?;
        let result: Row = tr
            .exec_first(s2, Params::Empty)
            .await?
            .expect("There is one row");
        tr.commit().await?;

        let id = result.get::<u32, usize>(0).expect("Is a valid id");

        let details = AppDetails {
            id,
            name: req.app_name.clone(),
            token: req.app_token.clone(),
            user_profile_schema: HashMap::new(),
        };

        Ok(details)
    }

    pub async fn admin_delete_app(&self, req: &DeleteAppRequest) -> Result<(), Error> {
        // Check app exists
        let app = self.admin_get_app_by_id(req.app_id).await?;
        if app.is_none() {
            return Err(Error::bad_request(format!("App not found: {}", req.app_id)));
        }
        let app = app.unwrap();

        let mut c = self.conn().await?;

        // Deletion should remove all users, rooms etc associated with the app
        // Note: we won't cache the statement or use a prepared statement here as app deletion is extremely rare compared to other operations

        // First: move any videos to the 'cloudflare_pending_video_deletions' table for later processing
        // Given the app could potentially have hundreds, thousands or more videos -- we can't synchronously
        // delete them all as part of the 'delete app' request.
        c.exec_drop(
            &formatcp!("INSERT INTO {CFS_PENDING_DELETION_TABLE} ({FAILED_VIDEO_DELETION_FIELDS}) \
            SELECT uuid, video_cfs_id, NULL, CURRENT_TIMESTAMP() FROM {CONTENTS_TABLE} WHERE app_id = ? AND video_cfs_id IS NOT NULL;"),
            Params::Positional(vec![app.id.into()])
        ).await?;

        //video_uploads
        c.exec_drop(
            &formatcp!("INSERT INTO {CFS_PENDING_DELETION_TABLE} ({FAILED_VIDEO_DELETION_FIELDS}) \
            SELECT uuid, cloudflare_video_id, NULL, CURRENT_TIMESTAMP() FROM {VIDEO_UPLOADS_TABLE} WHERE app_id = ?;"),
            Params::Positional(vec![app.id.into()])
        ).await?;

        // Delete all content
        c.exec_drop(
            &formatcp!("DELETE FROM {CONTENTS_TABLE} WHERE app_id = ?;"),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;
        c.exec_drop(
            &formatcp!("DELETE FROM {VIDEO_UPLOADS_TABLE} WHERE app_id = ?;"),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;
        c.exec_drop(
            &formatcp!("DELETE FROM {USER_PROPERTIES_TABLE} WHERE app_id = ?;"),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;
        c.exec_drop(
            &formatcp!("DELETE FROM {CONTENT_REPO_PROPERTIES_TABLE} WHERE app_id = ?;"),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;
        c.exec_drop(
            &formatcp!("DELETE FROM {APP_PROPERTIES_TABLE} WHERE app_id = ?;"),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;
        c.exec_drop(
            &formatcp!("DELETE FROM {USER_ACTIONS_TABLE} WHERE app_id = ?;"),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;
        c.exec_drop(
            &formatcp!("DELETE FROM {CONTENT_REPOS_TABLE} WHERE app_id = ?;"),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;
        c.exec_drop(
            &formatcp!("DELETE FROM {} WHERE app_id = ?;", USERS_TABLE),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;
        c.exec_drop(
            &formatcp!("DELETE FROM {} WHERE app_id = ?;", SSO_DATA_TABLE),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;
        c.exec_drop(
            &formatcp!("DELETE FROM {} WHERE id = ?;", APPS_TABLE),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;
        c.exec_drop(
            &formatcp!("DELETE FROM {} WHERE app_id = ?;", ROOMS_TABLE),
            Params::Positional(vec![app.id.into()]),
        )
        .await?;

        Ok(())
    }

    pub async fn admin_get_app_by_token(&self, app_token: &str) -> Result<Option<App>, Error> {
        let sql = formatcp!("SELECT {APP_FIELDS_SQL} FROM {APPS_TABLE} WHERE token = ?;");

        let mut c = self.conn().await?;

        let s = c.prep(sql).await?;

        match c
            .exec_first(s, Params::Positional(vec![app_token.into()]))
            .await
        {
            Ok(row) => match row {
                Some((id, name, token, description, login_config, register_config, sso_cfg)) => {
                    Ok(Some(App {
                        id,
                        name,
                        token,
                        description,
                        login_config,
                        register_config,
                        sso_config: sso_cfg,
                    }))
                }
                _ => Ok(None),
            },
            Err(e) => Err(Error::database(e.to_string())),
        }
    }

    pub async fn admin_get_app_by_id(&self, app_id: u32) -> Result<Option<App>, Error> {
        let mut c = self.conn().await?;

        let sql = formatcp!("SELECT {APP_FIELDS_SQL} FROM {APPS_TABLE} WHERE id = ?;");
        let s = c.prep(sql).await?;

        match c
            .exec_first(s, Params::Positional(vec![app_id.into()]))
            .await
        {
            Ok(row) => match row {
                Some((id, name, token, description, login_config, register_config, sso_cfg)) => {
                    Ok(Some(App {
                        id,
                        name,
                        token,
                        description,
                        login_config,
                        register_config,
                        sso_config: sso_cfg,
                    }))
                }
                _ => Ok(None),
            },
            Err(e) => Err(Error::database(e.to_string())),
        }
    }

    pub async fn admin_list_apps(&self) -> Result<Vec<AppDetails>, Error> {
        let mut conn = self.conn().await?;

        let sql = formatcp!("SELECT id, name, token FROM {APPS_TABLE};");
        let s = conn.prep(sql).await?;

        let result = conn
            .exec_map(s, Params::Empty, |(id, name, token)| AppDetails {
                id,
                name,
                token,
                user_profile_schema: HashMap::new(),
            })
            .await?;

        Ok(result)
    }

    pub async fn admin_list_events(&self, app_id: u32, user_id: u64) -> Result<Vec<Event>, Error> {
        let mut conn = self.conn().await?;

        let sql =
            formatcp!("SELECT event_type, event_data FROM {USER_ACTIONS_TABLE} WHERE app_id = ? AND user_id = ?;");
        let s = conn.prep(sql).await?;

        let result = conn
            .exec_map(
                s,
                Params::Positional(vec![app_id.into(), user_id.into()]),
                |(name, meta_data): (String, String)| Event {
                    event_type: name,
                    data: serde_json::from_str(meta_data.as_str()).unwrap(),
                },
            )
            .await?;

        Ok(result)
    }
}
