use crate::database::content::CONTENT_REPO_FIELDS_SQL_EX_ID_TS;
use crate::database::{Database, CONTENT_REPOS_TABLE, SSO_DATA_TABLE, USERS_TABLE};
use crate::utils::add_sql_like_clause;

use common::errors::Error;
use common::user::{list_users_request, AccountStatus, AuthProvider, UserProfileData};
use common::utils::{hash_argon2, unwrap_and_order_listing_results};
use const_format::formatcp;
use mysql_async::prelude::Queryable;
use mysql_async::Value;
use mysql_async::{Params, Row, TxOpts};

use super::common_types::User;
use super::common_types::{RepoType, SsoData};

const USER_FIELDS_SQL_EX_ID: &str =
    "sso_id, username, password, salt, email, phone, app_id, account_status, user_type, profile";
const USER_FIELDS_SQL: &str = formatcp!("id, {USER_FIELDS_SQL_EX_ID}");

const SSO_FIELDS_SQL_EX_ID: &str = "app_id, provider_id, identifier";

/// Used in list_users. If request limit is greater than this value truncate result to MAX_USERS_PAGE_SIZE entries
const MAX_USERS_PAGE_SIZE: u32 = 1000;

impl Database {
    ///
    /// Create user account, and return the user ID of the new account
    ///
    pub async fn create_user(
        &self,
        user: User,
        sso: Option<SsoData>,
        password_str: Option<&String>,
    ) -> Result<u64, Error> {
        let mut conn = self.conn().await?;

        // Create sso entry if applies, get sso_id
        let statement_sso = conn
            .prep(formatcp!(
                "INSERT INTO {SSO_DATA_TABLE} ({SSO_FIELDS_SQL_EX_ID}) VALUES (?,?,?);"
            ))
            .await?;
        // Create user entry, get user_id
        let statement_user = conn
            .prep(formatcp!(
                "INSERT INTO {USERS_TABLE} ({USER_FIELDS_SQL_EX_ID}) VALUES (?,?,?,?,?,?,?,?,?,?);"
            ))
            .await?;
        // Create user repository, use user_id as creator
        let statement_repository = conn.prep(formatcp!(
            "INSERT INTO {CONTENT_REPOS_TABLE} ({CONTENT_REPO_FIELDS_SQL_EX_ID_TS}) VALUES (?,?,?,?);"
        )).await?;
        // update user, set username and user_id in basic profile data
        let statement_profile = conn
            .prep(formatcp!(
                "UPDATE {USERS_TABLE} SET profile = ? WHERE id = ?"
            ))
            .await?;

        let (hash, salt) = if let Some(pass) = password_str {
            let (hash, salt) = hash_argon2(pass, true);
            (Some(hash), Some(salt))
        } else {
            (None, None)
        };

        let mut tr = conn.start_transaction(TxOpts::default()).await?;

        // SSO data
        let sso_id = if let Some(sso) = sso {
            let values = vec![
                sso.app_id.into(),
                Value::UInt(sso.provider as u64),
                sso.identifier.into(),
            ];

            tr.exec_drop(statement_sso, Params::Positional(values))
                .await?;
            let result: Row = tr
                .exec_first("SELECT LAST_INSERT_ID();", Params::Empty)
                .await?
                .expect("There is one row");

            Some(result.get::<u64, usize>(0).expect("Is a valid id"))
        } else {
            None
        };

        // User data
        let values = vec![
            sso_id.into(),
            user.username.clone().into(),
            hash.into(),
            salt.into(),
            user.email.into(),
            user.phone.into(),
            user.app_id.into(),
            Value::UInt(user.account_status as u64),
            Value::UInt(user.user_type as u64),
            Value::Bytes(UserProfileData::default().to_bytes()),
        ];

        tr.exec_drop(statement_user, Params::Positional(values))
            .await?;

        let result: Row = tr
            .exec_first("SELECT LAST_INSERT_ID();", Params::Empty)
            .await?
            .expect("There is one row");

        let user_id = result.get::<u64, usize>(0).expect("Is a valid id");

        if user.app_id.is_some() {
            // User repository data
            let values = vec![
                format!("{}_{}", user.app_id.as_ref().unwrap_or(&0), user.username).into(),
                user_id.into(),
                user.app_id.into(),
                (RepoType::User as u8).into(),
            ];

            tr.exec_drop(statement_repository, Params::Positional(values))
                .await?;
        }

        // Once id is known update profile column
        let profile = UserProfileData {
            user_id,
            username: user.username.into(),
            ..Default::default()
        };

        let profile_bytes = profile.to_bytes();

        let values = vec![Value::Bytes(profile_bytes), user_id.into()];

        tr.exec_drop(statement_profile, Params::Positional(values))
            .await?;

        tr.commit().await?;

        Ok(user_id)
    }

    pub async fn update_user_status(
        &self,
        username: &str,
        app_id: u32,
        status: AccountStatus,
    ) -> Result<(), Error> {
        let mut conn = self.conn().await?;

        let sql = "UPDATE users SET account_status = ? WHERE username = ? AND app_id = ?;";
        let values = vec![
            Value::UInt(status as u64),
            username.into(),
            Value::UInt(app_id as u64),
        ];

        let statement = conn.prep(sql).await?;

        conn.exec_drop(statement, Params::Positional(values))
            .await?;

        Ok(())
    }

    pub async fn get_user(
        &self,
        username: &str,
        app_id: Option<u32>,
    ) -> Result<Option<User>, Error> {
        let (sql, values) = if let Some(id) = app_id {
            (
                formatcp!(
                    "SELECT {USER_FIELDS_SQL} FROM `users` WHERE username = ? AND app_id = ?"
                ),
                vec![username.into(), Value::UInt(id as u64)],
            )
        } else {
            (
                formatcp!(
                    "SELECT {USER_FIELDS_SQL} FROM `users` WHERE username = ? AND ISNULL(app_id);"
                ),
                vec![username.into()],
            )
        };

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        match conn.exec_first(stmt, Params::Positional(values)).await {
            Ok(result) => match result {
                Some(row) => {
                    let row: Row = row;
                    Ok(Some(User::try_from(row)?))
                }
                _ => Ok(None),
            },
            Err(e) => Err(Error::database(format!("Connection error: {:?}", e))),
        }
    }

    pub async fn get_user_by_sso_data(
        &self,
        identifier: &str,
        provider: AuthProvider,
        app_id: u32,
    ) -> Result<Option<User>, Error> {
        let sql = formatcp!(
            "SELECT {USER_FIELDS_SQL} FROM `users` WHERE sso_id = (SELECT id FROM {SSO_DATA_TABLE} WHERE app_id = ? AND provider_id = ? AND identifier = ?);");

        let values = vec![
            app_id.into(),
            Value::Int(provider as i64),
            identifier.into(),
        ];

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        match conn.exec_first(stmt, Params::Positional(values)).await {
            Ok(result) => match result {
                Some(row) => {
                    let row: Row = row;
                    Ok(Some(User::try_from(row)?))
                }
                _ => Ok(None),
            },
            Err(e) => Err(Error::database(format!("Connection error: {:?}", e))),
        }
    }

    pub async fn get_user_by_id(&self, id: u64) -> Result<Option<User>, Error> {
        let sql = formatcp!("SELECT {USER_FIELDS_SQL} FROM `users` WHERE id = ?;");

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        match conn
            .exec_first(stmt, Params::Positional(vec![Value::UInt(id as u64)]))
            .await
        {
            Ok(result) => match result {
                Some(row) => {
                    let row: Row = row;
                    Ok(Some(User::try_from(row)?))
                }
                _ => Ok(None),
            },
            Err(e) => Err(Error::database(format!("Connection error: {:?}", e))),
        }
    }

    pub async fn get_user_by_email(
        &self,
        email: &str,
        app_id: Option<u32>,
    ) -> Result<Option<User>, Error> {
        let (sql, values) = if let Some(id) = app_id {
            (
                formatcp!("SELECT {USER_FIELDS_SQL} FROM `users` WHERE email = ? AND app_id = ?"),
                vec![email.into(), Value::UInt(id as u64)],
            )
        } else {
            (
                formatcp!(
                    "SELECT {USER_FIELDS_SQL} FROM `users` WHERE username = ? AND ISNULL(app_id);"
                ),
                vec![email.into()],
            )
        };

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        match conn.exec_first(stmt, Params::Positional(values)).await {
            Ok(result) => match result {
                Some(row) => {
                    let row: Row = row;
                    Ok(Some(User::try_from(row)?))
                }
                _ => Ok(None),
            },
            Err(e) => Err(Error::database(format!("Connection error: {:?}", e))),
        }
    }

    pub async fn update_user_profile(&self, profile: &UserProfileData) -> Result<(), Error> {
        let mut conn = self.conn().await?;
        let statement_profile = conn
            .prep(formatcp!(
                "UPDATE {USERS_TABLE} SET profile = ?, email = ? WHERE id = ?"
            ))
            .await?;

        let profile_bytes = profile.to_bytes();

        let values = vec![
            Value::Bytes(profile_bytes),
            profile.email.clone().into(),
            profile.user_id.into(),
        ];

        conn.exec_drop(statement_profile, Params::Positional(values))
            .await?;

        Ok(())
    }

    ///
    /// List contents
    ///
    pub async fn list_users(
        &self,
        app_id: u32,
        search_phrase: Option<String>,
        order_by: list_users_request::Order,
        fields: Vec<list_users_request::SearchField>,
        desc: bool,
        offset: Option<&UserProfileData>,
        forward: bool,
        limit: u32,
    ) -> Result<Vec<UserProfileData>, Error> {
        let (order, cmp_sign) = common::utils::calc_order_by_args(desc, forward);

        let (mut sql, mut values) = (
            format!("SELECT profile FROM {} WHERE app_id = ?", USERS_TABLE,),
            vec![Value::UInt(app_id.into())],
        );

        if !fields.is_empty() {
            let phrase = search_phrase.ok_or(Error::bad_request("Missing search phrase"))?;
            let fields: Result<Vec<&str>, Error> =
                fields.iter().map(|f| f.to_column_str()).collect();
            sql.push_str(" AND (");
            add_sql_like_clause(&mut sql, &mut values, &phrase, fields?);
            sql.push_str(")");
        }

        if let Some(u) = offset {
            if order_by == list_users_request::Order::Id {
                sql.push_str(&format!(" AND id {} ?", cmp_sign));
                values.push(u.user_id.into());
            } else {
                sql.push_str(&format!(
                    " AND ({} {} ? OR ({} = ? AND id {} ?))",
                    order_by.to_column_str()?,
                    cmp_sign,
                    order_by.to_column_str()?,
                    cmp_sign
                ));
                values.push(order_by.get_offset_value(u)?);
                values.push(order_by.get_offset_value(u)?);
                values.push(u.user_id.into());
            }
        }

        sql.push_str(" ORDER BY ");
        if order_by == list_users_request::Order::Id {
            sql.push_str(&format!("{} {}", order_by.to_column_str()?, order));
        } else {
            sql.push_str(&format!(
                "{} {}, {} {}",
                order_by.to_column_str()?,
                order,
                list_users_request::Order::Id.to_column_str()?,
                order
            ));
        }

        sql.push_str(" LIMIT ?");
        values.push(limit.min(MAX_USERS_PAGE_SIZE).into());

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        let list = conn
            .exec_map(stmt, Params::Positional(values), |row: Row| {
                UserProfileData::try_from(row)
            })
            .await
            .map_err(|e| Error::database(format!("Connection error: {:?}", e)))?;

        if list.iter().any(|i| {
            if let Err(e) = i {
                log::error!("User profile conversion error: {:?}", e);
                true
            } else {
                false
            }
        }) {
            return Err(Error::database("User profile conversion error."));
        }

        let list = unwrap_and_order_listing_results(list, forward);

        Ok(list)
    }
}
