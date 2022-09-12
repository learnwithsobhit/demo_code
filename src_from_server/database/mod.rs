use common::errors::Error;
use common::user::{AccountStatus, UserProfileData, UserType};
use common::utils::hash_argon2;
use const_format::formatcp;
use mysql_async::{prelude::Queryable, Conn, Opts, OptsBuilder, Params, Pool, TxOpts};

use crate::config::{BootstrapConfig, DatabaseConfig};

pub mod admin;
pub mod app_properties;
pub mod common_types;
pub mod content;
pub mod content_repo_properties;
pub mod rooms;
pub mod user;
pub mod user_actions;
pub mod user_properties;

pub const USERS_TABLE: &str = "users";
pub const ROOMS_TABLE: &str = "rooms";
pub const ROOM_MEMBERS_TABLE: &str = "room_members";
pub const ROOM_BANNED_MEMBERS_TABLE: &str = "room_members_banned";
pub const USER_PROPERTIES_TABLE: &str = "user_properties";
pub const USER_ACTIONS_TABLE: &str = "user_actions";
pub const CONTENT_REPO_PROPERTIES_TABLE: &str = "content_repo_properties";
pub const APP_PROPERTIES_TABLE: &str = "app_properties";
pub const SSO_DATA_TABLE: &str = "sso_data";
pub const APPS_TABLE: &str = "apps";
pub const CONTENT_REPOS_TABLE: &str = "content_repos";
pub const CONTENTS_TABLE: &str = "contents";
pub const VIDEO_UPLOADS_TABLE: &str = "video_uploads";
pub const CFS_PENDING_DELETION_TABLE: &str = "cloudflare_pending_video_deletions";

pub struct Database {
    pool: Pool,
}

impl Database {
    ///
    /// Get database connection from the pool
    ///
    async fn conn(&self) -> Result<Conn, Error> {
        self.pool.get_conn().await.map_err(|e| e.into())
    }
}

impl Database {
    ///
    /// Initialize the database (bootstrapping) - create initial tables
    ///
    pub async fn init_db(
        cfg: &DatabaseConfig,
        bootstrap_cfg: BootstrapConfig,
    ) -> Result<(), Error> {
        // Create db structure
        let script = std::fs::read_to_string(bootstrap_cfg.setup_script)?;
        let opts = Opts::from(
            OptsBuilder::default()
                .ip_or_hostname(&cfg.ip)
                .tcp_port(cfg.port)
                .user(Some(&cfg.user))
                .pass(Some(&cfg.password)),
        );
        let mut conn = Conn::new(opts).await?;
        let queries = script.split(';');
        let tx_opts = TxOpts::default();

        {
            let mut tr = conn.start_transaction(tx_opts).await?;
            for q in queries.filter(|&x| !x.trim().is_empty()) {
                tr.exec_drop(q.trim(), Params::Empty).await?;
            }
            tr.commit().await?;
        }

        // Create platform admin account
        // Client side pre-hashing
        let (hash, _salt) = hash_argon2(&bootstrap_cfg.password, false);
        // Server side hashing
        let (hash, salt) = hash_argon2(&hash, true);
        let sql = format!("INSERT INTO `platform`.`users` (`username`, `password`, `salt`, `app_id`, `account_status`, `user_type`, `profile`) VALUES
         ('{}','{}','{}',NULL,{},{},?)",bootstrap_cfg.username, hash, salt, AccountStatus::Registered as u8, UserType::Admin as u8);

        conn.exec_drop(
            sql,
            Params::Positional(vec![UserProfileData::default().to_bytes().into()]),
        )
        .await?;

        let result: mysql_async::Row = conn
            .exec_first("SELECT LAST_INSERT_ID();", Params::Empty)
            .await?
            .expect("There is one row");

        let user_id = result.get::<u64, usize>(0).expect("Is a valid id");

        // update user, set username and user_id in basic profile data
        let statement_profile = conn
            .prep(formatcp!(
                "UPDATE {USERS_TABLE} SET profile = ? WHERE id = ?"
            ))
            .await?;

        conn.exec_drop(
            statement_profile,
            Params::Positional(vec![
                UserProfileData {
                    user_id,
                    username: bootstrap_cfg.username,
                    ..Default::default()
                }
                .to_bytes()
                .into(),
                user_id.into(),
            ]),
        )
        .await?;

        Ok(())
    }

    pub async fn connect(cfg: &DatabaseConfig) -> Result<Self, Error> {
        let opts = Opts::from(
            OptsBuilder::default()
                .ip_or_hostname(&cfg.ip)
                .tcp_port(cfg.port)
                .user(Some(&cfg.user))
                .pass(Some(&cfg.password))
                .db_name(cfg.db_name.as_ref()),
        );
        let pool = Pool::new(opts);
        Ok(Self { pool })
    }
}
