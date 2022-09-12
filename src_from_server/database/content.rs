use crate::database::{
    Database, CFS_PENDING_DELETION_TABLE, CONTENTS_TABLE, CONTENT_REPOS_TABLE, USERS_TABLE,
    VIDEO_UPLOADS_TABLE,
};
use crate::utils::add_sql_like_clause;

use common::common::TimeUuid;
use common::content::list_contents_request;
use common::content::list_contents_request::SearchField;
use common::content::list_repositories_request;
use common::content::{
    self, content::Metadata, Content, ContentRepository, ContentType, UploadInProgress, Video,
    VideoDetailsSummary,
};
use common::errors::Error;
use common::utils::unwrap_and_order_listing_results;
use const_format::formatcp;
use mysql_async::prelude::Queryable;
use mysql_async::Value;
use mysql_async::{Params, Row, TxOpts};
use std::convert::TryInto;

use super::common_types::RepoType;

pub const CONTENT_REPO_FIELDS_SQL_EX_ID_TS: &str = "name, creator_id, app_id, repo_type";
const CONTENT_REPO_FIELDS_SQL: &str =
    formatcp!("id, created_at, {CONTENT_REPO_FIELDS_SQL_EX_ID_TS}");
const CONTENT_FIELDS_SQL: &str =
    "uuid, repository_id, app_id, creator_id, title, description, filename, filesize, content_type, data, length, video_cfs_metadata, video_cfs_id";
const VIDEO_UPLOADS_FIELDS: &str = "uuid, app_id, repository_id, user_id, title, description, cloudflare_video_id, cloudflare_tus_url, node_id, node_last_check_timestamp, upload_failed";
pub const FAILED_VIDEO_DELETION_FIELDS: &str =
    "video_uuid, cloudflare_video_id, last_error, timestamp_failed";

/// Used in list_contents. If request limit is greater than this value truncate result to MAX_CONTENTS_PAGE_SIZE entries
const MAX_CONTENTS_PAGE_SIZE: u32 = 1000;

impl Database {
    ///
    /// Create content repository, and return the new repository ID
    ///
    pub async fn create_content_repository(
        &self,
        repository: ContentRepository,
        app_id: u32,
        repo_type: RepoType,
    ) -> Result<u64, Error> {
        let mut conn = self.conn().await?;

        let sql = formatcp!(
            "INSERT INTO {CONTENT_REPOS_TABLE} ({CONTENT_REPO_FIELDS_SQL_EX_ID_TS}) VALUES (?,?,?,?);"
        );

        let values = vec![
            repository.name.into(),
            repository.creator_id.into(),
            app_id.into(),
            (repo_type as u8).into(),
        ];

        let statement = conn.prep(sql).await?;

        let mut tr = conn.start_transaction(TxOpts::default()).await?;
        tr.exec_drop(statement, Params::Positional(values)).await?;

        let result: Row = tr
            .exec_first("SELECT LAST_INSERT_ID();", Params::Empty)
            .await?
            .expect("There is one row");
        tr.commit().await?;

        let repository_id = result.get::<u64, usize>(0).expect("Is a valid id");

        Ok(repository_id)
    }

    pub async fn get_content_repository(
        &self,
        repository_id: u64,
        repo_type: Option<RepoType>,
    ) -> Result<Option<ContentRepository>, Error> {
        let mut sql =
            formatcp!("SELECT {CONTENT_REPO_FIELDS_SQL} FROM {CONTENT_REPOS_TABLE} WHERE id = ?")
                .to_string();
        let mut values = vec![Value::UInt(repository_id)];

        if let Some(t) = repo_type {
            sql.push_str(" AND repo_type = ?");
            values.push(Value::UInt(t as u64));
        }

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        match conn.exec_first(stmt, Params::Positional(values)).await {
            Ok(row) => match row {
                Some((
                    id,
                    created_at,
                    name,
                    creator_id,
                    Value::Int(_app_id),
                    Value::Int(_repo_type),
                )) => Ok(Some(ContentRepository {
                    id,
                    ts: created_at,
                    name,
                    creator_id,
                })),
                _ => Ok(None),
            },
            Err(e) => Err(Error::database(format!("Connection error: {:?}", e))),
        }
    }

    pub async fn delete_content_repository(&self, repository_id: u64) -> Result<(), Error> {
        // TODO : remove contents

        let mut conn = self.conn().await?;
        let mut t = conn.start_transaction(TxOpts::default()).await?;

        let sql = formatcp!("DELETE FROM {CONTENTS_TABLE} WHERE repository_id = ?");
        let stmt = t.prep(sql).await?;
        t.exec_drop(stmt, Params::Positional(vec![Value::UInt(repository_id)]))
            .await
            .map_err(|e| Error::database(format!("Connection error: {:?}", e)))?;

        let sql = formatcp!("DELETE FROM {CONTENT_REPOS_TABLE} WHERE id = ?");
        let stmt = t.prep(sql).await?;
        t.exec_drop(stmt, Params::Positional(vec![Value::UInt(repository_id)]))
            .await
            .map_err(|e| Error::database(format!("Connection error: {:?}", e)))?;

        t.commit().await?;

        Ok(())
    }

    pub async fn list_content_repository(
        &self,
        creator_id: Option<u64>,
        app_id: Option<u32>,
        order: list_repositories_request::Order,
        desc: bool,
        repo_type: Option<RepoType>,
    ) -> Result<Vec<ContentRepository>, Error> {
        let (mut sql, mut values) = if let Some(cid) = creator_id {
            (
                format!(
                    "SELECT {} FROM {} WHERE creator_id = ?",
                    CONTENT_REPO_FIELDS_SQL, CONTENT_REPOS_TABLE,
                ),
                vec![Value::UInt(cid)],
            )
        } else if let Some(aid) = app_id {
            (
                format!(
                    // TODO check performance vs JOIN version
                    "SELECT {} FROM {} WHERE creator_id in (
                    SELECT id FROM {} WHERE app_id = ?
                )",
                    CONTENT_REPO_FIELDS_SQL, CONTENT_REPOS_TABLE, USERS_TABLE,
                ),
                vec![Value::UInt(aid as u64)],
            )
        } else {
            return Err(Error::bad_request("Search criteria missing"));
        };

        if let Some(t) = repo_type {
            sql.push_str(" AND repo_type = ?");
            values.push((t as u64).into());
        }

        let sql = String::from(sql)
            + " ORDER BY "
            + order.to_column_str()?
            + if desc { " DESC" } else { " ASC" };

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        conn.exec_map(
            stmt,
            Params::Positional(values),
            |(id, created_at, name, creator_id, app_id, repo_type)| {
                let _repo_type: u8 = repo_type;
                let _app_id: u32 = app_id;
                ContentRepository {
                    id,
                    ts: created_at,
                    name,
                    creator_id,
                }
            },
        )
        .await
        .map_err(|e| Error::database(format!("Connection error: {:?}", e)))
    }

    ///
    /// Add content, and return content uuid
    ///
    pub async fn add_content(&self, app_id: u32, content: &Content) -> Result<(), Error> {
        let mut conn = Box::new(self.conn().await?);
        let sql = formatcp!(
            "INSERT INTO {CONTENTS_TABLE} ({CONTENT_FIELDS_SQL}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);"
        );
        let statement = conn.prep(sql).await?;

        let values = self.values_for_add_content(app_id, content, None).await;

        conn.exec_drop(statement, Params::Positional(values))
            .await?;

        Ok(())
    }

    ///
    /// Helper function far converting Content to Vec<Value>
    ///
    async fn values_for_add_content(
        &self,
        app_id: u32,
        content: &Content,
        video_cf_metadata: Option<VideoDetailsSummary>,
    ) -> Vec<Value> {
        let mut values = vec![
            content.uuid.as_ref().unwrap().to_uuid_v6().into(),
            content.repository_id.into(),
            app_id.into(),
            content.creator_id.into(),
            content.title.clone().into(),
            content.description.clone().into(),
            content.filename.clone().into(),
            content.size.clone().into(),
        ];

        match content.metadata.clone().unwrap() {
            content::content::Metadata::I(data) => {
                values.push((ContentType::Image as u64).into());
                values.push(serde_json::to_string(&data).unwrap().into());
                values.push(Value::NULL);
            }
            content::content::Metadata::F(data) => {
                values.push((ContentType::File as u64).into());
                values.push(serde_json::to_string(&data).unwrap().into());
                values.push(Value::NULL);
            }
            content::content::Metadata::V(data) => {
                values.push((ContentType::Video as u64).into());
                values.push(serde_json::to_string(&data).unwrap().into());
                values.push(data.length_seconds.into()); // duplicated for search only as already in data
            }
        }

        let (cf_json, cf_id) = if let Some(vds) = video_cf_metadata {
            (
                Some(
                    serde_json::to_string(&vds)
                        .expect("Failed to serialize VideoDetailsSummary to JSON"),
                ),
                Some(vds.uid.clone()),
            )
        } else {
            (None, None)
        };
        values.push(cf_json.into());
        values.push(cf_id.into());

        values
    }

    ///
    /// Add content, and return content uuid
    ///
    pub async fn get_content(
        &self,
        repository_id: u64,
        uuid: &TimeUuid,
    ) -> Result<Option<Content>, Error> {
        let mut conn = self.conn().await?;

        let sql = formatcp!(
            "SELECT {CONTENT_FIELDS_SQL} FROM {CONTENTS_TABLE} WHERE uuid = ? AND repository_id = ? ;"
        );

        let values = vec![
            Value::Bytes(uuid.to_uuid_v6().to_vec()),
            repository_id.into(),
        ];

        let statement = conn.prep(sql).await?;
        "uuid, repository_id, app_id, creator_id, title, filename, filesize, content_type, data, length";
        match conn.exec_first(statement, Params::Positional(values)).await {
            Ok(row_opt) => match row_opt {
                Some(row) => {
                    let row: Row = row;
                    Ok(Some(Content::try_from(row)?))
                }
                None => Ok(None),
            },
            Err(e) => Err(Error::database(format!("Connection error: {:?}", e))),
        }
    }

    ///
    /// Get the Cloudflare Stream video metadata for the specified video
    ///
    pub async fn get_content_cloudflare_metadata(
        &self,
        uuid: &TimeUuid,
    ) -> Result<Option<VideoDetailsSummary>, Error> {
        let mut c = self.conn().await?;

        let sql = formatcp!("SELECT video_cfs_metadata FROM {CONTENTS_TABLE} WHERE uuid = ?;");
        let s = c.prep(sql).await?;

        let opt_result = c
            .exec_first(&s, vec![Value::Bytes(uuid.to_uuid_v6().to_vec())])
            .await?;
        if let Some(r) = opt_result {
            let r: Row = r;
            let json: Option<String> = r.get(0).unwrap();
            if let Some(json) = json {
                let out: VideoDetailsSummary = serde_json::from_str(json.as_str())?;
                return Ok(Some(out));
            }
        }

        Ok(None)
    }

    ///
    /// Delete content
    ///
    pub async fn delete_content(&self, repository_id: u64, uuid: &TimeUuid) -> Result<(), Error> {
        let mut conn = self.conn().await?;

        let sql = formatcp!("DELETE FROM {CONTENTS_TABLE} WHERE uuid = ? AND repository_id = ?;");
        let values = vec![
            Value::Bytes(uuid.to_uuid_v6().to_vec()),
            repository_id.into(),
        ];

        let stmt = conn.prep(sql).await?;

        conn.exec_drop(stmt, Params::Positional(values)).await?;
        Ok(())
    }

    ///
    /// List contents
    ///
    pub async fn list_contents(
        &self,
        repository_id: Option<u64>,
        creator_id: Option<u64>,
        ctype: Option<ContentType>,
        order_by: list_contents_request::Order,
        desc: bool,
        offset: Option<&Content>,
        forward: bool,
        limit: u32,
        search_phrase: Option<&String>,
        fields: Vec<SearchField>,
        app_id: Option<u32>,
    ) -> Result<Vec<Content>, Error> {
        let (order, cmp_sign) = common::utils::calc_order_by_args(desc, forward);

        let (mut sql, mut values) = if let Some(rid) = repository_id {
            (
                format!(
                    "SELECT {} FROM {} WHERE repository_id = ?",
                    CONTENT_FIELDS_SQL, CONTENTS_TABLE
                ),
                vec![Value::UInt(rid)],
            )
        } else if let Some(cid) = creator_id {
            (
                format!(     // TODO check performance vs JOIN version
                "SELECT {} FROM {} WHERE repository_id in (SELECT id FROM {} WHERE creator_id = ? AND repo_type = {})",
                 CONTENT_FIELDS_SQL, CONTENTS_TABLE, CONTENT_REPOS_TABLE, RepoType::Normal as u8),
                vec![Value::UInt(cid as u64)],
            )
        } else {
            if search_phrase.is_none() || app_id.is_none() {
                return Err(Error::bad_request("Search criteria missing"));
            }
            (
                format!(
                    "SELECT {} FROM {} WHERE app_id = ?",
                    CONTENT_FIELDS_SQL, CONTENTS_TABLE,
                ),
                vec![app_id.unwrap().into()],
            )
        };

        if let Some(ct) = ctype {
            sql.push_str(" AND content_type = ?");
            values.push(Value::UInt(ct as u64));
        }

        if !fields.is_empty() {
            let phrase = search_phrase.ok_or(Error::bad_request("Missing search phrase"))?;
            let fields: Result<Vec<&str>, Error> =
                fields.iter().map(|f| f.to_column_str()).collect();
            sql.push_str(" AND (");
            add_sql_like_clause(&mut sql, &mut values, &phrase, fields?);
            sql.push_str(")");
        }

        if let Some(o) = offset {
            if order_by == list_contents_request::Order::Created {
                sql.push_str(&format!(" AND uuid {} ?", cmp_sign));
                values.push(Value::Bytes(o.uuid.as_ref().unwrap().to_uuid_v6().to_vec()));
            } else {
                sql.push_str(&format!(
                    " AND ({} {} ? OR ({} = ? AND uuid {} ?))",
                    order_by.to_column_str()?,
                    cmp_sign,
                    order_by.to_column_str()?,
                    cmp_sign
                ));
                values.push(order_by.get_offset_value(o)?);
                values.push(order_by.get_offset_value(o)?);
                values.push(Value::Bytes(o.uuid.as_ref().unwrap().to_uuid_v6().to_vec()));
            }
        }

        sql.push_str(" ORDER BY ");
        if order_by == list_contents_request::Order::Created {
            sql.push_str(&format!("{} {}", order_by.to_column_str()?, order));
        } else {
            sql.push_str(&format!(
                "{} {}, {} {}",
                order_by.to_column_str()?,
                order,
                list_contents_request::Order::Created.to_column_str()?,
                order
            ));
        }

        sql.push_str(" LIMIT ?");
        values.push(limit.min(MAX_CONTENTS_PAGE_SIZE).into());

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        let list = conn
            .exec_map(stmt, Params::Positional(values), |row: Row| {
                Content::try_from(row)
            })
            .await
            .map_err(|e| Error::database(format!("Connection error: {:?}", e)))?;

        if list.iter().any(|i| {
            if let Err(e) = i {
                log::error!("Content conversion error: {:?}", e);
                true
            } else {
                false
            }
        }) {
            return Err(Error::database("Content conversion error."));
        }
        let list = unwrap_and_order_listing_results(list, forward);

        Ok(list)
    }

    ///
    /// Insert details of an in-progress video upload
    ///
    pub async fn video_upload_insert(
        &self,
        uuid: &TimeUuid,
        app_id: u32,
        user_id: u64,
        repository_id: u64,
        title: &str,
        description: &str,
        cloudflare_video_id: &str,
        cloudflare_tus_url: &str,
        node_id: &str,
    ) -> Result<(), Error> {
        let mut c = self.conn().await?;

        let sql = formatcp!("INSERT INTO {VIDEO_UPLOADS_TABLE} ({VIDEO_UPLOADS_FIELDS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP(), false);");

        let s = c.prep(sql).await?;

        let v = vec![
            Value::Bytes(uuid.to_uuid_v6().to_vec()),
            app_id.into(),
            repository_id.into(),
            user_id.into(),
            title.into(),
            description.into(),
            cloudflare_video_id.into(),
            cloudflare_tus_url.into(),
            node_id.into(),
        ];

        c.exec_drop(&s, Params::Positional(v)).await?;

        Ok(())
    }

    ///
    /// Get details of an in-progress video upload, along with the app ID for the upload
    ///
    pub async fn video_upload_get(
        &self,
        uuid: &TimeUuid,
    ) -> Result<Option<(UploadInProgress, u32)>, Error> {
        let mut c = self.conn().await?;
        let sql =
            formatcp!("SELECT {VIDEO_UPLOADS_FIELDS} FROM {VIDEO_UPLOADS_TABLE} WHERE uuid = ? AND upload_failed = false;");
        let s = c.prep(sql).await?;

        let opt_row = c
            .exec_first(&s, vec![Value::Bytes(uuid.to_uuid_v6().to_vec())])
            .await?;

        let result = opt_row.map(|r| {
            let r: Row = r;
            let uuid: Vec<u8> = r.get(0).unwrap();
            let app_id: u32 = r.get(1).unwrap();
            let repository_id: u64 = r.get(2).unwrap();
            let user_id: u64 = r.get(3).unwrap();
            let title: Option<String> = r.get(4).unwrap();
            let description: Option<String> = r.get(5).unwrap();
            let tus_url: String = r.get(7).unwrap();

            (
                UploadInProgress {
                    id: Some(TimeUuid::from_uuid_v6(
                        uuid.try_into().expect("Uuid bytes of incorrect length"),
                    )),
                    repository_id,
                    user_id,
                    tus_url,
                    title: title.unwrap_or_else(|| "".to_string()),
                    description: description.unwrap_or_else(|| "".to_string()),
                },
                app_id,
            )
        });

        Ok(result)
    }

    ///
    /// Remove an in-progress video upload from the database, if one with the specified ID exists
    ///
    pub async fn video_upload_delete(&self, uuid: &TimeUuid) -> Result<(), Error> {
        let mut c = self.conn().await?;
        let sql = formatcp!("DELETE FROM {VIDEO_UPLOADS_TABLE} where uuid = ?;");

        let s = c.prep(sql).await?;

        c.exec_drop(&s, vec![Value::Bytes(uuid.to_uuid_v6().to_vec())])
            .await?;

        Ok(())
    }

    ///
    /// Get cloudflare ID of the video upload
    ///
    pub async fn video_upload_cloudflare_id(
        &self,
        uuid: &TimeUuid,
    ) -> Result<Option<String>, Error> {
        let mut c = self.conn().await?;
        let sql =
            formatcp!("SELECT cloudflare_video_id FROM {VIDEO_UPLOADS_TABLE} WHERE uuid = ?;");
        let s = c.prep(sql).await?;

        Ok(
            c.exec_first(&s, vec![Value::Bytes(uuid.to_uuid_v6().to_vec())])
                .await?
                .map(|r: Row| r.get::<String, usize>(0).unwrap()),
        )
    }

    ///
    /// Finalize a video upload -- this means that, in one transaction:
    /// 1. It should be removed from the `video_uploads` table
    /// 2. It should be inserted into `contents` (content repository contents) table
    ///
    /// # Arguments
    /// * `uuid`: UUID of the video
    /// * `cloudflare_details`: Cloudflare Stream metadata to record for the video
    ///
    pub async fn video_upload_finalize(
        &self,
        uuid: &TimeUuid,
        cloudflare_details: VideoDetailsSummary,
    ) -> Result<(), Error> {
        // Get in-progress video details
        let details = self.video_upload_get(uuid).await?;
        if details.is_none() {
            return Err(Error::content_not_found(
                0,
                uuid.to_string(),
                "Video upload not found",
            ));
        }
        let (vuip, app_id) = details.unwrap();

        let content = Content {
            uuid: Some(uuid.clone()),
            repository_id: vuip.repository_id,
            creator_id: vuip.user_id,
            title: vuip.title,
            filename: "".to_string(),
            description: vuip.description,
            size: 0,
            // Because we'll have multiple video providers, we'll dynamically fill in the video metadata on retrieval
            metadata: Some(Metadata::V(Video {
                length_seconds: cloudflare_details.duration,
                hls_url: "".to_string(),
                dash_url: "".to_string(),
                thumbnail_url_static: "".to_string(),
                thumbnail_url_dynamic: "".to_string(),
            })),
        };

        // Prepare statements for transaction
        let mut c = self.conn().await?;
        let remove_pending_upload_statement = c
            .prep(formatcp!(
                "DELETE FROM {VIDEO_UPLOADS_TABLE} WHERE uuid = ?;"
            ))
            .await?;

        let add_content_sql = formatcp!(
            "INSERT INTO {CONTENTS_TABLE} ({CONTENT_FIELDS_SQL}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);"
        );
        let add_content_statement = c.prep(add_content_sql).await?;

        let mut tx = c.start_transaction(TxOpts::default()).await?;

        // Execute transaction: Record video in content table, and remove now-finished upload from video_uploads table
        let values = self
            .values_for_add_content(app_id, &content, Some(cloudflare_details))
            .await;
        tx.exec_drop(add_content_statement, values).await?;

        tx.exec_drop(
            &remove_pending_upload_statement,
            Params::Positional(vec![Value::Bytes(uuid.to_uuid_v6().to_vec())]),
        )
        .await?;

        tx.commit().await?;

        Ok(())
    }

    ///
    /// When a video upload fails (for example, due to Cloudflare Stream being down) we'll move
    /// it from `video_uploads` to `cloudflare_dead_videos` for manual processing and removal later.
    /// If the video still exists in Cloudflare, we need to manually delete it, otherwise we'll
    /// be stuck paying for storage for a video that nobody can ever watch.
    ///
    pub async fn video_upload_failed(&self, video_uuid: &TimeUuid) -> Result<(), Error> {
        let mut c = self.conn().await?;

        let sql =
            formatcp!("UPDATE {VIDEO_UPLOADS_TABLE} SET upload_failed = true WHERE uuid = ?;");
        let statement = c.prep(sql).await?;

        c.exec_drop(
            statement,
            vec![Value::Bytes(video_uuid.to_uuid_v6().to_vec())],
        )
        .await?;

        Ok(())
    }

    ///
    /// Called when a video, hosted in Cloudflare Stream, was attempted to be deleted but it failed
    /// Adds a record to the `cloudflare_pending_video_deletions` table
    ///
    pub async fn video_cfs_deletion_failed(
        &self,
        video_uuid: &TimeUuid,
        cloudflare_video_id: &str,
        last_error: Option<String>,
    ) -> Result<(), Error> {
        let mut c = self.conn().await?;

        let sql = formatcp!("INSERT INTO {CFS_PENDING_DELETION_TABLE} ({FAILED_VIDEO_DELETION_FIELDS}) VALUES (?, ?, ?, CURRENT_TIMESTAMP());");

        let statement = c.prep(sql).await?;
        c.exec_drop(
            statement,
            vec![
                Value::Bytes(video_uuid.to_uuid_v6().to_vec()),
                cloudflare_video_id.into(),
                last_error.into(),
            ],
        )
        .await?;

        Ok(())
    }

    ///
    /// List all of the uploads that the specified user is currently doing
    ///
    pub async fn video_uploads_list_in_progress(
        &self,
        user_id: u64,
    ) -> Result<Vec<UploadInProgress>, Error> {
        let mut c = self.conn().await?;
        let sql = formatcp!(
            "SELECT {VIDEO_UPLOADS_FIELDS} FROM {VIDEO_UPLOADS_TABLE} WHERE user_id = ? AND upload_failed = false;"
        );
        let s = c.prep(sql).await?;

        let v = vec![Value::UInt(user_id)];

        let rows: Vec<UploadInProgress> = c
            .exec(&s, Params::Positional(v))
            .await?
            .into_iter()
            .map(|r: Row| r.try_into().expect("Failed to convert row"))
            .collect();

        Ok(rows)
    }

    ///
    /// List all of the in-progress video uploads that this node is responsible for polling/handling
    ///
    pub async fn video_uploads_list_in_progress_for_node(
        &self,
        node_id: &str,
    ) -> Result<Vec<UploadInProgress>, Error> {
        let mut c = self.conn().await?;
        let sql = formatcp!(
            "SELECT {VIDEO_UPLOADS_FIELDS} FROM {VIDEO_UPLOADS_TABLE} WHERE node_id = ? AND upload_failed = false;"
        );
        let s = c.prep(sql).await?;

        let rows: Vec<UploadInProgress> = c
            .exec(&s, Params::Positional(vec![node_id.into()]))
            .await?
            .into_iter()
            .map(|r: Row| r.try_into().expect("Failed to convert row"))
            .collect();

        Ok(rows)
    }

    ///
    /// Update the "last polled" timestamp for this video and node
    ///
    pub async fn video_upload_update_polled_timestamp(
        &self,
        video_id: &TimeUuid,
        node_id: &str,
    ) -> Result<(), Error> {
        let mut c = self.conn().await?;
        let sql = formatcp!(
            "UPDATE {VIDEO_UPLOADS_TABLE} SET node_last_check_timestamp = CURRENT_TIMESTAMP() WHERE uuid = ? AND node_id = ?;"
        );
        let s = c.prep(sql).await?;

        c.exec_drop(
            s,
            Params::Positional(vec![video_id.to_uuid_v6().into(), node_id.into()]),
        )
        .await?;

        Ok(())
    }
}
