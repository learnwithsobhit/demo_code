use crate::database::{Database, USER_PROPERTIES_TABLE};
use common::common::{PrivacyType, Property, Value as CValue};
use common::errors::Error;
use common::utils::get_comma_seperated_string_of_characters;
use const_format::formatcp;
use mysql_async::prelude::Queryable;
use mysql_async::Params;
use mysql_async::Value;

const USER_PROPERTIES_FIELDS_SQL: &str =
    formatcp!("app_id, user_id, property_name, value, privacy, last_changed_timestamp");

const PROPERTIES_FIELDS_SQL: &str = formatcp!("property_name, value, privacy");

impl Database {
    pub async fn upsert_user_properties(
        &self,
        app_id: u32,
        user_id: u64,
        user_properties: Vec<Property>,
    ) -> Result<(), Error> {
        let user_prop_len = user_properties.len();
        let sql_value_string = get_comma_seperated_string_of_characters(
            "(?,?,?,?,?,CURRENT_TIMESTAMP())",
            user_prop_len,
        );

        let sql_user_property = String::from(formatcp!(
            "INSERT INTO {USER_PROPERTIES_TABLE} ({USER_PROPERTIES_FIELDS_SQL}) VALUES "
        )) + &sql_value_string
            + "ON DUPLICATE KEY UPDATE value = VALUES(value),privacy = VALUES(privacy)";

        /* remove trailing comma(,) as it will create panic in sql preperation */
        //strip_trailing_coma(&mut sql_user_property);

        /* build a param vector and execute it in signle shot */
        let mut params = Vec::new();
        for property in user_properties {
            let prop_value: Vec<u8> = property.value.unwrap().into();
            params.push(Value::from(app_id));
            params.push(Value::from(user_id));
            params.push(Value::from(property.name));
            params.push(Value::from(prop_value));
            params.push(Value::from(property.privacy_type));
        }

        let mut conn = self.conn().await?;
        let statement_user_property = conn.prep(sql_user_property.as_str()).await?;
        conn.exec_drop(statement_user_property.clone(), Params::Positional(params))
            .await?;

        Ok(())
    }

    pub async fn get_all_user_properties(
        &self,
        app_id: u32,
        user_id: u64,
        include_private_properties: bool,
    ) -> Result<Vec<Property>, Error> {
        let (mut sql,mut values) =
            (
                String::from(formatcp!(
                    "SELECT {PROPERTIES_FIELDS_SQL} FROM {USER_PROPERTIES_TABLE} WHERE app_id = ? AND user_id = ?"
                )),
                vec![Value::UInt(app_id as u64),Value::UInt(user_id as u64)],
            );

        if !include_private_properties {
            let public_property_sql = " AND privacy = ?";
            sql = sql + &public_property_sql;
            values.push(Value::UInt(PrivacyType::Public as u64));
        }

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        conn.exec_map(
            stmt,
            Params::Positional(values),
            |(property_name, value, privacy): (String, Vec<u8>, i32)| Property {
                name: property_name,
                value: Some(CValue::from_bytes(value)),
                privacy_type: privacy as i32,
            },
        )
        .await
        .map_err(|e| Error::database(format!("Connection error: {:?}", e)))
    }

    pub async fn get_user_properties_by_names(
        &self,
        app_id: u32,
        user_id: u64,
        include_private_properties: bool,
        names: Vec<String>,
    ) -> Result<Vec<Property>, Error> {
        let (mut sql,mut values) =
            (
                String::from(formatcp!(
                    "SELECT {PROPERTIES_FIELDS_SQL} FROM {USER_PROPERTIES_TABLE} WHERE app_id = ? AND user_id = ?"
                )),
                vec![Value::UInt(app_id as u64),Value::UInt(user_id as u64)],
            );

        if !include_private_properties {
            let public_property_sql = " AND privacy = ?";
            sql = sql + &public_property_sql;
            values.push(Value::UInt(PrivacyType::Public as u64));
        }
        let input_length = names.len();
        if input_length > 0 {
            let number_of_inputs = get_comma_seperated_string_of_characters("?", input_length);
            let public_property_sql =
                " AND property_name IN (".to_owned() + { number_of_inputs.as_str() } + ")";
            sql = sql + &public_property_sql;
            let value_vec: Vec<Value> = names.iter().map(|s| s.to_owned().into()).collect();
            values.extend(value_vec);
        }
        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        conn.exec_map(
            stmt,
            Params::Positional(values),
            |(property_name, value, privacy): (String, Vec<u8>, i32)| Property {
                name: property_name,
                value: Some(CValue::from_bytes(value)),
                privacy_type: privacy as i32,
            },
        )
        .await
        .map_err(|e| Error::database(format!("Connection error: {:?}", e)))
    }

    pub async fn delete_user_property(
        &self,
        property_names: Vec<String>,
        user_id: u64,
        app_id: u32,
    ) -> Result<(), Error> {
        let mut conn = self.conn().await?;

        let mut sql = String::from(formatcp!(
            "DELETE FROM {USER_PROPERTIES_TABLE} WHERE app_id = ? AND user_id = ?"
        ));
        let mut values = vec![app_id.into(), user_id.into()];
        let input_length = property_names.len();
        if input_length > 0 {
            let number_of_inputs = get_comma_seperated_string_of_characters("?", input_length);
            let property_name_sql =
                " AND property_name IN (".to_owned() + { number_of_inputs.as_str() } + ");";
            sql = sql + &property_name_sql;
            let value_vec: Vec<Value> =
                property_names.iter().map(|s| s.to_owned().into()).collect();
            values.extend(value_vec);
            //atleast 1 property name required
            let stmt = conn.prep(sql).await?;
            conn.exec_drop(stmt, Params::Positional(values)).await?;
            Ok(())
        } else {
            Err(Error::not_authorized("No User property name provided!").into())
        }
    }
}
