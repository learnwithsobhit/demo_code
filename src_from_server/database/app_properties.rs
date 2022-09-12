use crate::database::{Database, APP_PROPERTIES_TABLE};
use common::common::{PrivacyType, Property, Value as CValue};
use common::errors::Error;
use common::utils::get_comma_seperated_string_of_characters;
use const_format::formatcp;
use mysql_async::prelude::Queryable;
use mysql_async::Params;
use mysql_async::Value;

const APP_PROPERTIES_FIELDS_SQL: &str =
    formatcp!("app_id, property_name, value, last_changed_timestamp");

const PROPERTIES_FIELDS_SQL: &str = formatcp!("property_name, value");

impl Database {
    pub async fn upsert_app_properties(
        &self,
        app_id: u64,
        app_properties: Vec<Property>,
    ) -> Result<(), Error> {
        let app_prop_len = app_properties.len();
        let sql_value_string =
            get_comma_seperated_string_of_characters("(?,?,?,CURRENT_TIMESTAMP())", app_prop_len);

        let sql_app_property = String::from(formatcp!(
            "INSERT INTO {APP_PROPERTIES_TABLE} ({APP_PROPERTIES_FIELDS_SQL}) VALUES "
        )) + &sql_value_string
            + "ON DUPLICATE KEY UPDATE value = VALUES(value)";

        /* build a param vector and execute it in signle shot */
        let mut params = Vec::new();
        for property in app_properties {
            let prop_value: Vec<u8> = property.value.unwrap().into();
            params.push(Value::from(app_id));
            params.push(Value::from(property.name));
            params.push(Value::from(prop_value));
        }

        let mut conn = self.conn().await?;
        let statement_app_property = conn.prep(sql_app_property.as_str()).await?;
        conn.exec_drop(statement_app_property.clone(), Params::Positional(params))
            .await?;
        Ok(())
    }

    pub async fn get_all_app_properties(&self, app_id: u32) -> Result<Vec<Property>, Error> {
        let (sql, values) = (
            String::from(formatcp!(
                "SELECT {PROPERTIES_FIELDS_SQL} FROM {APP_PROPERTIES_TABLE} WHERE app_id = ?"
            )),
            vec![Value::UInt(app_id as u64)],
        );

        let mut conn = self.conn().await?;
        let stmt = conn.prep(sql).await?;

        conn.exec_map(
            stmt,
            Params::Positional(values),
            |(property_name, value): (String, Vec<u8>)| Property {
                name: property_name,
                value: Some(CValue::from_bytes(value)),
                privacy_type: PrivacyType::Public as i32,
            },
        )
        .await
        .map_err(|e| Error::database(format!("Connection error: {:?}", e)))
    }

    pub async fn get_app_properties_by_names(
        &self,
        app_id: u32,
        names: Vec<String>,
    ) -> Result<Vec<Property>, Error> {
        let (mut sql, mut values) = (
            String::from(formatcp!(
                "SELECT {PROPERTIES_FIELDS_SQL} FROM {APP_PROPERTIES_TABLE} WHERE app_id = ?"
            )),
            vec![Value::UInt(app_id as u64)],
        );
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
            |(property_name, value): (String, Vec<u8>)| Property {
                name: property_name,
                value: Some(CValue::from_bytes(value)),
                privacy_type: PrivacyType::Public as i32,
            },
        )
        .await
        .map_err(|e| Error::database(format!("Connection error: {:?}", e)))
    }

    pub async fn delete_app_property(
        &self,
        property_names: Vec<String>,
        app_id: u64,
    ) -> Result<(), Error> {
        let mut sql = String::from(formatcp!(
            "DELETE FROM {APP_PROPERTIES_TABLE} WHERE app_id = ?"
        ));
        let mut values = vec![app_id.into()];
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
            let mut conn = self.conn().await?;
            let stmt = conn.prep(sql).await?;
            conn.exec_drop(stmt, Params::Positional(values)).await?;
            Ok(())
        } else {
            Err(Error::bad_request("No App property name provided!").into())
        }
    }
}
