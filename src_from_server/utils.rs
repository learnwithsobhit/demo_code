use common::utils::escape_chars;
use mysql_async::Value;

/// Adds to sql query LIKE clause with escape char defined and extends query statement values vec
pub fn add_sql_like_clause(
    sql: &mut String,
    values: &mut Vec<Value>,
    phrase: &str,
    fields: Vec<&str>,
) {
    let mut first = true;
    for f in fields {
        if first {
            sql.push_str(&format!("{} LIKE ? ESCAPE '|'", f));
            first = false;
            values.push(format!("%{}%", escape_chars(&phrase, vec!['_', '%'], '|')).into());
        } else {
            sql.push_str(&format!(" OR {} LIKE ? ESCAPE '|'", f));
            values.push(format!("%{}%", escape_chars(&phrase, vec!['_', '%'], '|')).into());
        }
    }
}
