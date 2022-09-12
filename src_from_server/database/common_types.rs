use common::user::{AccountStatus, UserProfileData, UserType};
use mysql_async::Row;
use num_traits::FromPrimitive;

/// Struct for data in database apps table
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct App {
    pub id: u32,
    pub name: String,
    pub token: String,
    pub description: String,
    /// Json with serialized login flow state transition tree
    pub login_config: String,
    /// Json with serialized register flow state transition tree
    pub register_config: String,
    /// Json with serialized AuthProvider to SsoConfig map
    pub sso_config: Option<String>,
}

/// Struct for data in database users table
#[derive(Debug, PartialEq, Clone)]
pub struct User {
    /// User id
    pub id: u64,
    /// Id of sso_data table entry if user uses SSO
    pub sso_id: Option<u64>,
    /// Username
    pub username: String,
    /// User password hash
    pub password: Option<String>,
    /// Salt used to hash password. 16-byte data base64 encoded
    pub salt: Option<String>,
    /// Email
    pub email: Option<String>,
    /// Phone number
    pub phone: Option<String>,
    /// App id
    pub app_id: Option<u32>,
    /// Account status
    pub account_status: AccountStatus,
    /// User type
    pub user_type: UserType,
    /// Profile data
    pub profile: UserProfileData,
}

/// Struct for data in database sso_data table
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SsoData {
    /// SSO data id
    pub id: u64,
    /// Application id
    pub app_id: u32,
    /// SSO authentication provider
    pub provider: common::user::AuthProvider,
    /// Provider specidic SSO identifier uniquely definig a user within an app
    pub identifier: String,
}

pub enum RepoType {
    /// User private repository created at account registration. Can't be deleted until account exists and is not accesible to other users.
    User = 1,
    /// Normal repository
    Normal = 2,
}

impl TryFrom<Row> for User {
    type Error = common::errors::Error;
    fn try_from(r: Row) -> Result<Self, Self::Error> {
        let id = r.get(0).unwrap();
        let sso_id = r.get(1).unwrap();
        let username = r.get(2).unwrap();
        let password = r.get(3).unwrap();
        let salt = r.get(4).unwrap();
        let email = r.get(5).unwrap();
        let phone = r.get(6).unwrap();
        let app_id = r.get(7).unwrap();
        let account_status: u64 = r.get(8).unwrap();
        let user_type: u64 = r.get(9).unwrap();
        let profile: Vec<u8> = r.get(10).unwrap();

        let status = AccountStatus::from_u64(account_status)
            .ok_or_else(|| common::errors::Error::database("Unsupported registration flow"))?;
        let utype = UserType::from_u64(user_type)
            .ok_or_else(|| common::errors::Error::database("Unsupported user type"))?;

        let profile = UserProfileData::from_bytes(&profile)?;

        Ok(User {
            id,
            sso_id,
            username,
            password,
            salt,
            email,
            phone,
            app_id,
            account_status: status,
            user_type: utype,
            profile,
        })
    }
}
