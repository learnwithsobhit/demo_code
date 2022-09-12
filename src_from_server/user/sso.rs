use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    hash::{Hash, Hasher},
    time::SystemTime,
};

use common::{
    admin::SsoConfig,
    errors::{Error, JwtErrorType},
    user::{
        AccountStatus, AuthProvider, GoogleIdToken, SsoLoginData, SsoRegisterData,
        TokenProfileData, UserClaims, UserProfileData, UserType, GOOGLE_ISS,
    },
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use log::warn;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::database::common_types::{self, App, User};

use super::UserEndpoints;

// TODO replace with endpoits discovery
// See: https://developers.google.com/identity/protocols/oauth2/openid-connect#discovery
const GOOGLE_KEYS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Response to get decryption keys of KeyCache used in integration tests
/// n and e in first key is generated from keys in test_common::keys
const TEST_KEYS_RESPONSE: &str = r#"{
    "keys": [
    {
        "use": "sig",
        "e": "AQAB",
        "n": "fYups8xROXeAVa6dSQSUQqWHicAQZ8-cNmJj-XPrpq3y1DaV9pcjwvjFyLDEn-i3Ix6sAAtHHCdDhoeTzfGCT6m04elVbgrIDlJbOEfPOZOl_H0IbrXSs-GUh4x-bGGHHgw7fS2DcSQ00XxxVEfa3MeCFFTbo_d2fqfLEKR_SFd7P0kA78MZSN3c-alZcUelEp7j8dk18jDkxHeI9bfIO2XdxJnqrywht-LPDiw52WbAjCCEdnubCcnlkO-7wGfTkOEaQwTAX4iXqA5YhZ8d8A_UbbO5sWdJH4gznSGBWaLDWgvcgDRuzaJ018hYFIjywOn4k33NbSDYJcG9A8_aGQ",
        "alg": "RS256",
        "kty": "RSA",
        "kid": "58b429662db0786f2efefe13c1eb12a28dc442d"
    },
    {
        "e": "AQAB",
        "n": "1YWUM8Y5UExSfXsBrF6oACI48nITxDf07CiYKn_VTbLRlpXX1AfNtQhrjm-jPjC16qXnGCBhdlZHdCycfezoMg8svo41U7YIVLP5G5H6f7VxAEglmV5IGc0kj35__qmqy3t1Eug_iqxCOyRlcDELQ75MNOhYFQtjeEtLuw4ErpPpOeYVX71vOH3Q9epItMM0n18FXW5Dd6BkCiHvMkb5eSHOH07J0h-MkRF133R-YSPPgDlqLeRxdjDo2rwqKFsOa68edzconVcETWR2YSoFtangVd-IBhzFrax8gyVsntKpmbg8XyJZU2vtgMiTdP0wAjAe8gy78Dg1WIOVOe58lQ",
        "use": "sig",
        "kty": "RSA",
        "kid": "cec13debf4b96479683736205082466c14797bd0",
        "alg": "RS25"
    }
    ]
}"#;

/// Json Web Key
/// Detailed fields description: https://www.ietf.org/rfc/rfc7517.txt
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JWKey {
    /// Key type: RSA, EC ...
    pub kty: String,
    /// i=Intended use of the public key: sig/enc
    #[allow(dead_code)]
    pub r#use: Option<String>,
    /// Key Operations
    #[allow(dead_code)]
    pub key_ops: Option<Vec<String>>,
    #[allow(dead_code)]
    pub alg: Option<String>,
    /// Key id
    #[allow(dead_code)]
    pub kid: Option<String>,
    /// URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280]
    #[allow(dead_code)]
    pub x5u: Option<String>,
    /// A chain of one or more PKIX certificates [RFC5280]
    #[allow(dead_code)]
    pub x5c: Option<Vec<String>>,
    /// X.509 Certificate SHA-1 Thumbprint
    #[allow(dead_code)]
    pub x5t: Option<Vec<String>>,
    /// X.509 Certificate SHA-256 Thumbprint
    #[allow(dead_code)]
    #[serde(rename = r#"x5t#S256"#)]
    pub x5ts256: Option<String>,
    /// RSA algorithm modulus. If kty == RSA this field is set
    pub n: Option<String>,
    /// RSA algorithm exponent. If kty == RSA this field is set
    pub e: Option<String>,
    /// Elliptic Curve type
    pub crv: Option<String>,
    /// eliptic curve x
    pub x: Option<String>,
    /// Eliptic curve y
    pub y: Option<String>,
}

impl JWKey {
    /// Gets jsonwebtoken decoding key
    pub fn decoding_key(&self) -> Result<DecodingKey, Error> {
        match self.kty.as_str() {
            "RSA" => DecodingKey::from_rsa_components(
                &self.n.as_ref().unwrap(),
                &self.e.as_ref().unwrap(),
            )
            .map_err(|e| {
                Error::jwt(
                    JwtErrorType::InvalidJwt,
                    format!("Raw components parse error: {}", e),
                )
            }),
            _ => {
                return Err(Error::unsupported(format!(
                    "{} algorithm is unupported",
                    self.kty.as_str()
                )))
            }
        }
    }
}

/// Set of JWKeys
/// See JWK Set here https://www.ietf.org/rfc/rfc7517.txt
#[derive(Serialize, Deserialize, Debug)]
struct JWKSet {
    pub keys: Vec<JWKey>,
}

#[async_trait::async_trait]
pub trait KeyCache: Send + Sync {
    /// Validates token using app cfg and returns extracted profile data.
    async fn get_token_profile_data(
        &self,
        token: &str,
        app: &App,
    ) -> Result<TokenProfileData, Error>;
}

/// Helper struct to store Validtion object and hash of sso_data value for the app.
/// Validation object to need to be parsed/ecaluated again if config_did not change.
/// Note: Change in one provider config will result in reevaluatin all Validation objs for all providers in thi app.
/// However sso config changes is expect to be extremly rare and should not have performance impact.
#[derive(Clone, Debug)]
struct ValidationWrapper {
    /// Validation object
    pub validation: Validation,
    /// Hash of serialized sso config for an app
    pub hash: u64,
}

/// Wrapper around of keys and next check to modify it with using one lock
#[derive(Debug)]
struct KeysWraper {
    /// Key set
    keys: Vec<JWKey>,
    /// Timestamp (Unix time in seconds) after wchich next refresh should be called
    /// Calculated based on keys response Cache-Control header
    /// See docs: https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token
    next_check: u64,
}

/// KeyCache implementation for Google
pub struct GoogleKeyCache {
    /// Keys wrapper
    keys_wrapper: RwLock<KeysWraper>,
    /// Http client
    client: reqwest::Client,
    /// If running integration tests don't not use real google endpoint and parse fixed response
    integration_tests: bool,
    // Validaution objects map. Key are App ids.
    validation: RwLock<HashMap<u32, ValidationWrapper>>,
}

impl GoogleKeyCache {
    pub fn new(integration_tests: bool) -> GoogleKeyCache {
        GoogleKeyCache {
            keys_wrapper: RwLock::new(KeysWraper {
                keys: vec![],
                next_check: 0,
            }),
            client: reqwest::Client::new(),
            integration_tests,
            validation: RwLock::new(HashMap::new()),
        }
    }

    /// Decodes google id_token using given key. Returns sso identifier.
    async fn get_sso_claims(
        &self,
        token: &str,
        key: &DecodingKey,
        app: &App,
    ) -> Result<GoogleIdToken, Error> {
        let mut validation = self
            .validation
            .read()
            .await
            .get(&app.id)
            .unwrap()
            .validation
            .clone();
        let header = jsonwebtoken::decode_header(token)?;
        validation.algorithms = vec![header.alg];

        let result = jsonwebtoken::decode::<GoogleIdToken>(&token, &key, &validation)?;

        // Manual check because iss can be one of two options according to https://developers.google.com/identity/sign-in/web/backend-auth
        if !GOOGLE_ISS.iter().any(|el| *el == result.claims.iss) {
            return Err(Error::jwt(JwtErrorType::InvalidJwt, "Invalid issuer"));
        }

        Ok(result.claims)
    }

    /// Calculates hash of sso config for an App. If something changed recalulates validation obj
    /// Note: RS256 is assumed, but it is overwritten in while decoding real token
    async fn update_validation_obj(&self, app: &App) -> Result<(), Error> {
        let mut s = DefaultHasher::new();
        app.sso_config.hash(&mut s);
        let hash = s.finish();

        if self.validation.read().await.get(&app.id).is_none()
            || self
                .validation
                .read()
                .await
                .get(&app.id)
                .as_ref()
                .unwrap()
                .hash
                != hash
        {
            let cfg_str = app
                .sso_config
                .as_ref()
                .ok_or(Error::internal_server_error_internal("Missing sso config"))?;

            let sso_cfg =
                serde_json::from_str::<HashMap<i32, SsoConfig>>(cfg_str).map_err(|e| {
                    Error::internal_server_error_internal(format!("SSo cfg parse error: {}", e))
                })?;

            let google_cfg = sso_cfg.get(&(AuthProvider::Google as i32)).ok_or(
                Error::internal_server_error_internal("Missing sso cfg for Google"),
            )?;

            if let Some(common::admin::sso_config::Cfg::Google(cfg)) = &google_cfg.cfg {
                let mut validation = Validation::new(Algorithm::RS256);
                validation.validate_exp = true;
                let aud = HashSet::from_iter(cfg.client_ids.clone().into_iter());
                validation.aud = Some(aud);

                self.validation
                    .write()
                    .await
                    .insert(app.id, ValidationWrapper { validation, hash });
            } else {
                return Err(Error::internal_server_error_internal(
                    "Invalid sso cfg for Google",
                ));
            }
        }

        Ok(())
    }

    /// Checks if key need refresh
    async fn needs_refresh(&self) -> bool {
        self.keys_wrapper.read().await.keys.is_empty()
            || self.keys_wrapper.read().await.next_check
                <= SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::MAX)
                    .as_secs()
    }

    /// Refreshes keys if needed
    async fn refresh(&self) -> Result<(), Error> {
        if !self.integration_tests {
            if self.needs_refresh().await {
                let response = self.client.get(GOOGLE_KEYS_URL).send().await?;
                let mut keys_guard = self.keys_wrapper.write().await;
                keys_guard.next_check = 0;
                if let Some(header) = response.headers().get(reqwest::header::CACHE_CONTROL) {
                    let value = header.to_str().unwrap();
                    if let Some(idx) = value.find("max-age=") {
                        let begin = idx + 8; // 8 - lenght of max-age=
                        if let Some(len) = value[begin..].find(",") {
                            if let Ok(v) = value[begin..begin + len].parse::<u64>() {
                                keys_guard.next_check = SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                                    + v;
                            }
                        }
                    }
                }

                match response.json::<JWKSet>().await {
                    Ok(parsed) => {
                        let filtered = parsed
                            .keys
                            .iter()
                            .filter(|key| match key.kty.as_str() {
                                "RSA" => {
                                    let valid = key.n.is_some() && key.e.is_some();
                                    if !valid {
                                        warn!("Invalid RSA key: {:?}", key);
                                    }
                                    valid
                                }
                                _ => {
                                    warn!("Unsupported key type: {}", key.kty.as_str());
                                    false
                                }
                            })
                            .cloned()
                            .collect();
                        keys_guard.keys = filtered;
                    }
                    Err(e) => {
                        keys_guard.next_check = 0;
                        return Err(e.into());
                    }
                }
            }
        } else {
            let response = serde_json::from_str::<JWKSet>(&TEST_KEYS_RESPONSE).unwrap();
            self.keys_wrapper.write().await.keys = response.keys;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl KeyCache for GoogleKeyCache {
    async fn get_token_profile_data(
        &self,
        token: &str,
        app: &App,
    ) -> Result<TokenProfileData, Error> {
        // Update validation obj if app sso cfg is changed
        self.update_validation_obj(app).await?;

        // refresh decryption keys
        self.refresh().await?;

        let keys_guard = self.keys_wrapper.read().await;
        for key in &keys_guard.keys {
            match self.get_sso_claims(token, &key.decoding_key()?, app).await {
                Ok(claims) => {
                    return Ok(TokenProfileData {
                        identifier: claims.sub,
                        email: claims.email,
                    });
                }
                Err(e) => {
                    if let Some(common::errors::error::Err::JwtError(t)) = &e.err {
                        if !t.message.eq("InvalidSignature") {
                            return Err(e);
                        }
                        // InvalidSignature: try another key
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Err(Error::jwt(JwtErrorType::InvalidJwt, "InvalidSignature"))
    }
}

impl UserEndpoints {
    /// Resister flow state machine for init -> sso -> finish
    pub async fn process_register_step_sso(
        &self,
        data: &SsoRegisterData,
        claims: UserClaims,
        app: App,
    ) -> Result<UserClaims, Error> {
        let provider = AuthProvider::from_i32(data.provider)
            .ok_or(Error::unsupported("Authenticity provider not supported"))?;

        let profile_data = self
            .get_token_profile_data(provider, &data.id_token, &app)
            .await?;

        let sso_data: common_types::SsoData = common_types::SsoData {
            id: 0, // will be generated
            app_id: app.id,
            provider: provider,
            identifier: profile_data.identifier,
        };

        // check if token is free
        if self
            .db
            .get_user_by_sso_data(&sso_data.identifier, sso_data.provider, app.id)
            .await?
            .is_some()
        {
            return Err(Error::id_in_use("SSO", "Sso id already exists"));
        }

        let mut user = User {
            id: 0, // ingored, autoincrement
            sso_id: None,
            username: data.username.clone().unwrap_or_default(),
            password: None,
            salt: None,
            email: profile_data.email,
            phone: None,
            app_id: Some(app.id),
            account_status: AccountStatus::Registered,
            user_type: UserType::User,
            profile: UserProfileData::default(), // Basic data like ids will be filled in db entry generation
        };

        loop {
            if data.username.is_none() {
                user.username = fake::Fake::fake(&fake::faker::internet::en::Username());
            }

            if self
                .db
                .get_user(&user.username, Some(app.id))
                .await?
                .is_none()
            {
                // TODO?: There is a tiny chance that another thread generates the same name
                user.id = self
                    .db
                    .create_user(user.clone(), Some(sso_data), None)
                    .await?;

                self.generate_and_upload_user_avatar(user.id).await?;

                break;
            } else {
                if let Some(u) = &data.username {
                    return Err(Error::id_in_use(
                        "username",
                        &format!("Username {} already exists", u),
                    ));
                }
            }
        }

        let new_claims = UserClaims {
            login_step: AccountStatus::Registered,
            user_id: user.id,
            username: user.username,
            role: user.user_type,
            ..claims
        };

        Ok(new_claims)
    }

    /// Login flow state machine for init -> sso -> finish
    pub async fn process_login_step_sso(
        &self,
        data: &SsoLoginData,
        claims: UserClaims,
        app: &App,
    ) -> Result<UserClaims, Error> {
        let provider = AuthProvider::from_i32(data.provider)
            .ok_or(Error::unsupported("Athenticy provider not supported"))?;

        let profile_data = self
            .get_token_profile_data(provider, &data.id_token, app)
            .await?;

        let user = self
            .db
            .get_user_by_sso_data(&profile_data.identifier, provider, app.id)
            .await?
            .ok_or_else(|| Error::user_not_found(0, ""))?;

        let new_claims = UserClaims {
            user_id: user.id as u64,
            username: user.username.clone(),
            role: user.user_type,
            login_step: AccountStatus::Registered,
            ..claims
        };

        Ok(new_claims)
    }

    /// Validates token and returns sso identifier
    async fn get_token_profile_data(
        &self,
        provider: AuthProvider,
        id_token: &str,
        app: &App,
    ) -> Result<TokenProfileData, Error> {
        let cache = self.keys_cache_map.get(&provider).unwrap();

        cache.get_token_profile_data(id_token, app).await
        //     },
        //     _ => Err(Error::unknown("Unsupported auth provider")),
        // }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use common::admin::GoogleSsoCfg;
    use jsonwebtoken::{Algorithm, Validation};
    use serde::{Deserialize, Serialize};
    use std::time::Duration;
    use test_common::{
        keys::{TEST_DEC_KEY, TEST_ENC_KEY},
        ANDROID_GOOGLE_CLIENT_ID, IOS_GOOGLE_CLIENT_ID, WEB_GOOGLE_CLIENT_ID,
    };

    #[derive(Serialize, Deserialize, Debug)]
    struct OAuthResp {
        pub access_token: String,
        pub id_token: String,
        pub expires_in: u32,
        pub scope: Option<String>,
        pub refresh_token: String,
    }

    #[tokio::test]
    #[ntest::timeout(10000)]
    async fn test_decode_google_token_id() {
        let cache = GoogleKeyCache::new(true);

        let mut sso_cfg_map = HashMap::new();
        sso_cfg_map.insert(
            AuthProvider::Google as i32,
            SsoConfig::google(GoogleSsoCfg {
                client_ids: vec![
                    ANDROID_GOOGLE_CLIENT_ID.into(),
                    IOS_GOOGLE_CLIENT_ID.into(),
                    WEB_GOOGLE_CLIENT_ID.into(),
                ],
            }),
        );

        let app = App {
            id: 1,
            name: "".into(),
            token: "".into(),
            description: "".into(),
            register_config: "".to_string(),
            login_config: "".to_string(),
            sso_config: Some(serde_json::to_string(&sso_cfg_map).unwrap()),
        };

        let token = GoogleIdToken {
            iss: GOOGLE_ISS[0].to_string(),
            sub: "".to_string(),
            aud: ANDROID_GOOGLE_CLIENT_ID.to_string(),
            iat: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::MAX)
                .as_secs()
                - 3600,
            exp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::MAX)
                .as_secs()
                + 3600,
            email: Some("a".to_string()),
            email_verified: Some(true),
            name: Some("A name".to_string()),
            ..Default::default()
        };

        let mut valid = vec![token];
        valid.push(GoogleIdToken {
            iss: GOOGLE_ISS[1].to_string(),
            ..valid[0].clone()
        });

        valid.push(GoogleIdToken {
            aud: ANDROID_GOOGLE_CLIENT_ID.to_string(),
            ..valid[0].clone()
        });

        valid.push(GoogleIdToken {
            aud: WEB_GOOGLE_CLIENT_ID.to_string(),
            ..valid[0].clone()
        });

        cache.update_validation_obj(&app).await.unwrap();

        for v in &valid {
            let encoded = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(Algorithm::RS256),
                &v,
                &*TEST_ENC_KEY,
            )
            .unwrap();
            let decoded = cache
                .get_sso_claims(&encoded, &TEST_DEC_KEY, &app)
                .await
                .unwrap();
            assert_eq!(*v, decoded);
        }

        // Invalid issuer
        let encoded = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::RS256),
            &GoogleIdToken {
                iss: "issuer".to_string(),
                ..valid[0].clone()
            },
            &TEST_ENC_KEY,
        )
        .unwrap();
        match cache
            .get_sso_claims(&encoded, &TEST_DEC_KEY, &app)
            .await
            .err()
            .unwrap()
            .err
            .unwrap()
        {
            common::errors::error::Err::JwtError(e) => {
                assert_eq!(e.err_type, common::errors::JwtErrorType::InvalidJwt as i32);
            }
            _ => assert!(false),
        }

        // Invalid audience
        let encoded = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::RS256),
            &GoogleIdToken {
                aud: "wrong".to_string(),
                ..valid[0].clone()
            },
            &TEST_ENC_KEY,
        )
        .unwrap();
        match cache
            .get_sso_claims(&encoded, &TEST_DEC_KEY, &app)
            .await
            .err()
            .unwrap()
            .err
            .unwrap()
        {
            common::errors::error::Err::JwtError(e) => {
                assert_eq!(
                    e.err_type,
                    common::errors::JwtErrorType::InvalidAudience as i32
                );
            }
            _ => assert!(false),
        }

        // Expired
        let leeway = cache
            .validation
            .read()
            .await
            .get(&app.id)
            .unwrap()
            .validation
            .leeway;
        let encoded = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::RS256),
            &GoogleIdToken {
                exp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or(Duration::MAX)
                    .as_secs()
                    - leeway
                    - 1,
                ..valid[0].clone()
            },
            &*TEST_ENC_KEY,
        )
        .unwrap();
        match cache
            .get_sso_claims(&encoded, &TEST_DEC_KEY, &app)
            .await
            .err()
            .unwrap()
            .err
            .unwrap()
        {
            common::errors::error::Err::JwtError(e) => {
                assert_eq!(e.err_type, common::errors::JwtErrorType::ExpiredJwt as i32);
            }
            _ => assert!(false),
        }
    }

    #[tokio::test]
    #[ntest::timeout(10000)]
    async fn test_decode_deps_works() {
        let token_response_str = r#"{
            "access_token": "ya29.A0ARrdaM92Jcq0Fb7Yw3bHOPFMEO9uhp1t82HqbgElMvRH0C1rOJy_zuYpN95C4jM7mxKMEdPLfOiRy3DFyccuVo0Rv8Sw5TInpB7JHCLFmdJcmEBqwUnW4MmSf5HUpMdneDwZVf60ayZJep92vTT4Q5ZQKDIh", 
            "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQzMzJhYjU0NWNjMTg5ZGYxMzNlZmRkYjNhNmM0MDJlYmY0ODlhYzIiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5NjMzODk1MDE1OTgtaDhndmYxMzdvMGc0dGs5aDBnc2k2dmpub3N1Z2thdDUuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5NjMzODk1MDE1OTgtaDhndmYxMzdvMGc0dGs5aDBnc2k2dmpub3N1Z2thdDUuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE4MDg2Njg2OTMzMTEwNzQxMTUiLCJoZCI6ImFsYW4uY28iLCJlbWFpbCI6Im5pa2l0YS5lcm9zaGluQGFsYW4uY28iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IjZTa3RaUFZfSlo5VjYyZVRJMGJSbEEiLCJub25jZSI6Ilh3czFrUHZ5WGU2V2V0N18zWm52RVA2S0xhT0t5Y2QtMEpPOHFsQnJRYWMiLCJuYW1lIjoiTmlraXRhIEVyb3NoaW4iLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtL0FPaDE0R2pTWVRzaHlHcmFmbm5lUzY5UDVUdnhYQmVsMmljUmxlX25HdWs5PXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6Ik5pa2l0YSIsImZhbWlseV9uYW1lIjoiRXJvc2hpbiIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjQ5OTQzOTM4LCJleHAiOjE2NDk5NDc1Mzh9.WEJwzkcNBkgafZHj4DD9JgfNEkj6u7HSW3wcAMMj9BKlN2NcDCeosuZK3OGjjR4hctVzwvpbjgOYeAZ6xMoWTCWYsTTF6_lYjALVM11fMz8wCwQ-W1a98NVhWjZKLQXUqGivBC__ZPegQhjRXLF_2nbIzSXMwf7qja5FgWfRTsrpxJ2ACWd8gmEvmNtSzdpbwOFBiwHjH8vAXnRxhYp5zna5BY0k4LhrdgoDXs6IcdEGGzgPFCufnpfHpEq9Ajf0Pst3fadF27Qg7AnzG_uk5RmL4Dxg19F1dVQxGsWNK9Bfy_1OrJ-l0cYzt5kA4QASB-_PTSVywPMoZJ909bOohQ",
            "expires_in": 3599, 
            "token_type": "Bearer", 
            "scope": "openid https://www.googleapis.com/auth/userinfo.email", 
            "refresh_token": "1//04WufBsP-JVENCgYIARAAGAQSNwF-L9IrU53HNeKdH9S5z-KS2AyLg9eoa9BI3C1FP-hOtJWWvC-CCAElyu5TayXdm5ln51YO0Pw"
          }"#;

        let parsed = serde_json::from_str::<OAuthResp>(token_response_str);
        let id_token = parsed.unwrap().id_token;

        let keys_str = r#"{
            "keys": [
              {
                "kid": "f1338ca26835863f671408f41738a7b49e740fc0",
                "e": "AQAB",
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": "vCk1vqT3qTLWsZ0yyO6T5sHBFUMPI9bcjT9yO94cZUfJjttRV_RMxUgvB-c3o-dx7f4WrM3knYoWn5pmGH6_B3vJbvnTzfnjojaBfsqn8Cdof1mI3N6ZKmhFVWz-Sui65ycb9F2MVw-z0DcZxk_DcBEMG6Jxps9I2_hFm7xkCPjiN2Q8T-MLNhJYnoxBe1VtuyCFFEDAtU5VXIyJEdDoz_MXIR7o8TsQTnX1ZpB4SijtShz4oJXaQGeSb8eb9AgwiOuiFKHndiMaemtEfnIkU4EXZ_MXXLdi0Rq-euA7XVFk-j1jVxRtVOhrz0VIMy2B8g6l817zKHqC3ZIv1PbUVQ"
              },
              {
                "alg": "RS256",
                "n": "pnvsf_d6daVCXm6NoBHxpIhkk345edh7GaiXl25XR4_q2ATkiZMBF8foXaa_LTyr8W5dmvqIE71p_T9ygVLMoP7YumjOimrbwB3gEV1ekI-d2rkRbCFg56bzifkAi8gdQW3pj4j-bouOSNkEAUeVSDsHst1f-sFmckZmb1Pe1bWLI-k6TXirXQpGDEZKeh1AWxillo9AWqmDXalurQt46W6rd1y2RCj5Y5zXQheNF6Il0Izc4K5RDBKkanyZ7Dq_ZFuTpVJkxPgCjN6G8cfzM0JKujWX4Zit2xCmZhVfr7hDodnNEPo1IppWNrjcfZOtA_Jh6yBlB7T8DWd1l1PvUQ",
                "e": "AQAB",
                "kty": "RSA",
                "use": "sig",
                "kid": "d332ab545cc189df133efddb3a6c402ebf489ac2"
              }
            ]
          }"#;

        let keys = serde_json::from_str::<JWKSet>(keys_str).unwrap();
        let dk1 = DecodingKey::from_rsa_components(
            keys.keys[0].n.as_ref().unwrap(),
            keys.keys[0].e.as_ref().unwrap(),
        )
        .unwrap();
        let dk2 = DecodingKey::from_rsa_components(
            keys.keys[1].n.as_ref().unwrap(),
            keys.keys[1].e.as_ref().unwrap(),
        )
        .unwrap();

        let mut v = Validation::new(Algorithm::RS256);
        v.validate_exp = false;

        let result = jsonwebtoken::decode::<GoogleIdToken>(&id_token, &dk1, &v);
        assert_eq!(result.err().unwrap().to_string(), "InvalidSignature");
        let result = jsonwebtoken::decode::<GoogleIdToken>(&id_token, &dk2, &v).unwrap();

        assert_eq!(
            result.claims.email.as_ref().unwrap(),
            "nikita.eroshin@alan.co"
        );
        assert_eq!(result.claims.email_verified, Some(true));
        assert_eq!(result.claims.aud, IOS_GOOGLE_CLIENT_ID);

        // Certs obtained in the same time as keys above. Not used at the moment.
        let _certs = r#"{
            "cec13debf4b96479683736205082466c14797bd0": "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIIfCd+3igkjOowDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAwwrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0yMjAzMjgxNTIxNDVaFw0yMjA0MTQwMzM2NDVaMDYxNDAyBgNVBAMMK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVhZQzxjlQTFJ9ewGsXqgAIjjychPEN/Ts\nKJgqf9VNstGWldfUB821CGuOb6M+MLXqpecYIGF2Vkd0LJx97OgyDyy+jjVTtghU\ns/kbkfp/tXEASCWZXkgZzSSPfn/+qarLe3US6D+KrEI7JGVwMQtDvkw06FgVC2N4\nS0u7DgSuk+k55hVfvW84fdD16ki0wzSfXwVdbkN3oGQKIe8yRvl5Ic4fTsnSH4yR\nEXXfdH5hI8+AOWot5HF2MOjavCooWw5rrx53NyidVwRNZHZhKgW1qeBV34gGHMWt\nrHyDJWye0qmZuDxfIllTa+2AyJN0/TACMB7yDLvwODVYg5U57nyVAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQCGQB8vb3V60AzYX1vr/He+9gvtsaHZ\nXXI8lTN3EmAiY/k9uvvNJ2rY8Dii7zI5sRKH/LxexRt5zxvzkIIXyf7EOwuHWovD\nh0Nn35HxbdUWoUZjs9X5v2NiwM18ZZQrng4fR+iXnaQyl/07h9VZaTriRCXMj9+H\nh2OTl8JCRMt0klJA97ljuUK/cEigvfl8xXO8/A+csq6nkXUz5exCetcpmquG4X5Y\nN0WlfGY/hoX9nVikRQXw6Ywag1duwTBTxT10GVu5QzuVPsP/1UxtdPcDPPYNfTD3\nFApdXi+nx8WUiuneTLRw81xLAJCc+XFGH7dJC1cZas9KO/JEt2DiwimS\n-----END CERTIFICATE-----\n",
            "58b429662db0786f2efefe13c1eb12a28dc442d0": "-----BEGIN CERTIFICATE-----\nMIIDJzCCAg+gAwIBAgIJAMf2yiWg8kw9MA0GCSqGSIb3DQEBBQUAMDYxNDAyBgNV\nBAMMK2ZlZGVyYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20w\nHhcNMjIwMzIwMTUyMTQyWhcNMjIwNDA2MDMzNjQyWjA2MTQwMgYDVQQDDCtmZWRl\ncmF0ZWQtc2lnbm9uLnN5c3RlbS5nc2VydmljZWFjY291bnQuY29tMIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxszAZmDzaUa5d8anZL6ZExj0YNiUVZqz\nFxWQGKT3fPw5N5lKb/eVtxFKFjgyfOx8Lm1NbVIFVBNTGFsd42MMSU+CrEMMsWe3\nWTgSzwCmW4t5XE//y1b7MkUTd4WkSzgifMok/SD4D8x+Gd1+awC6nLu0bEbqLWca\nXtwfogDiO2nMTgQcuVBGH3ZA+sS7ASgNK+3bNM0mXeVvaIzRPAahZ9tzJ/CEj8mr\nDVdmgSsO42PTnYtfQc1nytLwNX19/92HQAvWLtQ3+zjZ0FlJUGFTUui8whktgRXv\n2eXyp+bNkprD7HORUjzCU0Ugwq+nfa1zyYrBDpwQ8FVnS6opUK7iAQIDAQABozgw\nNjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggr\nBgEFBQcDAjANBgkqhkiG9w0BAQUFAAOCAQEAWpYRuREqmIZ37hoAHsVwNBtnU6sQ\nIQKe+WzToRb+0wLPC0aE7RPdn0vHXgc2BO6elWO10UpiUeTpAk6YzYnDVTiCLGRT\nNeQn2wS7mxwoF664E0z4bS8AoPHmpRnYk9xe/bJy7KlJGtkHYyCZYzcu40KkTkqY\nAWHrCYqVB2vSIJvGiO2wWqCFK3esXtln0xa5P17fgtqyXERivDdv4VmNCmyOnUyH\nK7u0/vBAX3vFbinqNNJlHmAtMIyUu7QMkG/3e50A4EmwLGTo5OHUPJ1n8esuG3W9\nd4eRuewcX1Gw1CNT0PFt2VKJVBkooy274qhMUgRR1T/682IqhAMP+U422Q==\n-----END CERTIFICATE-----\n"
        }"#;
    }

    #[tokio::test]
    #[ntest::timeout(10000)]
    async fn test_get_google_keys() {
        let cache = GoogleKeyCache::new(false);

        assert!(cache.needs_refresh().await);
        cache.refresh().await.unwrap();
        assert!(!cache.needs_refresh().await);

        assert!(!cache.keys_wrapper.read().await.keys.is_empty());
        for k in &cache.keys_wrapper.read().await.keys {
            let _ = k.decoding_key().unwrap();
        }
    }

    #[tokio::test]
    #[ntest::timeout(10000)]
    async fn test_id_tree_serialize_preserve_node_ids() {
        use id_tree::InsertBehavior::*;
        use id_tree::*;

        //      0
        //     / \
        //    1   2
        //   / \
        //  3   4
        let mut tree: Tree<i32> = TreeBuilder::new().with_node_capacity(5).build();

        let root_id: NodeId = tree.insert(Node::new(0), AsRoot).unwrap();
        let child_id: NodeId = tree.insert(Node::new(1), UnderNode(&root_id)).unwrap();
        tree.insert(Node::new(2), UnderNode(&root_id)).unwrap();
        tree.insert(Node::new(3), UnderNode(&child_id)).unwrap();
        tree.insert(Node::new(4), UnderNode(&child_id)).unwrap();

        println!("Pre-order:");
        for node in tree.traverse_pre_order(&root_id).unwrap() {
            print!("{}, ", node.data());
        }

        println!("");
        for node in tree.traverse_pre_order_ids(&root_id).unwrap() {
            print!("{:?}, ", node);
        }

        let serialized = serde_json::to_string(&tree).unwrap();

        println!("{}", serialized);

        let deserialized = serde_json::from_str::<Tree<i32>>(&serialized).unwrap();
        for node in deserialized.traverse_pre_order(&root_id).unwrap() {
            print!("{}, ", node.data());
        }

        println!("");
        for node in deserialized.traverse_pre_order_ids(&root_id).unwrap() {
            print!("{:?}, ", node);
        }

        assert_eq!(deserialized, tree);
    }
}
