#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::OnceLock;

use axum::extract::{FromRef, FromRequestParts};
use axum::response::{IntoResponse, Response};
use axum::{async_trait, Json, RequestPartsExt};
use axum_extra::typed_header::TypedHeaderRejection;
use axum_extra::TypedHeader;
use headers::authorization::Bearer;
use headers::Authorization;
use http::request::Parts;
use http::StatusCode;
use regex::Regex;
use uuid::Uuid;

use thumbs_up::prelude::ApiIdentity as _ApiIdentity;

use crate::app::PublicKeyRegistry;

/// Defines the maximum length of time we consider any individual token valid in seconds. If the
/// expiration is still in the future, but it was issued more than this many seconds in the past
/// we'll reject the token even if its otherwise valid.
const MAXIMUM_TOKEN_AGE: u64 = 900;

static KEY_ID_PATTERN: &str = r"^[0-9a-f]{64}$";

static KEY_ID_VALIDATOR: OnceLock<Regex> = OnceLock::new();

pub struct ApiIdentity(_ApiIdentity);

#[async_trait]
impl<S> FromRequestParts<S> for ApiIdentity
where
    PublicKeyRegistry: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiIdentityError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let public_key_registry = PublicKeyRegistry::from_ref(state);
        let key_validator = KEY_ID_VALIDATOR.get_or_init(|| Regex::new(KEY_ID_PATTERN).unwrap());

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(ApiIdentityError::MissingHeader)?;

        let raw_token = bearer.token();

        let unvalidated_metadata = ApiTokenMetadata::try_from(raw_token)?;

        let key_id = match unvalidated_metadata.kid() {
            Ok(key_id) => {
                if !key_validator.is_match(key_id) {
                    return Err(ApiIdentityError::InvalidKeyId);
                }
                key_id
            }
            Err(_) => return Err(ApiIdentityError::MissingKeyId),
        };

        // Get the aud and sub claims from the token
        let aud = unvalidated_metadata
            .aud()
            .ok_or(ApiIdentityError::SubjectMissing)?;
        let sub = unvalidated_metadata
            .sub()
            .ok_or(ApiIdentityError::SubjectMissing)?;

        // Find the public key for the sub claim
        let (kid, public_key) = public_key_registry
            .get_sub(sub)
            .unwrap_or_else(|| return Err(ApiIdentityError::KeyUnavailable));

        // Validate the token
        let _ = ApiToken::decode_from(&raw_token, &public_key)?;

        // Validate the token's nonce
        let nonce = unvalidated_metadata
            .nonce()
            .ok_or(ApiIdentityError::NonceMissing)?;
        let 
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiIdentityError {
    #[error("key error: {0}")]
    Key(#[from] thumbs_up::prelude::KeyError),

    #[error("key ID included in JWT header did not match our expected format")]
    InvalidKeyId,

    #[error("unable to find JWT verification key in server state")]
    KeyUnavailable,

    #[error("authenticated route was missing authorization header")]
    MissingHeader(TypedHeaderRejection),

    #[error("no key ID was included in the JWT header")]
    MissingKeyId,

    #[error("no nonce was included in the token")]
    NonceMissing,

    #[error("provided subject was not a valid UUID")]
    SubjectInvalid,

    #[error("no subject was included in the token")]
    SubjectMissing,

    #[error("validation of the provided JWT failed")]
    ValidationFailed(jwt_simple::Error),
}

impl IntoResponse for ApiIdentityError {
    fn into_response(self) -> Response {
        use ApiIdentityError::*;

        match self {
            KeyUnavailable => {
                let err_msg =
                    serde_json::json!({ "status": "authentication services unavailable" });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(err_msg)).into_response()
            }
            _ => {
                let err_msg = serde_json::json!({ "status": "invalid bearer token" });
                (StatusCode::BAD_REQUEST, Json(err_msg)).into_response()
            }
        }
    }
}

