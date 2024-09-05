#![allow(dead_code)]

use std::convert::TryFrom;
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

use thumbs_up::prelude::{
    ApiToken, ApiTokenMetadata, TUVerificationOptions as VerificationOptions,
};

use crate::app::{AllowedAudiences, PublicKeyRegistry};

/// Defines the maximum length of time we consider any individual token valid in seconds. If the
/// expiration is still in the future, but it was issued more than this many seconds in the past
/// we'll reject the token even if its otherwise valid.
const MAXIMUM_TOKEN_AGE: u64 = 900;

static KEY_ID_PATTERN: &str = r"^[0-9a-f]{64}$";

static KEY_ID_VALIDATOR: OnceLock<Regex> = OnceLock::new();

#[derive(Debug)]
pub struct ApiIdentity {
    // TODO: this should be a more specific type
    subject: String,
    audience: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for ApiIdentity
where
    AllowedAudiences: FromRef<S>,
    PublicKeyRegistry: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiIdentityError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let public_key_registry = PublicKeyRegistry::from_ref(state);
        let allowed_audiences = AllowedAudiences::from_ref(state);
        let key_validator = KEY_ID_VALIDATOR.get_or_init(|| Regex::new(KEY_ID_PATTERN).unwrap());

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(ApiIdentityError::MissingHeader)?;

        let raw_token = bearer.token();

        let unvalidated_metadata = ApiTokenMetadata::try_from(raw_token.to_string())?;

        // Enforces that the key ID is a valid SHA-256 hash
        let key_id = match unvalidated_metadata.kid() {
            Ok(key_id) => {
                if !key_validator.is_match(key_id) {
                    return Err(ApiIdentityError::InvalidKeyId);
                }
                key_id
            }
            Err(_) => return Err(ApiIdentityError::MissingKeyId),
        };

        // Find the public key for the sub claim
        let (subject, public_key) = match public_key_registry.get(key_id) {
            Some(key) => key,
            None => return Err(ApiIdentityError::KeyUnavailable),
        };

        // generate verification options
        let mut options = VerificationOptions::default();
        options
            // TODO: proper time handling
            // .reject_before(unvalidated_metadata.iat().unwrap_or(0) - MAXIMUM_TOKEN_AGE)
            .required_subject(&subject)
            .allowed_audiences(if allowed_audiences.len() > 0 {
                Some(allowed_audiences.0)
            } else {
                None
            });

        // Get the decoded token
        let token = ApiToken::decode_from(raw_token, &public_key, Some(options.clone()))?;

        // TODO: Validate the token's nonce
        let _nonce = token.nnc()?;

        // Get the audience from the token
        let audience = token.aud()?;

        Ok(Self {
            subject: subject.to_string(),
            audience: audience.to_string(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiIdentityError {
    #[error("key error: {0}")]
    ThumbsUp(#[from] thumbs_up::prelude::KeyError),

    #[error("key unavailable")]
    KeyUnavailable,

    #[error("key ID included in JWT header did not match our expected format")]
    InvalidKeyId,

    #[error("provided subject was not a valid UUID")]
    InvalidSubject,

    #[error("authenticated route was missing authorization header")]
    MissingHeader(TypedHeaderRejection),

    #[error("no key ID was included in the JWT header")]
    MissingKeyId,

    #[error("no nonce was included in the token")]
    MissingNonce,

    #[error("no subject was included in the token")]
    MissingSubject,

    #[error("no audience was included in the token")]
    MissingAudience,
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
                (StatusCode::UNAUTHORIZED, Json(err_msg)).into_response()
            }
        }
    }
}
