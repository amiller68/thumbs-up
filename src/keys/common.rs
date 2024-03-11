use super::hex_fingerprint;
use crate::prelude::*;
use jwt_simple::prelude::*;
use rand::{distributions::Alphanumeric, Rng};
use std::error::Error;

/// How long Nonce values are
pub const NONCE_SIZE: usize = 12;

/// Number of bytes present in an unformatted fingerprint.
pub const FINGERPRINT_SIZE: usize = 20;

/// Number of bytes used for our salts and IVs
pub const SALT_SIZE: usize = 16;

/// The number of seconds JWTs are valid for
pub const JWT_DURATION: u64 = 870;

/// The number of seconds JWTs are valid for
pub const JWT_LEEWAY: u64 = 30;

/// A PrivateKey is an opinionated cryptographic type designed for encrypting and
/// decrypting (wrapping) a symmetric AES key using an EC group key, or signing and verifying
/// a JWT token
pub trait PrivateKey: Sized + Send {
    /// The error type that will commonly be returned by all concrete implementations of the type.
    type Error: Error;

    /// This is the type that will constitute the public portion of this concrete implementation.
    type PublicKey: PublicKey<Error = Self::Error>;

    /// Converts the private key representation into a PEM wrapped PKCS8 private key. The returned
    /// bytes should all be printable UTF8 characters which can be turned into a string on demand.
    ///
    /// This format should be preferred if the data is going to be visible to people or platforms
    /// as it is immediately recognizable.
    fn export(&self) -> Result<Vec<u8>, Self::Error>;

    /// Export the internal private key into a DER encoded set of bytes.
    fn export_bytes(&self) -> Result<Vec<u8>, Self::Error>;

    /// Create a standards compliant SHA1 fingerprint of the associated public key encoded as a
    /// fixed length bytes string. This is usually presented to users by running it through the
    /// prettifier [`crate::key_seal::pretty_fingerprint()`].
    fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], Self::Error> {
        let public_key: Self::PublicKey = self.public_key()?;
        public_key.fingerprint()
    }

    /// Creates a secure new private key matching the security and use requirements for use as a EC
    /// wrapping key.
    fn generate() -> Result<Self, Self::Error>;

    /// Parses a PEM encoded EC private key into the internal type appropriate for being used as a
    /// wrapping key.
    fn import(pem_bytes: &[u8]) -> Result<Self, Self::Error>;

    /// Parses a DER encoded EC private key into the internal type appropriate for being used as a
    /// wrapping key.
    fn import_bytes(der_bytes: &[u8]) -> Result<Self, Self::Error>;

    fn public_key(&self) -> Result<Self::PublicKey, Self::Error>;
}

/// The public portion of a [`PrivateKey`]. The public portion is important for tracking
/// the identity of the keys and can be used to encrypt any plain key in a way the holder the
/// private key can get access to.
pub trait PublicKey: Sized + Send + Sync {
    /// The error type that will commonly be returned by all concrete implementations of the type.
    type Error: Error;

    /// Converts the public portion of the wrapping key into a PEM/SPKI formatted version that is
    /// easy to exchange in a visibly identifiable way and works over ASCII only channels.
    fn export(&self) -> Result<Vec<u8>, Self::Error>;

    /// Exports the public portion of a private key as a DER formatted byte string. Preferred when
    /// exchanging and embedding in formats that will already be encoded using other means.
    fn export_bytes(&self) -> Result<Vec<u8>, Self::Error>;

    /// Generates a SHA1 over the standardized compressed form representation of an EC key. This is
    /// usually presented to users by running it through the prettifier
    /// [`crate::key_seal::pretty_fingerprint()`].
    fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], Self::Error>;

    /// IMPORT A STANDARD PEM FORMATTED VERSION OF AN EC KEY.
    fn import(pem_bytes: &[u8]) -> Result<Self, Self::Error>;

    /// Import a standard DER formatted EC key byte string
    fn import_bytes(der_bytes: &[u8]) -> Result<Self, Self::Error>;
}

// TODO: Add CustomClaims
/// Defines standard pyaload interface for a JWT token
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiToken(pub(crate) JWTClaims<NoCustomClaims>);

/// Defines struct around a JWt bearer token. Can be used to extract metadata on a signed /encoded token
#[derive(Debug, Clone)]
pub struct ApiTokenMetadata(pub(crate) TokenMetadata);

impl ApiToken {
    /// Create a new token
    /// # Arguments
    /// * `audience` - The audience for the token
    /// * `subject` - The subject for the token
    /// # Returns
    /// A new Jwt
    pub fn new(audience: String, subject: String) -> Self {
        Self(
            Claims::create(Duration::from_secs(JWT_DURATION))
                .with_audience(audience)
                .with_subject(subject)
                .with_nonce(
                    rand::thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(16)
                        .map(char::from)
                        .collect::<String>(),
                ),
        )
    }

    /// Refresh the token
    /// # Arguments
    /// * `private_key` - The private key to use to sign the token
    /// # Returns
    /// Self, but with a new expirations and nonce
    pub fn refresh(&self) -> Result<Self, KeyError> {
        let audience = self.aud()?;
        let subject = self.sub()?;
        Ok(Self::new(audience.to_string(), subject.to_string()))
    }

    /// Determine if the token is expired
    /// # Returns
    /// True if the token is expired, false otherwise
    /// # Errors
    /// If the expiration is not set
    pub fn is_expired(&self) -> Result<bool, KeyError> {
        let exp = self.exp()?;
        Ok(exp < (chrono::Utc::now().timestamp() as u64 + JWT_LEEWAY))
    }

    /// Get the audience for the token
    /// # Returns
    /// The audience for the token
    /// # Errors
    /// If the audience is not a set
    pub fn aud(&self) -> Result<&str, KeyError> {
        let auds = self
            .0
            .audiences
            .as_ref()
            .ok_or_else(|| KeyError::JwtMissingClaims("audience".to_string()))?;
        let aud = match auds {
            Audiences::AsSet(aud) => aud
                .iter()
                .next()
                .ok_or_else(|| KeyError::JwtMissingClaims("audience".to_string()))?,
            Audiences::AsString(aud) => aud,
        };
        Ok(aud)
    }

    /// Get the subject for the token
    /// # Returns
    /// The subject for the token
    /// # Errors
    /// If the subject is not set
    pub fn sub(&self) -> Result<&str, KeyError> {
        let sub = self
            .0
            .subject
            .as_ref()
            .ok_or_else(|| KeyError::JwtMissingClaims("subject".to_string()))?;
        Ok(sub)
    }

    /// Get the nonce for the token
    /// # Returns
    /// The nonce for the token
    /// # Errors
    /// If the nonce is not set
    pub fn nnc(&self) -> Result<&str, KeyError> {
        let nonce = self
            .0
            .nonce
            .as_ref()
            .ok_or_else(|| KeyError::JwtMissingClaims("nonce".to_string()))?;
        Ok(nonce)
    }

    /// Get when the token was issued
    /// # Returns
    /// When the token was issued
    /// # Errors
    /// If the issued at is not set
    pub fn iat(&self) -> Result<u64, KeyError> {
        let iat = self
            .0
            .issued_at
            .as_ref()
            .ok_or_else(|| KeyError::JwtMissingClaims("issued at".to_string()))?;
        Ok(iat.as_secs())
    }

    /// Get when the token expires
    /// # Returns
    /// When the token expires
    /// # Errors
    /// If the expiration is not set
    pub fn exp(&self) -> Result<u64, KeyError> {
        let exp = self
            .0
            .expires_at
            .as_ref()
            .ok_or_else(|| KeyError::JwtMissingClaims("expiration".to_string()))?;
        Ok(exp.as_secs())
    }

    /// Get when the token is invalid before
    /// # Returns
    /// When the token is invalid before
    /// # Errors
    /// If the invalid before is not set
    pub fn nbf(&self) -> Result<u64, KeyError> {
        let nbf = self
            .0
            .invalid_before
            .as_ref()
            .ok_or_else(|| KeyError::JwtMissingClaims("not before".to_string()))?;
        Ok(nbf.as_secs())
    }
}

impl ApiTokenMetadata {
    /// Get the algorithm for the token
    /// # Returns
    /// The algorithm for the token
    pub fn alg(&self) -> &str {
        self.0.algorithm()
    }

    /// Get the key id for the token
    /// # Returns
    /// The key id for the token
    /// # Errors
    /// If the key id is not set
    pub fn kid(&self) -> Result<&str, KeyError> {
        let kid = self
            .0
            .key_id()
            .ok_or_else(|| KeyError::JwtMissingHeaderField("kid".to_string()))?;
        Ok(kid)
    }

    /// Get the type for the token
    /// # Returns
    /// The type for the token
    /// # Errors
    /// If the type is not set
    pub fn typ(&self) -> Result<&str, KeyError> {
        let typ = self
            .0
            .signature_type()
            .ok_or_else(|| KeyError::JwtMissingHeaderField("typ".to_string()))?;
        Ok(typ)
    }
}

impl TryFrom<String> for ApiTokenMetadata {
    type Error = KeyError;
    fn try_from(token: String) -> Result<Self, Self::Error> {
        let metadata = Token::decode_metadata(&token).map_err(KeyError::JwtError)?;
        Ok(Self(metadata))
    }
}

impl ApiToken {
    /// Decode a token from a string
    /// # Arguments
    /// * `token` - The token to decode
    /// * `public_key` - The public key to use to verify the token
    pub fn decode_from(token: &str, public_key: &EcPublicKey) -> Result<Self, KeyError> {
        let key_bytes = public_key.export_bytes()?;
        let key_id = hex_fingerprint(public_key.fingerprint()?.as_slice());
        let decoding_key = ES384PublicKey::from_der(&key_bytes)
            .map_err(KeyError::JwtError)?
            .with_key_id(&key_id);

        let token = decoding_key
            .verify_token::<NoCustomClaims>(token, None)
            .map_err(KeyError::JwtError)?;

        Ok(Self(token))
    }

    /// Encode a token to a string
    /// # Arguments
    /// * `private_key` - The private key to use to sign the token
    /// # Returns
    /// A string representation of the token
    pub fn encode_to(&self, signing_key: &EcKey) -> Result<String, KeyError> {
        let pem_bytes = signing_key.export()?;
        let pem_string = std::str::from_utf8(&pem_bytes).map_err(KeyError::InvalidUtf8)?;
        let encoding_key = ES384KeyPair::from_pem(pem_string)
            .map_err(KeyError::JwtError)?
            .with_key_id(&hex_fingerprint(signing_key.fingerprint()?.as_slice()));
        let claims = &self.0;
        let token = encoding_key
            .sign::<NoCustomClaims>(claims.clone())
            .map_err(KeyError::JwtError)?;
        Ok(token)
    }
}
