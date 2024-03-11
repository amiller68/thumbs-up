#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("Invalid Base64: {0}")]
    InvalidBase64(base64ct::Error),
    #[error("Private key export bytes failed")]
    PrivateKeyExportBytesFailed,
    #[error("Private key import bytes failed")]
    PrivateKeyImportBytesFailed,
    #[error("Private key export failed: {0}")]
    PrivateKeyExportFailed(p384::pkcs8::Error),
    #[error("Private key import failed: {0}")]
    PrivateKeyImportFailed(p384::pkcs8::Error),
    #[error("Public key export failed: {0}")]
    PublicKeyExportFailed(#[from] p384::pkcs8::spki::Error),
    #[error("Public key import failed: {0}")]
    PublicKeyImportFailed(p384::pkcs8::spki::Error),
    #[error("JWT error: {0}")]
    JwtError(#[from] jwt_simple::Error),
    #[error("Missing JWT claims: {0}")]
    JwtMissingClaims(String),
    #[error("Missing JWT header field: {0}")]
    JwtMissingHeaderField(String),
}
