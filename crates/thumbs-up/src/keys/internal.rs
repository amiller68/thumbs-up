use base64ct::LineEnding;
use blake3::Hasher;
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    PublicKey as P384PublicKey, SecretKey as P384SecretKey,
};

use crate::keys::common::FINGERPRINT_SIZE;
use crate::prelude::KeyError;

/// Blake3 compressed point fingerprint function
pub fn fingerprint<'a>(public_key: impl Into<&'a P384PublicKey>) -> [u8; FINGERPRINT_SIZE] {
    let public_key = public_key.into();
    let compressed_point = public_key.as_ref().to_encoded_point(true);
    let compressed_point = compressed_point.as_bytes();
    let mut hasher = Hasher::new();
    hasher.update(compressed_point);
    let mut output = [0u8; FINGERPRINT_SIZE];
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut output);
    output
}

pub fn gen_ec_key() -> P384SecretKey {
    let mut rng = rand::thread_rng();
    P384SecretKey::random(&mut rng)
}

pub fn import_key_bytes(der_bytes: &[u8]) -> Result<P384SecretKey, KeyError> {
    P384SecretKey::from_sec1_der(der_bytes).map_err(|_| KeyError::PrivateKeyImportBytesFailed)
}
pub fn export_key_bytes(private_key: &P384SecretKey) -> Result<Vec<u8>, KeyError> {
    Ok(private_key
        .to_sec1_der()
        .map_err(|_| KeyError::PrivateKeyExportBytesFailed)?
        .to_vec())
}
pub fn import_key_pem(pem_bytes: &[u8]) -> Result<P384SecretKey, KeyError> {
    let pem_string = std::str::from_utf8(pem_bytes).map_err(KeyError::InvalidUtf8)?;
    P384SecretKey::from_pkcs8_pem(pem_string).map_err(KeyError::PrivateKeyImportFailed)
}
pub fn export_key_pem(private_key: &P384SecretKey) -> Result<Vec<u8>, KeyError> {
    Ok(private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(KeyError::PrivateKeyExportFailed)?
        .as_bytes()
        .to_vec())
}
pub fn import_public_key_bytes(der_bytes: &[u8]) -> Result<P384PublicKey, KeyError> {
    P384PublicKey::from_public_key_der(der_bytes).map_err(KeyError::PublicKeyImportFailed)
}
pub fn export_public_key_bytes(public_key: &P384PublicKey) -> Result<Vec<u8>, KeyError> {
    Ok(public_key
        .to_public_key_der()
        .map_err(KeyError::PublicKeyExportFailed)?
        .into_vec())
}
pub fn import_public_key_pem(pem_bytes: &[u8]) -> Result<P384PublicKey, KeyError> {
    let pem_string = std::str::from_utf8(pem_bytes).map_err(KeyError::InvalidUtf8)?;
    P384PublicKey::from_public_key_pem(pem_string).map_err(KeyError::PublicKeyImportFailed)
}
pub fn export_public_key_pem(public_key: &P384PublicKey) -> Result<Vec<u8>, KeyError> {
    Ok(public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(KeyError::PublicKeyExportFailed)?
        .as_bytes()
        .to_vec())
}
