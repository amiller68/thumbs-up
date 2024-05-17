pub mod common;

mod ec_key;
mod ec_public_key;
mod error;
mod internal;

pub use ec_key::EcKey;
pub use ec_public_key::EcPublicKey;
pub use error::KeyError;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signature_key_roundtripping() -> Result<(), KeyError> {
        use crate::keys::common::{PrivateKey, PublicKey};

        let key = EcKey::generate()?;
        let public_key = key.public_key()?;

        // dirty comparisons but works for now
        let raw_key_bytes = key.export_bytes()?;
        let imported_key = EcKey::import_bytes(&raw_key_bytes)?;
        let reexported_key_bytes = imported_key.export_bytes()?;
        assert_eq!(raw_key_bytes, reexported_key_bytes);

        let raw_public_key_bytes = public_key.export_bytes()?;
        let imported_public_key = EcPublicKey::import_bytes(&raw_public_key_bytes)?;
        let reexported_public_key_bytes = imported_public_key.export_bytes()?;
        assert_eq!(raw_public_key_bytes, reexported_public_key_bytes);

        let raw_key_pem = key.export()?;
        let imported_key = EcKey::import(&raw_key_pem)?;
        let reexported_key_pem = imported_key.export()?;
        assert_eq!(raw_key_pem, reexported_key_pem);

        let raw_public_key_pem = public_key.export()?;
        let imported_public_key = EcPublicKey::import(&raw_public_key_pem)?;
        let reexported_public_key_pem = imported_public_key.export()?;
        assert_eq!(raw_public_key_pem, reexported_public_key_pem);

        Ok(())
    }

    fn test_api_token() -> Result<(), KeyError> {
        use crate::keys::common::{ApiToken, ApiTokenMetadata, PrivateKey, PublicKey};
        let key = EcKey::generate()?;
        let public_key = key.public_key()?;

        let claims = ApiToken::new("test".to_string(), "test".to_string());
        let token = claims.encode_to(&key)?;
        let _ = ApiToken::decode_from(&token, &public_key, None)?;
        let metadata = ApiTokenMetadata::try_from(token)?;
        let key_id = public_key.key_id()?;

        // Check the metadata
        assert_eq!(metadata.alg(), "ES384");
        assert_eq!(metadata.kid()?, key_id);
        assert_eq!(metadata.typ()?, "JWT");

        // Check the claims
        assert!(!claims.is_expired()?);
        assert!(claims.iat()? < claims.exp()?);
        assert!(claims.nbf()? < claims.exp()?);
        assert_eq!(claims.aud()?, "test");
        assert_eq!(claims.sub()?, "test");

        Ok(())
    }

    fn test_api_token_fail() -> Result<(), KeyError> {
        use crate::keys::common::{ApiToken, PrivateKey};
        let key = EcKey::generate()?;
        let bad_key = EcKey::generate()?;
        let bad_public_key = bad_key.public_key()?;

        let claims = ApiToken::new("test".to_string(), "test".to_string());
        let token = claims.encode_to(&key)?;
        let _ = ApiToken::decode_from(&token, &bad_public_key, None)?;

        Ok(())
    }

    // TODO: test verification options

    #[cfg(not(target_arch = "wasm32"))]
    mod native_tests {
        use super::*;

        #[test]
        fn signature_key_roundtripping() -> Result<(), KeyError> {
            test_signature_key_roundtripping()
        }

        #[test]
        fn api_token() -> Result<(), KeyError> {
            test_api_token()
        }

        #[test]
        #[should_panic]
        fn api_token_fail() {
            test_api_token_fail().unwrap();
        }
    }

    #[cfg(target_arch = "wasm32")]
    mod wasm_tests {
        use super::*;
        use wasm_bindgen_test::*;

        wasm_bindgen_test_configure!(run_in_browser);

        #[wasm_bindgen_test]
        fn signature_key_roundtripping() -> Result<(), KeyError> {
            test_signature_key_roundtripping()
        }

        #[wasm_bindgen_test]
        fn api_token() -> Result<(), KeyError> {
            test_api_token()
        }

        #[wasm_bindgen_test]
        #[should_panic]
        fn api_token_fail() -> Result<(), KeyError> {
            test_api_token_fail()
        }
    }
}
