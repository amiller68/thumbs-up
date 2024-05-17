use crate::keys::common::{PublicKey, FINGERPRINT_SIZE};
use crate::keys::internal::{
    export_public_key_bytes, export_public_key_pem, fingerprint, import_public_key_bytes,
    import_public_key_pem,
};
use crate::keys::KeyError;

use p384::PublicKey as P384PublicKey;

#[derive(Clone, Debug)]
pub struct EcPublicKey(pub(crate) P384PublicKey);

impl PublicKey for EcPublicKey {
    type Error = KeyError;

    fn export(&self) -> Result<Vec<u8>, KeyError> {
        export_public_key_pem(&self.0)
    }

    fn export_bytes(&self) -> Result<Vec<u8>, KeyError> {
        export_public_key_bytes(&self.0)
    }

    fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], KeyError> {
        Ok(fingerprint(&self.0))
    }

    fn import(pem_bytes: &[u8]) -> Result<Self, KeyError> {
        Ok(Self(import_public_key_pem(pem_bytes)?))
    }
    fn import_bytes(der_bytes: &[u8]) -> Result<Self, KeyError> {
        Ok(Self(import_public_key_bytes(der_bytes)?))
    }
}
