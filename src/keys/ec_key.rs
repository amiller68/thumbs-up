use crate::keys::common::{PrivateKey, PublicKey, FINGERPRINT_SIZE};
use crate::keys::ec_public_key::EcPublicKey;
use crate::keys::internal::{
    export_key_bytes, export_key_pem, gen_ec_key, import_key_bytes, import_key_pem,
};
use crate::keys::KeyError;

use p384::SecretKey as P384SecretKey;

#[derive(Clone, Debug)]
pub struct EcKey(pub(crate) P384SecretKey);

impl PrivateKey for EcKey {
    type Error = KeyError;
    type PublicKey = EcPublicKey;

    fn export(&self) -> Result<Vec<u8>, KeyError> {
        export_key_pem(&self.0)
    }

    fn export_bytes(&self) -> Result<Vec<u8>, KeyError> {
        export_key_bytes(&self.0)
    }

    fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], KeyError> {
        self.public_key()?.fingerprint()
    }

    fn generate() -> Result<Self, KeyError> {
        Ok(Self(gen_ec_key()))
    }

    fn import(pem_bytes: &[u8]) -> Result<Self, KeyError> {
        Ok(Self(import_key_pem(pem_bytes)?))
    }

    fn import_bytes(der_bytes: &[u8]) -> Result<Self, KeyError> {
        Ok(Self(import_key_bytes(der_bytes)?))
    }

    fn public_key(&self) -> Result<EcPublicKey, KeyError> {
        let p384_public_key = self.0.public_key();
        Ok(EcPublicKey(p384_public_key))
    }
}
