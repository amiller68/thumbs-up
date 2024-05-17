use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::extract::FromRef;

use thumbs_up::prelude::{EcPublicKey, KeyError, PublicKey};

use super::config::Config;

#[derive(Clone, Debug)]
pub struct AllowedAudiences(pub(crate) HashSet<String>);

impl Deref for AllowedAudiences {
    type Target = HashSet<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct PublicKeyRegistry(Arc<Mutex<HashMap<String, (String, EcPublicKey)>>>);

impl PublicKeyRegistry {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, AppStateSetupError> {
        let mut map = HashMap::new();

        // Make sure the path is a directory
        let path = path.as_ref();
        if !path.is_dir() {
            return Err(AppStateSetupError::PathIsNotDirectory(path.to_path_buf()));
        }
        // Iterate through the .pem files in the directory
        // and load the public keys
        for entry in path.read_dir()? {
            let entry = entry?;
            let path = entry.path();
            let ext = path.extension();
            if ext.is_none() || ext.unwrap() != "pem" {
                continue;
            }
            let sub = path.file_stem().unwrap().to_string_lossy();

            let pem_bytes = std::fs::read(path.clone())?;
            let ec_public_key = EcPublicKey::import(&pem_bytes)?;
            let key_id = ec_public_key.key_id()?;
            map.insert(key_id, (sub.to_string(), ec_public_key));
        }

        Ok(Self(Arc::new(Mutex::new(map))))
    }

    pub fn get(&self, key_id: &str) -> Option<(String, EcPublicKey)> {
        self.0.lock().unwrap().get(key_id).cloned()
    }
}

#[derive(Clone)]
pub struct AppState {
    listen_addr: String,
    public_key_registry: PublicKeyRegistry,
    allowed_audiences: HashSet<String>,
}

impl AppState {
    pub async fn from_config(config: &Config) -> Result<Self, AppStateSetupError> {
        let listen_addr = config.listen_addr().clone();
        let public_key_registry = PublicKeyRegistry::from_path(config.pem_data_path())?;
        // Turn the vec into a set
        let allowed_audiences = config
            .allowed_audiences()
            .iter().cloned()
            .collect();
        Ok(Self {
            listen_addr,
            public_key_registry,
            allowed_audiences,
        })
    }

    pub fn listen_addr(&self) -> &str {
        &self.listen_addr
    }

    pub fn public_key_registry(&self) -> &PublicKeyRegistry {
        &self.public_key_registry
    }

    pub fn allowed_audiences(&self) -> &HashSet<String> {
        &self.allowed_audiences
    }
}

impl FromRef<AppState> for AllowedAudiences {
    fn from_ref(state: &AppState) -> Self {
        AllowedAudiences(state.allowed_audiences.clone())
    }
}

impl FromRef<AppState> for PublicKeyRegistry {
    fn from_ref(state: &AppState) -> Self {
        state.public_key_registry.clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppStateSetupError {
    #[error("key error: {0}")]
    Key(#[from] KeyError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("path is not a directory: {0}")]
    PathIsNotDirectory(PathBuf),
}
