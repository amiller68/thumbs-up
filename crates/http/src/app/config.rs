use std::env;
use std::path::PathBuf;
use std::str::FromStr;

use dotenvy::dotenv;

#[derive(Debug)]
pub struct Config {
    // Listen Address
    listen_address: String,
    // Database URL
    listen_port: u16,

    // Path to pems directory
    pem_data_path: PathBuf,
    // Logging Level
    log_level: tracing::Level,
}

impl Config {
    pub fn from_env() -> Result<Config, ConfigError> {
        if dotenv().is_err() {
            tracing::warn!("No .env file found");
        }

        let listen_address = match env::var("LISTEN_ADDRESS") {
            Ok(address) => address,
            Err(_e) => {
                tracing::warn!("No LISTEN_ADDRESS found in .env. Using default");
                "127.0.0.1".to_string()
            }
        };
        let listen_port = match env::var("LISTEN_PORT") {
            Ok(port) => port.parse::<u16>().expect("Invalid LISTEN_PORT in .env"),
            Err(_e) => {
                tracing::warn!("No LISTEN_PORT found in .env. Using default");
                3001
            }
        };

        let pem_data_path_str = match env::var("PEM_DATA_PATH") {
            Ok(path) => path,
            Err(_e) => {
                tracing::warn!("No PEM_DATA_PATH found in .env. Using default");
                "pems".to_string()
            }
        };
        let pem_data_path = PathBuf::from(pem_data_path_str);

        let log_level_str = match env::var("LOG_LEVEL") {
            Ok(level) => level,
            Err(_e) => {
                tracing::warn!("No LOG_LEVEL found in .env. Using default");
                "info".to_string()
            }
        };
        let log_level = match tracing::Level::from_str(&log_level_str) {
            Ok(level) => level,
            Err(_e) => {
                tracing::warn!("Invalid LOG_LEVEL found in .env. Using default");
                tracing::Level::INFO
            }
        };

        Ok(Config {
            listen_address,
            listen_port,
            pem_data_path,
            log_level,
        })
    }

    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.listen_address, self.listen_port)
    }

    pub fn pem_data_path(&self) -> &PathBuf {
        &self.pem_data_path
    }

    pub fn log_level(&self) -> &tracing::Level {
        &self.log_level
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing Env: {0}")]
    InvalidEnv(#[from] env::VarError),
}
