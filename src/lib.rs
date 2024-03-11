mod keys;

pub use crate::keys::hex_fingerprint;
pub use crate::keys::pretty_fingerprint;

pub mod prelude {
    pub use crate::keys::common::*;
    pub use crate::keys::{EcKey, EcPublicKey, KeyError};
}
