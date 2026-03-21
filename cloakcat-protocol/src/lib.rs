//! CloakCat C2 protocol types, constants, and crypto.
//! Shared by cat-server, cat-agent, and cat-cli.

pub mod constants;
pub mod crypto;
pub mod kdf;
pub mod malleable;
pub mod paths;
pub mod profile;
pub mod types;

pub use constants::*;
pub use crypto::{sign_result, verify_result};
pub use kdf::DerivedKeys;
pub use malleable::{
    CertConfig, ClientConfig, HttpBlock, HttpHeader, MalleableProfile, ProfileMetadata,
    ServerConfig, StageConfig, TransformConfig,
};
pub use paths::*;
pub use profile::{
    profile_by_name, DefaultProfile, HealthProfile, ListenerProfile,
};
pub use types::*;
