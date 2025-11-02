// XMSS wrapper module providing ergonomic API over hash-sig library
//
// This module provides a clean abstraction over the hash-sig XMSS library,
// handling message preprocessing, epoch validation, and type conversion
// between hash-sig types and xmss-types.

pub mod error;
pub mod message;
pub mod epoch;
pub mod conversions;
pub mod config;
pub mod wrapper;

#[cfg(test)]
pub mod test_utils;

// Re-exports will be added as types are implemented
// pub use error::WrapperError;
// pub use message::MessagePreprocessor;
// pub use epoch::EpochValidator;
// pub use conversions::TypeConverter;
// pub use config::{ParameterSet, ParameterMetadata};
// pub use wrapper::{XmssWrapper, WrappedPublicKey, WrappedSecretKey, WrappedSignature};
