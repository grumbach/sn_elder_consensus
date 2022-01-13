// #![deny(missing_docs)]
#[cfg(any(
    all(feature = "ed25519", feature = "blsttc"),
    all(feature = "bad_crypto", feature = "ed25519"),
    all(feature = "bad_crypto", feature = "blsttc"),
    not(any(feature = "ed25519", feature = "blsttc", feature = "bad_crypto"))
))]
compile_error!("Must enable either `ed25519`, `blsttc` or `bad_crypto` feature flags");

pub mod handover;
pub(crate) mod proposal;
pub(crate) mod vote;

#[cfg(feature = "bad_crypto")]
pub mod bad_crypto;
#[cfg(feature = "blsttc")]
pub mod blsttc;
#[cfg(feature = "ed25519")]
pub mod ed25519;

pub use crate::handover::HandoverState;
pub use crate::vote::{Ballot, Generation, SignedVote, Vote, VoteMsg};

#[cfg(feature = "bad_crypto")]
pub use crate::bad_crypto::{PublicKey, SecretKey, Signature};
#[cfg(feature = "blsttc")]
pub use crate::blsttc::{PublicKey, SecretKey, Signature};
#[cfg(feature = "ed25519")]
pub use crate::ed25519::{PublicKey, SecretKey, Signature};

pub mod error;
pub use crate::error::Error;
pub type Result<T> = std::result::Result<T, Error>;
