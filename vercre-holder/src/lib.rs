#![allow(clippy::missing_const_for_fn)]
#![feature(let_chains)]

//! # `OpenID` Wallet
//!
//! A vercre-wallet that supports `OpenID` for Verifiable Credential Issuance and Presentation.
//!
//! The crate does not provide a user or service interface - that is the job of a wallet
//! implementation. See examples for simple (not full-featured) implementations.
//!
//! # Design
//!
//! ** Endpoints **
//!
//! Similar to the `vercre-issuer` and `vercre-verifier` crates, the library is architected around the
//! endpoints. The request and response types serialize to and from JSON, and where interaction with
//! `OpenID4VC` occurs those types are used in accordance with the specification.
//!
//! The endpoints are designed to be used with Rust-based HTTP servers but are not specifically tied
//! to any particular protocol.
//!
//! ** Provider **
//!
//! Implementors need to implement 'Provider' traits that are responsible for handling storage and
//! signing. See [`core-utils`](https://docs.rs/core-utils/latest/core_utils/) for core provider
//! traits, and the `provider` module in this crate for traits specific to holder agents.
//!
//! # Example
//!
//! See the `examples` directory for more complete examples.
// TODO: implement client registration/ client metadata endpoints

// TODO: support [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)(https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
//        - add Token endpoint
//        - add Metadata endpoint
//        - add Registration endpoint

pub mod credential;
mod issuance;
pub mod presentation;
pub mod provider;

pub use issuance::accept::accept;
pub use issuance::credential::get_credentials;
pub use issuance::offer::offer;
pub use issuance::pin::pin;
pub use presentation::authorize::authorize;
pub use presentation::present::present;
pub use presentation::request::request;
pub use vercre_core_utils::Quota;
pub use vercre_dif_exch::Constraints;
pub use vercre_openid::issuer::{
    CredentialConfiguration, CredentialOffer, CredentialRequest, CredentialResponse, GrantType,
    Issuer, MetadataRequest, MetadataResponse, Proof, ProofClaims, TokenRequest, TokenResponse,
    TxCode,
};
pub use vercre_openid::verifier::{
    RequestObject, RequestObjectRequest, RequestObjectResponse, ResponseRequest, ResponseResponse,
};

// pub use issuance::Issuance;
pub use crate::credential::{Credential, Logo};
pub use crate::issuance::offer::OfferRequest;
pub use crate::issuance::pin::PinRequest;
pub use crate::issuance::{Issuance, Status};
pub use crate::presentation::Presentation;
