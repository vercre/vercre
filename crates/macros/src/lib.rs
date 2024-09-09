//! # Core Utilities for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.

mod create_offer;
mod authorization;
mod parse;

use parse::Data;
use proc_macro::TokenStream;
use syn::{parse_macro_input, Error};

/// Generate a `CreateOfferRequest` using a JSON-like format.
///
/// # Example
///
/// ```rust
/// const CREDENTIAL_ISSUER: &str = "http://vercre.io";
/// let subject_id = "normal_user";
///
/// let request = create_offer_request!({
///     "credential_issuer": CREDENTIAL_ISSUER,
///     "credential_configuration_ids": ["EmployeeID_JWT"],
///     "subject_id": subject_id,
///     "pre-authorize": true,
///     "tx_code_required": true,
///     "send_type": SendType::ByVal
/// });
///
/// assert_eq!(request.credential_issuer, CREDENTIAL_ISSUER);
/// ```
#[proc_macro]
pub fn create_offer_request(input: TokenStream) -> TokenStream {
    create_offer::request(&parse_macro_input!(input as Data))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Generate an `AuthorizationRequest` using a JSON-like format.
///
/// # Example
///
/// ```rust
/// const CREDENTIAL_ISSUER: &str = "http://vercre.io";
/// let subject_id = "normal_user";
///
/// let request = authorization_request!({
///     "credential_issuer": CREDENTIAL_ISSUER,
///     "credential_configuration_ids": ["EmployeeID_JWT"],
///     "subject_id": subject_id,
///     "pre-authorize": true,
///     "tx_code_required": true,
///     "send_type": SendType::ByVal
/// });
///
/// assert_eq!(request.credential_issuer, CREDENTIAL_ISSUER);
/// ```
#[proc_macro]
pub fn authorization_request(input: TokenStream) -> TokenStream {
    authorization::request(&parse_macro_input!(input as Data))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
