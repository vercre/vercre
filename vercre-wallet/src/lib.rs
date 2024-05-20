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
//! Similar to the `vercre-vci` and `vercre-vp` crates, the library is architected around the
//! [OpenID4VCI] endpoints, each with its own `XxxRequest` and `XxxResponse` types. The types
//! serialize to and from JSON, in accordance with the specification.
//! 
//! The endpoints are designed to be used with Rust-based HTTP servers but are not specifically tied
//! to any particular protocol.
//! 
//! ** Provider **
//! 
//! Implementors need to implement 'Provider' traits that are responsible for handling storage and
//! signing. See [`vercre-core`](https://docs.rs/vercre-core/latest/vercre_core/).
//! 
//! # Example
//! 
//! The following example demonstrates how a single endpoint might be surfaced. See the `examples`
//! directory for more complete examples.
//! 
//! ```rust,ignore
//! #[tokio::main]
//! async fn main() {
//!    // `Provider` implements the `Provider` traits
//!   let endpoint = Arc::new(Endpoint::new(Provider::new()));
//! 
//!   let router = Router::new()
//!     // --- other routes ---
//!     .route("/offer", post(credential))
//!     // --- other routes ---
//!    .with_state(endpoint);
//! 
//!   let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
//!   axum::serve(listener, router).await.expect("server should run");
//! }
//! 
//! // Offer endpoint
//! async fn offer(
//!     State(endpoint): State<Arc<Endpoint<Provider>>>, TypedHeader(host): TypedHeader<Host>,
//!     Json(mut req): Json<OfferRequest>,
//! ) -> AxResult<OfferResponse> {
//!    TODO: this
//! }
// TODO: implement server metatdata endpoint
// TODO: implement client registration/ client metadata endpoints

// TODO: support [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)(https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
//        - add Token endpoint
//        - add Metadata endpoint
//        - add Registration endpoint

pub mod offer;

pub use std::fmt::Debug;

pub use vercre_core::provider::{Callback, Signer, StateManager, Storer};

/// Endpoint is used to surface the public wallet endpoints to clients.
#[derive(Debug)]
pub struct Endpoint<P>
where
    P: Callback + Signer + StateManager + Storer + Clone + Debug,
{
    provider: P,
}

/// Endpoint is used to provide a thread-safe way of handling requests. Each request passes through
/// a number of steps which require state to be maintained between steps.
/// 
/// The Endpoint also provides common top-level tracing, error-handling and client callback
/// functionality for all endpoints. The act of setting a request causes the Endpoint to select the
/// endpoint implementation of `Endpoint::call` specific to the request.
impl<P> Endpoint<P>
where
    P: Callback + Signer + StateManager + Storer + Clone + Debug,
{
    /// Create a new `Endpoint` with the provided `Provider`.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> vercre_core::Endpoint for Endpoint<P>
where
    P: Callback + Signer + StateManager + Storer + Clone + Debug,
{
    type Provider = P;

    fn provider(&self) -> &P {
        &self.provider
    }
}
