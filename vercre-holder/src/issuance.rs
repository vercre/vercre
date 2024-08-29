//! # Issuance
//!
//! The Issuance endpoints implement the vercre-holder's credential issuance flow.

pub mod accept;
pub mod credential;
pub mod offer;
pub mod pin;

use std::collections::HashMap;
use std::fmt::Debug;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vercre_openid::issuer::{CredentialConfiguration, CredentialOffer, TokenResponse};

use crate::provider::{HolderProvider, StateStore};

/// `Issuance` represents app state across the steps of the issuance flow.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Issuance {
    /// The unique identifier for the issuance flow. Not used internally but passed to providers
    /// so that wallet clients can track interactions with specific flows.
    pub id: String,

    /// Client ID of the holder's agent (eg. wallet)
    pub client_id: String,

    /// The current status of the issuance flow.
    pub status: Status,

    /// The `CredentialOffer` received from the issuer.
    pub offer: CredentialOffer,

    /// A list of `CredentialConfiguration`s, one for each credential offered.
    pub offered: HashMap<String, CredentialConfiguration>,

    /// The user's pin, as set from the shell.
    pub pin: Option<String>,

    /// The `TokenResponse` received from the issuer.
    pub token: TokenResponse,
}

/// Issuance Status values.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "IssuanceStatus")]
pub enum Status {
    /// No credential offer is being processed.
    #[default]
    Inactive,

    /// A new credential offer has been received.
    Offered,

    /// Metadata has been retrieved and the offer is ready to be viewed.
    Ready,

    /// The offer requires a user pin to progress.
    PendingPin,

    /// The offer has been accepted and the credential is being issued.
    Accepted,

    /// A credential has been requested.
    Requested,

    /// The credential offer has failed, with an error message.
    Failed(String),
}

/// Get and put issuance state information using the supplied provider.
async fn get_issuance(provider: impl HolderProvider, id: &str) -> anyhow::Result<Issuance> {
    StateStore::get(&provider, id).await
}

async fn put_issuance(provider: impl HolderProvider, issuance: &Issuance) -> anyhow::Result<()> {
    StateStore::put(
        &provider,
        &issuance.id,
       &issuance,
        DateTime::<Utc>::MAX_UTC,
    )
    .await
}
