//! # Presentation
//!
//! The Presentation endpoints implement the vercre-holder's credential
//! presentation flow.

pub(crate) mod authorize;
pub(crate) mod present;
pub(crate) mod request;

use std::fmt::{Debug, Display};
use std::str::FromStr;

use anyhow::anyhow;
pub use authorize::authorize;
use chrono::{DateTime, Utc};
pub use present::present;
pub use request::request;
use serde::{Deserialize, Serialize};
use vercre_dif_exch::{Constraints, PresentationSubmission};
use vercre_openid::verifier::RequestObject;

use crate::credential::Credential;
use crate::provider::{HolderProvider, StateStore};

/// `Presentation` maintains app state across steps of the presentation flow.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Presentation {
    /// The unique identifier for the presentation flow. Not used internally but
    /// passed to providers so that wallet clients can track interactions
    /// with specific flows.
    pub id: String,

    /// The current status of the presentation flow.
    pub status: Status,

    /// The request object received from the verifier.
    pub request: RequestObject,

    /// The list of credentials matching the verifier's request (Presentation
    /// Definition).
    pub credentials: Vec<Credential>,

    /// The `JSONPath` query used to match credentials to the verifier's
    /// request.
    pub filter: Constraints,

    /// The presentation submission token.
    pub submission: PresentationSubmission,
}

/// Presentation Status values.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "PresentationStatus")]
pub enum Status {
    /// No authorization request is being processed.
    #[default]
    Inactive,

    /// A new authorization request has been received.
    Requested,

    /// The authorization request has been authorized.
    Authorized,

    /// The authorization request has failed, with an error message.
    Failed(String),
}

/// Get a string representation of the `Status`.
impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inactive => write!(f, "Inactive"),
            Self::Requested => write!(f, "Requested"),
            Self::Authorized => write!(f, "Authorized"),
            Self::Failed(e) => write!(f, "Failed: {e}"),
        }
    }
}

/// Parse a `Status` from a string.
impl FromStr for Status {
    // TODO: strongly typed error
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        if s.starts_with("Failed") {
            return Ok(Self::Failed(s[8..].to_string()));
        }
        match s {
            "Inactive" => Ok(Self::Inactive),
            "Requested" => Ok(Self::Requested),
            "Authorized" => Ok(Self::Authorized),
            _ => Err(anyhow!("Invalid status: {s}")),
        }
    }
}

/// Get and put presentation state information using the supplied provider.
async fn get_presentation(provider: impl HolderProvider, id: &str) -> anyhow::Result<Presentation> {
    StateStore::get(&provider, id).await
}

async fn put_presentation(
    provider: impl HolderProvider, presentation: &Presentation,
) -> anyhow::Result<()> {
    StateStore::put(&provider, &presentation.id, &presentation, DateTime::<Utc>::MAX_UTC).await?;
    Ok(())
}
