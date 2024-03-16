//! # Verifiable Credential Store

use crux_core::capability::{CapabilityContext, Operation};
use crux_core::macros::Capability;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vercre_core::w3c::vp::Constraints;

use crate::credential::Credential;

/// Errors that can be returned by the Store capability.
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq)]
pub enum Error {
    /// The request was invalid.
    #[error("invalid store request {0}")]
    InvalidRequest(String),
    /// The capability response was invalid.
    #[error("invalid store response {0}")]
    InvalidResponse(String),
}

// manually implement serde::Serialize
impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

/// Result type for the Store capability.
pub type Result<T> = std::result::Result<T, Error>;

/// Operations supported (by the Store capability).
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub enum StoreRequest {
    /// Add a credential to the store
    Add(String, Vec<u8>),

    /// List credentials in the store
    List,

    /// Delete a credential from the store
    Delete(String),
}

/// A store entry. A serialized credential.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub struct StoreEntry(pub Vec<u8>);

/// Convert a Vec<u8> to a `StoreEntry`
impl From<Vec<u8>> for StoreEntry {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Convert a `StoreEntry` to a Vec<u8>
impl From<StoreEntry> for Vec<u8> {
    fn from(val: StoreEntry) -> Self {
        val.0
    }
}

/// `StoreResponse` represents the output expected from any implementer of the
/// Store capability.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub enum StoreResponse {
    /// The store operation returned without error and, optionally, one or more
    /// credentials.
    Ok,

    /// The store operation returned a list of credentials.
    List(Vec<StoreEntry>),

    // The store operation returned with the specified error.
    Err(String),
}

/// `Operation` provides a Crux wrapper for the `StoreRequest` consumed by the
/// Shell.
///
/// The Output type allows us to specify the expected response type from the
/// Shell.
impl Operation for StoreRequest {
    type Output = StoreResponse;
}

/// The Store type used to implement the capability.
#[derive(Capability)]
pub struct Store<Ev> {
    context: CapabilityContext<StoreRequest, Ev>,
}

impl<Ev> Store<Ev>
where
    Ev: 'static,
{
    /// Create a new Store capability context.
    #[must_use]
    pub const fn new(context: CapabilityContext<StoreRequest, Ev>) -> Self {
        Self { context }
    }

    /// Add a credential to the store.
    /// Typically the bytes would be a value serialized/deserialized by the app.
    ///
    /// Dispatches the App 'callback' event specified when the capability was
    /// requested.
    pub fn add<F>(&self, credential: Credential, make_event: F)
    where
        F: Fn(Result<()>) -> Ev + Send + Sync + 'static,
    {
        self.context.spawn({
            let ctx = self.context.clone();

            let Ok(ser) = serde_json::to_vec(&credential) else {
                return ctx.update_app(make_event(Err(Error::InvalidRequest(String::from(
                    "error serializing credential",
                )))));
            };

            async move {
                let request = StoreRequest::Add(credential.id, ser);

                match ctx.request_from_shell(request).await {
                    StoreResponse::Ok => ctx.update_app(make_event(Ok(()))),
                    StoreResponse::Err(err) => {
                        ctx.update_app(make_event(Err(Error::InvalidRequest(err))));
                    }
                    StoreResponse::List(_) => {
                        ctx.update_app(make_event(Err(Error::InvalidRequest(String::from(
                            "unexpected response from store",
                        )))));
                    }
                }
            }
        });
    }

    /// Query credentials matching the provided `JSONPath` expression.
    pub fn list<F>(&self, filter: Option<Constraints>, make_event: F)
    where
        F: Fn(Result<Vec<Credential>>) -> Ev + Send + Sync + 'static,
    {
        self.context.spawn({
            let ctx = self.context.clone();

            async move {
                let request = StoreRequest::List;

                match ctx.request_from_shell(request).await {
                    // all credentials stored by the shell
                    StoreResponse::List(entries) => {
                        let list: Result<Vec<Credential>> = entries
                            .iter()
                            .map(|entry| match serde_json::from_slice(&entry.0) {
                                Ok(credential) => Ok(credential),
                                Err(e) => Err(Error::InvalidResponse(format!(
                                    "error deserializing list: {e}"
                                ))),
                            })
                            .collect();
                        let list = match list {
                            Ok(list) => list,
                            Err(e) => {
                                #[cfg(feature = "wasm")]
                                web_sys::console::error_2(
                                    &"store capability list error:".into(),
                                    &e.to_string().into(),
                                );
                                return ctx.update_app(make_event(Err(e)));
                            }
                        };

                        // if no filter, return all credentials
                        let Some(constraints) = filter else {
                            return ctx.update_app(make_event(Ok(list)));
                        };

                        // otherwise, filter credentials
                        let mut matched: Vec<Credential> = vec![];

                        for credential in &list {
                            match constraints.satisfied(&credential.vc) {
                                Ok(true) => matched.push(credential.clone()),
                                Ok(false) => continue,
                                Err(e) => {
                                    return ctx.update_app(make_event(Err(Error::InvalidRequest(
                                        format!("error matching credentials: {e}"),
                                    ))));
                                }
                            }
                        }

                        ctx.update_app(make_event(Ok(matched)));
                    }
                    // error retrieving credentials
                    StoreResponse::Err(err) => {
                        ctx.update_app(make_event(Err(Error::InvalidRequest(err))));
                    }
                    // we should never get here
                    StoreResponse::Ok => {
                        ctx.update_app(make_event(Err(Error::InvalidRequest(String::from(
                            "unexpected response from store",
                        )))));
                    }
                }
            }
        });
    }

    /// Delete the credential specified by `id` from the store.
    pub fn delete<F>(&self, id: &str, make_event: F)
    where
        F: Fn(Result<()>) -> Ev + Send + Sync + 'static,
    {
        self.context.spawn({
            let ctx = self.context.clone();
            let id = id.to_string();

            async move {
                let request = StoreRequest::Delete(id);

                match ctx.request_from_shell(request).await {
                    StoreResponse::Ok => ctx.update_app(make_event(Ok(()))),
                    StoreResponse::Err(err) => {
                        ctx.update_app(make_event(Err(Error::InvalidRequest(err))));
                    }
                    StoreResponse::List(_) => {
                        ctx.update_app(make_event(Err(Error::InvalidRequest(String::from(
                            "unexpected response from store",
                        )))));
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_entry_serde() {
        // Simulate a credential stored in the store
        let cred = Credential::sample();
        let ser = serde_json::to_vec(&cred).unwrap();
        let entry = StoreEntry::from(ser);
        let entries = vec![entry.clone()];

        // Simulate getting the credential from the store
        let creds = entries
            .iter()
            .map(|entry| match serde_json::from_slice(&entry.0) {
                Ok(credential) => Ok(credential),
                Err(e) => Err(Error::InvalidResponse(format!("error deserializing list: {e}"))),
            })
            .collect::<Result<Vec<Credential>>>();
        let creds = creds.unwrap();
        assert_eq!(creds[0].id, cred.id);
        assert_eq!(creds[0].issued, cred.issued);
    }
}
