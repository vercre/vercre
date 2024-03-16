//! # Credential App
//!
//! The Credential app module implements `crux::App` for credential management.

pub(crate) mod model;

use crux_core::macros::Effect;
#[cfg(feature = "typegen")]
use crux_core::macros::Export;
use crux_core::render::Render;
use crux_http::Http;
use serde::{Deserialize, Serialize};
#[allow(clippy::module_name_repetitions)]
pub use vercre_core::metadata::{CredentialConfiguration, CredentialDisplay};
use vercre_core::w3c::vp::Constraints;
#[allow(clippy::module_name_repetitions)]
pub use vercre_core::w3c::VerifiableCredential;

use crate::capabilities::delay::Delay;
use crate::capabilities::signer::Signer;
use crate::capabilities::store::{self, Store};
#[allow(clippy::module_name_repetitions)]
pub use crate::credential::model::{Credential, Logo};

/// App implements `crux::App` for the Credential management.
#[derive(Default)]
pub struct App;

/// Events supported by the Wallet app.
///
/// Sub-app events are delegated to the appropriate sub-app through top-level
/// wrapper events.
///
/// Events may be external (initiated by the shell), internal (initiated by
/// local processing), or both. Local events are not published
/// (`#[serde(skip)]`) to the shell.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename = "CredentialEvent")]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    // -----------------------
    // Shell-initiated actions
    // -----------------------
    /// Request from shell to list stored credentials. An optional set of
    /// constraints may be provided to filter the credentials.
    List,

    // -----------------------
    // Capability callbacks
    // -----------------------
    /// An internal event to find credentials matching a Presentation Request.
    #[serde(skip)]
    ListLocal(Option<Constraints>),

    /// An internal event to set credentials fetched in `Find` into the model.
    #[serde(skip)]
    Listed(store::Result<Vec<model::Credential>>),

    // // FIXME: box to reduce the total size of the enum: Add(Box<Credential>),
    // /// Add adds a Credential to the store.
    // #[serde(skip)]
    // Add(Credential),

    // /// Added is set after a credential has been saved to the store.
    // #[serde(skip)]
    // Added(store::Result<()>),
    /// Shell-initiated event to delete a credential. The `String` is the
    /// credential `id`.
    Delete(String),

    /// An internal event initated on completion of a `Delete` event.
    #[serde(skip)]
    Deleted(store::Result<()>),

    /// Fail is set when an error occurs.
    #[serde(skip)]
    Fail(String),
}

/// Model holds an internal representation of app state.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Model {
    filter: Option<Constraints>,
    credentials: Vec<model::Credential>,
    error: Option<String>,
}

/// The view model represents the App's 'external' state to the shell.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "CredentialView")]
pub struct ViewModel {
    pub credentials: Vec<model::Credential>,

    #[serde(skip)]
    pub error: Option<String>,
}

/// App `Capabilities` allow the app to interface with the shell and external
/// systems.
///
/// They create `effects` (technically side effects) that are handled by the
/// shell, with the manner of handling unique to a particualr shell.
#[cfg_attr(feature = "typegen", derive(Export))]
#[derive(Effect)]
#[effect(app = "App")]
pub struct Capabilities {
    /// The Render capability allows the app to request a re-render of the UI.
    pub render: Render<Event>,

    /// The Http capability allows the app to make HTTP requests.
    pub http: Http<Event>,

    /// The Store capability allows the app to store and retrieve credentials.
    pub store: Store<Event>,

    /// The Signer capability allows the app to sign and verify messages.
    pub signer: Signer<Event>,

    /// The Delay capability allows the app to delay processing.
    pub delay: Delay<Event>,
}

impl crux_core::App for App {
    type Capabilities = Capabilities;
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;

    // Called in response to an event, usually by the shell but can also be in
    // response to a capability executing, or an internal processing step.
    fn update(&self, event: Self::Event, model: &mut Self::Model, caps: &Self::Capabilities) {
        match event {
            Event::List => {
                caps.store.list(None, Event::Listed);
                model.filter = None;
            }
            Event::ListLocal(filter) => {
                caps.store.list(filter.clone(), Event::Listed);
                model.filter = filter;
            }
            Event::Listed(Ok(response)) => {
                model.credentials = response;
            }
            Event::Delete(id) => {
                caps.store.delete(&id, Event::Deleted);
            }
            Event::Deleted(Ok(())) => {
                // re-query stored credentials
                self.update(Event::List, model, caps);
            }

            // ----------------------------------------------------------------
            // Error handling
            // ----------------------------------------------------------------
            Event::Listed(Err(e)) => {
                let msg = format!("Issue retrieving credentials: {e:?}");
                self.update(Event::Fail(msg), model, caps);
            }
            Event::Deleted(Err(e)) => {
                let msg = format!("Issue deleting credential: {e:?}");
                self.update(Event::Fail(msg), model, caps);
            }
            Event::Fail(msg) => {
                log::error!("{}", msg);
                model.error = Some(msg);
            }
        }

        caps.render.render();
    }

    // `view` is called by the shell to render the current state of the app.
    // Typically, this is invoked by the `render()` method of the Render
    // capability.
    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        ViewModel {
            credentials: model.credentials.clone(),
            error: model.error.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use crux_core::testing::AppTester;

    // use insta::{assert_yaml_snapshot, internals::Redaction};
    use super::*;
    use crate::capabilities::store::{StoreEntry, StoreResponse};

    /// Test that a `Event::List(filter)` event causes the app to fetch the
    /// credentials specified in the query.
    #[tokio::test]
    async fn find() {
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        let mut update = app.update(Event::List, &mut model);

        // make real metadata request
        assert_let!(Effect::Store(request), &mut update.effects[0]);
        assert_eq!(request.operation, store::StoreRequest::List);

        let credentials = Vec::<Credential>::new();
        let values: Vec<StoreEntry> = credentials
            .iter()
            .map(|c| StoreEntry::from(serde_json::to_vec(c).expect("should serialize")))
            .collect();
        let response = StoreResponse::List(values.clone());

        let update = app.resolve(request, response).expect("should resolve");
        assert_eq!(update.events[0], Event::Listed(Ok(credentials.clone())));
    }
}
