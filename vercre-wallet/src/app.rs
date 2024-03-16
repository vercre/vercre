//! # Wallet App
//!
//! The Wallet app module is the top level implementation for `crux::App`.

use crux_core::macros::Effect;
#[cfg(feature = "typegen")]
use crux_core::macros::Export;
use crux_core::render::Render;
use crux_core::Capability;
use crux_http::Http;
use serde::{Deserialize, Serialize};

use crate::capabilities::delay::Delay;
use crate::capabilities::signer::Signer;
use crate::capabilities::store::Store;
use crate::{credential, issuance, presentation};

/// App is the main entry point for the Wallet 'backend'.
///
/// By implementing `crux::App` it provides core functionality in an
/// event-driven manner. Sets of events are delegated to sub-apps (issuance and
/// presentation) and for managing Wallet interactions.
#[derive(Default)]
pub struct App {
    credential: credential::App,
    issuance: issuance::App,
    presentation: presentation::App,
}

/// Events supported by the Wallet app.
///
/// Sub-app events are delegated to the appropriate sub-app through top-level
/// wrapper events.
///
/// Events may be external (initiated by the shell), internal (initiated by
/// local processing), or both. Local events are not published
/// (`#[serde(skip)]`) to the shell.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    // FIXME: box to reduce the total size of the enum: Credential(Box<credential::Event>),
    /// Delegates the nested event to the presentation sub-app.
    Credential(credential::Event),

    /// Delegates the nested event to the issuance sub-app.
    Issuance(issuance::Event),

    /// Delegates the nested event to the presentation sub-app.
    Presentation(presentation::Event),

    /// Shell-initiated event to cancel an in-process flow such as issuance or
    /// presentation.
    Cancel,

    /// Used to display a splash screen on normal application start.
    Start,

    /// Used to close a splash screen after application has started.
    Started,
}

/// Model holds an internal representation of app state.
#[derive(Debug, Default)]
pub struct Model {
    starting: bool,
    credential: credential::Model,
    issuance: issuance::Model,
    presentation: presentation::Model,
    error: Option<String>,
}

/// Explicit views for the app. This is a convenience so each shell does not need to repeat code to
/// infer the view from state.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum View {
    // #[default]
    Credential,
    Issuance,
    Presentation,
    Splash,
}

/// The view model represents the App's 'external' state to the shell.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct ViewModel {
    pub credential: credential::ViewModel,
    pub issuance: issuance::ViewModel,
    pub presentation: presentation::ViewModel,
    pub error: Option<String>,
    pub view: View,
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

// Use credential::App as a sub-app
impl From<&Capabilities> for credential::Capabilities {
    fn from(incoming: &Capabilities) -> Self {
        Self {
            render: incoming.render.map_event(Event::Credential),
            http: incoming.http.map_event(Event::Credential),
            store: incoming.store.map_event(Event::Credential),
            signer: incoming.signer.map_event(Event::Credential),
            delay: incoming.delay.map_event(Event::Credential),
        }
    }
}

// Use issuance::App as a sub-app
impl From<&Capabilities> for issuance::Capabilities {
    fn from(incoming: &Capabilities) -> Self {
        Self {
            render: incoming.render.map_event(Event::Issuance),
            http: incoming.http.map_event(Event::Issuance),
            store: incoming.store.map_event(Event::Issuance),
            signer: incoming.signer.map_event(Event::Issuance),
            delay: incoming.delay.map_event(Event::Issuance),
        }
    }
}

// Use presentation::App as a sub-app
impl From<&Capabilities> for presentation::Capabilities {
    fn from(incoming: &Capabilities) -> Self {
        Self {
            render: incoming.render.map_event(Event::Presentation),
            http: incoming.http.map_event(Event::Presentation),
            store: incoming.store.map_event(Event::Presentation),
            signer: incoming.signer.map_event(Event::Presentation),
            delay: incoming.delay.map_event(Event::Presentation),
        }
    }
}

impl crux_core::App for App {
    type Capabilities = Capabilities;
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;

    // Top-level app event processing, called in response to shell-initiated events.
    fn update(&self, event: Self::Event, model: &mut Self::Model, caps: &Self::Capabilities) {
        match event {
            Event::Credential(ev) => {
                // delegate to credential sub-app
                self.credential.update(ev, &mut model.credential, &caps.into());
            }
            Event::Issuance(ev) => {
                // delegate to issuance sub-app
                self.issuance.update(ev, &mut model.issuance, &caps.into());
            }
            Event::Presentation(ev) => {
                // delegate to presentation sub-app
                self.presentation.update(ev, &mut model.presentation, &caps.into());
            }
            Event::Cancel => {
                model.issuance.reset();
                model.presentation.reset();
            }
            Event::Start => {
                model.starting = false;
                if (model.issuance.status == issuance::Status::Inactive)
                    && (model.presentation.status == presentation::Status::Inactive)
                {
                    model.starting = true;
                    caps.delay.start(3000, Event::Started);
                }
            }
            Event::Started => {
                model.starting = false;
            }
        }

        caps.render.render();
    }

    // `view` is called by the shell to render the current state of the app.
    // Typically, this is invoked by the `render()` method of the Render
    // capability. Default to the credential view and try to infer the view from the various
    // sub-app states.
    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        let mut vm = ViewModel {
            credential: credential::App::view(&self.credential, &model.credential),
            issuance: issuance::App::view(&self.issuance, &model.issuance),
            presentation: presentation::App::view(&self.presentation, &model.presentation),
            error: model.error.clone(),
            view: View::Credential,
        };
        if model.starting {
            vm.view = View::Splash;
        } else if model.issuance.status != issuance::Status::Inactive {
            vm.view = View::Issuance;
        } else if model.presentation.status != presentation::Status::Inactive {
            vm.view = View::Presentation;
        }
        #[cfg(feature = "wasm")]
        web_sys::console::debug_2(&"app view".into(), &format!("{vm:?}").into());
        vm
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use crux_core::testing::AppTester;

    // use insta::{assert_yaml_snapshot, internals::Redaction};
    use super::*;
    use crate::capabilities::delay::DelayOperation;
    use crate::capabilities::store::{self, StoreResponse};
    use crate::credential::Credential;
    use crate::store::StoreEntry;

    /// Test that a `credential::Event::Find` event causes the app to fetch
    /// credentials specified in the query.
    #[tokio::test]
    async fn credentials_list() {
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // initiate credential Event::List event
        let ev = Event::Credential(credential::Event::List);
        let mut update = app.update(ev, &mut model);

        // make real credential request
        assert_let!(Effect::Store(request), &mut update.effects[0]);
        assert_eq!(request.operation, store::StoreRequest::List);

        let credential = Credential::default();
        let value = serde_json::to_vec(&credential).expect("should serialize");
        let credentials = vec![StoreEntry(value)];
        let response = StoreResponse::List(credentials.clone());

        // resolving request should trigger credential Event::Listed event
        let credentials_as_vec = vec![credential];
        let update = app.resolve(request, response).expect("should resolve");
        assert_eq!(
            update.events[0],
            Event::Credential(credential::Event::Listed(Ok(credentials_as_vec.clone())))
        );
    }

    /// Test a `app::Event::Start` event causes the app to request a `Splash` render.
    #[tokio::test]
    async fn app_start() {
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // initiate app Event::Start event
        let ev = Event::Start;
        let mut requests = app.update(ev, &mut model).into_effects().filter_map(Effect::into_delay);
        assert!(model.starting);

        let vm = app.view(&model);
        assert_eq!(vm.view, View::Splash);

        let mut request = requests.next().expect("should have request");
        assert_let!(DelayOperation { delay_ms: 3000 }, request.operation.clone());
        assert!(requests.next().is_none());

        let update = app.resolve(&mut request, ()).expect("should resolve");
        assert_eq!(update.events[0], Event::Started);
        for event in update.events {
            app.update(event, &mut model);
        }

        let vm = app.view(&model);
        assert_eq!(vm.view, View::Credential);
    }
}
