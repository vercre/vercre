//! # Issuance App
//!
//! The Issuance app implements the vercre-wallet's credential issuance flow.

pub(crate) mod model;

use std::collections::HashMap;

use crux_core::macros::Effect;
#[cfg(feature = "typegen")]
use crux_core::macros::Export;
use crux_core::render::Render;
use crux_http::Http;
pub use model::{Model, Status};
use serde::{Deserialize, Serialize};
use vercre_core::metadata::CredentialConfiguration;
use vercre_core::vci::{CredentialResponse, MetadataResponse, TokenResponse};

use crate::capabilities::delay::Delay;
use crate::capabilities::signer::{self, Signer};
use crate::capabilities::store::{self, Store};
use crate::credential;

/// App implements `crux::App` for the Issuance flow.
#[derive(Default)]
pub struct App;

/// Issuance events drive the issuance process.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename = "IssuanceEvent")]
pub enum Event {
    // -----------------------
    // Shell-initiated actions
    // -----------------------
    /// Offer is set from the shell on receipt of a new Credential Offer.
    Offer(String),

    // TODO: is an offer and 'all or nothing' thing or can the user select
    // which credentials to accept?
    /// Accept is set when the user has accepted selected credentials for issuance.
    Accept,

    /// Set from the shell when the user has entered their pin.
    Pin(String),

    // -----------------------
    // Capability callbacks
    // -----------------------
    /// Callback from the Http capability with the Issuer's response to a
    /// request for credential metadata.
    #[serde(skip)]
    Metadata(crux_http::Result<crux_http::Response<MetadataResponse>>),

    /// Initiate the process of requesting an access token from the issuer.
    #[serde(skip)]
    GetToken,

    /// Callback from the Http capability with the Issuer's response to a
    /// request for an access token.
    #[serde(skip)]
    Token(crux_http::Result<crux_http::Response<TokenResponse>>),

    /// Callback from the Signer capability with proof method and key id used
    /// in signing.
    #[serde(skip)]
    Proof(signer::Result<(String, String)>),

    /// Callback from the Signer capability with a signed `vp_token`.
    #[serde(skip)]
    Signed(signer::Result<String>),

    /// `CredentialReceived` receives the results of the credential request. Will send
    /// a `GetLogo` event if the credential information includes a logo, or will
    /// send an `SaveCredential` event if no logo is present to store the credential.
    #[serde(skip)]
    Credential(crux_http::Result<crux_http::Response<CredentialResponse>>),

    /// Callback from the Http capability on receipt of a logo (or error).
    #[serde(skip)]
    Logo(credential::Credential, crux_http::Result<crux_http::Response<Vec<u8>>>),

    // SaveCredential adds the supplied credential to the model.
    #[serde(skip)]
    SaveCredential(credential::Credential),

    /// Callback from the Store capability with the result of a request to add a
    /// Credential.
    #[serde(skip)]
    CredentialSaved(store::Result<()>),

    /// Fail is set when an error occurs.
    #[serde(skip)]
    Fail(String),
}

/// `ViewModel` represents the issuance App's state to the shell.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "IssuanceView")]
pub struct ViewModel {
    #[allow(rustdoc::bare_urls)]
    /// The credential issuer's URI (e.g. "`https://credibil.io`").
    pub issuer: String,

    /// A list of credentials being offered by the issuer.
    pub offered: HashMap<String, CredentialConfiguration>,

    /// The current status of the issuance flow.
    pub status: Status,
}

/// Capabilities required by the issuance App.
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

// TODO: add error handling using Model Status::Failed(reason)
impl crux_core::App for App {
    type Capabilities = Capabilities;
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;

    // Called in response to an event, usually by the shell but can also be in
    // response to a capability executing, or an internal processing step.
    #[allow(clippy::too_many_lines)]
    fn update(&self, event: Self::Event, model: &mut Self::Model, caps: &Self::Capabilities) {
        match event {
            Event::Offer(url_param) => {
                log::info!("Offer");
                #[cfg(feature = "wasm")]
                web_sys::console::debug_2(&"Event::Offer".into(), &url_param.clone().into());
                if let Err(e) = model.new_offer(&url_param) {
                    self.update(Event::Fail(e.to_string()), model, caps);
                    return;
                };
                caps.http
                    .get(format!(
                        "{}/.well-known/openid-credential-issuer",
                        model.offer.credential_issuer
                    ))
                    .expect_json()
                    .send(Event::Metadata);
            }
            Event::Metadata(Ok(response)) => {
                log::info!("Metadata: {response:?}");
                #[cfg(feature = "wasm")]
                web_sys::console::debug_2(&"Event::Metadata Ok".into(), &format!("{response:?}").into());
                // process metadata response
                if let Err(e) = model.metadata_response(response) {
                    self.update(Event::Fail(e.to_string()), model, caps);
                }
            }
            Event::Accept => {
                log::info!("Accept");
                if let Err(e) = model.accept() {
                    self.update(Event::Fail(e.to_string()), model, caps);
                    return;
                }

                // if no user pin is required, make request
                if model.status == Status::Accepted {
                    self.update(Event::GetToken, model, caps);
                }
            }
            Event::Pin(pin) => {
                log::info!("Pin: {pin}");
                model.pin(pin);
                self.update(Event::GetToken, model, caps);
            }
            Event::GetToken => {
                log::info!("GetToken");
                // generate access token request
                let Ok(req) = model.token_request() else {
                    let msg = String::from("Issue building token request");
                    self.update(Event::Fail(msg), model, caps);
                    return;
                };
                caps.http
                    .post(format!("{}/token", model.offer.credential_issuer))
                    .content_type("application/x-www-form-urlencoded")
                    .body(req)
                    .expect_json()
                    .send(Event::Token);
            }
            Event::Token(Ok(response)) => {
                log::info!("Token: {response:?}");
                // process token response
                if let Err(e) = model.token_response(response) {
                    self.update(Event::Fail(e.to_string()), model, caps);
                };
                caps.signer.verification(Event::Proof);
            }
            Event::Proof(Ok((alg, kid))) => {
                log::info!("Proof");
                caps.signer.sign(&model.request_jwt(alg, kid), Event::Signed);
            }
            Event::Signed(Ok(signed_jwt)) => {
                // request each offered credential
                for cfg_id in model.offered.clone().keys() {
                    let Ok(request) = model.credential_request(cfg_id, &signed_jwt) else {
                        let msg = String::from("Issue building credential request");
                        self.update(Event::Fail(msg), model, caps);
                        return;
                    };

                    caps.http
                        .post(format!("{}/credential", model.offer.credential_issuer))
                        .header("authorization", format!("Bearer {}", model.token.access_token))
                        .body(request)
                        .expect_json()
                        .send(Event::Credential);
                }
            }
            Event::Credential(Ok(response)) => {
                log::info!("Credential: {response:?}");
                let Ok(credential) = model.credential_response(response) else {
                    let msg = String::from("Issue processing credential response");
                    self.update(Event::Fail(msg), model, caps);
                    return;
                };

                let Some(url) = model::logo_url(&credential) else {
                    self.update(Event::SaveCredential(credential), model, caps);
                    return;
                };

                caps.http
                    .get(url)
                    .header("accept", "image/*")
                    .send(|response| Event::Logo(credential, response));
            }
            Event::Logo(mut credential, Ok(response)) => {
                log::info!("Logo: {response:?}");
                let Some(logo) = model::logo_response(&response) else {
                    let msg = String::from("Issue processing logo response");
                    self.update(Event::Fail(msg), model, caps);
                    return;
                };

                credential.logo = Some(logo);
                self.update(Event::SaveCredential(credential), model, caps);
            }
            Event::SaveCredential(credential) => {
                log::info!("SaveCredential: {credential:?}");
                caps.store.add(credential, Event::CredentialSaved);
            }
            Event::CredentialSaved(Ok(())) => {
                log::info!("CredentialSaved");
                // TODO: check for outstanding requests before marking flow as complete
                model.reset();
            }

            // ----------------------------------------------------------------
            // Error handling
            // ----------------------------------------------------------------
            Event::Metadata(Err(e)) => {
                #[cfg(feature = "wasm")]
                web_sys::console::error_2(&"Event::Metadata Error".into(), &format!("{e:?}").into());
                self.update(Event::Fail(format!("Issue fetching metadata: {e:?}")), model, caps);
            }
            Event::Token(Err(e)) => {
                self.update(Event::Fail(format!("Issue fetching token: {e:?}")), model, caps);
            }
            Event::Proof(Err(e)) => {
                self.update(Event::Fail(format!("Issue fetching proof: {e:?}")), model, caps);
            }
            Event::Signed(Err(e)) => {
                self.update(Event::Fail(format!("Issue signing proof JWT: {e:?}")), model, caps);
            }
            Event::Credential(Err(e)) => {
                self.update(Event::Fail(format!("Issue fetching credential: {e:?}")), model, caps);
            }
            Event::CredentialSaved(Err(e)) => {
                self.update(Event::Fail(format!("Issue storing credential: {e:?}")), model, caps);
            }
            Event::Logo(credential, Err(e)) => {
                // Just store the credential without the logo
                log::error!("Error fetching logo: {e:?}");
                caps.store.add(credential, Event::CredentialSaved);
            }
            Event::Fail(msg) => {
                log::error!("{}", msg);
                model.status = Status::Failed(msg);
            }
        }

        // trigger a UI re-render
        caps.render.render();
    }

    // Called by the shell to render the current state of the app. Typically, this is
    // invoked by the `render()` method of the Render capability.
    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        ViewModel {
            issuer: model.offer.credential_issuer.clone(),
            offered: model.offered.clone(),
            status: model.status.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use crux_core::testing::AppTester;
    use crux_http::protocol::{HttpResponse, HttpResult};
    use crux_http::testing::ResponseBuilder;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use lazy_static::lazy_static;
    use serde_json::{json, Value};
    use vercre_core::metadata::Issuer;
    use vercre_core::vci::{CredentialOffer, CredentialRequest};

    use super::*;
    use crate::capabilities::store::{StoreRequest, StoreResponse};

    /// Test that a `NewOffer` event causes the app to fetch credential
    /// metatdata.
    #[test]
    fn set_offer() {
        // instantiate our app via the test harness, which gives us access to the model
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        let offer = OFFER.to_string();
        let mut update = app.update(Event::Offer(offer), &mut model);

        // check the model was updated correctly
        let offer: CredentialOffer =
            serde_json::from_value(OFFER.to_owned()).expect("should deserialize");
        assert_eq!(model.offer, offer.clone());
        assert_eq!(model.status, Status::Offered);

        // check that the app emitted an HTTP request
        assert_let!(Effect::Http(request), &mut update.effects[0]);
        let op = &request.operation;
        assert_eq!(
            op.url,
            format!("{}/.well-known/openid-credential-issuer", &model.offer.credential_issuer)
        );

        // resolve the app request with a simulated response
        let http_resp = HttpResponse::ok().json(METADATA.to_owned()).build();
        let update = app.resolve(request, HttpResult::Ok(http_resp)).expect("an update");

        // check that the app emitted an (internal) event to update the model
        let resp: MetadataResponse =
            serde_json::from_value(METADATA.to_owned()).expect("should deserialize");
        let actual = update.events;
        let expected = vec![Event::Metadata(Ok(ResponseBuilder::ok().body(resp).build()))];
        assert_eq!(actual, expected);
    }

    #[test]
    fn set_metadata() {
        // instantiate our app via the test harness, which gives us access to the model
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // setup the model
        let offer = OFFER.to_string();
        model.new_offer(&offer).expect("Offer to be processed");

        let resp: MetadataResponse =
            serde_json::from_value(METADATA.to_owned()).expect("should deserialize");
        let http_resp = ResponseBuilder::ok().body(resp).build();

        app.update(Event::Metadata(Ok(http_resp)), &mut model);

        // check the model was updated correctly
        assert_eq!(model.offered.len(), 1);
        assert_snapshot!("set-metadata", model.offered,{
            "." => insta::sorted_redaction(),
            ".*.credential_definition.credentialSubject" => insta::sorted_redaction(),
        });

        assert_eq!(model.status, Status::Ready);
    }

    #[test]
    fn accept_offer() {
        // instantiate our app via the test harness, which gives us access to the model
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // setup the model
        let offer = OFFER.to_string();
        model.new_offer(&offer).expect("Offer to be processed");

        app.update(Event::Accept, &mut model);

        // check the model was updated correctly
        assert_eq!(model.status, Status::PendingPin);
    }

    #[test]
    fn accept_offer_no_pin() {
        // instantiate our app via the test harness, which gives us access to the model
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // setup the model
        let offer = OFFER_NO_PIN.to_string();
        model.new_offer(&offer).expect("Offer to be processed");

        app.update(Event::Accept, &mut model);

        // check the model was updated correctly
        assert_eq!(model.status, Status::Accepted);
    }

    #[test]
    fn set_pin() {
        // instantiate our app via the test harness, which gives us access to the model
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // setup the model
        let offer = OFFER.to_string();
        model.new_offer(&offer).expect("Offer to be processed");

        let mut update = app.update(Event::Pin(String::from("123456")), &mut model);

        // check the model was updated correctly
        assert_eq!(model.pin, Some(String::from("123456")));
        assert_eq!(model.status, Status::Accepted);

        // check that the app emitted an HTTP request
        assert_let!(Effect::Http(request), &mut update.effects[0]);
        let op = &request.operation;
        assert_eq!(op.url, format!("{}/token", &model.offer.credential_issuer));

        // resolve the app request with a simulated response
        let http_resp = HttpResponse::ok().json(TOKEN.to_owned()).build();
        let update = app.resolve(request, HttpResult::Ok(http_resp)).expect("an update");

        // check that the app emitted an (internal) event to update the model
        let resp: TokenResponse =
            serde_json::from_value(TOKEN.to_owned()).expect("should deserialize");
        let expected = Event::Token(Ok(ResponseBuilder::ok().body(resp).build()));
        assert_eq!(update.events[0], expected);
    }

    #[test]
    fn set_token() {
        // instantiate our app via the test harness, which gives us access to the model
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // create a token response
        let token: TokenResponse =
            serde_json::from_value(TOKEN.to_owned()).expect("should deserialize");
        let http_resp = ResponseBuilder::ok().body(token.clone()).build();

        let mut update = app.update(Event::Token(Ok(http_resp)), &mut model);

        // check the model was updated correctly
        assert_eq!(model.token.access_token, token.access_token);
        assert_eq!(Some(model.token.c_nonce.unwrap()), token.c_nonce);

        // check that the app emitted a Signer request
        assert_let!(Effect::Signer(_), &mut update.effects[0]);
    }

    #[test]
    fn get_credential() {
        // instantiate our app via the test harness, which gives us access to the model
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // setup the model
        model.new_offer(&OFFER.to_string()).expect("Offer to be processed");
        let md: MetadataResponse =
            serde_json::from_value(METADATA.to_owned()).expect("should deserialize");
        let http_resp = ResponseBuilder::ok().body(md.clone()).build();
        model.metadata_response(http_resp).expect("Metadata to be processed");
        let signed_jwt = String::from("a-signed-jwt.signature");

        let mut update = app.update(Event::Signed(signer::Result::Ok(signed_jwt)), &mut model);

        // check that the app emitted an HTTP request
        assert_let!(Effect::Http(request), &mut update.effects[0]);

        // check url
        let op = &request.operation;
        assert_eq!(op.url, format!("{}/credential", &model.offer.credential_issuer));

        // compare the request body to the snapshot
        let req: CredentialRequest = serde_json::from_slice(&op.body).expect("should deserialize");

        assert_snapshot!("credential-request", req);
    }

    #[test]
    fn add_credential() {
        // instantiate our app via the test harness, which gives us access to the model
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // setup the model
        let offer = OFFER.to_string();
        model.new_offer(&offer).expect("Offer to be processed");

        let md: MetadataResponse =
            serde_json::from_value(METADATA.to_owned()).expect("should deserialize");
        let http_resp = ResponseBuilder::ok().body(md.clone()).build();
        model.metadata_response(http_resp).expect("Metadata to be processed");

        let cr = json!({
            "format": "jwt_vc_json",
            "c_nonce": "emtrYiVjcSFOQ2VhWGZLcGsqVUxWbWxVb00xVUtINng",
            "c_nonce_expires_in": 600,
            "credential": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSNwdWJsaWNLZXlNb2RlbDFJZCIsInR5cCI6Imp3dCJ9.eyJzdWIiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSIsImp0aSI6IkVtcGxveWVlSURfSldUIiwiaXNzIjoiaHR0cDovL2NyZWRpYmlsLmlvIiwibmJmIjoxNzAwNTIyNTE1LCJpYXQiOjE3MDA1MjI1MTUsImV4cCI6bnVsbCwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwOi8vY3JlZGliaWwuaW8vY3JlZGVudGlhbHMvdjEiXSwiaWQiOiJFbXBsb3llZUlEX0pXVCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJFbXBsb3llZUlEQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vY3JlZGliaWwuaW8iLCJpc3N1YW5jZURhdGUiOiIyMDIzLTExLTIwVDIzOjIxOjU1LjQ4ODY1OVoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDppb246RWlEeU9RYmJaQWEzYWlSemVDa1Y3TE94M1NFUmpqSDkzRVhvSU0zVW9ONG9XZzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp3ZFdKc2FXTkxaWGxOYjJSbGJERkpaQ0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSnpaV053TWpVMmF6RWlMQ0pyZEhraU9pSkZReUlzSW5naU9pSjBXRk5MUWw5eWRXSllVemR6UTJwWWNYVndWa3BGZWxSalZ6Tk5jMnB0UlhaeE1WbHdXRzQ1Tmxwbklpd2llU0k2SW1SUGFXTlljV0pxUm5odlIwb3RTekF0UjBveGEwaFpTbkZwWTE5RVgwOU5kVlYzYTFFM1QydzJibXNpZlN3aWNIVnljRzl6WlhNaU9sc2lZWFYwYUdWdWRHbGpZWFJwYjI0aUxDSnJaWGxCWjNKbFpXMWxiblFpWFN3aWRIbHdaU0k2SWtWalpITmhVMlZqY0RJMU5tc3hWbVZ5YVdacFkyRjBhVzl1UzJWNU1qQXhPU0o5WFN3aWMyVnlkbWxqWlhNaU9sdDdJbWxrSWpvaWMyVnlkbWxqWlRGSlpDSXNJbk5sY25acFkyVkZibVJ3YjJsdWRDSTZJbWgwZEhBNkx5OTNkM2N1YzJWeWRtbGpaVEV1WTI5dElpd2lkSGx3WlNJNkluTmxjblpwWTJVeFZIbHdaU0o5WFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkV0SmEzZHhUelk1U1ZCSE0zQlBiRWhyWkdJNE5tNVpkREJoVG5oVFNGcDFNbkl0WW1oRmVtNXFaRUVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVTm1SRmRTYmxsc1kwUTVSVWRCTTJSZk5Wb3hRVWgxTFdsWmNVMWlTamx1Wm1seFpIbzFVemhXUkdKbklpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ1prOWFaRTEwVlRaUFFuYzRVR3M0TnpsUmRGb3RNa290T1VaaVltcFRXbmx2WVVGZlluRkVOSHBvUVNKOWZRIn0sInByb29mIjp7InR5cGUiOiIiLCJjcnlwdG9zdWl0ZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSIsInByb29mUHVycG9zZSI6IiIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDppb246RWlEeU9RYmJaQWEzYWlSemVDa1Y3TE94M1NFUmpqSDkzRVhvSU0zVW9ONG9XZzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp3ZFdKc2FXTkxaWGxOYjJSbGJERkpaQ0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSnpaV053TWpVMmF6RWlMQ0pyZEhraU9pSkZReUlzSW5naU9pSjBXRk5MUWw5eWRXSllVemR6UTJwWWNYVndWa3BGZWxSalZ6Tk5jMnB0UlhaeE1WbHdXRzQ1Tmxwbklpd2llU0k2SW1SUGFXTlljV0pxUm5odlIwb3RTekF0UjBveGEwaFpTbkZwWTE5RVgwOU5kVlYzYTFFM1QydzJibXNpZlN3aWNIVnljRzl6WlhNaU9sc2lZWFYwYUdWdWRHbGpZWFJwYjI0aUxDSnJaWGxCWjNKbFpXMWxiblFpWFN3aWRIbHdaU0k2SWtWalpITmhVMlZqY0RJMU5tc3hWbVZ5YVdacFkyRjBhVzl1UzJWNU1qQXhPU0o5WFN3aWMyVnlkbWxqWlhNaU9sdDdJbWxrSWpvaWMyVnlkbWxqWlRGSlpDSXNJbk5sY25acFkyVkZibVJ3YjJsdWRDSTZJbWgwZEhBNkx5OTNkM2N1YzJWeWRtbGpaVEV1WTI5dElpd2lkSGx3WlNJNkluTmxjblpwWTJVeFZIbHdaU0o5WFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkV0SmEzZHhUelk1U1ZCSE0zQlBiRWhyWkdJNE5tNVpkREJoVG5oVFNGcDFNbkl0WW1oRmVtNXFaRUVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVTm1SRmRTYmxsc1kwUTVSVWRCTTJSZk5Wb3hRVWgxTFdsWmNVMWlTamx1Wm1seFpIbzFVemhXUkdKbklpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ1prOWFaRTEwVlRaUFFuYzRVR3M0TnpsUmRGb3RNa290T1VaaVltcFRXbmx2WVVGZlluRkVOSHBvUVNKOWZRI3B1YmxpY0tleU1vZGVsMUlkIiwicHJvb2ZWYWx1ZSI6IiJ9fX0.yUsvBJDMk5rS7BjGlOT4TwUeI4IczC5RihwNSm4ErRgd8CfSdf0aEIzMGcHxxYNVaMHPV0yzM8VgC0jLsv14aQ"
        });
        let resp: CredentialResponse = serde_json::from_value(cr).expect("should deserialize");
        let http_resp = ResponseBuilder::ok().body(resp.clone()).build();

        let mut update = app.update(Event::Credential(Ok(http_resp.clone())), &mut model);

        // check the app emitted an http request for a logo
        let cred =
            model.credential_response(http_resp.clone()).expect("credential to be processed");
        assert_let!(Effect::Http(request), &mut update.effects[0]);

        // check url and effect
        let op = &request.operation;
        assert_eq!(
            op.url,
            cred.clone().metadata.display.unwrap()[0].logo.clone().unwrap().uri.unwrap()
        );

        // resolve the app request with a simulated response
        let http_resp = ResponseBuilder::ok()
            .body(b"sample".to_vec())
            .header("Content-Type", "image/png")
            .build();
        let mut update = app.update(Event::Logo(cred.clone(), Ok(http_resp.clone())), &mut model);

        assert_let!(Effect::Store(request), &mut update.effects[0]);
        assert_let!(StoreRequest::Add(id, value), &request.operation);
        assert!(!id.is_empty());

        // check credential was stored correctly
        let stored = serde_json::from_slice::<credential::Credential>(value)
            .expect("credential to deserialize");
        let actual = stored.issued.as_str();
        let expected = resp.credential.expect("credential should be set");

        assert_eq!(Some(actual), expected.as_str());

        // resolve the app request with a simulated response
        let response = StoreResponse::Ok;
        let update = app.resolve(request, response).expect("an update");
        app.update(update.events[0].clone(), &mut model);
    }

    lazy_static! {
        static ref OFFER: Value = json!({
            "credential_issuer":"http://127.0.0.1:8000",
            "credential_configuration_ids":["EmployeeID_JWT"],
            "grants":{
                "authorization_code":{
                    "issuer_state":"KSZBaEJaSTEwTTVRcU83U35tNDg3aWxXWHhnMkhKeCU"
                },
                "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                    "pre-authorized_code":"XnFPIW56SlEpZzRpYyEpZTMzMXJmKFJJSmFGem1hKGU",
                    "tx_code": {
                        "input_mode":"numeric",
                        "length":6,
                        "description":"Please provide the one-time code that was sent via e-mail"
                    }
                }
            }
        });
        static ref OFFER_NO_PIN: Value = json!({
            "credential_issuer":"http://127.0.0.1:8000",
            "credential_configuration_ids":["EmployeeID_JWT"],
            "grants":{
                "authorization_code":{
                    "issuer_state":"KSZBaEJaSTEwTTVRcU83U35tNDg3aWxXWHhnMkhKeCU"
                },
                "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                    "pre-authorized_code":"XnFPIW56SlEpZzRpYyEpZTMzMXJmKFJJSmFGem1hKGU"
                }
            }
        });
        static ref METADATA: Value =
            serde_json::to_value(Issuer::sample()).expect("should serialize");
        static ref TOKEN: Value = json!({
            "access_token":"UndnTTJub1VTIXFtVDkmQjNQUFV6T29sODExRVRFUUs",
            "authorization_pending":false,
            "c_nonce":"OUAycjVMTzEoYXdhMDhXOVZsIWVnbVRVZFg2JmxNajE",
            "c_nonce_expires_in":600,
            "expires_in":900,
            "interval":0,
            "token_type":"Bearer"
        });
    }
}
