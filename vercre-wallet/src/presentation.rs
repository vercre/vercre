//! # Presentation App
//!
//! The Presentation app implements the vercre-wallet's credential presentation flow.

pub(crate) mod model;

use crux_core::macros::Effect;
#[cfg(feature = "typegen")]
use crux_core::macros::Export;
use crux_core::render::Render;
use crux_http::Http;
// use http_types::mime;
pub use model::{Model, Status};
use serde::{Deserialize, Serialize};
use vercre_core::vp::RequestObjectResponse;

use crate::capabilities::delay::Delay;
use crate::capabilities::signer::{self, Signer};
use crate::capabilities::store::{self, Store};
use crate::credential::Credential;

/// App implements `crux::App` for the Presentation flow.
#[derive(Default)]
pub struct App;

/// Presentation events drive the presentation process. Local events are not
/// published (`#[serde(skip)]`) to the shell.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename = "PresentationEvent")]
pub enum Event {
    // -----------------------
    // Shell-initiated actions
    // -----------------------
    /// Raised on receipt of a new Authorization Request.
    Requested(String),

    /// Raised by the Holder authorizing credentials for presentation.
    Authorized,

    // -----------------------
    // Capability callbacks
    // -----------------------
    /// Callback from the Http capability with the Verifier's response to a
    /// request to fetch an Authorization Request Object.
    #[serde(skip)]
    Fetched(crux_http::Result<crux_http::Response<RequestObjectResponse>>),

    /// Matched receives the results of querying the shell (Store capability)
    /// for credentials matching the Presentation Definition.
    #[serde(skip)]
    Matched(store::Result<Vec<Credential>>),

    /// Callback from the Signer capability with proof method and key id used
    /// in signing.
    #[serde(skip)]
    Proof(signer::Result<(String, String)>),

    /// Callback from the Signer capability with a signed `vp_token`.
    #[serde(skip)]
    Signed(signer::Result<String>),

    /// Callback from the Http capability with the Verifier's response to a
    /// Presentation Submission.
    #[serde(skip)]
    Submitted(crux_http::Result<crux_http::Response<serde_json::Value>>),

    /// Set from another event when an error occurs.
    #[serde(skip)]
    Fail(String),
}

/// `ViewModel` is used to surface internal data Model for use by the shell.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "PresentationView")]
pub struct ViewModel {
    /// The list of credentials matching the verifier's request (Presentation
    /// Definition).
    pub credentials: Vec<Credential>,

    /// The current status of the presentation flow.
    pub status: Status,
}

/// Capabilities required by the presentation App.
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

    /// The Signer capability allows the app to sign presentation submissions.
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
    #[allow(clippy::too_many_lines)]
    fn update(&self, event: Self::Event, model: &mut Self::Model, caps: &Self::Capabilities) {
        match event {
            Event::Requested(request) => {
                log::info!("Requested: {request}");
                if let Err(e) = model.new_request(&request) {
                    self.update(Event::Fail(e.to_string()), model, caps);
                    return;
                };

                // request contains `RequestObject` — process immediately
                if model.status == Status::Requested {
                    caps.store.list(model.filter.clone(), Event::Matched);
                    return;
                }

                // request contains `request_uri` — fetch `RequestObject` from Verifier
                let Ok(request_uri) = urlencoding::decode(&request) else {
                    self.update(Event::Fail(String::from("Issue decoding offer")), model, caps);
                    return;
                };
                caps.http.get(request_uri).expect_json().send(Event::Fetched);
            }
            Event::Fetched(Ok(response)) => {
                log::info!("Fetched");
                if let Err(e) = model.request_object_response(response) {
                    self.update(Event::Fail(e.to_string()), model, caps);
                    return;
                };
                caps.store.list(model.filter.clone(), Event::Matched);
            }
            Event::Matched(Ok(response)) => {
                log::info!("Matched");
                model.credentials = response;
            }
            Event::Authorized => {
                log::info!("Authorized");
                model.status = Status::Authorized;
                caps.signer.verification(Event::Proof);
            }
            Event::Proof(Ok((alg, kid))) => {
                log::info!("Proof");
                // create and sign vp_token
                let Ok(vp_token) = model.vp_token(&alg, kid) else {
                    let msg = String::from("Issue creating vp_token");
                    self.update(Event::Fail(msg), model, caps);
                    return;
                };
                caps.signer.sign(&vp_token, Event::Signed);
            }
            Event::Signed(Ok(signed)) => {
                log::info!("Signed");

                // TODO: cater for unsigned vp_tokens (JSON objects) in resposne
                // TODO: cater more than 1 vp_token in response

                let Ok((response_uri, form)) = model.submission_request(signed) else {
                    let msg = String::from("Issue creating response body");
                    self.update(Event::Fail(msg), model, caps);
                    return;
                };

                // send response
                caps.http
                    .post(response_uri)
                    .content_type("application/x-www-form-urlencoded")
                    .body(form)
                    .expect_json()
                    .send(Event::Submitted);
            }
            Event::Submitted(Ok(response)) => {
                log::info!("Submitted");
                if !response.status().is_success() {
                    let msg = format!("Failed to verify: {:?}", response.body());
                    self.update(Event::Fail(msg), model, caps);
                    return;
                }

                model.reset();
            }

            // ----------------------------------------------------------------
            // Error handling
            // ----------------------------------------------------------------
            Event::Fetched(Err(e)) => {
                let msg = format!("Issue retrieving request object: {e}");
                self.update(Event::Fail(msg), model, caps);
            }
            Event::Matched(Err(e)) => {
                let msg = format!("Issue finding matching credentials: {e}");
                self.update(Event::Fail(msg), model, caps);
            }
            Event::Proof(Err(e)) => {
                let msg = format!("Issue retrieving proof details: {e}");
                self.update(Event::Fail(msg), model, caps);
            }
            Event::Signed(Err(e)) => {
                let msg = format!("Issue signing vp_token: {e}");
                self.update(Event::Fail(msg), model, caps);
            }
            Event::Submitted(Err(e)) => {
                let msg = format!("Issue submitting presentation: {e}");
                self.update(Event::Fail(msg), model, caps);
            }
            Event::Fail(msg) => {
                log::error!("{}", msg);
                model.status = Status::Failed(msg);
            }
        }

        caps.render.render();
    }

    /// `view` is called by the shell to render the current state of the app.
    /// Typically, this is invoked by the `render()` method of the Render
    /// capability.
    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        ViewModel {
            credentials: model.credentials.clone(),
            status: model.status.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use crux_core::testing::AppTester; // assert_effect,
    use crux_http::protocol::{HttpResponse, HttpResult};
    use crux_http::testing::ResponseBuilder;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use lazy_static::lazy_static;
    use serde_json::{json, Value};
    use test_utils::wallet;
    use vercre_core::jwt::{self, Jwt};
    use vercre_core::vp::RequestObject;
    use vercre_core::w3c::vp::PresentationSubmission;

    use super::*;
    use crate::capabilities::signer::{SignerRequest, SignerResponse};
    use crate::capabilities::store::{StoreEntry, StoreRequest, StoreResponse};

    // Event::RequestReceived
    //   1. triggers retrieval of an Authorization Request from Verifier.
    #[test]
    fn request_uri() {
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        let request_uri = "http://credibil.io/request/1234";

        let mut update = app.update(Event::Requested(request_uri.to_string()), &mut model);
        assert_snapshot!("new-request", app.view(&model));

        // verify the expected HttpRequest<RequestObject> was emitted
        assert_let!(Effect::Http(request), &mut update.effects[0]);
        assert_eq!(&request.operation.url, request_uri);

        // mock RequestObject response
        let response = RequestObjectResponse {
            request_object: serde_json::from_value(REQ_OBJ.to_owned()).expect("should deserialize"),
            jwt: None,
        };

        let http_resp = HttpResponse::ok().json(&response).build();
        let update = app.resolve(request, HttpResult::Ok(http_resp)).expect("an update");

        // check the app emitted an (internal) event to update the model
        let http_resp = ResponseBuilder::ok().body(response).build();
        assert_eq!(update.events, vec![Event::Fetched(Ok(http_resp))]);
    }

    // Event::RequestObject
    //   1. updates the model with the request object
    //   2. creates a StoreRequest to find matching credentials
    //   3. emits Event::Matched
    #[test]
    fn request_object() {
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        let req_obj: RequestObject =
            serde_json::from_value(REQ_OBJ.to_owned()).expect("should deserialize");

        let jwt = Jwt {
            header: jwt::Header {
                typ: String::from("JWT"),
                alg: wallet::alg(),
                kid: wallet::kid(),
            },
            claims: req_obj.clone(),
        };
        let jwt_enc = jwt.to_string();

        let sig = wallet::sign(&jwt_enc.as_bytes());
        let sig_enc = Base64UrlUnpadded::encode_string(&sig);

        // create mock HttpResponse<RequestObject>
        let response = RequestObjectResponse {
            request_object: None,
            jwt: Some(format!("{jwt_enc}.{sig_enc}")),
        };
        let http_resp = ResponseBuilder::ok().body(response).build();

        // Event::Fetched
        let mut update = app.update(Event::Fetched(Ok(http_resp)), &mut model);
        assert_snapshot!("set-request", app.view(&model));

        // 1. check model was updated correctly
        assert_eq!(model.request, Some(req_obj));
        assert_eq!(model.status, Status::Requested);

        // 2. check that the app created a Store request
        assert_let!(Effect::Store(request), &mut update.effects[0]);
        assert_let!(StoreRequest::List, &request.operation);

        // simulate StoreResponse
        let matches: Vec<Credential> =
            serde_json::from_value(CREDENTIALS.to_owned()).expect("should deserialize");
        let results = matches
            .iter()
            .map(|m| StoreEntry::from(serde_json::to_vec(m).expect("should serialize")))
            .collect();
        let response = StoreResponse::List(results);
        let update = app.resolve(request, response).expect("an update");

        // 3. verify Event::Matched emitted
        assert_let!(Event::Matched(Ok(_)), &update.events[0]);
    }

    #[test]
    fn set_credentials() {
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // setup
        let matches: Vec<Credential> =
            serde_json::from_value(CREDENTIALS.to_owned()).expect("should deserialize");

        app.update(Event::Matched(Ok(matches.clone())), &mut model);

        // verify the model was updated correctly
        assert_eq!(model.credentials, matches);
    }

    // Event::Authorize
    //   1. updates the model status to Authorized
    //   2. creates a SignerRequest get the signer's proof method
    //   3. emits a Proof event
    #[test]
    fn authorize() {
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        let mut update = app.update(Event::Authorized, &mut model);

        assert_let!(Effect::Signer(request), &mut update.effects[0]);
        assert_let!(SignerRequest::Verification, &request.operation);

        // simulate the SignerResponse
        let alg = wallet::alg();
        let kid = wallet::kid();
        let response = SignerResponse::Verification { alg, kid };
        let update = app.resolve(request, response).expect("an update");

        // verify the app emitted a Proof event
        assert_let!(Event::Proof(Ok((_, _))), &update.events[0]);
    }

    // Event::Proof
    //  1. updates the model with a submission
    //  2. creates a SignerRequest to sign the vp_token
    //  3. emits a Signed event on resolution of request
    #[test]
    fn set_verification() {
        let app = AppTester::<App, _>::default();

        let req_obj: RequestObject =
            serde_json::from_value(REQ_OBJ.to_owned()).expect("should deserialize");
        let req_uri = serde_qs::to_string(&req_obj).expect("should serialize");

        // prepare model
        let mut model = Model {
            credentials: serde_json::from_value(CREDENTIALS.to_owned())
                .expect("should deserialize"),
            ..Default::default()
        };
        model.new_request(&req_uri).expect("Request Object is valid");

        let alg = wallet::alg();
        let kid = wallet::kid();

        // trigger Event::Proof event
        let mut update = app.update(Event::Proof(Ok((alg, kid))), &mut model);
        assert_snapshot!("set-proof", app.view(&model), {
            ".credentials" => insta::sorted_redaction(),
            ".credentials[].metadata.credential_definition.credentialSubject" => insta::sorted_redaction()
        });

        assert_let!(Effect::Signer(request), &mut update.effects[0]);
        assert_let!(SignerRequest::Sign(msg), &request.operation);

        // simulate the SignerResponse
        let signed = wallet::sign(msg);
        let response = SignerResponse::Signature(signed);
        let update = app.resolve(request, response).expect("an update");

        // verify the app emitted a Signed event
        assert_let!(Event::Signed(Ok(_)), &update.events[0]);
    }

    // Event::Signed
    //   1. creates a SignerRequest to sign the direct post jwt
    //   2. emits a JwtSigned event on resolution of request
    #[test]
    fn token_signed() {
        let app = AppTester::<App, _>::default();
        let mut model = Model::default();

        // setup model
        let req_obj: RequestObject =
            serde_json::from_value(REQ_OBJ.to_owned()).expect("should deserialize");
        let req_uri = serde_qs::to_string(&req_obj).expect("should serialize");
        let submission: PresentationSubmission =
            serde_json::from_value(SUBMISSION.to_owned()).expect("should deserialize");
        // let alg = wallet::alg();
        // let kid = format!("{}#{}", HOLDER_DID, KEY_ID);

        model.new_request(&req_uri).expect("Request Object is valid");
        model.submission = Some(submission);
        // model.proof = Some((alg, kid));

        // trigger event
        let mut update = app.update(Event::Signed(Ok(VP_TOKEN.to_string())), &mut model);
        assert_let!(Effect::Http(request), &mut update.effects[0]);
        assert_eq!(request.operation.url, req_obj.response_uri.unwrap());

        // simulate the HttpResponse
        let req = json!( {
            "redirect_uri":"https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee"
        });

        let http_resp = HttpResponse::ok().json(&req).build();
        let update = app.resolve(request, HttpResult::Ok(http_resp)).expect("an update");

        let http_resp = ResponseBuilder::ok().body(req).build();
        assert_eq!(Event::Submitted(Ok(http_resp)), update.events[0]);
    }

    // test data
    lazy_static! {
        static ref REQ_OBJ: Value = json!({
            "response_type":"vp_token",
            "response_uri":"http://localhost:8080/direct_post.jwt",
            "response_mode":"direct_post.jwt",
            "client_id":"http://credibil.io/post",
            "redirect_uri":"http://localhost:8080/verified",
            "presentation_definition":{
                "id":"3f79561e-d53f-44fd-bcef-9ac34561491c",
                "input_descriptors":[
                    {
                        "id": "EmployeeIDCredential",
                        "constraints": {
                            "fields": [{
                                "path":["$.type"],
                                "filter": {
                                    "type": "string",
                                    "const": "EmployeeIDCredential"
                                }
                            }]
                        }
                    },
                    {
                        "id": "CitizenshipCredential",
                        "constraints": {
                            "fields": [{
                                "path":["$.type"],
                                "filter": {
                                    "type": "string",
                                    "const": "CitizenshipCredential"
                                }
                            }]
                        }
                    }
                ],
                "format": {
                    "jwt_vc": {
                        "alg": ["ES256K"]
                    }
                }
            },
            "nonce":"eV5LSmU0dSVZYkQza0dzQyFmOE5NV0p1WGhxQjFlXnE",
            "state":"ZkR2VXBeOVpRUDg5TFFXaXc0a2xZMCk2bH5WfjExalk",
            "client_id_scheme":"did",
            "client_metadata":{
                "client_id":"http://credibil.io",
                "redirect_uris":["http://localhost:3000/callback"],
                "grant_types":["authorization_code"],
                "response_types":["vp_token","id_token vp_token"],
                "vp_formats":{
                    "jwt_vp_json":{
                        "alg":["ES256K"],
                        "proof_type":["JsonWebSignature2020"]
                    },
                    "jwt_vc_json":{
                        "alg":["ES256K"],
                        "proof_type":["JsonWebSignature2020"]
                    }
                },
                "client_id_scheme":"did"
            }
        });
        static ref CREDENTIALS: Value =
            json!([serde_json::to_value(Credential::sample()).expect("should serialize")]);
        static ref SUBMISSION: Value = json!({
            "id": "14518edf-5262-4941-b262-b3d5893a0bf8",
            "definition_id": "3f79561e-d53f-44fd-bcef-9ac34561491c",
            "descriptor_map": [
                {
                    "id": "EmployeeIDCredential",
                    "format": "jwt_vc_json",
                    "path": "$",
                    "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
                },
                {
                    "id": "CitizenshipCredential",
                     "format": "jwt_vc_json",
                     "path": "$",
                     "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
                }
            ]
        });
    }

    const VP_TOKEN: &str = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSNwdWJsaWNLZXlNb2RlbDFJZCIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0In0.eyJpc3MiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSIsImp0aSI6Ijk2Zjg0MmExLTJiNTEtNGFkMC1iOGYyLTk4YjU5ZDgyZjBkZSIsImF1ZCI6Imh0dHBzOi8vY3JlZGliaWwuaW8iLCJuYmYiOjE3MDA3ODgxMDQsImlhdCI6MTcwMDc4ODEwNCwiZXhwIjoxNzAwNzkxNzA0LCJub25jZSI6ImVWNUxTbVUwZFNWWllrUXphMGR6UXlGbU9FNU5WMHAxV0doeFFqRmxYbkUiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vZXhhbXBsZS5jb20vY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwiRW1wbG95ZWVJRFByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJcImV5SmhiR2NpT2lKRlV6STFOa3NpTENKcmFXUWlPaUprYVdRNmFXOXVPa1ZwUkhsUFVXSmlXa0ZoTTJGcFVucGxRMnRXTjB4UGVETlRSVkpxYWtnNU0wVlliMGxOTTFWdlRqUnZWMmM2WlhsS2ExcFhlREJaVTBrMlpYbEtkMWxZVW1waFIxWjZTV3B3WW1WNVNtaFpNMUp3WWpJMGFVOXBTbmxhV0VKeldWZE9iRWxwZDJsYVJ6bHFaRmN4YkdKdVVXbFBibk5wWTBoV2FXSkhiR3BUTWxZMVkzbEpObGN6YzJsaFYxRnBUMmxLZDJSWFNuTmhWMDVNV2xoc1RtSXlVbXhpUkVaS1drTkpjMGx1UWpGWmJYaHdXVEIwYkdWVmNETmhlVWsyWlhsS2FtTnVXV2xQYVVwNldsZE9kMDFxVlRKaGVrVnBURU5LY21SSWEybFBhVXBHVVhsSmMwbHVaMmxQYVVvd1YwWk9URkZzT1hsa1YwcFpWWHBrZWxFeWNGbGpXRlozVm10d1JtVnNVbXBXZWs1T1l6SndkRkpZV25oTlZteDNWMGMwTlU1c2NHNUphWGRwWlZOSk5rbHRVbEJoVjA1WlkxZEtjVkp1YUhaU01HOTBVM3BCZEZJd2IzaGhNR2hhVTI1R2NGa3hPVVZZTURsT1pGWldNMkV4UlROVU1uY3lZbTF6YVdaVGQybGpTRlo1WTBjNWVscFlUV2xQYkhOcFdWaFdNR0ZIVm5Wa1IyeHFXVmhTY0dJeU5HbE1RMHB5V2xoc1Fsb3pTbXhhVnpGc1ltNVJhVmhUZDJsa1NHeDNXbE5KTmtsclZtcGFTRTVvVlRKV2FtTkVTVEZPYlhONFZtMVdlV0ZYV25CWk1rWXdZVmM1ZFZNeVZqVk5ha0Y0VDFOS09WaFRkMmxqTWxaNVpHMXNhbHBZVFdsUGJIUTNTVzFzYTBscWIybGpNbFo1Wkcxc2FscFVSa3BhUTBselNXNU9iR051V25CWk1sWkdZbTFTZDJJeWJIVmtRMGsyU1cxb01HUklRVFpNZVRrelpETmpkV015Vm5sa2JXeHFXbFJGZFZreU9YUkphWGRwWkVoc2QxcFRTVFpKYms1c1kyNWFjRmt5VlhoV1NHeDNXbE5LT1ZoWU1UbFlVM2RwWkZoQ2ExbFlVbXhSTWpsMFlsZHNNR0pYVm5Wa1EwazJTV3RXY0ZKRmRFcGhNMlI0VkhwWk5WTldRa2hOTTBKUVlrVm9jbHBIU1RST2JUVmFaRVJDYUZSdWFGUlRSbkF4VFc1SmRGbHRhRVpsYlRWeFdrVkZhV1pUZDJsak0xWnRXbTFzTkZKSFJqQlpVMGsyWlhsS2ExcFhlREJaVldob1l6Sm5hVTlwU2taaFZVNXRVa1prVTJKc2JITlpNRkUxVWxWa1FrMHlVbVpPVm05NFVWVm9NVXhYYkZwalZURnBVMnBzZFZwdGJIaGFTRzh4Vlhwb1YxSkhTbTVKYVhkcFkyMVdhbUl6V214amJteEVZakl4ZEdGWVVuUmFWelV3U1dwdmFWSlhiRU5hYXpsaFdrVXhNRlpVV2xCUmJtTTBWVWR6TkU1NmJGSmtSbTkwVFd0dmRFOVZXbWxaYlhCVVYyNXNkbGxWUm1aWmJrWkZUa2h3YjFGVFNqbG1VU053ZFdKc2FXTkxaWGxOYjJSbGJERkpaQ0lzSW5SNWNDSTZJbXAzZENKOS5leUp6ZFdJaU9pSmthV1E2YVc5dU9rVnBSSGxQVVdKaVdrRmhNMkZwVW5wbFEydFdOMHhQZUROVFJWSnFha2c1TTBWWWIwbE5NMVZ2VGpSdlYyYzZaWGxLYTFwWGVEQlpVMGsyWlhsS2QxbFlVbXBoUjFaNlNXcHdZbVY1U21oWk0xSndZakkwYVU5cFNubGFXRUp6V1ZkT2JFbHBkMmxhUnpscVpGY3hiR0p1VVdsUGJuTnBZMGhXYVdKSGJHcFRNbFkxWTNsSk5sY3pjMmxoVjFGcFQybEtkMlJYU25OaFYwNU1XbGhzVG1JeVVteGlSRVpLV2tOSmMwbHVRakZaYlhod1dUQjBiR1ZWY0ROaGVVazJaWGxLYW1OdVdXbFBhVXA2V2xkT2QwMXFWVEpoZWtWcFRFTktjbVJJYTJsUGFVcEdVWGxKYzBsdVoybFBhVW93VjBaT1RGRnNPWGxrVjBwWlZYcGtlbEV5Y0ZsaldGWjNWbXR3Um1Wc1VtcFdlazVPWXpKd2RGSllXbmhOVm14M1YwYzBOVTVzY0c1SmFYZHBaVk5KTmtsdFVsQmhWMDVaWTFkS2NWSnVhSFpTTUc5MFUzcEJkRkl3YjNoaE1HaGFVMjVHY0ZreE9VVllNRGxPWkZaV00yRXhSVE5VTW5jeVltMXphV1pUZDJsalNGWjVZMGM1ZWxwWVRXbFBiSE5wV1ZoV01HRkhWblZrUjJ4cVdWaFNjR0l5TkdsTVEwcHlXbGhzUWxvelNteGFWekZzWW01UmFWaFRkMmxrU0d4M1dsTkpOa2xyVm1wYVNFNW9WVEpXYW1ORVNURk9iWE40Vm0xV2VXRlhXbkJaTWtZd1lWYzVkVk15VmpWTmFrRjRUMU5LT1ZoVGQybGpNbFo1Wkcxc2FscFlUV2xQYkhRM1NXMXNhMGxxYjJsak1sWjVaRzFzYWxwVVJrcGFRMGx6U1c1T2JHTnVXbkJaTWxaR1ltMVNkMkl5YkhWa1EwazJTVzFvTUdSSVFUWk1lVGt6WkROamRXTXlWbmxrYld4cVdsUkZkVmt5T1hSSmFYZHBaRWhzZDFwVFNUWkpiazVzWTI1YWNGa3lWWGhXU0d4M1dsTktPVmhZTVRsWVUzZHBaRmhDYTFsWVVteFJNamwwWWxkc01HSlhWblZrUTBrMlNXdFdjRkpGZEVwaE0yUjRWSHBaTlZOV1FraE5NMEpRWWtWb2NscEhTVFJPYlRWYVpFUkNhRlJ1YUZSVFJuQXhUVzVKZEZsdGFFWmxiVFZ4V2tWRmFXWlRkMmxqTTFadFdtMXNORkpIUmpCWlUwazJaWGxLYTFwWGVEQlpWV2hvWXpKbmFVOXBTa1poVlU1dFVrWmtVMkpzYkhOWk1GRTFVbFZrUWsweVVtWk9WbTk0VVZWb01VeFhiRnBqVlRGcFUycHNkVnB0YkhoYVNHOHhWWHBvVjFKSFNtNUphWGRwWTIxV2FtSXpXbXhqYm14RVlqSXhkR0ZZVW5SYVZ6VXdTV3B2YVZKWGJFTmFhemxoV2tVeE1GWlVXbEJSYm1NMFZVZHpORTU2YkZKa1JtOTBUV3R2ZEU5VldtbFpiWEJVVjI1c2RsbFZSbVpaYmtaRlRraHdiMUZUU2psbVVTSXNJbXAwYVNJNklrVnRjR3h2ZVdWbFNVUmZTbGRVSWl3aWFYTnpJam9pYUhSMGNEb3ZMMk55WldScFltbHNMbWx2SWl3aWJtSm1Jam94TnpBd05USXlOVEUxTENKcFlYUWlPakUzTURBMU1qSTFNVFVzSW1WNGNDSTZiblZzYkN3aWRtTWlPbnNpUUdOdmJuUmxlSFFpT2xzaWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNdmRqRWlMQ0pvZEhSd09pOHZZM0psWkdsaWFXd3VhVzh2WTNKbFpHVnVkR2xoYkhNdmRqRWlYU3dpYVdRaU9pSkZiWEJzYjNsbFpVbEVYMHBYVkNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pGYlhCc2IzbGxaVWxFUTNKbFpHVnVkR2xoYkNKZExDSnBjM04xWlhJaU9pSm9kSFJ3T2k4dlkzSmxaR2xpYVd3dWFXOGlMQ0pwYzNOMVlXNWpaVVJoZEdVaU9pSXlNREl6TFRFeExUSXdWREl6T2pJeE9qVTFMalE0T0RZMU9Wb2lMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKcFpDSTZJbVJwWkRwcGIyNDZSV2xFZVU5UlltSmFRV0V6WVdsU2VtVkRhMVkzVEU5NE0xTkZVbXBxU0RrelJWaHZTVTB6Vlc5T05HOVhaenBsZVVwcldsZDRNRmxUU1RabGVVcDNXVmhTYW1GSFZucEphbkJpWlhsS2FGa3pVbkJpTWpScFQybEtlVnBZUW5OWlYwNXNTV2wzYVZwSE9XcGtWekZzWW01UmFVOXVjMmxqU0ZacFlrZHNhbE15VmpWamVVazJWek56YVdGWFVXbFBhVXAzWkZkS2MyRlhUa3hhV0d4T1lqSlNiR0pFUmtwYVEwbHpTVzVDTVZsdGVIQlpNSFJzWlZWd00yRjVTVFpsZVVwcVkyNVphVTlwU25wYVYwNTNUV3BWTW1GNlJXbE1RMHB5WkVocmFVOXBTa1pSZVVselNXNW5hVTlwU2pCWFJrNU1VV3c1ZVdSWFNsbFZlbVI2VVRKd1dXTllWbmRXYTNCR1pXeFNhbFo2VGs1ak1uQjBVbGhhZUUxV2JIZFhSelExVG14d2JrbHBkMmxsVTBrMlNXMVNVR0ZYVGxsalYwcHhVbTVvZGxJd2IzUlRla0YwVWpCdmVHRXdhRnBUYmtad1dURTVSVmd3T1U1a1ZsWXpZVEZGTTFReWR6SmliWE5wWmxOM2FXTklWbmxqUnpsNldsaE5hVTlzYzJsWldGWXdZVWRXZFdSSGJHcFpXRkp3WWpJMGFVeERTbkphV0d4Q1dqTktiRnBYTVd4aWJsRnBXRk4zYVdSSWJIZGFVMGsyU1d0V2FscElUbWhWTWxacVkwUkpNVTV0YzNoV2JWWjVZVmRhY0ZreVJqQmhWemwxVXpKV05VMXFRWGhQVTBvNVdGTjNhV015Vm5sa2JXeHFXbGhOYVU5c2REZEpiV3hyU1dwdmFXTXlWbmxrYld4cVdsUkdTbHBEU1hOSmJrNXNZMjVhY0ZreVZrWmliVkozWWpKc2RXUkRTVFpKYldnd1pFaEJOa3g1T1ROa00yTjFZekpXZVdSdGJHcGFWRVYxV1RJNWRFbHBkMmxrU0d4M1dsTkpOa2x1VG14amJscHdXVEpWZUZaSWJIZGFVMG81V0ZneE9WaFRkMmxrV0VKcldWaFNiRkV5T1hSaVYyd3dZbGRXZFdSRFNUWkphMVp3VWtWMFNtRXpaSGhVZWxrMVUxWkNTRTB6UWxCaVJXaHlXa2RKTkU1dE5WcGtSRUpvVkc1b1ZGTkdjREZOYmtsMFdXMW9SbVZ0TlhGYVJVVnBabE4zYVdNelZtMWFiV3cwVWtkR01GbFRTVFpsZVVwcldsZDRNRmxWYUdoak1tZHBUMmxLUm1GVlRtMVNSbVJUWW14c2Mxa3dVVFZTVldSQ1RUSlNaazVXYjNoUlZXZ3hURmRzV21OVk1XbFRhbXgxV20xc2VGcEliekZWZW1oWFVrZEtia2xwZDJsamJWWnFZak5hYkdOdWJFUmlNakYwWVZoU2RGcFhOVEJKYW05cFVsZHNRMXByT1dGYVJURXdWbFJhVUZGdVl6UlZSM00wVG5wc1VtUkdiM1JOYTI5MFQxVmFhVmx0Y0ZSWGJteDJXVlZHWmxsdVJrVk9TSEJ2VVZOS09XWlJJbjBzSW5CeWIyOW1JanA3SW5SNWNHVWlPaUlpTENKamNubHdkRzl6ZFdsMFpTSTZJa1ZqWkhOaFUyVmpjREkxTm1zeFZtVnlhV1pwWTJGMGFXOXVTMlY1TWpBeE9TSXNJbkJ5YjI5bVVIVnljRzl6WlNJNklpSXNJblpsY21sbWFXTmhkR2x2YmsxbGRHaHZaQ0k2SW1ScFpEcHBiMjQ2UldsRWVVOVJZbUphUVdFellXbFNlbVZEYTFZM1RFOTRNMU5GVW1wcVNEa3pSVmh2U1UwelZXOU9ORzlYWnpwbGVVcHJXbGQ0TUZsVFNUWmxlVXAzV1ZoU2FtRkhWbnBKYW5CaVpYbEthRmt6VW5CaU1qUnBUMmxLZVZwWVFuTlpWMDVzU1dsM2FWcEhPV3BrVnpGc1ltNVJhVTl1YzJsalNGWnBZa2RzYWxNeVZqVmplVWsyVnpOemFXRlhVV2xQYVVwM1pGZEtjMkZYVGt4YVdHeE9ZakpTYkdKRVJrcGFRMGx6U1c1Q01WbHRlSEJaTUhSc1pWVndNMkY1U1RabGVVcHFZMjVaYVU5cFNucGFWMDUzVFdwVk1tRjZSV2xNUTBweVpFaHJhVTlwU2taUmVVbHpTVzVuYVU5cFNqQlhSazVNVVd3NWVXUlhTbGxWZW1SNlVUSndXV05ZVm5kV2EzQkdaV3hTYWxaNlRrNWpNbkIwVWxoYWVFMVdiSGRYUnpRMVRteHdia2xwZDJsbFUwazJTVzFTVUdGWFRsbGpWMHB4VW01b2RsSXdiM1JUZWtGMFVqQnZlR0V3YUZwVGJrWndXVEU1UlZnd09VNWtWbFl6WVRGRk0xUXlkekppYlhOcFpsTjNhV05JVm5salJ6bDZXbGhOYVU5c2MybFpXRll3WVVkV2RXUkhiR3BaV0ZKd1lqSTBhVXhEU25KYVdHeENXak5LYkZwWE1XeGlibEZwV0ZOM2FXUkliSGRhVTBrMlNXdFdhbHBJVG1oVk1sWnFZMFJKTVU1dGMzaFdiVlo1WVZkYWNGa3lSakJoVnpsMVV6SldOVTFxUVhoUFUwbzVXRk4zYVdNeVZubGtiV3hxV2xoTmFVOXNkRGRKYld4clNXcHZhV015Vm5sa2JXeHFXbFJHU2xwRFNYTkpiazVzWTI1YWNGa3lWa1ppYlZKM1lqSnNkV1JEU1RaSmJXZ3daRWhCTmt4NU9UTmtNMk4xWXpKV2VXUnRiR3BhVkVWMVdUSTVkRWxwZDJsa1NHeDNXbE5KTmtsdVRteGpibHB3V1RKVmVGWkliSGRhVTBvNVdGZ3hPVmhUZDJsa1dFSnJXVmhTYkZFeU9YUmlWMnd3WWxkV2RXUkRTVFpKYTFad1VrVjBTbUV6WkhoVWVsazFVMVpDU0UwelFsQmlSV2h5V2tkSk5FNXROVnBrUkVKb1ZHNW9WRk5HY0RGTmJrbDBXVzFvUm1WdE5YRmFSVVZwWmxOM2FXTXpWbTFhYld3MFVrZEdNRmxUU1RabGVVcHJXbGQ0TUZsVmFHaGpNbWRwVDJsS1JtRlZUbTFTUm1SVFlteHNjMWt3VVRWU1ZXUkNUVEpTWms1V2IzaFJWV2d4VEZkc1dtTlZNV2xUYW14MVdtMXNlRnBJYnpGVmVtaFhVa2RLYmtscGQybGpiVlpxWWpOYWJHTnViRVJpTWpGMFlWaFNkRnBYTlRCSmFtOXBVbGRzUTFwck9XRmFSVEV3VmxSYVVGRnVZelJWUjNNMFRucHNVbVJHYjNSTmEyOTBUMVZhYVZsdGNGUlhibXgyV1ZWR1psbHVSa1ZPU0hCdlVWTktPV1pSSTNCMVlteHBZMHRsZVUxdlpHVnNNVWxrSWl3aWNISnZiMlpXWVd4MVpTSTZJaUo5ZlgwLnlVc3ZCSkRNazVyUzdCakdsT1Q0VHdVZUk0SWN6QzVSaWh3TlNtNEVyUmdkOENmU2RmMGFFSXpNR2NIeHhZTlZhTUhQVjB5ek04VmdDMGpMc3YxNGFRXCIiXX19.o-6wwCJk_54DZiLkzHbQL54PkJRjVEImWmuII9RAlthrqw3gDqkyG2v9y7uQNPsZf2ChKmvF-hHUoYaCplXB_A";
}
