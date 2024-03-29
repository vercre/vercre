//! # Batch Credential Endpoint
//!
//! The Batch Credential Endpoint issues multiple Credentials in one Batch Credential
//! Response as approved by the End-User upon presentation of a valid Access Token
//! representing this approval.
//!
//! A Wallet can request issuance of multiple Credentials of certain types and formats
//! in one Batch Credential Request. This includes Credentials of the same type and
//! multiple formats, different types and one format, or both.

use std::fmt::Debug;
use std::str::FromStr;

use anyhow::anyhow;
use chrono::{TimeDelta, Utc};
use tracing::{instrument, trace};
use uuid::Uuid;
use vercre_core::error::{Ancillary as _, Err};
use vercre_core::jwt::Jwt;
use vercre_core::metadata::{CredentialDefinition, Issuer as IssuerMetadata};
use vercre_core::provider::{Callback, Client, Holder, Issuer, Server, Signer, StateManager};
use vercre_core::vci::ProofClaims;
#[allow(clippy::module_name_repetitions)]
pub use vercre_core::vci::{
    BatchCredentialRequest, BatchCredentialResponse, CredentialRequest, CredentialResponse,
};
use vercre_core::w3c::{self, CredentialSubject, VerifiableCredential};
use vercre_core::{err, gen, Result};

use super::Endpoint;
use crate::state::{Deferred, Expire, State};

impl<P> Endpoint<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Batch credential request handler.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    pub async fn batch(&self, request: &BatchCredentialRequest) -> Result<BatchCredentialResponse> {
        let Ok(buf) = StateManager::get(&self.provider, &request.access_token).await else {
            err!(Err::AccessDenied, "invalid access token");
        };
        let Ok(state) = State::try_from(buf) else {
            err!(Err::AccessDenied, "invalid state for access token");
        };

        let ctx = Context {
            callback_id: state.callback_id.clone(),
            state,
            issuer_meta: Issuer::metadata(&self.provider, &request.credential_issuer).await?,
            holder_did: String::new(),
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    callback_id: Option<String>,
    issuer_meta: IssuerMetadata,
    state: State,
    holder_did: String,
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    type Provider = P;
    type Request = BatchCredentialRequest;
    type Response = BatchCredentialResponse;

    fn callback_id(&self) -> Option<String> {
        self.callback_id.clone()
    }

    #[instrument]
    async fn verify(&mut self, provider: &P, request: &Self::Request) -> Result<&Self> {
        trace!("Context::verify");

        let Some(token_state) = &self.state.token else {
            err!(Err::AccessDenied, "invalid access token state");
        };

        // c_nonce expiry
        if token_state.c_nonce_expired() {
            err!(Err::AccessDenied, "c_nonce has expired");
        }

        // TODO: add support for `credential_identifier`
        // verify each credential request
        for request in &request.credential_requests {
            if request.format.is_some() && request.credential_identifier.is_some() {
                return Err(Err::InvalidCredentialRequest)
                    .hint("format and credential_identifier cannot both be set");
            };
            if request.format.is_none() && request.credential_identifier.is_none() {
                return Err(Err::InvalidCredentialRequest)
                    .hint("format or credential_identifier must be set");
            };

            // format and type request
            if let Some(format) = &request.format {
                let Some(cred_def) = &request.credential_definition else {
                    err!(Err::InvalidCredentialRequest, "credential definition not set");
                };

                // check request has been authorized:
                //   - match format + type against authorized items in state
                let mut authorized = false;
                for (k, v) in &self.issuer_meta.credential_configurations_supported {
                    if (&v.format == format) && (v.credential_definition.type_ == cred_def.type_) {
                        authorized = self.state.credential_configuration_ids.contains(k);
                        break;
                    }
                }
                if !authorized {
                    return Err(Err::InvalidCredentialRequest)
                        .hint("Requested credential has not been authorized");
                }
            };

            // ----------------------------------------------------------------
            // TODO: check `proof_types_supported` param in `credential_configurations_supported`
            // is non-empty
            // ----------------------------------------------------------------
            let Some(proof) = &request.proof else {
                err!(Err::InvalidCredentialRequest, "proof not set");
            };
            // ----------------------------------------------------------------

            let Some(proof_jwt) = &proof.jwt else {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(Err::InvalidProof(nonce, expires_in), "Proof not set");
            };

            // TODO: allow passing verifier into this method
            let jwt = match Jwt::<ProofClaims>::from_str(proof_jwt) {
                Ok(jwt) => jwt,
                Err(e) => {
                    let (nonce, expires_in) = self.err_nonce(provider).await?;
                    err!(
                        Err::InvalidProof(nonce, expires_in),
                        "{}",
                        e.error_description().unwrap_or_default()
                    );
                }
            };

            // algorithm
            if !(jwt.header.alg == "ES256K" || jwt.header.alg == "EdDSA") {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(Err::InvalidProof(nonce, expires_in), "Proof JWT 'alg' is not recognised");
            }
            // proof type
            if jwt.header.typ != "vercre-vci-proof+jwt" {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(
                    Err::InvalidProof(nonce, expires_in),
                    "Proof JWT 'typ' is not 'vercre-vci-proof+jwt'"
                );
            }
            // previously issued c_nonce
            if jwt.claims.nonce != token_state.c_nonce {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(Err::InvalidProof(nonce, expires_in), "Proof JWT nonce claim is invalid");
            }
            // Key ID
            if jwt.header.kid.is_empty() {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(Err::InvalidProof(nonce, expires_in), "Proof JWT 'kid' is missing");
            };

            // HACK: save extracted DID for later use when issuing credential
            let Some(did) = jwt.header.kid.split('#').next() else {
                let (nonce, expires_in) = self.err_nonce(provider).await?;
                err!(Err::InvalidProof(nonce, expires_in), "Proof JWT DID is invalid");
            };
            self.holder_did = did.to_string();
        }

        Ok(self)
    }

    #[instrument]
    async fn process(&self, provider: &P, request: &Self::Request) -> Result<Self::Response> {
        trace!("Context::process");

        // process credential requests
        let mut responses = Vec::<CredentialResponse>::new();
        for c_req in request.credential_requests.clone() {
            responses.push(self.make_response(provider, &c_req).await?);
        }

        // generate nonce and update state
        let Some(token_state) = &self.state.token else {
            err!("Invalid token state");
        };

        // --------------------------------------------------------------------
        // TODO: refresh c_nonce and c_nonce_expires_at
        // -> requires c_nonce HashMap in State to cater for deferred requests
        //    with proof based on an older c_nonce
        // --------------------------------------------------------------------
        // let Some(provider) = &self.provider else {
        //     err!("provider not set");
        // };

        // let c_nonce = gen::nonce();
        // token_state.c_nonce = c_nonce.to_string();
        // token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
        // state.token = Some(token_state.clone());
        // let buf = serde_json::to_vec(&state)?;
        // StateManager::put(provider, &token_state.access_token, buf, state.expires_at).await?;

        Ok(BatchCredentialResponse {
            credential_responses: responses.clone(),
            c_nonce: Some(token_state.c_nonce.clone()),
            c_nonce_expires_in: Some(token_state.c_nonce_expires_in()),
        })
    }
}

impl<P> Context<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    // Processes the Credential Request to generate a Credential Response.
    #[instrument]
    async fn make_response(
        &self, provider: &P, request: &CredentialRequest,
    ) -> Result<CredentialResponse> {
        trace!("Context::make_response");

        // Try to create a VC. If None, then return a deferred issuance response.
        let Some(mut vc) = self.make_vc(provider, request).await? else {
            //--------------------------------------------------
            // Defer credential issuance
            //--------------------------------------------------
            let mut state = self.state.clone();
            let txn_id = gen::transaction_id();

            // save credential request in state for later use in a deferred request.
            state.deferred = Some(Deferred {
                transaction_id: txn_id.clone(),
                credential_request: request.clone(),
            });
            state.token = None;

            let buf = serde_json::to_vec(&state)?;
            StateManager::put(provider, &txn_id, buf, state.expires_at).await?;

            // only need to return transaction_id
            return Ok(CredentialResponse {
                transaction_id: Some(txn_id),
                ..Default::default()
            });
        };

        // transform to JWT
        let mut vc_jwt = vc.to_jwt()?;
        vc_jwt.claims.sub.clone_from(&self.holder_did);
        let signed = vc_jwt.sign(provider.clone()).await?;

        Ok(CredentialResponse {
            credential: Some(serde_json::to_value(signed)?),
            ..Default::default()
        })
    }

    // Attempt to generate a Verifiable Credential from information provided in the Credential
    // Request. May return `None` if the credential is not ready to be issued because the request
    // for Holder is pending.
    #[instrument]
    async fn make_vc(
        &self, provider: &P, request: &CredentialRequest,
    ) -> Result<Option<VerifiableCredential>> {
        trace!("Context::make_vc");

        let cred_def = self.credential_definition(request)?;
        let Some(holder_id) = &self.state.holder_id else {
            err!(Err::AccessDenied, "holder not found");
        };

        // claim values
        let holder_claims = Holder::claims(provider, holder_id, &cred_def).await?;
        if holder_claims.pending {
            return Ok(None);
        }

        // check mandatory claims are populated
        let Some(cred_subj) = cred_def.credential_subject.clone() else {
            err!("Credential subject not set");
        };
        for (name, claim) in &cred_subj {
            if claim.mandatory.unwrap_or_default() && !holder_claims.claims.contains_key(name) {
                err!(Err::InvalidCredentialRequest, "mandatory claim {name} not populated");
            }
        }

        // create proof
        // TODO: add all fields required by JWT
        let proof = w3c::vc::Proof {
            id: Some(format!("urn:uuid:{}", Uuid::new_v4())),
            type_: Signer::algorithm(provider).proof_type(),
            verification_method: Signer::verification_method(provider),
            created: Some(Utc::now()),
            expires: Utc::now().checked_add_signed(TimeDelta::try_hours(1).unwrap_or_default()),
            //domain: Some(vec![request.client_id.clone()]),
            ..Default::default()
        };

        let credential_issuer = &self.issuer_meta.credential_issuer;

        // HACK: fix this
        let Some(types) = cred_def.type_ else {
            err!("Credential type not set");
        };

        let vc_id = format!("{credential_issuer}/credentials/{}", types[1].clone());

        let vc = VerifiableCredential::builder()
            .add_context(credential_issuer.clone() + "/credentials/v1")
            // TODO: generate credential id
            .id(vc_id)
            .add_type(types[1].clone())
            .issuer(credential_issuer.clone())
            .add_subject(CredentialSubject {
                id: Some(self.holder_did.clone()),
                claims: holder_claims.claims,
            })
            .add_proof(proof)
            .build()?;

        Ok(Some(vc))
    }

    // Get the request's credential definition. If it does not exist, create it.
    #[instrument]
    fn credential_definition(&self, request: &CredentialRequest) -> Result<CredentialDefinition> {
        trace!("Context::credential_definition");

        if let Some(mut cred_def) = request.credential_definition.clone() {
            // add credential subject when not present
            if cred_def.credential_subject.is_none() {
                let maybe_supported = request.credential_identifier.as_ref().map_or_else(
                    || {
                        self.issuer_meta.credential_configurations_supported.values().find(|v| {
                            Some(&v.format) == request.format.as_ref()
                                && v.credential_definition.type_ == cred_def.type_
                        })
                    },
                    |id| self.issuer_meta.credential_configurations_supported.get(id),
                );

                let Some(supported) = maybe_supported else {
                    err!(Err::InvalidCredentialRequest, "credential is not supported");
                };

                // copy credential subject
                cred_def
                    .credential_subject
                    .clone_from(&supported.credential_definition.credential_subject);
            };

            Ok(cred_def)
        } else {
            let Some(id) = &request.credential_identifier else {
                err!(Err::InvalidCredentialRequest, "no credential identifier");
            };
            let Some(supported) = self.issuer_meta.credential_configurations_supported.get(id)
            else {
                err!(Err::InvalidCredentialRequest, "no supported credential for identifier {id}");
            };

            Ok(CredentialDefinition {
                context: None,
                type_: supported.credential_definition.type_.clone(),
                credential_subject: supported.credential_definition.credential_subject.clone(),
            })
        }
    }

    /// Creates, stores, and returns new `c_nonce` and `c_nonce_expires`_in values
    /// for use in `Err::InvalidProof` errors, as per specification.
    async fn err_nonce(&self, provider: &P) -> Result<(String, i64)> {
        // generate nonce and update state
        let mut state = self.state.clone();
        let Some(mut token_state) = state.token else {
            err!("token state not set");
        };

        let c_nonce = gen::nonce();
        token_state.c_nonce.clone_from(&c_nonce);
        token_state.c_nonce_expires_at = Utc::now() + Expire::Nonce.duration();
        state.token = Some(token_state.clone());

        StateManager::put(provider, &token_state.access_token, state.to_vec(), state.expires_at)
            .await?;

        Ok((c_nonce, Expire::Nonce.duration().num_seconds()))
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::vci_provider::{Provider, ISSUER, NORMAL_USER};
    use test_utils::wallet;
    use vercre_core::jwt;
    use vercre_core::w3c::vc::VcClaims;

    use super::*;
    use crate::state::Token;

    #[tokio::test]
    async fn authorization_details() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let access_token = "ABCDEF";
        let c_nonce = "1234ABCD";
        let credentials = vec![String::from("EmployeeID_JWT")];

        // set up state
        let mut state = State::builder()
            .credential_issuer(ISSUER.to_string())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credential_configuration_ids(credentials)
            .holder_id(Some(NORMAL_USER.to_string()))
            .build()
            .expect("should build state");

        state.token = Some(Token {
            access_token: access_token.to_string(),
            token_type: String::from("Bearer"),
            c_nonce: c_nonce.to_string(),
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            ..Default::default()
        });

        StateManager::put(&provider, access_token, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        // create BatchCredentialRequest to 'send' to the app
        let jwt_enc = Jwt {
            header: jwt::Header {
                typ: String::from("vercre-vci-proof+jwt"),
                alg: wallet::alg(),
                kid: wallet::kid(),
            },
            claims: ProofClaims {
                iss: wallet::did(),
                aud: ISSUER.to_string(),
                iat: Utc::now().timestamp(),
                nonce: c_nonce.to_string(),
            },
        }
        .to_string();
        let sig = wallet::sign(jwt_enc.as_bytes());
        let sig_enc = Base64UrlUnpadded::encode_string(&sig);
        let signed_jwt = format!("{jwt_enc}.{sig_enc}");

        let body = json!({
            "credential_requests":[{
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": ["VerifiableCredential", "EmployeeIDCredential"],
                    "credentialSubject": {
                        "givenName": {},
                        "familyName": {},
                    }
                },
                "proof":{
                    "proof_type": "jwt",
                    "jwt": signed_jwt
                }
            }]
        });

        let mut request = serde_json::from_value::<BatchCredentialRequest>(body)
            .expect("request should deserialize");
        request.credential_issuer = ISSUER.to_string();
        request.access_token = access_token.to_string();

        let response =
            Endpoint::new(provider.clone()).batch(&request).await.expect("response is valid");
        assert_snapshot!("ad-response", &response, {
            ".credential_responses[0]" => "[credential]",
            ".c_nonce" => "[c_nonce]",
            ".c_nonce_expires_in" => "[c_nonce_expires_in]"
        });

        // verify credential
        assert!(response.credential_responses.len() == 1);
        let credential = response.credential_responses[0].credential.clone();

        let vc_val = credential.expect("VC is present");
        let vc_b64 = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
        let vc_jwt = Jwt::<VcClaims>::from_str(&vc_b64).expect("VC as JWT");
        assert_snapshot!("ad-vc_jwt", vc_jwt, {
            ".claims.iat" => "[iat]",
            ".claims.nbf" => "[nbf]",
            ".claims.vc.issuanceDate" => "[issuanceDate]",
            ".claims.vc.credentialSubject" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(buf), StateManager::get(&provider, access_token).await);
        let state = State::try_from(buf).expect("state is valid");
        assert_snapshot!("ad-state", state, {
            ".expires_at" => "[expires_at]",
            ".token.c_nonce"=>"[c_nonce]",
            ".token.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });
    }

    // #[tokio::test]
    // async fn credential_identifiers() {
    //     test_utils::init_tracer();

    //     let provider = Provider::new();
    //     let access_token = "ABCDEF";
    //     let c_nonce = "1234ABCD";
    //     let identifiers = vec![String::from("EmployeeID_JWT")];

    //     // set up state
    //     let mut state = State::builder()
    //         .credential_issuer(ISSUER.to_string())
    //         .expires_at(Utc::now() + Expire::AuthCode.duration())
    //         .holder_id(Some(NORMAL_USER.to_string()))
    //         .build()
    //         .expect("should build state");

    //     state.token = Some(Token {
    //         access_token: access_token.to_string(),
    //         token_type: String::from("Bearer"),
    //         c_nonce: c_nonce.to_string(),
    //         c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
    //         ..Default::default()
    //     });

    //     StateManager::put(&provider, access_token, state.to_vec(), state.expires_at)
    //         .await
    //         .expect("state exists");

    //     // create BatchCredentialRequest to 'send' to the app
    //     let jwt_enc = Jwt {
    //         header: jwt::Header {
    //             typ: String::from("vercre-vci-proof+jwt"),
    //             alg: wallet::alg(),
    //             kid: wallet::kid(),
    //         },
    //         claims: ProofClaims {
    //             iss: wallet::did(),
    //             aud: ISSUER.to_string(),
    //             iat: Utc::now().timestamp(),
    //             nonce: c_nonce.to_string(),
    //         },
    //     }
    //     .to_string();
    //     let sig = wallet::sign(jwt_enc.as_bytes());
    //     let sig_enc = Base64UrlUnpadded::encode_string(&sig);
    //     let signed_jwt = format!("{jwt_enc}.{sig_enc}");

    //     let body = json!({
    //         "credential_requests":[{
    //             "credential_identifier": "EmployeeID_JWT",
    //             "proof":{
    //                 "proof_type": "jwt",
    //                 "jwt": signed_jwt
    //             }
    //         }]
    //     });

    //     let mut request = serde_json::from_value::<BatchCredentialRequest>(body)
    //         .expect("request should deserialize");
    //     request.credential_issuer = ISSUER.to_string();
    //     request.access_token = access_token.to_string();

    //     let response =
    //         Endpoint::new(provider.clone()).batch(&request).await.expect("response is valid");
    //     assert_snapshot!("ci-response", response, {
    //         ".credential_responses[0]" => "[credential]",
    //         ".c_nonce" => "[c_nonce]",
    //         ".c_nonce_expires_in" => "[c_nonce_expires_in]"
    //     });

    //     // verify credential
    //     assert!(response.credential_responses.len() == 1);
    //     let credential = response.credential_responses[0].credential.clone();

    //     let vc_val = credential.expect("VC is present");
    //     let vc_b64 = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
    //     let vc_jwt = Jwt::<VcClaims>::from_str(&vc_b64).expect("VC as JWT");
    //     assert_snapshot!("ci-vc_jwt", vc_jwt, {
    //         ".claims.iat" => "[iat]",
    //         ".claims.nbf" => "[nbf]",
    //         ".claims.vc.issuanceDate" => "[issuanceDate]",
    //         ".claims.vc.credentialSubject" => insta::sorted_redaction()
    //     });

    //     // token state should remain unchanged
    //     assert_let!(Ok(buf), StateManager::get(&provider, access_token).await);
    //     let state = State::try_from(buf).expect("state is valid");
    //     assert_snapshot!("ci-state", state, {
    //         ".expires_at" => "[expires_at]",
    //         ".token.c_nonce"=>"[c_nonce]",
    //         ".token.c_nonce_expires_at" => "[c_nonce_expires_at]"
    //     });
    // }
}
