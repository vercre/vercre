//! # Credential Endpoint
//!
//! The Credential Handler issues a Credential as approved by the End-User upon
//! presentation of a valid Access Token representing this approval.
//!
//! The Wallet sends one Credential Request per individual Credential to the
//! Credential Handler. The Wallet MAY use the same Access Token to send
//! multiple Credential Requests to request issuance of multiple Credentials of
//! different types bound to the same proof, or multiple Credentials of the same
//! type bound to different proofs.
//!
//! ## Credential Requests
//!
//! - One (and only one) of `credential_identifier` or `format` is REQUIRED.
//! - `credential_identifier` is REQUIRED when `credential_identifiers` parameter
//!   was returned from the Token Response. MUST NOT be used otherwise.
//! - When `format` is set, `credential_definition` is REQUIRED.
//!
//! **VC Signed as a JWT, Not Using JSON-LD**
//!
//! - `format` is `"jwt_vc_json"`. REQUIRED.
//! - `credential_definition`. REQUIRED.
//!   - `type`. REQUIRED.
//!   - `credentialSubject`. OPTIONAL.
//!
//! ## Example
//!
//! ```json
// ! {
// !    "format": "jwt_vc_json",
// !    "credential_definition": {
// !       "type": [
// !          "VerifiableCredential",
// !          "UniversityDegreeCredential"
// !       ],
// !       "credentialSubject": {
// !          "given_name": {},
// !          "family_name": {},
// !          "degree": {}
// !       }
// !    },
// !    ...
// ! }
//! ```

use std::fmt::Debug;

use tracing::{instrument, trace};
use vercre_core::error::Err;
use vercre_core::provider::{Callback, Client, Holder, Issuer, Server, Signer, StateManager};
#[allow(clippy::module_name_repetitions)]
pub use vercre_core::vci::{BatchCredentialRequest, CredentialRequest, CredentialResponse};
use vercre_core::{err, Result};

use super::Endpoint;
use crate::state::State;

impl<P> Endpoint<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Credential request handler.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    pub async fn credential(&self, request: &CredentialRequest) -> Result<CredentialResponse> {
        let Ok(buf) = StateManager::get(&self.provider, &request.access_token).await else {
            err!(Err::AccessDenied, "invalid access token");
        };
        let Ok(state) = State::try_from(buf) else {
            err!(Err::AccessDenied, "invalid state for access token");
        };

        let ctx = Context {
            callback_id: state.callback_id.clone(),
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    callback_id: Option<String>,
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    type Provider = P;
    type Request = CredentialRequest;
    type Response = CredentialResponse;

    // TODO: get callback_id from state
    fn callback_id(&self) -> Option<String> {
        self.callback_id.clone()
    }

    #[instrument]
    async fn process(
        &self, provider: &Self::Provider, request: &Self::Request,
    ) -> Result<Self::Response> {
        trace!("Context::process");

        let batch_req = BatchCredentialRequest {
            credential_issuer: request.credential_issuer.clone(),
            access_token: request.access_token.clone(),
            credential_requests: vec![request.clone()],
        };
        let batch_res = Endpoint::new(provider.clone()).batch(&batch_req).await?;

        // set c_nonce and c_nonce_expires_at - batch endpoint sets them in the
        // top-level response, not each credential response
        let mut cred_res = batch_res.credential_responses[0].clone();
        cred_res.c_nonce = batch_res.c_nonce;
        cred_res.c_nonce_expires_in = batch_res.c_nonce_expires_in;

        Ok(cred_res)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use assert_let_bind::assert_let;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::vci_provider::{Provider, ISSUER, NORMAL_USER};
    use test_utils::wallet;
    use vercre_core::jwt::{self, Jwt};
    use vercre_core::vci::ProofClaims;
    use vercre_core::w3c::vc::VcClaims;

    use super::*;
    use crate::state::{Expire, Token};

    #[tokio::test]
    async fn credential_ok() {
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
            .expect("state saved");

        // create CredentialRequest to 'send' to the app
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
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ]
            },
            "proof":{
                "proof_type": "jwt",
                "jwt": signed_jwt
            }
        });

        let mut request =
            serde_json::from_value::<CredentialRequest>(body).expect("request should deserialize");
        request.credential_issuer = ISSUER.to_string();
        request.access_token = access_token.to_string();

        let response =
            Endpoint::new(provider.clone()).credential(&request).await.expect("response is valid");
        assert_snapshot!("response", &response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
            ".c_nonce_expires_in" => "[c_nonce_expires_in]"
        });

        // verify credential
        let vc_val = response.credential.expect("VC is present");
        let vc_b64 = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
        let vc_jwt = Jwt::<VcClaims>::from_str(&vc_b64).expect("VC as JWT");
        assert_snapshot!("vc_jwt", vc_jwt, {
            ".claims.iat" => "[iat]",
            ".claims.nbf" => "[nbf]",
            ".claims.vc.issuanceDate" => "[issuanceDate]",
            ".claims.vc.credentialSubject" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(buf), StateManager::get(&provider, access_token).await);
        let state = State::try_from(buf).expect("state is valid");
        assert_snapshot!("state", state, {
            ".expires_at" => "[expires_at]",
            ".token.c_nonce"=>"[c_nonce]",
            ".token.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });
    }
}
