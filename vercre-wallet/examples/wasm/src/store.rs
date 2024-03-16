// TODO: replace the hard-coded sample code with a call to a hosted storage service

use std::vec;

use chrono::{DateTime, TimeDelta, Utc};
use gloo_console::log;
use serde::ser::SerializeMap;
use serde_json::ser;
use test_utils::vci_provider::ISSUER;
use vercre_core::provider::{Holder, Issuer, Signer};
use vercre_core::w3c::vc::Proof;
use vercre_core::w3c::{CredentialSubject, VerifiableCredential};
use vercre_wallet::store::{StoreEntry, StoreRequest, StoreResponse};

pub async fn request(op: &StoreRequest) -> Result<StoreResponse, Option<String>> {
    match op {
        StoreRequest::Add(id, value) => add(id, value),
        StoreRequest::List => list().await,
        StoreRequest::Delete(id) => delete(id),
    }
}

fn add(id: &str, value: &[u8]) -> Result<StoreResponse, Option<String>> {
    Ok(StoreResponse::Ok)
}

async fn list() -> Result<StoreResponse, Option<String>> {
    Ok(StoreResponse::List(hard_coded_credentials().await))
}

fn delete(id: &str) -> Result<StoreResponse, Option<String>> {
    Ok(StoreResponse::Ok)
}

// TODO: remove this when real back-end storage is called.

async fn hard_coded_credentials() -> Vec<StoreEntry> {
    use vercre_wallet::credential::{Credential, Logo};

    let dt = DateTime::parse_from_rfc3339("2024-02-29T00:26:45Z")
        .expect("error converting date-time string");
    let dt_utc = dt.with_timezone(&Utc);

    let provider = test_utils::vci_provider::Provider::new();
    let issuer = Issuer::metadata(&provider, test_utils::vci_provider::ISSUER)
        .await
        .expect("failed to load test issuer metadata");

    let proof1 = Proof {
        id: Some("urn:uuid:".to_string()),
        type_: Signer::algorithm(&provider).proof_type(),
        verification_method: Signer::verification_method(&provider),
        created: Some(dt_utc),
        expires: dt_utc.checked_add_signed(TimeDelta::try_hours(1).unwrap_or_default()),
        ..Default::default()
    };
    let iss = issuer.clone();
    let cd1 = iss
        .credential_configurations_supported
        .get("EmployeeID_JWT")
        .expect("EmployeeID_JWT credential configuration not found on issuer metadata");
    let types1 = cd1
        .clone()
        .credential_definition
        .type_
        .expect("no credential type on credential definition");
    let vc_id1 = format!("{}/credentials/{}", issuer.credential_issuer.clone(), types1[1].clone());
    let claims1 = Holder::claims(
        &provider,
        test_utils::vci_provider::NORMAL_USER,
        &cd1.credential_definition,
    )
    .await
    .expect("error looking up holder claims");
    let vc1 = VerifiableCredential::builder()
        .add_context(issuer.credential_issuer.clone() + "/credentials/v1")
        .id(vc_id1.clone())
        .add_type(types1[1].clone())
        .issuer(issuer.credential_issuer.clone())
        .add_subject(CredentialSubject {
            id: Some(test_utils::vci_provider::NORMAL_USER.to_string()),
            claims: claims1.claims,
        })
        .add_proof(proof1)
        .build()
        .expect("error building VC");
    let logo1 = Logo {
        media_type: "image/png".to_string(),
        image: "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".to_string(),
    };
    let c1 = Credential {
        id: vc_id1.clone(),
        issued: "2024-02-29T00:26:45Z".to_string(),
        metadata: issuer
            .credential_configurations_supported
            .clone()
            .get("EmployeeID_JWT")
            .expect("EmployeeID_JWT credential configuration not found on issuer metadata")
            .clone(),
        issuer: issuer.credential_issuer.clone(),
        vc: vc1,
        logo: None,
    };

    let ser = serde_json::to_vec(&c1).expect("failed to serialize credential");

    vec![StoreEntry(ser)]
}
