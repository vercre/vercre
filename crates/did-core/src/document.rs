//! # DID Document
//!
//! A DID Document is a JSON-LD document that contains information related to a DID.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Jwk;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    #[serde(rename = "@context")]
    pub context: Vec<Kind<Value>>,

    /// The DID for a particular DID subject.
    ///
    /// The subject is defined as the entity identified by the DID and described by the
    /// DID document. Anything can be a DID subject: person, group, organization,
    /// physical thing, digital thing, logical thing, etc.
    pub id: String,

    /// A set of URIs taht are other identifiers for the subject of the above DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,

    /// One or more strings that conform to the rules DID Syntax. The corresponding
    /// DID document(s) SHOULD contain verification relationships that explicitly
    /// permit the use of certain verification methods for specific purposes.
    ///
    /// Any verification methods contained in the related DID documents
    /// SHOULD be accepted as authoritative, such that proofs that satisfy those
    /// verification methods are to be considered equivalent to proofs provided by the
    /// DID subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Quota<String>>,

    /// If set, MUST be a set of verification methods for the DID subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,

    /// -----------------------------------------------------------------------
    /// Verification Relationships
    ///
    /// A verification relationship expresses the relationship between the DID subject
    /// and a verification method.
    /// -----------------------------------------------------------------------

    /// The `authentication` verification relationship is used to specify how the DID
    /// subject is expected to be authenticated, for purposes such as logging into
    /// a website or engaging in any sort of challenge-response protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Kind<VerificationMethod>>>,

    /// The `assertion_method` verification relationship is used to specify how the DID
    /// subject is expected to express claims, such as for the purposes of issuing a
    /// Verifiable Credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<Kind<VerificationMethod>>>,

    /// The `key_agreement` verification relationship is used to specify how an entity
    /// can generate encryption material in order to transmit confidential information
    /// intended for the DID subject, such as for the purposes of establishing a secure
    /// communication channel with the recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<Kind<VerificationMethod>>>,

    /// The `capability_invocation` verification relationship is used to specify a
    /// verification method that might be used by the DID subject to invoke a
    /// cryptographic capability, such as the authorization to update the DID Document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<Kind<VerificationMethod>>>,

    /// The `capability_delegation` verification relationship is used to specify a
    /// mechanism that might be used by the DID subject to delegate a cryptographic
    /// capability to another party, such as delegating the authority to access a
    /// specific HTTP API to a subordinate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<Kind<VerificationMethod>>>,

    /// A set of services, that express ways of communicating with the DID subject
    /// or related entities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_metadata: Option<DocumentMetadata>,
}

/// A DID document can express verification methods, such as cryptographic public keys,
/// which can be used to authenticate or authorize interactions with the DID subject or
/// associated parties. For example, a cryptographic public key can be used as a
/// verification method with respect to a digital signature; in such usage, it verifies
/// that the signer could use the associated cryptographic private key. Verification
/// methods might take many parameters. An example of this is a set of five
/// cryptographic keys from which any three are required to contribute to a
/// cryptographic threshold signature.
///
/// MAY include additional properties which can be determined from the verification
/// method as registered in the
/// [DID Specification Registries](https://www.w3.org/TR/did-spec-registries/).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// Only used when the verification method uses terms not defined in the containing
    /// document.
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Kind<Value>>,

    /// A DID that identifies the verification method.
    pub id: String,

    /// Kind references a verification method type.
    ///
    /// The verification method type SHOULD be registered in the DID Specification
    /// Registries
    #[serde(rename = "type")]
    pub type_: String,

    /// The DID of the controller of the verification method.
    pub controller: String,

    /// The public key material for the verification method. MUST NOT be set if the
    /// `public_key_jwk` property is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,

    /// The public key material for the verification method. MUST NOT be set if the
    /// `public_key_multibase` property is set.
    ///
    /// It is RECOMMENDED that verification methods that use JWKs use the `kid` value
    /// as the fragment identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Jwk>,
}

/// Services are used to express ways of communicating with the DID subject or
/// associated entities. They can be any type of service the DID subject wants
/// to advertise, including decentralized identity management services for further
/// discovery, authentication, authorization, or interaction.
///
/// Service information is often service specific. For example, a reference to an
/// encrypted messaging service can detail how to initiate the encrypted link before
/// messaging begins.
///
/// Due to privacy concerns, revealing public information through services, such as
/// social media accounts, personal websites, and email addresses, is discouraged.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// A URI unique to the service.
    pub id: String,

    /// The service type. SHOULD be registered in the DID Specification Registries.
    #[serde(rename = "type")]
    pub type_: String,

    /// One or more endpoints for the service.
    #[allow(clippy::struct_field_names)]
    pub service_endpoint: Quota<Kind<Value>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::module_name_repetitions)]
pub struct DocumentMetadata {
    pub method: MethodMetadata,
    pub equivalent_id: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MethodMetadata {
    pub published: bool,
    pub recovery_commitment: String,
    pub update_commitment: String,
}

/// Determines how Serde will serialize/deserialize the field: as a single entity
/// or a set of entities.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Quota<T> {
    /// Value is a singleton.
    One(T),

    /// Value is a set.
    Many(Vec<T>),
}

impl<T: Default> Default for Quota<T> {
    fn default() -> Self {
        Self::One(T::default())
    }
}

/// Determines how Serde will serialize/deserialize the field: as a string or the
/// type specified by `T`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Kind<T> {
    /// Value is a string
    Simple(String),

    /// Value is an object
    Rich(T),
}

impl<T: Default> Default for Kind<T> {
    fn default() -> Self {
        Self::Simple(String::new())
    }
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use serde_json::{json, Value};

    use super::*;

    #[test]
    fn test_key() {
        let de: Document = serde_json::from_value(DID_KEY.to_owned()).expect("should deserialize");

        // re-serialise and compare with original
        let ser = serde_json::to_value(de).expect("should serialize");
        assert_eq!(DID_KEY.to_owned(), ser)
    }

    static DID_KEY: LazyLock<Value> = LazyLock::new(|| {
        json!({
          "@context": [
            "https://www.w3.org/ns/did/v1",
            {
              "Ed25519VerificationKey2018": "https://w3id.org/security#Ed25519VerificationKey2018",
              "publicKeyJwk": {
                "@id": "https://w3id.org/security#publicKeyJwk",
                "@type": "@json"
              }
            }
          ],
          "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
          "verificationMethod": [
            {
              "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
              "type": "Ed25519VerificationKey2018",
              "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
              "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"
              }
            }
          ],
          "authentication": [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
          ],
          "assertionMethod": [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
          ]
        })
    });
}