//! # W3C Verifiable Credentials Data Model
//!
//! An implementation of W3C [Verifiable Credentials Data Model v1.1].
//!
//! See [implementation guidelines].
//!
//! [Verifiable Credentials Data Model v1.1]: (https://www.w3.org/TR/vc-data-model)
//! [implementation guidelines]: (https://model.github.io/vc-imp-guide)

use std::collections::HashMap;
use std::convert::Infallible;
use std::str::FromStr;

use anyhow::bail;
use chrono::{DateTime, Utc};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{Context, OneSet, StrObj};
use crate::proof::integrity::Proof;

/// `VerifiableCredential` represents a naive implementation of the W3C Verifiable
/// Credential data model v1.1.
/// See <https://www.w3.org/TR/vc-data-model>.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct VerifiableCredential {
    // LATER: add support for @context objects
    #[allow(rustdoc::bare_urls)]
    /// The @context property is used to map property URIs into short-form aliases.
    /// It is an ordered set where the first item is "`https://www.w3.org/2018/credentials/v1`".
    /// Subsequent items may be composed of any combination of URLs and/or objects,
    /// each processable as a [JSON-LD Context](https://www.w3.org/TR/json-ld11/#the-context).
    #[serde(rename = "@context")]
    pub context: Vec<Context>,

    #[allow(rustdoc::bare_urls)]
    /// The credential's URI. It is RECOMMENDED that if dereferenced, the URI
    /// results in a document containing machine-readable information about
    /// the id (a schema). For example, "`http://example.edu/credentials/3732`".
    pub id: String,

    /// The type property is used to uniquely identify the type of the credential.
    /// That is, to indicate the set of claims the credential contains. It is an
    /// unordered set of URIs (full or relative to @context). It is RECOMMENDED that
    /// each URI, if dereferenced, will result in a document containing machine-readable
    /// information about the type. Syntactic conveniences, such as JSON-LD, SHOULD
    /// be used to ease developer usage.
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// A URI or object with an id property. It is RECOMMENDED that the
    /// URI/object id, dereferences to machine-readable information about
    /// the issuer that can be used to verify credential information.
    pub issuer: StrObj<Issuer>,

    /// An XMLSCHEMA11-2 (RFC3339) date-time the credential becomes valid.
    /// e.g. 2010-01-01T19:23:24Z.
    pub issuance_date: DateTime<Utc>,

    /// A set of objects containing claims about credential subjects(s).
    pub credential_subject: OneSet<CredentialSubject>,

    /// One or more cryptographic proofs that can be used to detect tampering
    /// and verify authorship of a credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneSet<Proof>>,

    /// An XMLSCHEMA11-2 (RFC3339) date-time the credential ceases to be valid.
    /// e.g. 2010-06-30T19:23:24Z
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,

    /// Used to determine the status of the credential, such as whether it is
    /// suspended or revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,

    /// The credentialSchema defines the structure and datatypes of the
    /// credential. Consists of one or more schemas that can be used to
    /// check credential data conformance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<OneSet<CredentialSchema>>,

    /// `RefreshService` can be used to provide a link to the issuer's refresh
    /// service so Holder's can refresh (manually or automatically) an
    /// expired credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_service: Option<RefreshService>,

    /// Terms of use can be utilized by an issuer or a holder to communicate the
    /// terms under which a verifiable credential or verifiable presentation
    /// was issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_use: Option<Vec<Term>>,

    /// Evidence can be included by an issuer to provide the verifier with
    /// additional supporting information in a credential. This could be
    /// used by the verifier to establish the confidence with which it
    /// relies on credential claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<Evidence>>,
}

// TODO: create structured @context object

impl VerifiableCredential {
    /// Returns a new [`VerifiableCredential`] configured with defaults.
    ///
    /// # Errors
    ///
    /// Fails with `Err::ServerError` if any of the VC's mandatory fields are not set.
    pub fn new() -> anyhow::Result<Self> {
        Self::builder().try_into()
    }

    /// Returns a new [`VcBuilder`], which can be used to build a [`VerifiableCredential`]
    #[must_use]
    pub fn builder() -> VcBuilder {
        VcBuilder::new()
    }

    /// Returns a sample [`VerifiableCredential`] for use in type generation
    #[must_use]
    pub fn sample() -> Self {
        use chrono::TimeZone;

        Self {
            context: vec![
                Context::Url("https://www.w3.org/2018/credentials/v1".into()),
                Context::Url("https://www.w3.org/2018/credentials/examples/v1".into()),
            ],
            type_: vec!["VerifiableCredential".into(), "EmployeeIDCredential".into()],
            issuer: StrObj::String("https://example.com/issuers/14".into()),
            id: "https://example.com/credentials/3732".into(),
            issuance_date: Utc.with_ymd_and_hms(2023, 11, 20, 23, 21, 55).unwrap(),
            credential_subject: OneSet::One(CredentialSubject {
                id: Some("did:example:ebfeb1f712ebc6f1c276e12ec21".into()),
                claims: HashMap::from([("employeeId".into(), serde_json::json!("1234567890"))]),
            }),
            expiration_date: Some(Utc.with_ymd_and_hms(2023, 12, 20, 23, 21, 55).unwrap()),

            ..Self::default()
        }
    }
}

impl vercre_exch::Claims for VerifiableCredential {
    fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(self).map_err(Into::into)
    }
}

// impl TryFrom<VerifiableCredential> for Value {
//     type Error = anyhow::Error;

//     fn try_from(vc: VerifiableCredential) -> anyhow::Result<Self> {
//         serde_json::to_value(vc).map_err(Into::into)
//     }
// }

/// Issuer identifies the issuer of the credential.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Issuer {
    /// The issuer URI. If dereferenced, it should result in a machine-readable
    /// document that can be used to verify the credential.
    pub id: String,

    /// Issuer-specific fields that may be used to express additional
    /// information about the issuer.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, Value>>,
}

/// Derserialize Issuer from string or object. If a string, then it is the issuer's
/// id, else deserialize as object.
impl FromStr for Issuer {
    type Err = Infallible;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        Ok(Self {
            id: s.to_string(),
            extra: None,
        })
    }
}

/// Serialize `Issuer` to string or object. If only the `id` field is set,
/// serialize to string, otherwise serialize to object.
impl Serialize for Issuer {
    fn serialize<S>(&self, serializer: S) -> anyhow::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(extra) = &self.extra {
            // serialize the entire object, flattening any 'extra' fields.
            tracing::debug!("serializing issuer to object: {:?}", &self);
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("id", &self.id)?;
            for (k, v) in extra {
                map.serialize_entry(&k, &v)?;
            }
            map.end()
        } else {
            // serialize to string when no extra fields are present
            tracing::debug!("serializing issuer to string: {}", &self.id);
            serializer.serialize_str(&self.id)
        }
    }
}

/// `CredentialSubject` holds claims about the subject(s) referenced by the credential.
/// Or, more correctly: a set of objects containing one or more properties related to
/// a subject of the credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialSubject {
    /// A URI that uniquely identifies the subject of the claims. if set, it
    /// MUST be the identifier used by others to identify the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Claims about the subject.
    #[serde(flatten)]
    pub claims: HashMap<String, Value>,
}

// Unused, but required by 'flexvec' deserializer FromStr trait
impl FromStr for CredentialSubject {
    type Err = Infallible;

    fn from_str(_: &str) -> anyhow::Result<Self, Self::Err> {
        unimplemented!("CredentialSubject::from_str")
    }
}

/// `CredentialStatus` can be used for the discovery of information about the
/// current status of a credential, such as whether it is suspended or revoked.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialStatus {
    /// A URI where credential status information can be retrieved.
    pub id: String,

    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential.
    #[serde(rename = "type")]
    pub type_: String,
}

/// `CredentialSchema` defines the structure of the credential and the datatypes
/// of each property contained. It can be used to verify if credential data is
/// syntatically correct. The precise contents of each data schema is determined
/// by the specific type definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialSchema {
    /// A URI identifying the schema file.
    pub id: String,

    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential. e.g. "`JsonSchemaValidator2018`"
    #[serde(rename = "type")]
    pub type_: String,
}

// Unused, but required by 'option_flexvec' deserializer FromStr trait
impl FromStr for CredentialSchema {
    type Err = Infallible;

    fn from_str(_: &str) -> anyhow::Result<Self, Self::Err> {
        unimplemented!("CredentialSchema::from_str")
    }
}

/// `RefreshService` can be used to provide a link to the issuer's refresh service
/// so Holder's can refresh (manually or automatically) an expired credential.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct RefreshService {
    /// A URI where credential status information can be retrieved.
    pub id: String,

    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential.
    #[serde(rename = "type")]
    pub type_: String,
}

/// Term is a single term used in defining the issuers terms of use.
/// In aggregate, the termsOfUse property tells the verifier what actions it is
/// required to perform (an obligation), not allowed to perform (a prohibition),
/// or allowed to perform (a permission) if it is to accept the verifiable
/// credential or verifiable presentation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Term {
    /// Refers to the status method used to provide the (machine readable)
    /// status of the credential.
    #[serde(rename = "type")]
    pub type_: String,

    /// A URI where credential policy information can be retrieved.
    pub id: String,

    /// A human-readable description of the term.
    pub profile: String,

    /// An obligation tells the verifier what actions it is required to perform
    /// if it is to accept the verifiable credential or verifiable presentation.
    pub obligation: Option<Vec<Policy>>,

    /// A prohibition tells the verifier what actions it is not allowed to
    /// perform if it is to accept the verifiable credential or verifiable
    /// presentation.
    pub prohibition: Option<Vec<Policy>>,

    /// A permission tells the verifier what actions it is allowed to perform
    /// if it is to accept the verifiable credential or verifiable presentation.
    pub permission: Option<Vec<Policy>>,
}

/// Prohibition defines what actions a verifier is not allowed to perform.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Policy {
    ///  A URI identifying the credential issuer.
    assigner: String,

    /// A URI identifying the credential verifier.
    assignee: String,

    /// A URI identifying the credential (the credential `id`).
    target: String,

    /// A list of prohibited actions
    action: Vec<String>,
}

/// Evidence can be included by an issuer to provide the verifier with
/// additional supporting information in a credential. This could be used by the
/// verifier to establish the confidence with which it relies on credential
/// claims.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Evidence {
    /// A URL pointing to where more information about this instance of evidence
    /// can be found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Type identifies the evidence scheme used for the instance of evidence.
    /// For example, "`DriversLicense`" or "`Passport`".
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// A URI identifying the credential issuer (i.e. verifier of evidence).
    pub verifier: String,

    /// Evidence document identifies the evidence scheme.
    #[serde(rename = "evidenceDocument")]
    pub evidence_document: String,

    /// Whether the subject was present when the evidence was collected.
    /// For example, "Physical".
    #[serde(rename = "subjectPresence")]
    pub subject_presence: String,

    /// Whether the evidence document was present when the evidence was
    /// collected. For example, "Physical".
    #[serde(rename = "documentPresence")]
    pub document_presence: String,

    /// A list of schema-specific evidence fields.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, String>>,
}

/// [`VcBuilder`] is used to build a [`VerifiableCredential`]
#[derive(Clone, Debug, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct VcBuilder {
    vc: VerifiableCredential,
}

impl VcBuilder {
    /// Returns a new [`VcBuilder`]
    pub fn new() -> Self {
        tracing::debug!("VcBuilder::new");

        let mut builder: Self = Self::default();

        // set some sensibile defaults
        builder.vc.context.push(Context::Url("https://www.w3.org/2018/credentials/v1".into()));
        builder.vc.type_.push("VerifiableCredential".into());
        builder.vc.issuance_date = chrono::Utc::now(); //.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        builder
    }

    /// Sets the `@context` property
    #[must_use]
    pub fn add_context(mut self, context: Context) -> Self {
        self.vc.context.push(context);
        self
    }

    /// Sets the `id` property
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.vc.id = id.into();
        self
    }

    /// Sets the `type_` property
    #[must_use]
    pub fn add_type(mut self, type_: impl Into<String>) -> Self {
        self.vc.type_.push(type_.into());
        self
    }

    /// Sets the `issuer` property
    #[must_use]
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.vc.issuer = StrObj::String(issuer.into());
        self
    }

    /// Adds one or more `credential_subject` properties.
    #[must_use]
    pub fn add_subject(mut self, subj: CredentialSubject) -> Self {
        let one_set = match self.vc.credential_subject {
            OneSet::One(one) => {
                if one == CredentialSubject::default() {
                    OneSet::One(subj)
                } else {
                    OneSet::Set(vec![one, subj])
                }
            }
            OneSet::Set(mut set) => {
                set.push(subj);
                OneSet::Set(set)
            }
        };

        self.vc.credential_subject = one_set;
        self
    }

    /// Adds one or more `proof` properties.
    #[must_use]
    pub fn add_proof(mut self, proof: Proof) -> Self {
        let one_set = match self.vc.proof {
            None => OneSet::One(proof),
            Some(OneSet::One(one)) => OneSet::Set(vec![one, proof]),
            Some(OneSet::Set(mut set)) => {
                set.push(proof);
                OneSet::Set(set)
            }
        };

        self.vc.proof = Some(one_set);
        self
    }

    /// Turns this builder into a [`VerifiableCredential`]
    ///
    /// # Errors
    ///
    /// Fails with `Err::ServerError` if any of the VC's mandatory fields are not set.
    pub fn build(self) -> anyhow::Result<VerifiableCredential> {
        tracing::debug!("VcBuilder::build");

        if self.vc.context.len() < 2 {
            bail!("no context set");
        }
        if self.vc.id.is_empty() {
            bail!("no id set");
        }
        if self.vc.type_.len() < 2 {
            bail!("no type set");
        }

        if let StrObj::String(id) = &self.vc.issuer {
            if id.is_empty() {
                bail!("no issuer.id set");
            }
        }

        if let OneSet::One(subj) = &self.vc.credential_subject {
            if *subj == CredentialSubject::default() {
                bail!("no credential_subject set");
            }
        }

        Ok(self.vc)
    }
}

impl TryFrom<VcBuilder> for VerifiableCredential {
    type Error = anyhow::Error;

    fn try_from(builder: VcBuilder) -> anyhow::Result<Self, Self::Error> {
        tracing::debug!("VerifiableCredential::try_from");
        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use serde_json::json;
    use tracing_subscriber::FmtSubscriber;

    use super::*;

    // initalise tracing once for all tests
    static INIT: Once = Once::new();

    // Initialise tracing for tests.
    fn init_tracer() {
        INIT.call_once(|| {
            let subscriber =
                FmtSubscriber::builder().with_max_level(tracing::Level::ERROR).finish();
            tracing::subscriber::set_global_default(subscriber).expect("subscriber set");
        });
    }

    #[test]
    fn builder() {
        init_tracer();

        let vc = VerifiableCredential::sample();
        let json_vc = serde_json::to_value(&vc).expect("should serialize to json");
        println!("{}", json_vc);

        // serialize
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");

        assert_eq!(
            *vc_json.get("@context").expect("@context should be set"),
            json!([
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ])
        );
        assert_eq!(
            *vc_json.get("id").expect("id should be set"),
            json!("https://example.com/credentials/3732")
        );
        assert_eq!(
            *vc_json.get("type").expect("type should be set"),
            json!(["VerifiableCredential", "EmployeeIDCredential"])
        );
        assert_eq!(
            *vc_json.get("credentialSubject").expect("credentialSubject should be set"),
            json!({"employeeId":"1234567890","id":"did:example:ebfeb1f712ebc6f1c276e12ec21"})
        );
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!("https://example.com/issuers/14")
        );

        assert_eq!(
            *vc_json.get("issuanceDate").expect("issuanceDate should be set"),
            json!(vc.issuance_date)
        );

        // deserialize
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.context, vc.context);
        assert_eq!(vc_de.id, vc.id);
        assert_eq!(vc_de.type_, vc.type_);
        assert_eq!(vc_de.credential_subject, vc.credential_subject);
        assert_eq!(vc_de.issuer, vc.issuer);
    }

    #[test]
    fn flexvec() {
        init_tracer();

        let mut vc = VerifiableCredential::sample();
        vc.credential_schema = Some(OneSet::Set(vec![
            CredentialSchema { ..Default::default() },
            CredentialSchema { ..Default::default() },
        ]));

        // serialize
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");
        assert!(vc_json.get("proof").is_none());
        assert_eq!(
            *vc_json.get("credentialSchema").expect("credentialSchema should be set"),
            json!([{"id":"","type":""},{"id":"","type":""}]),
            "Vec with len() > 1 should serialize to array"
        );

        // deserialize
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.proof, vc.proof, "should deserialize to Vec");
        assert_eq!(
            vc_de.credential_schema, vc.credential_schema,
            "array should deserialize to Vec"
        );
    }

    #[test]
    fn strobj() {
        init_tracer();

        let mut vc = VerifiableCredential::sample();

        // serialize with just issuer 'id' field set
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!("https://example.com/issuers/14")
        );

        // deserialize from issuer as string,  e.g."issuer":"<value>"
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.issuer, vc.issuer);

        let mut issuer = match &vc.issuer {
            StrObj::Object(issuer) => issuer.clone(),
            StrObj::String(id) => Issuer {
                id: id.clone(),
                ..Issuer::default()
            },
        };
        issuer.extra =
            Some(HashMap::from([("name".into(), Value::String("Example University".into()))]));
        vc.issuer = StrObj::Object(issuer);

        // serialize
        let vc_json = serde_json::to_value(&vc).expect("should serialize to json");
        assert_eq!(
            *vc_json.get("issuer").expect("issuer should be set"),
            json!({"id": "https://example.com/issuers/14", "name": "Example University"}),
            "issuer 'extra' fields should flatten on serialization"
        );

        // deserialize
        let vc_de: VerifiableCredential =
            serde_json::from_value(vc_json).expect("should deserialize");
        assert_eq!(vc_de.issuer, vc.issuer, "issuer 'extra' fields should be populated");
    }
}
