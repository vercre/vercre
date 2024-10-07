//! # MSO MDOC
//!
//! See pg 31 of spec.
//!
//! The Mobile Security Object (MSO) Mobile Device Object (MDOC) is a data
//! structure that contains the data elements that are signed by the issuer
//! and the mobile device. The issuer signs the data elements to authenticate
//! the issuer data, and the mobile device signs the data elements to
//! authenticate the mobile device data. The MSO MDOC is returned in the
//! DeviceResponse structure.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// DeviceResponse structure
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    /// Version of the DeviceResponse structure
    pub version: String,

    /// Returned documents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<Vec<Document>>,

    /// For unreturned documents, optional error codes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_errors: Option<HashMap<String, ErrorCode>>,
}

/// Document returned by the mdoc
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// Document type returned
    pub doc_type: String,

    /// Returned data elements signed by the issuer
    pub issuer_signed: IssuerSigned,

    /// Returned data elements signed by the mdoc
    pub device_signed: IssuerSigned,

    /// Optional errors for unreturned data elements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<ErrorCode>>,
}

/// Error codes for unreturned documents
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum ErrorCode {
    /// Error code for unreturned documents
    #[default]
    SomeCode,
}

/// Data elements signed by the issuer
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    /// Returned data elements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_spaces: Option<HashMap<String, Vec<IssuerSignedItem>>>,

    /// Contains the mobile security object (MSO) for issuer data authentication
    /// Encode as MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
    pub issuer_auth: MobileSecurityObject,
}

/// Issuer-signed data element
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    /// Digest ID for issuer data authentication
    digest_id: usize,

    /// Random hexadecimal value for issuer data authentication
    random: String,

    /// Data element identifier. For example, "family_name"
    element_identifier: String,

    /// Data element value. For example, "Smith"
    element_value: ElementValue,
}

/// Data element value
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ElementValue {
    /// String value
    String(String),

    /// Bytes value
    Bytes(Vec<u8>),
}

impl Default for ElementValue {
    fn default() -> Self {
        ElementValue::String(String::new())
    }
}

/// An mdoc digital signature is generated over the mobile security object (MSO).
/// See 9.1.2.4 Signing method and structure for MSO.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MobileSecurityObject {
    /// Version of the MobileSecurityObject
    version: String,

    /// Message digest algorithm used
    digest_algorithm: String,

    /// Digests of all data elements by namespace
    value_digests: HashMap<String, Vec<HashMap<usize, DeviceKey>>>,

    ///
    device_key_info: DeviceKeyInfo,

    /// docType as used in Documents
    doc_type: String,

    ///
    validity_info: ValidityInfo,
}

/// Device key info
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    /// Device key
    device_key: HashMap<usize, DeviceKey>,

    /// Key authorizations
    #[serde(skip_serializing_if = "Option::is_none")]
    key_authorizations: Option<Vec<KeyAuthorization>>,

    /// Key info
    #[serde(skip_serializing_if = "Option::is_none")]
    key_info: Option<HashMap<usize, DeviceKey>>,
}

/// Device key
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum DeviceKey {
    /// Device key as a string
    String(String),

    /// Device key as an integer
    Int(usize),
}

/// Key authorization
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorization {
    /// Key authorization namespace
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_spaces: Option<Vec<String>>,

    /// Map of data elements by name space.
    /// e.g. <namespace: [data elements]>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_elements: Option<HashMap<String, Vec<String>>>,
}

/// Validity information for the MSO
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValidityInfo {
    signed: String,

    valid_from: String,

    valid_until: String,
}
