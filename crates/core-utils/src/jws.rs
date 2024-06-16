//! # JOSE Proofs
//!
//! JSON Object Signing and Encryption ([JOSE]) proofs are a form of enveloping proofs
//! of Credentials based on JWT [RFC7519], JWS [RFC7515], and JWK [RFC7517].
//!
//! The Securing Verifiable Credentials using JOSE and COSE [VC-JOSE-COSE]
//! recommendation defines a "bridge" between these and the Verifiable Credentials Data
//! Model v2.0, specifying the suitable header claims, media types, etc.
//!
//! In the case of JOSE, the Credential is the "payload". This is preceded by a suitable
//! header whose details are specified by Securing Verifiable Credentials using JOSE and
//! COSE for the usage of JWT. These are encoded, concatenated, and signed, to be
//! transferred in a compact form by one entity to an other (e.g., sent by the holder to
//! the verifier). All the intricate details on signatures, encryption keys, etc., are
//! defined by the IETF specifications; see Example 6 for a specific case.
//!
//! ## Note
//!
//! If the JWT is only a JWE, iss, exp and aud MUST be omitted in the JWT Claims
//! Set of the JWE, and the processing rules as per JARM Section 2.4 related to
//! these claims do not apply. [OpenID4VP] JWT - JWE
//!
//! ```json
//! {
//!   "vp_token": "eyJI...",
//!   "presentation_submission": {...}
//! }
//! ```
//!
//! [JOSE]: https://datatracker.ietf.org/wg/jose/about
//! [RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
//! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
//! [VC-JOSE-COSE]: https://w3c.github.io/vc-jose-cose
//! [OpenID4VP]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

use std::fmt::{Debug, Display};
use std::str::{self, FromStr};

use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::Verifier;
use provider::{Algorithm, Signer};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The JWT `typ` claim.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Payload {
    /// JWT `typ` for Verifiable Credential.
    #[default]
    #[serde(rename = "jwt")]
    Credential,

    /// JWT `typ` for Verifiable Presentation.
    #[serde(rename = "jwt")]
    Presentation,

    /// JWT `typ` for Authorization Request Object.
    #[serde(rename = "oauth-authz-req+jwt")]
    Request,

    /// JWT `typ` for Wallet's Proof of possession of key material.
    #[serde(rename = "openidvci-proof+jwt")]
    Proof,
}

impl Display for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Encode the provided header and claims and sign, returning a JWT in compact JWS form.
///
/// # Errors
/// TODO: add error docs
pub async fn encode<T>(typ: Payload, claims: &T, signer: impl Signer) -> anyhow::Result<String>
where
    T: Serialize + Send + Sync,
{
    tracing::debug!("encode");

    // header
    let header = Header {
        alg: signer.algorithm(),
        typ,
        kid: Some(signer.verification_method()),
        ..Header::default()
    };

    // payload
    let header_raw = serde_json::to_vec(&header)?;
    let header_enc = Base64UrlUnpadded::encode_string(&header_raw);
    let claims_raw = serde_json::to_vec(claims)?;
    let claims_enc = Base64UrlUnpadded::encode_string(&claims_raw);
    let payload = format!("{header_enc}.{claims_enc}");

    // sign
    let sig = signer.try_sign(payload.as_bytes()).await?;
    let sig_enc = Base64UrlUnpadded::encode_string(&sig);

    Ok(format!("{payload}.{sig_enc}"))
}

// TODO: allow passing verifier into this method
/// Decode the JWT token and return the claims.
///
/// # Errors
/// TODO: Add errors
pub fn decode<T>(token: &str) -> anyhow::Result<Jwt<T>>
where
    T: DeserializeOwned,
{
    // TODO: cater for different key types
    let parts = token.split('.').collect::<Vec<&str>>();
    if parts.len() != 3 {
        bail!("invalid Compact JWS format");
    }

    // deserialize header, claims, and signature
    let decoded = Base64UrlUnpadded::decode_vec(parts[0])
        .map_err(|e| anyhow!("issue decoding header: {e}"))?;
    let header: Header =
        serde_json::from_slice(&decoded).map_err(|e| anyhow!("issue deserializing header: {e}"))?;
    let decoded = Base64UrlUnpadded::decode_vec(parts[1])
        .map_err(|e| anyhow!("issue decoding claims: {e}"))?;
    let claims =
        serde_json::from_slice(&decoded).map_err(|e| anyhow!("issue deserializing claims:{e}"))?;
    let sig = Base64UrlUnpadded::decode_vec(parts[2])
        .map_err(|e| anyhow!("issue decoding signature: {e}"))?;

    // check algorithm
    if !(header.alg == Algorithm::ES256K || header.alg == Algorithm::EdDSA) {
        bail!("'alg' is not recognised");
    }

    // verify signature
    let proof_jwk = Jwk::from_str(&header.kid.clone().unwrap_or_default())
        .map_err(|e| anyhow!("unable to parse 'kid' into JWK: {e}"))?;
    proof_jwk.verify(&format!("{}.{}", parts[0], parts[1]), &sig)?;

    Ok(Jwt { header, claims })
}

/// Represents a JWT as used for proof and credential presentation.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Jwt<T> {
    /// The JWT header.
    pub header: Header,

    /// The JWT claims.
    pub claims: T,
}

/// Represents the JWT header.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Header {
    /// Digital signature algorithm identifier as per IANA "JSON Web Signature
    /// and Encryption Algorithms" registry.
    pub alg: Algorithm,

    /// Used to declare the media type [IANA.MediaTypes](http://www.iana.org/assignments/media-types)
    /// of the JWS.
    pub typ: Payload,

    /// MAY be used if there are multiple keys associated with the issuer of the
    /// JWT. For example, kid can refer to a key in a DID document or a key
    /// inside a JWKS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Contains the key material the new Credential shall be bound to. It MUST NOT be
    /// present if kid is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,

    /// Contains a certificate or certificate chain corresponding to the key used to
    /// sign the JWT. This element MAY be used to convey a key attestation. In such a
    /// case, the actual key certificate will contain attributes related to the key
    /// properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<String>,

    /// Contains an OpenID.Federation Trust Chain. This element MAY be used to convey
    /// key attestation, metadata, metadata policies, federation Trust Marks and any
    /// other information related to a specific federation, if available in the chain.
    /// When used for signature verification, the header parameter kid MUST be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_chain: Option<String>,
}

/// Simplified JSON Web Key (JWK) key structure.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Jwk {
    /// Key identifier.
    /// For example, "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Key type. For example, "EC" for elliptic curve or "OKP" for octet
    /// key pair (Edwards curve).
    pub kty: String,

    /// Cryptographic curve type. For example, "ES256K" for secp256k1 and
    /// "X25519" for ed25519.
    pub crv: String,

    /// X coordinate.
    pub x: String,

    /// Y coordinate. Not required for `EdDSA` verification keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    /// Use of the key. For example, "sig" for signing or "enc" for
    /// encryption.
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

impl Jwk {
    /// Verify the signature of the provided message using the JWK.
    ///
    /// # Errors
    /// TODO: Add error descriptions
    pub fn verify(&self, msg: &str, sig: &[u8]) -> anyhow::Result<()> {
        match self.crv.as_str() {
            "ES256K" | "secp256k1" => self.verify_es256k(msg, sig), // kty: "EC"
            "X25519" => self.verify_eddsa(msg, sig),                // kty: "OKP"
            _ => bail!("Unsupported JWT signature algorithm"),
        }
    }

    // Verify the signature of the provided message using the ES256K algorithm.
    fn verify_es256k(&self, msg: &str, sig: &[u8]) -> anyhow::Result<()> {
        use ecdsa::{Signature, VerifyingKey};
        use k256::Secp256k1;

        // build verifying key
        let Some(y) = &self.y else {
            bail!("Proof JWT 'y' is invalid");
        };
        let mut sec1 = vec![0x04]; // uncompressed format
        sec1.append(&mut Base64UrlUnpadded::decode_vec(&self.x)?);
        sec1.append(&mut Base64UrlUnpadded::decode_vec(y)?);

        let verifying_key = VerifyingKey::<Secp256k1>::from_sec1_bytes(&sec1)?;
        let signature: Signature<Secp256k1> = Signature::from_slice(sig)?;

        Ok(verifying_key.verify(msg.as_bytes(), &signature)?)
    }

    // Verify the signature of the provided message using the EdDSA algorithm.
    fn verify_eddsa(&self, msg: &str, sig_bytes: &[u8]) -> anyhow::Result<()> {
        use ed25519_dalek::{Signature, VerifyingKey};

        // build verifying key
        let Ok(x_bytes) = Base64UrlUnpadded::decode_vec(&self.x) else {
            bail!("unable to base64 decode proof JWK 'x'");
        };
        let Ok(bytes) = &x_bytes.try_into() else {
            bail!("invalid public key length");
        };

        let Ok(verifying_key) = VerifyingKey::from_bytes(bytes) else {
            bail!("unable to build verifying key")
        };
        let Ok(signature) = Signature::from_slice(sig_bytes) else {
            bail!("unable to build signature")
        };

        let Ok(()) = verifying_key.verify(msg.as_bytes(), &signature) else {
            bail!("unable to verify signature")
        };

        Ok(())
    }
}

impl Display for Jwk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let jwk_str = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{jwk_str}")
    }
}

impl FromStr for Jwk {
    type Err = anyhow::Error;

    fn from_str(kid: &str) -> anyhow::Result<Self, Self::Err> {
        const DID_JWK: &str = "did:jwk:";
        const DID_ION: &str = "did:ion:";

        let jwk = if kid.starts_with(DID_JWK) {
            let jwk_b64 = kid.trim_start_matches(DID_JWK).trim_end_matches("#0");
            let Ok(jwk_vec) = Base64UrlUnpadded::decode_vec(jwk_b64) else {
                bail!("Issue decoding JWK base64");
            };
            let Ok(jwk_str) = str::from_utf8(&jwk_vec) else {
                bail!("Issue converting JWK bytes to string");
            };
            let Ok(jwk) = serde_json::from_str(jwk_str) else {
                bail!("Issue deserializing JWK string");
            };
            jwk
        } else if kid.starts_with(DID_ION) {
            verification_key(kid)?
        } else {
            bail!("Proof JWT 'kid' is invalid");
        };

        Ok(jwk)
    }
}

// Get the verification key for the specified DID.
fn verification_key(did: &str) -> anyhow::Result<Jwk> {
    let Some(did) = did.split('#').next() else {
        bail!("Unable to parse DID");
    };

    // if have long-form DID then try to extract key from metadata
    let did_parts: Vec<&str> = did.split(':').collect();
    if did_parts.len() != 4 {
        bail!("Short-form DID's are not supported");
    }

    let dec = match Base64UrlUnpadded::decode_vec(did_parts[3]) {
        Ok(dec) => dec,
        Err(e) => {
            bail!("Unable to decode DID: {e}");
        }
    };

    // let ion_op = serde_json::from_slice::<IonOperation>(&dec)?;
    let ion_op = serde_json::from_slice::<serde_json::Value>(&dec)?;
    let pk_val = ion_op
        .get("delta")
        .unwrap()
        .get("patches")
        .unwrap()
        .get(0)
        .unwrap()
        .get("document")
        .unwrap()
        .get("publicKeys")
        .unwrap()
        .get(0)
        .unwrap()
        .get("publicKeyJwk")
        .unwrap();

    Ok(serde_json::from_value(pk_val.clone())?)
}

// impl<T> Display for Jwt<T>
// where
//     T: Serialize + Default + Debug,
// {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let header_raw = serde_json::to_vec(&self.header).map_err(|_| std::fmt::Error)?;
//         let header_enc = Base64UrlUnpadded::encode_string(&header_raw);
//         let claims_raw = serde_json::to_vec(&self.claims).map_err(|_| std::fmt::Error)?;
//         let claims_enc = Base64UrlUnpadded::encode_string(&claims_raw);

//         write!(f, "{header_enc}.{claims_enc}")
//     }
// }

// impl<T> FromStr for Jwt<T>
// where
//     T: DeserializeOwned,
// {
//     type Err = anyhow::Error;

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         tracing::debug!("Jwt::from_str");

//         // verify signature
//         // TODO: cater for different key types
//         let parts: Vec<&str> = s.split('.').collect();
//         if parts.len() != 3 {
//             bail!("invalid proof JWT format");
//         }

//         let Ok(decoded_header) = Base64UrlUnpadded::decode_vec(parts[0]) else {
//             bail!("unable to base64 decode proof JWT header");
//         };
//         let Ok(header) = serde_json::from_slice(&decoded_header) else {
//             bail!("unable to deserialize proof JWT header");
//         };
//         let Ok(decoded_claims) = Base64UrlUnpadded::decode_vec(parts[1]) else {
//             bail!("unable to base64 decode proof JWT claims");
//         };
//         let Ok(claims) = serde_json::from_slice(&decoded_claims) else {
//             bail!("unable to deserialize proof JWT claims");
//         };

//         let jwt = Self { header, claims };

//         let msg = format!("{}.{}", parts[0], parts[1]);
//         let Ok(sig) = Base64UrlUnpadded::decode_vec(parts[2]) else {
//             bail!("unable to base64 decode proof signature");
//         };

//         let proof_jwk = match Jwk::from_str(&jwt.header.kid.clone().unwrap_or_default()) {
//             Ok(proof_jwk) => proof_jwk,
//             Err(e) => {
//                 bail!("unable to parse proof JWT 'kid' into JWK: {}", e.to_string());
//             }
//         };

//         proof_jwk.verify(&msg, &sig).map(|()| jwt)
//     }
// }

// impl FromStr for VerifiableCredential {
//     type Err = anyhow::Error;

//     fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
//         tracing::debug!("VerifiableCredential::from_str");
//         let vc_jwt = Jwt::<VcClaims>::from_str(s)?;
//         Ok(vc_jwt.claims.vc)
//     }
// }

// struct VisitorImpl<T>(PhantomData<fn() -> Jwt<T>>);

// impl<'de, T> Deserialize<'de> for Jwt<T>
// where
//     T: DeserializeOwned + Default,
// {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         deserializer.deserialize_any(VisitorImpl(PhantomData))
//     }
// }

// impl<'de, T> Visitor<'de> for VisitorImpl<T>
// where
//     T: DeserializeOwned + Default,
// {
//     type Value = Jwt<T>;

//     fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//         formatter.write_str("Jwt<T>")
//     }

//     fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
//         Jwt::from_str(value).map_or_else(
//             |_| Err(de::Error::invalid_value(de::Unexpected::Str(value), &self)),
//             |jwt| Ok(jwt),
//         )
//     }

//     fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
//     where
//         A: de::MapAccess<'de>,
//     {
//         let mut jwt = Jwt::<T>::default();

//         while let Some(key) = map.next_key::<String>()? {
//             match key.as_str() {
//                 "header" => jwt.header = map.next_value()?,
//                 "claims" => jwt.claims = map.next_value::<T>()?,
//                 _ => return Err(de::Error::unknown_field(&key, &["header", "claims"])),
//             }
//         }

//         Ok(jwt)
//     }
// }