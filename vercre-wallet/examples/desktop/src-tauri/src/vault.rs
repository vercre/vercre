use std::io::{BufRead, BufReader};

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use iota_stronghold::procedures::{
    Ed25519Sign, GenerateKey, KeyType, PublicKey, StrongholdProcedure,
};
use iota_stronghold::{Client, KeyProvider, Location};

const CLIENT: &[u8] = b"signing_client";
const VAULT: &[u8] = b"signing_key_vault";
const SIGNING_KEY: &[u8] = b"signing_key";

pub struct Stronghold {
    key_location: Location,
    client: Client,
}

use std::io;

impl Stronghold {
    /// Create new Stronghold instance.
    /// The method will attempt to load a Stronghold snapshot from the given path,
    /// or create a new one if it does not exist.
    ///
    /// When creating a new snapshot, a signing key will be generated and saved to
    /// the vault.
    ///
    /// The snapshot is encrypted using the password provided.
    pub fn new<S>(snapshot: &mut S, password: Vec<u8>) -> Result<Self>
    where
        S: io::Read + io::Write + Clone,
    {
        let stronghold = iota_stronghold::Stronghold::default();
        let key_provider = KeyProvider::try_from(password)?;
        let key_location = Location::generic(VAULT, SIGNING_KEY);

        // convert to BufReader in order to check if has data
        let mut reader = BufReader::new(io::Read::by_ref(snapshot));

        let client = {
            if reader.fill_buf()?.is_empty() {
                let client = stronghold.create_client(CLIENT)?;

                // generate signing key
                let proc = StrongholdProcedure::GenerateKey(GenerateKey {
                    ty: KeyType::Ed25519,
                    output: key_location.clone(),
                });
                let _ = client.execute_procedure(proc)?;

                // persist snapshot with client and signing key
                stronghold.save_snapshot(snapshot, &key_provider)?;

                client
            } else {
                stronghold.use_snapshot(&mut reader, &key_provider)?;
                stronghold.load_client(CLIENT)?
            }
        };

        Ok(Self { key_location, client })
    }

    /// Sign message using the snapshot's signing key.
    pub(super) fn sign(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
        let proc = StrongholdProcedure::Ed25519Sign(Ed25519Sign {
            msg,
            private_key: self.key_location.clone(),
        });
        let output = self.client.execute_procedure(proc)?;
        Ok(output.into())
    }

    /// Get the signing key's public key from the snapshot.
    pub(super) fn verifiction(&self) -> Result<String> {
        // get public key
        let proc = StrongholdProcedure::PublicKey(PublicKey {
            ty: KeyType::Ed25519,
            private_key: self.key_location.clone(),
        });
        let output = self.client.execute_procedure(proc)?;

        // convert to did:jwk
        let x_bytes: Vec<u8> = output.into();

        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": Base64UrlUnpadded::encode_string(&x_bytes),
        });
        let jwk_str = jwk.to_string();
        let jwk_b64 = Base64UrlUnpadded::encode_string(jwk_str.as_bytes());

        Ok(format!("did:jwk:{jwk_b64}#0"))
    }
}
