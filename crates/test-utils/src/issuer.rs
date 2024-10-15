use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
use vercre_did::{DidResolver, Document};
use vercre_infosec::{Algorithm, Decryptor, Encryptor, SecOps, Signer};
use vercre_openid::issuer::{
    Client, Dataset, Issuer, Metadata, Result, Server, StateStore, Subject,
};
use vercre_status::issuer::Status;

use crate::store::keystore::IssuerKeystore;
use crate::store::{issuance, resolver, state};

pub const CREDENTIAL_ISSUER: &str = "http://vercre.io";
pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";
pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";
pub const REDIRECT_URI: &str = "http://localhost:3000/callback";

#[derive(Default, Clone, Debug)]
pub struct Provider {
    pub client: issuance::ClientStore,
    pub issuer: issuance::IssuerStore,
    pub server: issuance::ServerStore,
    pub subject: issuance::DatasetStore,
    pub state: state::Store,
}

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: issuance::ClientStore::new(),
            issuer: issuance::IssuerStore::new(),
            server: issuance::ServerStore::new(),
            subject: issuance::DatasetStore::new(),
            state: state::Store::new(),
        }
    }
}

impl vercre_openid::issuer::Provider for Provider {}

impl Metadata for Provider {
    async fn client(&self, client_id: &str) -> Result<Client> {
        self.client.get(client_id)
    }

    async fn register(&self, client: &Client) -> Result<Client> {
        self.client.add(client)
    }

    async fn issuer(&self, issuer_id: &str) -> Result<Issuer> {
        self.issuer.get(issuer_id)
    }

    async fn server(&self, server_id: &str, _issuer_id: Option<&str>) -> Result<Server> {
        self.server.get(server_id)
    }
}

impl Subject for Provider {
    /// Authorize issuance of the specified credential for the holder.
    async fn authorize(
        &self, subject_id: &str, credential_configuration_id: &str,
    ) -> Result<Vec<String>> {
        self.subject.authorize(subject_id, credential_configuration_id)
    }

    async fn dataset(&self, subject_id: &str, credential_identifier: &str) -> Result<Dataset> {
        self.subject.dataset(subject_id, credential_identifier)
    }
}

impl StateStore for Provider {
    async fn put(&self, key: &str, state: impl Serialize, dt: DateTime<Utc>) -> Result<()> {
        self.state.put(key, state, dt)
    }

    async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T> {
        self.state.get(key)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state.purge(key)
    }
}

impl DidResolver for Provider {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        resolver::resolve_did(url).await
    }
}

struct IssuerSec(IssuerKeystore);

impl SecOps for Provider {
    fn signer(&self, _identifier: &str) -> anyhow::Result<impl Signer> {
        Ok(IssuerSec(IssuerKeystore {}))
    }

    fn encryptor(&self, _identifier: &str) -> anyhow::Result<impl Encryptor> {
        Ok(IssuerSec(IssuerKeystore {}))
    }

    fn decryptor(&self, _identifier: &str) -> anyhow::Result<impl Decryptor> {
        Ok(IssuerSec(IssuerKeystore {}))
    }
}

impl Signer for IssuerSec {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        IssuerKeystore::try_sign(msg)
    }

    async fn public_key(&self) -> Result<Vec<u8>> {
        IssuerKeystore::public_key()
    }

    fn algorithm(&self) -> Algorithm {
        IssuerKeystore::algorithm()
    }

    fn verification_method(&self) -> String {
        IssuerKeystore::verification_method()
    }
}

impl Encryptor for IssuerSec {
    async fn encrypt(&self, _plaintext: &[u8], _recipient_public_key: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }

    fn public_key(&self) -> Vec<u8> {
        todo!()
    }
}

impl Decryptor for IssuerSec {
    async fn decrypt(&self, _ciphertext: &[u8], _sender_public_key: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }
}

impl Status for Provider {}
