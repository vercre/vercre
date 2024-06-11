use std::path::PathBuf;

use tauri::{Manager, State};
use tauri_plugin_store::{with_store, StoreCollection};
use vercre_holder::credential::Credential;
use vercre_holder::provider::CredentialStorer;
use vercre_holder::Constraints;

pub struct Store {
    app_handle: tauri::AppHandle,
}

impl Store {
    /// Create a new credential store provider with a handle to the Tauri application.
    #[must_use]
    pub const fn new(app_handle: tauri::AppHandle) -> Self {
        Self { app_handle }
    }

    /// Get a reference to the file store.
    fn store<R>(&self) -> (PathBuf, State<StoreCollection<R>>)
    where
        R: tauri::Runtime,
    {
        let path = PathBuf::from("store.json");
        let collection = self.app_handle.state::<StoreCollection<R>>();
        (path, collection)
    }
}

/// Provider implementation
impl CredentialStorer for Store {
    /// Save a `Credential` to the store. Overwrite any existing credential with the same ID. Create
    /// a new credential if one with the same ID does not exist.
    async fn save(&self, credential: &Credential) -> anyhow::Result<()> {
        let (path, collection) = self.store();
        with_store(self.app_handle.clone(), collection, path, |store| {
            let id = credential.id.clone();
            let val = serde_json::to_value(credential)?;
            log::debug!("saving credential: {id}: {val}");
            store.insert(id, val)?;
            store.save()
        })?;
        Ok(())
    }

    /// Retrieve a `Credential` from the store with the given ID. Return None if no credential with
    /// the ID exists.
    async fn load(&self, id: &str) -> anyhow::Result<Option<Credential>> {
        let (path, collection) = self.store();
        let val =
            with_store(self.app_handle.clone(), collection, path, |store| match store.get(id) {
                Some(v) => Ok(Some(serde_json::from_value(v.clone())?)),
                None => Ok(None),
            })?;
        Ok(val)
    }

    /// Find the credentials that match the the provided filter. If `filter` is None, return all
    /// credentials in the store.
    async fn find(&self, filter: Option<Constraints>) -> anyhow::Result<Vec<Credential>> {
        let (path, collection) = self.store();
        let values = with_store(self.app_handle.clone(), collection, path, |store| {
            let values = store.values();
            let list: Vec<Credential> = values
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect();
            let Some(constraints) = filter else {
                return Ok(list);
            };
            let mut matched: Vec<Credential> = vec![];
            for cred in &list {
                match constraints.satisfied(&cred.vc) {
                    Ok(true) => matched.push(cred.clone()),
                    Ok(false) => continue,
                    Err(e) => log::error!("error checking constraints: {e}"),
                }
            }
            Ok(matched)
        })?;
        Ok(values)
    }

    /// Remove the credential with the given ID from the store. Return an error if the credential
    /// does not exist.
    async fn remove(&self, id: &str) -> anyhow::Result<()> {
        let (path, collection) = self.store();
        with_store(self.app_handle.clone(), collection, path, |store| {
            store.delete(id)?;
            store.save()
        })?;
        Ok(())
    }
}