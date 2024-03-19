use anyhow::{anyhow, Error, Result};
use futures::StreamExt;
use tauri::async_runtime::{block_on, spawn};
use tauri::Manager;
use vercre_wallet::signer::{SignerRequest, SignerResponse};

use crate::iroh::{Doc, DocType}; // Entry};
use crate::vault::Vault;
use crate::{error, IrohState};

const KEY_VAULT: &str = "docaaacaopj7u7mkmrbxv536p2j4ihk3t3qn36oycl27po2orshfl2srd3bafk62aofuwwwu5zb5ocvzj5v3rtqt6siglyuhoxhqtu4fxravvoteajcnb2hi4dthixs65ltmuys2mjomrsxe4bonfzg62bonzsxi53pojvs4lydaac2cyt22erablaraaa5ciqbfiaqj7ya6cbpuaaaaaaaaaaaahjce";
const ENTRY_KEY: &str = "stronghold.bin";

// initialise the key store
pub fn init(handle: &tauri::AppHandle) -> Result<()> {
    // iroh is async
    block_on(async {
        let state = handle.state::<IrohState>();
        let vault_doc: Doc = state.node.lock().await.join_doc(DocType::KeyVault, KEY_VAULT).await?;

        // doc events
        let handle2 = handle.clone();
        let mut stream = vault_doc.updates().await;
        spawn(async move {
            while stream.next().await.is_some() {
                println!("reloading vault");
                load_vault(&handle2).await.expect("failed to reload vault");
            }
        });

        // attempt to load vault
        if let Err(e) = load_vault(handle).await {
            println!("failed to load vault: {e}");
        };

        Ok::<(), Error>(())
    })
}

async fn load_vault(handle: &tauri::AppHandle) -> Result<()> {
    let state = handle.state::<IrohState>();
    let vault_doc: Doc = state.node.lock().await.join_doc(DocType::KeyVault, KEY_VAULT).await?;

    // FIXME: get passphrase from user and salt from file(?)
    let passphrase = b"pass-phrase";
    let salt = b"randomsalt";
    let password = argon2::hash_raw(passphrase, salt, &argon2::Config::default())?;

    let mut entry = vault_doc.entry(ENTRY_KEY).await?;
    let vault = Vault::new(&mut entry, password)?;
    handle.manage(vault);

    Ok(())
}

pub fn request<R>(
    op: &SignerRequest, app_handle: &tauri::AppHandle<R>,
) -> Result<SignerResponse, error::Error>
where
    R: tauri::Runtime,
{
    let stronghold = app_handle.state::<Vault>();

    match op {
        SignerRequest::Sign(msg) => {
            let signed = stronghold.sign(msg.clone()).unwrap();
            Ok(SignerResponse::Signature(signed))
        }
        SignerRequest::Verification => {
            // FIXME: implement
            let alg = String::from("EdDSA"); // String::from("ES256K");
            let Ok(kid) = stronghold.verifiction() else {
                return Err(error::Error::Other(anyhow!("verification failed")));
            };
            Ok(SignerResponse::Verification { alg, kid })
        }
    }
}

// TODO: fix unit tests

#[cfg(test)]
mod test {
    use std::fs::{File, OpenOptions};

    use assert_let_bind::assert_let;
    use tauri::test::{mock_builder, mock_context, noop_assets};

    use super::*;

    #[tokio::test]
    async fn sign() {
        // set up signer
        let app = create_app(mock_builder());

        let msg = String::from("hello world");
        let req = SignerRequest::Sign(msg.into_bytes());
        let resp = request(&req, app.app_handle()).expect("should be ok");

        // signature length is 64 bytes
        assert_let!(SignerResponse::Signature(sig), resp);
        assert_eq!(sig.len(), 64);
    }

    fn create_app<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::App<R> {
        let app = builder.build(mock_context(noop_assets())).expect("failed to build app");
        let handle = app.handle().clone();

        let password = argon2::hash_raw(b"pass-phrase", b"randomsalt", &argon2::Config::default())
            .expect("should hash");
        let mut snapshot: File =
            OpenOptions::new().read(true).open("stronghold.bin").expect("should open");

        let vault = Vault::new(&mut snapshot, password).expect("should create vault");
        handle.manage(vault);

        app
    }
}
