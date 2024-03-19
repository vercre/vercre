use futures::StreamExt;
use tauri::async_runtime::{block_on, spawn};
use tauri::Manager;
use vercre_wallet::store::{StoreEntry, StoreRequest, StoreResponse};

use super::get_list;
use crate::iroh::DocType;
use crate::{error, IrohState};

// Iroh document ticket for the credential store
const VC_STORE: &str = "docaaacb3j5mbv5b6geuxm3lkwi634s3o72ankhxysbazrje5bg3vpjtatjafk62aofuwwwu5zb5ocvzj5v3rtqt6siglyuhoxhqtu4fxravvoteajcnb2hi4dthixs65ltmuys2mjomrsxe4bonfzg62bonzsxi53pojvs4lydaac2cyt22erablaraaa5ciqbfiaqj7ya6cbpuaaaaaaaaaaaahjce";

// initialise the credential store on the Iroh node
pub fn init(handle: &tauri::AppHandle) -> anyhow::Result<()> {
    block_on(async {
        let state = handle.state::<IrohState>();
        let vc_doc = state.node.lock().await.join_doc(DocType::Credential, VC_STORE).await?;

        let handle2 = handle.clone();
        spawn(async move {
            while vc_doc.updates().await.next().await.is_some() {
                get_list(handle2.clone()).await.expect("should process event");
            }
        });

        Ok(())
    })
}

pub async fn request<R>(
    op: &StoreRequest, app_handle: &tauri::AppHandle<R>,
) -> Result<StoreResponse, error::Error>
where
    R: tauri::Runtime,
{
    let state = app_handle.state::<IrohState>();
    let vc_doc = state.node.lock().await.doc(DocType::Credential).unwrap();

    match op {
        StoreRequest::Add(id, value) => {
            vc_doc.add_entry(id.to_owned(), value.to_owned()).await?;
            Ok(StoreResponse::Ok)
        }
        StoreRequest::List => {
            let mut values = vec![];
            for v in vc_doc.entries().await? {
                values.push(StoreEntry(v));
            }

            Ok(StoreResponse::List(values))
        }
        StoreRequest::Delete(id) => {
            vc_doc.delete_entry(id.to_owned()).await?;
            Ok(StoreResponse::Ok)
        }
    }
}
