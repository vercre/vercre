mod error;
mod iroh;
#[path = "http.rs"]
mod mod_http;
mod signer;
mod store;
mod vault;

use std::sync::Arc;

use lazy_static::lazy_static;
use tauri::async_runtime::block_on;
use tauri::{generate_context, generate_handler, AppHandle, Manager};
use tauri_plugin_log::{Target, TargetKind};
use tokio::sync::Mutex;
use vercre_wallet::signer::SignerResponse;
use vercre_wallet::store::StoreResponse;
use vercre_wallet::{credential, issuance, presentation, App, Capabilities, Core, Effect, Event};

// TODO:  Iroh VC doc ticket should come from user (somehow)

lazy_static! {
    static ref CORE: Arc<Core<Effect, App>> = Arc::new(Core::new::<Capabilities>());
}

/// Tauri entry point
///
/// # Panics
///
/// TODO: add panics
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::default()
                .targets([Target::new(TargetKind::Stdout), Target::new(TargetKind::Webview)])
                .level(log::LevelFilter::Error)
                .build(),
        )
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let handle = app.handle().clone();

            init_iroh(&handle)?;
            store::init(&handle)?;
            signer::init(&handle)?;

            // initialise deep link listener
            app.listen("deep-link://new-url", move |event| deep_link(&event, &handle));
            Ok(())
        })
        .invoke_handler(generate_handler![
            accept, authorize, cancel, delete, get_list, set_pin, start, offer, present
        ])
        .run(generate_context!())
        .expect("error while running tauri application");
}

pub struct IrohState {
    node: Mutex<iroh::Node>,
}

// start local Iroh node
// ~/Library/Application Support/io.credibil.wallet/iroh
fn init_iroh(handle: &tauri::AppHandle) -> anyhow::Result<()> {
    // start node
    let path = handle.path().app_local_data_dir()?.join("iroh");
    let node = block_on(async { iroh::Node::new(path).await.expect("should start node") });

    // save node and event listener to Tauri state
    let state = IrohState {
        node: Mutex::new(node),
    };
    handle.manage(state);

    Ok(())
}

// Handle deep links
fn deep_link(event: &tauri::Event, handle: &AppHandle) {
    // credential offer
    const OFFER_PREFIX: &str = "openid-vc://credential_offer?credential_offer=";
    const REQUEST_PREFIX: &str = "openid-vc://request_uri=";

    // trim '[]' wrapping payload
    let payload = event.payload();
    let Some(link) = payload.get(2..payload.len() - 2) else {
        return;
    };

    if link.starts_with(OFFER_PREFIX) {
        let offer = link.strip_prefix(OFFER_PREFIX).unwrap_or_default();
        let _ = process_event(Event::Issuance(issuance::Event::Offer(offer.to_string())), handle);
    } else if link.starts_with(REQUEST_PREFIX) {
        let request = link.strip_prefix(REQUEST_PREFIX).unwrap_or_default();
        let _ = process_event(
            Event::Presentation(presentation::Event::Requested(request.to_string())),
            handle,
        );
    }
}

// ----------------------------------------------------------------------------
// App lifecycle
// ----------------------------------------------------------------------------
#[tauri::command]
async fn start(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Start, &handle)
}

#[tauri::command]
async fn cancel(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Cancel, &handle)
}

// ----------------------------------------------------------------------------
// Credential management
// ----------------------------------------------------------------------------
#[tauri::command]
async fn get_list(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Credential(credential::Event::List), &handle)
}

#[tauri::command]
async fn delete(id: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Credential(credential::Event::Delete(id)), &handle)
}

// ----------------------------------------------------------------------------
// Issuance flow
// ----------------------------------------------------------------------------
#[tauri::command]
async fn offer(url: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Issuance(issuance::Event::Offer(url)), &handle)
}

#[tauri::command]
async fn accept(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Issuance(issuance::Event::Accept), &handle)
}

#[tauri::command]
async fn set_pin(pin: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Issuance(issuance::Event::Pin(pin)), &handle)
}

// ----------------------------------------------------------------------------
// Presentation flow
// ----------------------------------------------------------------------------
#[tauri::command]
async fn present(url: String, handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Presentation(presentation::Event::Requested(url)), &handle)
}

#[tauri::command]
async fn authorize(handle: AppHandle) -> Result<(), error::Error> {
    process_event(Event::Presentation(presentation::Event::Authorized), &handle)
}

// Trigger an App event and process the resulting effects.
fn process_event(event: Event, handle: &AppHandle) -> Result<(), error::Error> {
    for effect in CORE.process_event(event) {
        process_effect(effect, handle.clone())?;
    }
    Ok(())
}

// Process `Capability` effects.
fn process_effect(effect: Effect, handle: AppHandle) -> Result<(), error::Error> {
    match effect {
        Effect::Render(_) => handle.emit("render", CORE.view()).map_err(error::Error::Tauri),
        Effect::Http(mut request) => {
            tauri::async_runtime::spawn({
                async move {
                    let result = mod_http::request(&request.operation)
                        .await
                        .expect("error processing Http effect");

                    for effect in CORE.resolve(&mut request, result) {
                        let _ = process_effect(effect, handle.clone());
                    }
                }
            });

            Ok(())
        }
        Effect::Store(mut request) => {
            tauri::async_runtime::spawn({
                async move {
                    let response = match store::request(&request.operation, &handle).await {
                        Ok(resp) => resp,
                        Err(err) => StoreResponse::Err(err.to_string()),
                    };

                    for effect in CORE.resolve(&mut request, response) {
                        let _ = process_effect(effect, handle.clone());
                    }
                }
            });

            Ok(())
        }
        Effect::Signer(mut request) => {
            tauri::async_runtime::spawn({
                async move {
                    let response = match signer::request(&request.operation, &handle) {
                        Ok(resp) => resp,
                        Err(err) => SignerResponse::Err(err.to_string()),
                    };

                    for effect in CORE.resolve(&mut request, response) {
                        let _ = process_effect(effect, handle.clone());
                    }
                }
            });

            Ok(())
        }
        Effect::Delay(mut request) => {
            tauri::async_runtime::spawn({
                async move {
                    let response = ();
                    std::thread::sleep(std::time::Duration::from_millis(
                        request.operation.delay_ms,
                    ));

                    for effect in CORE.resolve(&mut request, response) {
                        let _ = process_effect(effect, handle.clone());
                    }
                }
            });

            Ok(())
        }
    }
}
