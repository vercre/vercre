use std::path::PathBuf;

use tauri::Manager;
use tauri_plugin_store::with_store;
use vercre_holder::credential::Credential;
use vercre_holder::provider::CredentialStorer;
use vercre_holder::Constraints;

use super::Provider;

const STORE: &str = "store.json";

/// Provider implementation
impl CredentialStorer for Provider {
    /// Save a `Credential` to the store. Overwrite any existing credential with the same ID. Create
    /// a new credential if one with the same ID does not exist.
    async fn save(&self, credential: &Credential) -> anyhow::Result<()> {
        let path = PathBuf::from(STORE);
        let collection = self.app_handle.state();
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
        let path = PathBuf::from(STORE);
        let collection = self.app_handle.state();
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
        let path = PathBuf::from(STORE);
        let collection = self.app_handle.state();
        let values = with_store(self.app_handle.clone(), collection, path, |store| {
            let values = store.values();
            let list: Vec<Credential> =
                values.filter_map(|v| serde_json::from_value(v.clone()).ok()).collect();
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
        let path = PathBuf::from(STORE);
        let collection = self.app_handle.state();
        with_store(self.app_handle.clone(), collection, path, |store| {
            store.delete(id)?;
            store.save()
        })?;
        Ok(())
    }
}

// #[cfg(test)]
// mod test {
//     use std::{collections::HashMap, sync::{Arc, LazyLock}};

//     use futures::lock::Mutex;
//     use serde_json::{json, Value};
//     use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime};

//     use super::*;

//     #[tokio::test]
//     async fn list() {
//         // set up store
//         let app = create_app(mock_builder());

//         let stores = app.app_handle().state::<StoreCollection<MockRuntime>>();
//         let path = PathBuf::from("store.json");

//         // insert item and return count of items in store
//         let count = with_store(app.app_handle().clone(), stores, path, |store| {
//             for value in ENTRIES.as_array().unwrap() {
//                 let id = value.get("id").unwrap().as_str().unwrap();
//                 store.insert(id.to_string(), value.to_owned())?;
//             }
//             Ok(store.len())
//         })
//         .expect("should return count");

//         // query for all credentials ("" or "$[:]")
//         let store = Provider::new(app.app_handle().clone(), Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new())));
//         let res = store.find(None).await.expect("should be ok");
//         assert_eq!(count, res.len());
//     }

//     fn create_app<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::App<R> {
//         builder
//             .plugin(tauri_plugin_store::Builder::<R>::default().build())
//             .build(mock_context(noop_assets()))
//             .expect("failed to build app")
//     }

//     static ENTRIES: LazyLock<Value> = LazyLock::new(|| {
//         json!([{
//             "id": "https://vercre.io/credentials/3732",
//             "issued": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSNwdWJsaWNLZXlNb2RlbDFJZCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSIsIm5iZiI6MTcwNTgyMzcwMCwiaXNzIjoiaHR0cDovL2NyZWRpYmlsLmlvIiwiaWF0IjoxNzA1ODIzNzAwLCJqdGkiOiJodHRwczovL2NyZWRpYmlsLmlvL2NyZWRlbnRpYWxzLzM3MzIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHA6Ly9jcmVkaWJpbC5pby9jcmVkZW50aWFscy92MSJdLCJpZCI6Imh0dHBzOi8vY3JlZGliaWwuaW8vY3JlZGVudGlhbHMvMzczMiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJFbXBsb3llZUlEQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vY3JlZGliaWwuaW8iLCJpc3N1YW5jZURhdGUiOiIyMDI0LTAxLTIxVDA3OjU1OjAwLjY5MTgwN1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDppb246RWlEeU9RYmJaQWEzYWlSemVDa1Y3TE94M1NFUmpqSDkzRVhvSU0zVW9ONG9XZzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp3ZFdKc2FXTkxaWGxOYjJSbGJERkpaQ0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSnpaV053TWpVMmF6RWlMQ0pyZEhraU9pSkZReUlzSW5naU9pSjBXRk5MUWw5eWRXSllVemR6UTJwWWNYVndWa3BGZWxSalZ6Tk5jMnB0UlhaeE1WbHdXRzQ1Tmxwbklpd2llU0k2SW1SUGFXTlljV0pxUm5odlIwb3RTekF0UjBveGEwaFpTbkZwWTE5RVgwOU5kVlYzYTFFM1QydzJibXNpZlN3aWNIVnljRzl6WlhNaU9sc2lZWFYwYUdWdWRHbGpZWFJwYjI0aUxDSnJaWGxCWjNKbFpXMWxiblFpWFN3aWRIbHdaU0k2SWtWalpITmhVMlZqY0RJMU5tc3hWbVZ5YVdacFkyRjBhVzl1UzJWNU1qQXhPU0o5WFN3aWMyVnlkbWxqWlhNaU9sdDdJbWxrSWpvaWMyVnlkbWxqWlRGSlpDSXNJbk5sY25acFkyVkZibVJ3YjJsdWRDSTZJbWgwZEhBNkx5OTNkM2N1YzJWeWRtbGpaVEV1WTI5dElpd2lkSGx3WlNJNkluTmxjblpwWTJVeFZIbHdaU0o5WFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkV0SmEzZHhUelk1U1ZCSE0zQlBiRWhyWkdJNE5tNVpkREJoVG5oVFNGcDFNbkl0WW1oRmVtNXFaRUVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVTm1SRmRTYmxsc1kwUTVSVWRCTTJSZk5Wb3hRVWgxTFdsWmNVMWlTamx1Wm1seFpIbzFVemhXUkdKbklpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ1prOWFaRTEwVlRaUFFuYzRVR3M0TnpsUmRGb3RNa290T1VaaVltcFRXbmx2WVVGZlluRkVOSHBvUVNKOWZRIiwiZ2l2ZW5OYW1lIjoiTm9ybWFsIiwiZW1haWwiOiJub3JtYWwudXNlckBleGFtcGxlLmNvbSIsImZhbWlseU5hbWUiOiJQZXJzb24ifX19.2So2UoF1R_sVD3zUxOnBZvLK12WaJ1doRYoeO4JIcdhls0GrkzkiUEdbQiM9K4vF43yL3Fpgdm9e3k6tsVm8DQ",
//             "issuer": "http://localhost:8080",
//             "metadata": {
//                 "credential_definition": {
//                     "credentialSubject": {
//                         "email": {
//                             "display": [
//                                 {
//                                     "locale": "en-NZ",
//                                     "name": "Email"
//                                 }
//                             ],
//                             "mandatory": true,
//                             "value_type": "string"
//                         },
//                         "familyName": {
//                             "display": [
//                                 {
//                                     "locale": "en-NZ",
//                                     "name": "Family name"
//                                 }
//                             ],
//                             "mandatory": true,
//                             "value_type": "string"
//                         },
//                         "givenName": {
//                             "display": [
//                                 {
//                                     "locale": "en-NZ",
//                                     "name": "Given name"
//                                 }
//                             ],
//                             "mandatory": true,
//                             "value_type": "string"
//                         }
//                     },
//                     "type": [
//                         "VerifiableCredential",
//                         "EmployeeIDCredential"
//                     ]
//                 },
//                 "cryptographic_binding_methods_supported": [
//                     "did:ion"
//                 ],
//                 "cryptographic_suites_supported": [
//                     "ES256K"
//                 ],
//                 "display": [
//                     {
//                         "background_color": "#12107c",
//                         "description": "Vercre employee ID credential",
//                         "locale": "en-NZ",
//                         "logo": {
//                             "alt_text": "Vercre Logo",
//                             "uri": "http://vercre.io/logo.png"
//                         },
//                         "name": "Employee ID",
//                         "text_color": "#ffffff"
//                     }
//                 ],
//                 "format": "jwt_vc_json",
//                 "scope": "EmployeeIDCredential"
//             },
//             "vc": {
//                 "@context": [
//                     "https://www.w3.org/2018/credentials/v1",
//                     "http://vercre.io/credentials/v1"
//                 ],
//                 "credentialSubject": {
//                     "email": "normal.user@example.com",
//                     "familyName": "Person",
//                     "givenName": "Normal",
//                     "id": "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ"
//                 },
//                 "id": "https://vercre.io/credentials/3732",
//                 "issuanceDate": "2024-01-21T07:55:00.691807Z",
//                 "issuer": "http://vercre.io",
//                 "type": [
//                     "VerifiableCredential",
//                     "EmployeeIDCredential"
//                 ]
//             }
//         }])
//     });
// }
