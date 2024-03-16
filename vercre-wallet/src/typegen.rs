//! This build script generates UI-specific types used by each user interface to
//! communicate with the `vercre-wallet` core.
//!
//! N.B. Due to the way the type generator works, types cannot use `serde` macros
//! that lead to asymmetry between serialization and deserialization. For example,
//! using `#[serde(flatten)]` will lead to issues generating a type.

#![cfg(feature = "typegen")]

use std::collections::HashMap;

use crux_core::bridge::Request;
use crux_core::typegen::TypeGen;
use crux_http::HttpError;
use vercre_core::metadata::{CredentialConfiguration, ValueType};
use vercre_core::vci::Format;

use crate::credential::Credential;
use crate::{app, credential, issuance, presentation};

pub enum Language {
    Java,
    Swift,
    Typescript,
}

/// Generate UI-specific types used by each user interface to communicate with the
/// `vercre-wallet` core.
pub fn generate(lang: Language, gen_dir: &str) {
    let mut gen = TypeGen::new();

    // register FFI types
    gen.register_type::<Request<app::EffectFfi>>().expect("should register");
    gen.register_type::<app::EffectFfi>().expect("should register");
    gen.register_type::<HttpError>().expect("should register");

    // register credential type
    gen.register_type::<Format>().expect("should register");
    gen.register_type::<ValueType>().expect("should register");
    gen.register_samples::<Credential>(vec![Credential::sample()]).expect("should register");

    // register issuance app
    let ivm = issuance::ViewModel {
        issuer: "https://example.com".to_string(),
        offered: HashMap::from([("EmployeeID_JWT".to_string(), CredentialConfiguration::sample())]),
        status: issuance::Status::Offered,
    };
    gen.register_samples::<issuance::ViewModel>(vec![ivm.clone()])
        .expect("should register issuance::ViewModel");
    gen.register_app::<issuance::App>().expect("should register issuance::App");
    gen.register_type::<issuance::Status>().expect("should register");

    // register presentation app
    // HACK: workaround for serde_reflection issues with Credential
    let pvm = presentation::ViewModel {
        credentials: vec![Credential::sample()],
        status: presentation::Status::Authorized,
    };
    gen.register_samples::<presentation::ViewModel>(vec![pvm.clone()])
        .expect("should register presentation::ViewModel");
    gen.register_app::<presentation::App>().expect("should register presentation::App");
    gen.register_type::<presentation::Status>().expect("should register presentation::Status");

    // register credential app
    // HACK: workaround for serde_reflection issues with Credential
    let cvm = credential::ViewModel {
        credentials: vec![Credential::sample()],
        error: Some(String::new()),
    };
    gen.register_samples::<credential::ViewModel>(vec![cvm.clone()])
        .expect("should register credential::ViewModel");
    gen.register_app::<credential::App>().expect("should register credential::App");

    // register wallet root app
    let vm = app::ViewModel {
        credential: cvm,
        issuance: ivm,
        presentation: pvm,
        error: Some(String::new()),
        view: app::View::Issuance,
    };
    gen.register_samples::<app::ViewModel>(vec![vm]).expect("should register app::ViewModel");
    gen.register_app::<app::App>().expect("should register app::App");
    gen.register_type::<app::View>().expect("should register app::View");

    // generate specified type
    // let gen_dir = PathBuf::from(path);

    match lang {
        Language::Java => gen
            .java("io.credibil.shared_types", format!("{gen_dir}/java"))
            .expect("should generate types"),
        Language::Swift => {
            gen.swift("SharedTypes", format!("{gen_dir}/swift")).expect("should generate types")
        }
        Language::Typescript => gen
            .typescript("shared_types", format!("{gen_dir}/typescript"))
            .expect("should generate types"),
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_generate() {
        let gen_dir = "src/gen";
        let lang = Language::Typescript;

        generate(lang, gen_dir);

        let path = PathBuf::from(gen_dir).join("typescript/types/shared_types.ts");
        assert!(path.exists());

        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("export class Credential"));

        fs::remove_dir_all(gen_dir).unwrap();
    }
}
