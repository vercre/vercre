//! # Core Utilities for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.

// generic member access API on the error trait
// https://github.com/rust-lang/rust/issues/99301
#![feature(error_generic_member_access)]

pub mod gen;

use serde::{Deserialize, Serialize};

/// Wrap the @context property to support serialization/deserialization of an ordered
/// set composed of any combination of URLs and/or objects, each processable as a
/// [JSON-LD Context](https://www.w3.org/TR/json-ld11/#the-context).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Kind<T> {
    /// Simple string value
    String(String),

    /// Complex object value
    Object(T),
}

impl<T: Default> Default for Kind<T> {
    fn default() -> Self {
        Self::String(String::new())
    }
}

/// `Quota` allows serde to serialize/deserialize a single object or a set of objects.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Quota<T> {
    /// Single object
    One(T),

    /// Set of objects
    Many(Vec<T>),
}

impl<T: Default> Default for Quota<T> {
    fn default() -> Self {
        Self::One(T::default())
    }
}
