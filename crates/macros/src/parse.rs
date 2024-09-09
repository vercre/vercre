use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::parse::{Parse, ParseStream}; // Error,
use syn::punctuated::{Pair, Punctuated};
use syn::{braced, bracketed, token, Result};

#[derive(Default)]
pub struct Data {
    pub fields: HashMap<String, Value>,
}

struct Field {
    lhs: String,
    rhs: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<Self>),
    Object(HashMap<String, Self>),
    Ident(syn::Ident),
    Enum(syn::Ident, syn::Ident),
}

impl Parse for Data {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut data = Self::default();

        if input.peek(token::Brace) {
            let content;
            braced!(content in input);

            let fields = Punctuated::<Field, token::Comma>::parse_terminated(&content)?;
            for field in fields.into_pairs() {
                let field = field.into_value();
                data.fields.insert(field.lhs, field.rhs);
            }
        }

        Ok(data)
    }
}

impl Parse for Field {
    fn parse(input: ParseStream) -> Result<Self> {
        let lhs = input.parse::<syn::LitStr>()?;
        input.parse::<token::Colon>()?;

        Ok(Self {
            lhs: lhs.value(),
            rhs: input.parse::<Value>()?,
        })
    }
}

impl Parse for Value {
    fn parse(input: ParseStream) -> Result<Self> {
        let l = input.lookahead1();

        let rhs = if l.peek(syn::LitStr) {
            let string = input.parse::<syn::LitStr>()?.value();
            Self::String(string)
        } else if l.peek(syn::LitInt) {
            Self::Number(input.parse::<syn::LitInt>()?.base10_parse::<u64>()?)
        } else if l.peek(syn::LitBool) {
            Self::Bool(input.parse::<syn::LitBool>()?.value())
        } else if l.peek(token::Brace) {
            let mut data = HashMap::new();
            let content;
            braced!(content in input);
            let fields = Punctuated::<Field, token::Comma>::parse_terminated(&content)?;
            for field in fields.into_pairs() {
                let field = field.into_value();
                data.insert(field.lhs, field.rhs);
            }
            Self::Object(data)
        } else if l.peek(token::Bracket) {
            let contents;
            bracketed!(contents in input);
            let items = Punctuated::<Self, token::Comma>::parse_terminated(&contents)?;
            let values = items.into_pairs().map(Pair::into_value).collect();
            Self::Array(values)
        } else if l.peek(syn::Ident) {
            let ident = input.parse::<syn::Ident>()?;

            // is this an enum variant?
            let l = input.lookahead1();
            if l.peek(token::PathSep) {
                input.parse::<token::PathSep>()?;
                let variant = input.parse::<syn::Ident>()?;
                Self::Enum(ident, variant)
            } else {
                Self::Ident(ident)
            }
        } else {
            // dump(input)?;
            return Err(input.error("unexpected token"));
        };

        Ok(rhs)
    }
}

impl ToTokens for Value {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Null => tokens.extend(quote! { None }),
            Self::Bool(b) => tokens.extend(quote! { #b }),
            Self::String(s) => tokens.extend(quote! { #s.to_string() }),
            Self::Number(n) => tokens.extend(quote! { #n }),
            Self::Array(a) => {
                let values = a.iter().map(|v| {
                    let mut tokens = TokenStream::new();
                    v.to_tokens(&mut tokens);
                    tokens
                });
                tokens.extend(quote! { vec![#(#values),*] });
            }
            Self::Object(o) => {
                let fields = o.iter().map(|(k, v)| {
                    let mut tokens = TokenStream::new();
                    v.to_tokens(&mut tokens);
                    quote! {#k: #tokens}
                });
                tokens.extend(quote! { #(#fields),* });
            }
            Self::Ident(i) => tokens.extend(quote! { #i.to_string() }),
            Self::Enum(i, v) => tokens.extend(quote! { #i::#v }),
        }
    }
}

#[allow(dead_code)]
fn dump(input: ParseStream) -> Result<()> {
    input.step(|cursor| {
        let mut rest = *cursor;
        while let Some((tt, next)) = rest.token_tree() {
            println!("{tt:?}");
            rest = next;
        }
        Ok(((), rest))
    })
}
