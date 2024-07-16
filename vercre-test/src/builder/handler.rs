//! # `OpenID` Core

use futures::Future;
use openid::Result;
// use openid::endpoint::{Callback, Payload, Status};
// use openid::Err;

pub trait Handler<'a, R, U> {
    type Response: Future<Output = Result<U>>;

    fn handle(self, request: &'a R) -> Self::Response;
}

impl<'a, R: 'a, U, F, Fut> Handler<'a, R, U> for F
where
    F: FnOnce(&'a R) -> Fut,
    Fut: Future<Output = Result<U>> + 'a,
{
    type Response = Fut;

    fn handle(self, s: &'a R) -> Self::Response {
        self(s)
    }
}

pub async fn wrapper<R, U, F>(request: &R, f: F) -> Result<U>
where
    F: for<'r> Handler<'r, R, U>,
{
    f.handle(request).await
}
