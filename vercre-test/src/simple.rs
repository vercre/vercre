use std::fmt::Debug;

use openid::{endpoint, Err, Result};

#[derive(Clone, Debug, Default)]
pub struct TestRequest {
    pub return_ok: bool,
}

pub struct TestResponse {}

impl<P> super::Endpoint<P>
where
    P: super::Provider + Clone + Debug,
{
    /// Mock a request to the endpoint.
    pub async fn mock_request(&mut self, request: &TestRequest) -> Result<TestResponse> {
        let ctx = Context {
            _p: std::marker::PhantomData,
        };
        endpoint::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> endpoint::Context for Context<P>
where
    P: super::Provider + Clone + Debug,
{
    type Provider = P;
    type Request = TestRequest;
    type Response = TestResponse;

    fn callback_id(&self) -> Option<String> {
        Some("callback_id".into())
    }

    async fn process(
        &self, _provider: &Self::Provider, request: &Self::Request,
    ) -> Result<Self::Response> {
        match request.return_ok {
            true => Ok(TestResponse {}),
            false => return Err(Err::InvalidRequest("invalid request".into()).into()),
        }
    }
}
