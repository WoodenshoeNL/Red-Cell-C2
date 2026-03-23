//! Trailing-slash normalization for the teamserver HTTP stack.
//!
//! [`NormalizedMakeService`] wraps an inner `MakeService` (typically
//! `IntoMakeServiceWithConnectInfo`) so that every per-connection service is
//! wrapped with [`tower_http::normalize_path::NormalizePath`].  Because the
//! normalization layer sits *outside* the Axum router, it rewrites the request
//! URI **before** routing — ensuring `/havoc/`, `/api/v1/agents/`, and any
//! other path with a trailing slash is handled identically to its canonical
//! form without one.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tower::{Layer, Service};
use tower_http::normalize_path::{NormalizePath, NormalizePathLayer};

/// A `MakeService` adapter that wraps every inner service with
/// [`NormalizePathLayer::trim_trailing_slash`].
///
/// This preserves whatever the inner `MakeService` does (e.g. injecting
/// `ConnectInfo`) while adding path normalization at the outermost layer.
#[derive(Clone, Debug)]
pub struct NormalizedMakeService<M> {
    inner: M,
}

impl<M> NormalizedMakeService<M> {
    /// Create a new `NormalizedMakeService` wrapping the given inner make
    /// service.
    pub fn new(inner: M) -> Self {
        Self { inner }
    }
}

impl<M, T> Service<T> for NormalizedMakeService<M>
where
    M: Service<T>,
    M::Future: Send + 'static,
    M::Response: Send + 'static,
    M::Error: Send + 'static,
{
    type Response = NormalizePath<M::Response>;
    type Error = M::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, target: T) -> Self::Future {
        let fut = self.inner.call(target);
        Box::pin(async move {
            let svc = fut.await?;
            Ok(NormalizePathLayer::trim_trailing_slash().layer(svc))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use tower::ServiceExt;

    async fn hello() -> impl IntoResponse {
        "hello"
    }

    /// Build a make-service (returns a fresh `Router` clone for each call)
    /// wrapped with [`NormalizedMakeService`].
    fn make_normalized() -> NormalizedMakeService<
        impl Service<
            (),
            Response = Router,
            Error = std::convert::Infallible,
            Future = impl Future<Output = Result<Router, std::convert::Infallible>> + Send,
        >,
    > {
        let router = Router::new().route("/test", get(hello));
        let make_svc = tower::service_fn(move |_: ()| {
            let r = router.clone();
            async move { Ok::<_, std::convert::Infallible>(r) }
        });
        NormalizedMakeService::new(make_svc)
    }

    /// `NormalizedMakeService::poll_ready` delegates to the inner service.
    #[tokio::test]
    async fn normalized_make_service_poll_ready_delegates() {
        let mut nms = make_normalized();
        // `ready()` drives `poll_ready` until `Poll::Ready` — if delegation
        // is broken this will hang or panic.
        nms.ready().await.expect("poll_ready should succeed");
    }

    /// Constructing a `NormalizedMakeService` and calling it should return a
    /// service that strips trailing slashes (end-to-end through the wrapper).
    #[tokio::test]
    async fn normalized_make_service_strips_trailing_slash() {
        let mut nms = make_normalized();
        nms.ready().await.expect("poll_ready");
        let svc = nms.call(()).await.expect("call should return wrapped service");

        // With trailing slash — normalization should strip it before routing.
        let resp = svc
            .clone()
            .oneshot(Request::builder().uri("/test/").body(Body::empty()).expect("build"))
            .await
            .expect("request");
        assert_eq!(resp.status(), StatusCode::OK);

        // Without trailing slash — should work as normal.
        let resp = svc
            .oneshot(Request::builder().uri("/test").body(Body::empty()).expect("build"))
            .await
            .expect("request");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A path that does not exist should still return 404 even after
    /// normalization — ensures the wrapper doesn't swallow routing errors.
    #[tokio::test]
    async fn normalized_make_service_unknown_path_returns_404() {
        let mut nms = make_normalized();
        nms.ready().await.expect("poll_ready");
        let svc = nms.call(()).await.expect("call");

        let resp = svc
            .oneshot(Request::builder().uri("/no-such-path/").body(Body::empty()).expect("build"))
            .await
            .expect("request");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Requests with a trailing slash should be routed to the handler
    /// registered without one, thanks to the normalization layer.
    #[tokio::test]
    async fn trailing_slash_is_normalized() {
        let router = Router::new().route("/test", get(hello));
        let layer = NormalizePathLayer::trim_trailing_slash();
        let svc = layer.layer(router);

        // Without trailing slash — should work normally.
        let resp = svc
            .clone()
            .oneshot(Request::builder().uri("/test").body(Body::empty()).expect("build"))
            .await
            .expect("call");
        assert_eq!(resp.status(), StatusCode::OK);

        // With trailing slash — should also work after normalization.
        let resp = svc
            .oneshot(Request::builder().uri("/test/").body(Body::empty()).expect("build"))
            .await
            .expect("call");
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
