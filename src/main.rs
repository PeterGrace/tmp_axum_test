#[macro_use]
extern crate tracing;
use aide::axum::routing::get_with;
use aide::axum::{routing::get, ApiRouter, IntoApiResponse};
use aide::openapi::{OpenApi, Tag};
use aide::redoc::Redoc;
use aide::scalar::Scalar;
use aide::swagger::Swagger;
use aide::transform::TransformOpenApi;
use axum::{response, response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_sessions::cookie::time::Duration;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer};
use tracing_subscriber::EnvFilter;

const COUNTER_KEY: &str = "counter";

#[derive(Default, Deserialize, Serialize)]
struct Counter(usize);

async fn handler(session: Session) -> impl IntoApiResponse {
    let counter: Counter = session.get(COUNTER_KEY).await.unwrap().unwrap_or_default();
    session.insert(COUNTER_KEY, counter.0 + 1).await.unwrap();
    format!("Current count: {}", counter.0)
}

#[tokio::main]
async fn main() {
    aide::generate::on_error(|error| {
        error!("aide: {error}");
    });

    aide::generate::extract_schemas(true);

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("debug"))
        .unwrap();
    tracing_subscriber::fmt()
        .with_env_filter(filter_layer)
        .with_file(true)
        .with_line_number(true)
        .init();

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(10)));

    let mut api = OpenApi::default();

    let app = ApiRouter::new()
        .layer(session_layer)
        .api_route("/", get(handler))
        .nest_api_service("/docs", docs_routes())
        .finish_api_with(&mut api, api_docs)
        .layer(Extension(Arc::new(api)));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
fn api_docs(api: TransformOpenApi) -> TransformOpenApi {
    api.title("Aide axum Open API")
        .summary("An example Todo application")
        .description(include_str!("../README.md"))
        .tag(Tag {
            name: "todo".into(),
            description: Some("Todo Management".into()),
            ..Default::default()
        })
        .security_scheme(
            "ApiKey",
            aide::openapi::SecurityScheme::ApiKey {
                location: aide::openapi::ApiKeyLocation::Header,
                name: "X-Auth-Key".into(),
                description: Some("A key that is ignored.".into()),
                extensions: Default::default(),
            },
        )
}
pub fn docs_routes() -> ApiRouter {
    // We infer the return types for these routes
    // as an example.
    //
    // As a result, the `serve_redoc` route will
    // have the `text/html` content-type correctly set
    // with a 200 status.
    aide::generate::infer_responses(true);

    let router: ApiRouter = ApiRouter::new()
        .api_route_with(
            "/",
            get_with(
                Scalar::new("/docs/private/api.json")
                    .with_title("Aide Axum")
                    .axum_handler(),
                |op| op.description("This documentation page."),
            ),
            |p| p.security_requirement("ApiKey"),
        )
        .api_route_with(
            "/redoc",
            get_with(
                Redoc::new("/docs/private/api.json")
                    .with_title("Aide Axum")
                    .axum_handler(),
                |op| op.description("This documentation page."),
            ),
            |p| p.security_requirement("ApiKey"),
        )
        .api_route_with(
            "/swagger",
            get_with(
                Swagger::new("/docs/private/api.json")
                    .with_title("Aide Axum")
                    .axum_handler(),
                |op| op.description("This documentation page."),
            ),
            |p| p.security_requirement("ApiKey"),
        )
        .route("/private/api.json", get(serve_docs));

    // Afterwards we disable response inference because
    // it might be incorrect for other routes.
    aide::generate::infer_responses(false);

    router
}

async fn serve_docs(Extension(api): Extension<Arc<OpenApi>>) -> impl IntoApiResponse {
    Json(api).into_response()
}
