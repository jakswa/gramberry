use gramberry::router;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(
            router()
                .layer(tower_http::trace::TraceLayer::new_for_http())
                .into_make_service(),
        )
        .await
        .unwrap();
}
