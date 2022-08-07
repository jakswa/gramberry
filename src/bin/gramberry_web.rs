use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(
            gramberry::build_router()
                .layer(tower_http::trace::TraceLayer::new_for_http())
                .into_make_service(),
        )
        .await
        .unwrap();
}
