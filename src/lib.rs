use axum_extra::extract::cookie::Key as CookieKey;
mod routes;

pub fn build_router() -> axum::Router {
    let key = match std::env::var("GRAMBERRY_SECRET") {
        Ok(secret) => CookieKey::from(secret[..].as_bytes()),
        _ => CookieKey::generate(),
    };
    routes::build().layer(axum::Extension(key))
}
