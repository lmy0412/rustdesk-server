use axum::{
    body::Body,
    http::{
        header::{self, HeaderName, HeaderValue},
        Method, Response, StatusCode, Uri,
    },
};
use rust_embed::RustEmbed;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'";

#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct WebAssets;

pub async fn handle_web_request(method: Method, uri: Uri) -> Response<Body> {
    if method != Method::GET && method != Method::HEAD {
        let mut method_not_allowed = response(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            b"method not allowed".to_vec(),
            false,
            false,
        );
        method_not_allowed
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return method_not_allowed;
    }

    let requested = uri.path().trim_start_matches('/');
    if invalid_path(requested) {
        return not_found(false);
    }
    if requested == "api" || requested.starts_with("api/") {
        return response(
            StatusCode::NOT_FOUND,
            "application/json; charset=utf-8",
            br#"{"error":"not found"}"#.to_vec(),
            method == Method::HEAD,
            false,
        );
    }

    let path = if requested.is_empty() {
        "index.html"
    } else {
        requested
    };
    if let Some(asset) = WebAssets::get(path) {
        return response(
            StatusCode::OK,
            content_type(path),
            asset.data.into_owned(),
            method == Method::HEAD,
            path.starts_with("assets/"),
        );
    }

    if !has_file_extension(path) {
        if let Some(index) = WebAssets::get("index.html") {
            return response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                index.data.into_owned(),
                method == Method::HEAD,
                false,
            );
        }
    }
    not_found(method == Method::HEAD)
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    bytes: Vec<u8>,
    head_only: bool,
    immutable: bool,
) -> Response<Body> {
    let length = bytes.len().to_string();
    let cache_control = if immutable {
        "public, max-age=31536000, immutable"
    } else {
        "no-store"
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, length)
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::X_FRAME_OPTIONS, "DENY")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        )
        .body(if head_only {
            Body::empty()
        } else {
            Body::from(bytes)
        })
        .expect("static web response headers are valid")
}

fn not_found(head_only: bool) -> Response<Body> {
    response(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        b"not found".to_vec(),
        head_only,
        false,
    )
}

fn invalid_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    path.contains('\\')
        || path.split('/').any(|segment| segment == "..")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
}

fn has_file_extension(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|name| name.contains('.'))
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or_default() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::HttpBody;

    #[test]
    fn serves_index_assets_and_spa_routes_with_security_headers() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let index = handle_web_request(Method::GET, Uri::from_static("/")).await;
            assert_eq!(index.status(), StatusCode::OK);
            assert_eq!(
                index.headers()[header::CONTENT_TYPE],
                "text/html; charset=utf-8"
            );
            assert_eq!(index.headers()[header::CACHE_CONTROL], "no-store");
            let csp = index.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap();
            assert!(csp.contains("script-src 'self'"));
            assert!(!csp.contains("unsafe-inline"));
            assert!(!csp.contains("unsafe-eval"));

            let spa = handle_web_request(Method::GET, Uri::from_static("/devices")).await;
            assert_eq!(spa.status(), StatusCode::OK);
            assert_eq!(
                spa.headers()[header::CONTENT_TYPE],
                "text/html; charset=utf-8"
            );

            let asset_path = WebAssets::iter()
                .find(|path| path.starts_with("assets/") && path.ends_with(".js"))
                .expect("Vite JavaScript asset must be embedded");
            let asset_uri: Uri = format!("/{asset_path}").parse().unwrap();
            let asset = handle_web_request(Method::GET, asset_uri).await;
            assert_eq!(asset.status(), StatusCode::OK);
            assert_eq!(
                asset.headers()[header::CONTENT_TYPE],
                "text/javascript; charset=utf-8"
            );
            assert!(asset.headers()[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("immutable"));
        });
    }

    #[test]
    fn preserves_api_and_missing_asset_404_and_supports_head() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let api = handle_web_request(Method::GET, Uri::from_static("/api/missing")).await;
            assert_eq!(api.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                api.headers()[header::CONTENT_TYPE],
                "application/json; charset=utf-8"
            );

            let missing =
                handle_web_request(Method::GET, Uri::from_static("/assets/missing.js")).await;
            assert_eq!(missing.status(), StatusCode::NOT_FOUND);

            let mut head = handle_web_request(Method::HEAD, Uri::from_static("/dashboard")).await;
            assert_eq!(head.status(), StatusCode::OK);
            assert!(head.body_mut().data().await.is_none());

            let traversal =
                handle_web_request(Method::GET, Uri::from_static("/../Cargo.toml")).await;
            assert_eq!(traversal.status(), StatusCode::NOT_FOUND);
            let encoded_traversal =
                handle_web_request(Method::GET, Uri::from_static("/%2e%2e/devices")).await;
            assert_eq!(encoded_traversal.status(), StatusCode::NOT_FOUND);

            let method = handle_web_request(Method::POST, Uri::from_static("/")).await;
            assert_eq!(method.status(), StatusCode::METHOD_NOT_ALLOWED);
        });
    }
}
