use crate::api::{
    access::ApiError,
    sysinfo::{plain_text, require_json_or_text},
};
use axum::{
    body::Bytes,
    http::{header, HeaderMap, StatusCode},
    response::Response,
};

pub async fn handle_sysinfo_ver(headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    if headers.contains_key(header::CONTENT_TYPE) {
        require_json_or_text(&headers)?;
    }
    if !body.iter().all(u8::is_ascii_whitespace) {
        return Err(ApiError::bad_request("sysinfo_ver body must be empty"));
    }
    Ok(plain_text(
        StatusCode::OK,
        format!("{}-pro", crate::version::VERSION),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn version_suffix_is_pro() {
        let response =
            plain_text(StatusCode::OK, format!("{}-pro", crate::version::VERSION)).into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
