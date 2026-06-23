use once_cell::sync::Lazy;
use openidconnect::{HttpRequest, HttpResponse};
use reqwest::Client;
use std::{error::Error, fmt, time::Duration};

static REQWEST_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .user_agent(format!("rustdesk-server/{}", crate::version::VERSION))
        .build()
        .expect("failed to create OIDC HTTP client")
});

pub async fn oidc_http_client(request: HttpRequest) -> Result<HttpResponse, OidcHttpError> {
    let mut req = REQWEST_CLIENT.request(request.method.clone(), request.url);

    for (name, value) in request.headers.iter() {
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(OidcHttpError::from_error)?;
        let header_value = reqwest::header::HeaderValue::from_bytes(value.as_bytes())
            .map_err(OidcHttpError::from_error)?;
        req = req.header(header_name, header_value);
    }

    if !request.body.is_empty() {
        req = req.body(request.body);
    }

    let resp = req.send().await.map_err(OidcHttpError::from_error)?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .bytes()
        .await
        .map_err(OidcHttpError::from_error)?
        .to_vec();
    Ok(HttpResponse {
        status_code: status,
        headers,
        body,
    })
}

#[derive(Debug, Clone)]
pub struct OidcHttpError(String);

impl OidcHttpError {
    fn from_error(error: impl Error) -> Self {
        Self(error.to_string())
    }
}

impl fmt::Display for OidcHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for OidcHttpError {}
