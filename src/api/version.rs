use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct VersionResponse {
    pub version: &'static str,
    pub rustc: &'static str,
    pub features: Vec<&'static str>,
}

pub async fn handle_version() -> Json<VersionResponse> {
    let mut features = Vec::new();
    if cfg!(feature = "pro") {
        features.push("pro");
    }

    Json(VersionResponse {
        version: crate::version::VERSION,
        rustc: option_env!("RUSTC_VERSION").unwrap_or("unknown"),
        features,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_ok() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let Json(response) = rt.block_on(handle_version());

        assert!(!response.version.is_empty());
        assert!(!response.rustc.is_empty());
    }

    #[test]
    fn test_version_features() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let Json(response) = rt.block_on(handle_version());

        #[cfg(not(feature = "pro"))]
        assert!(response.features.is_empty());
        #[cfg(feature = "pro")]
        assert_eq!(response.features, vec!["pro"]);
    }
}
