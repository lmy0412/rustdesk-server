use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub db: &'static str,
}

pub async fn handle_health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        db: "not_configured",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_ok() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let Json(response) = rt.block_on(handle_health());

        assert_eq!(response.status, "ok");
        assert_eq!(response.db, "not_configured");
    }
}
