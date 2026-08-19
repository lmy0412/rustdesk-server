use crate::database::Database;
use axum::{http::StatusCode, Extension, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub db: &'static str,
}

pub async fn handle_health(
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<HealthResponse>) {
    match db.health_check().await {
        Ok(()) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok",
                db: db.backend().as_str(),
            }),
        ),
        Err(error) => {
            hbb_common::log::warn!("数据库健康检查失败: {}", error);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    status: "unavailable",
                    db: db.backend().as_str(),
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_ok() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let path =
            std::env::temp_dir().join(format!("rustdesk-health-{}.sqlite3", uuid::Uuid::new_v4()));
        let db = rt.block_on(Database::new(path.to_str().unwrap())).unwrap();
        let (status, Json(response)) = rt.block_on(handle_health(Extension(db)));

        assert_eq!(status, StatusCode::OK);
        assert_eq!(response.status, "ok");
        assert_eq!(response.db, "sqlite");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(format!("{}.migration.lock", path.display())).ok();
    }
}
