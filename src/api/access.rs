use crate::{
    auth::jwt::CurrentUser,
    database::{InventoryError, OwnerScope},
    models::patch::{ValidationError, ValidationStatus},
};
use axum::{
    async_trait,
    body::HttpBody,
    extract::{
        rejection::{BytesRejection, JsonRejection},
        FromRequest, RequestParts,
    },
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    BoxError, Json,
};
use hbb_common::log;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::error::Error as StdError;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    body: Value,
    retry_after_seconds: Option<u64>,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({ "error": message.into() }),
            retry_after_seconds: None,
        }
    }

    pub fn with_body(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            body,
            retry_after_seconds: None,
        }
    }

    pub fn retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub fn not_found(resource: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, format!("{resource} not found"))
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(self.body)).into_response();
        if let Some(seconds) = self.retry_after_seconds {
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

pub async fn require_inventory_write_access<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    if matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        let current = request
            .extensions()
            .get::<CurrentUser>()
            .ok_or_else(|| ApiError::internal("authenticated user context is unavailable"))?;
        write_access(current)?;
    }
    Ok(next.run(request).await)
}

#[derive(Debug)]
pub struct LimitedJson<T>(pub T);

#[async_trait]
impl<T, B> FromRequest<B> for LimitedJson<T>
where
    T: DeserializeOwned,
    B: HttpBody + Send,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Rejection = ApiError;

    async fn from_request(request: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or_default().trim());
        if !content_type.is_some_and(|mime| mime.eq_ignore_ascii_case("application/json")) {
            return Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json",
            ));
        }
        match Json::<T>::from_request(request).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(JsonRejection::BytesRejection(error)) => Err(bytes_rejection_error(error)),
            Err(JsonRejection::MissingJsonContentType(_)) => Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json",
            )),
            Err(JsonRejection::JsonDataError(_)) | Err(JsonRejection::JsonSyntaxError(_)) => {
                Err(ApiError::bad_request("invalid JSON request body"))
            }
            Err(_) => Err(ApiError::bad_request("invalid JSON request body")),
        }
    }
}

fn bytes_rejection_error(error: BytesRejection) -> ApiError {
    if error_chain_contains_length_limit(&error) {
        return ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the 256 KiB limit",
        );
    }
    match error {
        BytesRejection::BodyAlreadyExtracted(_) => {
            ApiError::internal("request body was already extracted")
        }
        _ => ApiError::bad_request("failed to read request body"),
    }
}

fn error_chain_contains_length_limit(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<http_body::LengthLimitError>()
            .is_some()
        {
            return true;
        }
        current = error.source();
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessRole {
    Admin,
    User,
    Viewer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryAccess {
    pub role: AccessRole,
    pub scope: OwnerScope,
}

impl InventoryAccess {
    pub fn is_admin(self) -> bool {
        self.role == AccessRole::Admin
    }
}

pub fn read_access(current: &CurrentUser) -> Result<InventoryAccess, ApiError> {
    let role = parse_role(&current.role)?;
    let scope = match role {
        AccessRole::Admin => OwnerScope::All,
        AccessRole::User | AccessRole::Viewer => OwnerScope::Owner(current.id),
    };
    Ok(InventoryAccess { role, scope })
}

pub fn write_access(current: &CurrentUser) -> Result<InventoryAccess, ApiError> {
    let access = read_access(current)?;
    match access.role {
        AccessRole::Admin | AccessRole::User => Ok(access),
        AccessRole::Viewer => Err(ApiError::forbidden("viewer role is read-only")),
    }
}

pub fn create_owner(
    current: &CurrentUser,
    access: InventoryAccess,
    requested_owner: Option<i64>,
) -> Result<i64, ApiError> {
    if access.is_admin() {
        return Ok(requested_owner.unwrap_or(current.id));
    }
    if requested_owner.is_some() {
        return Err(ApiError::forbidden("only admin can specify owner_user_id"));
    }
    Ok(current.id)
}

pub fn validation_error(error: ValidationError) -> ApiError {
    let status = match error.status {
        ValidationStatus::BadRequest => StatusCode::BAD_REQUEST,
        ValidationStatus::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
    };
    ApiError::new(status, error.message)
}

pub fn inventory_error(error: InventoryError, operation: &str) -> ApiError {
    match error {
        InventoryError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "resource not found"),
        InventoryError::Conflict(code) => ApiError::new(StatusCode::CONFLICT, code),
        InventoryError::DepthExceeded => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "group depth exceeds the supported limit",
        ),
        InventoryError::TooLarge => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "inventory operation exceeds the supported limit",
        ),
        InventoryError::Busy => {
            ApiError::service_unavailable("database is busy; retry the request").retry_after(1)
        }
        InventoryError::Internal(detail) => {
            log::error!("{}: {}", operation, detail);
            ApiError::internal(operation)
        }
    }
}

fn parse_role(role: &str) -> Result<AccessRole, ApiError> {
    match role {
        "admin" => Ok(AccessRole::Admin),
        "user" => Ok(AccessRole::User),
        "viewer" => Ok(AccessRole::Viewer),
        _ => Err(ApiError::forbidden("unknown role is not permitted")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::rejection::BodyAlreadyExtracted;

    fn current(role: &str) -> CurrentUser {
        CurrentUser {
            id: 7,
            username: "tester".to_string(),
            role: role.to_string(),
        }
    }

    #[test]
    fn scopes_roles_and_rejects_unknown_roles() {
        assert_eq!(
            read_access(&current("admin")).unwrap().scope,
            OwnerScope::All
        );
        assert_eq!(
            read_access(&current("user")).unwrap().scope,
            OwnerScope::Owner(7)
        );
        assert_eq!(
            read_access(&current("viewer")).unwrap().scope,
            OwnerScope::Owner(7)
        );
        assert!(read_access(&current("unexpected")).is_err());
    }

    #[test]
    fn viewer_is_read_only_and_user_cannot_supply_owner() {
        assert!(write_access(&current("viewer")).is_err());
        let user = current("user");
        let access = write_access(&user).unwrap();
        assert!(create_owner(&user, access, Some(7)).is_err());
        assert_eq!(create_owner(&user, access, None).unwrap(), 7);
    }

    #[test]
    fn non_length_body_rejection_is_not_reported_as_payload_too_large() {
        let error = bytes_rejection_error(BytesRejection::BodyAlreadyExtracted(
            BodyAlreadyExtracted::default(),
        ));
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
