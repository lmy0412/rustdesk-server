use crate::{
    api::{
        access::ApiError,
        auth_service::hash_plain_password,
        middleware::{invalidate_token_cache, ApiProtectionState},
    },
    auth::jwt::CurrentUser,
    database::{Database, UpdateUserFields},
    models::user::{
        validate_safe_user_id, validate_username, CreateUserRequest, UpdateUserRequest,
        UserSummary, MAX_SAFE_INTEGER,
    },
};
use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    Json,
};
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pagination {
    page: Option<i64>,
    page_size: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserListResponse {
    items: Vec<UserSummary>,
    total: i64,
}

pub async fn handle_list_users(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<UserListResponse>, ApiError> {
    if current.role == "admin" {
        let (users, total) = db
            .list_users(
                pagination.page.unwrap_or(1),
                pagination.page_size.unwrap_or(20),
            )
            .await
            .map_err(|_| ApiError::internal("list users failed"))?;
        if !(0..=MAX_SAFE_INTEGER).contains(&total)
            || users
                .iter()
                .any(|user| validate_safe_user_id(user.id).is_err())
        {
            return Err(ApiError::internal("invalid user list response"));
        }
        return Ok(Json(UserListResponse {
            items: users.into_iter().map(UserSummary::from).collect(),
            total,
        }));
    }

    let user = db
        .find_user_by_id(current.id)
        .await
        .map_err(|_| ApiError::internal("user lookup failed"))?
        .ok_or_else(not_found)?;
    validate_safe_user_id(user.id).map_err(|_| ApiError::internal("invalid user id"))?;
    Ok(Json(UserListResponse {
        items: vec![UserSummary::from(user)],
        total: 1,
    }))
}

pub async fn handle_create_user(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(protection): Extension<ApiProtectionState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserSummary>), ApiError> {
    require_admin(&current)?;
    validate_role(&payload.role)?;
    validate_username(&payload.username).map_err(ApiError::bad_request)?;

    if db
        .find_user_by_username(&payload.username)
        .await
        .map_err(|_| ApiError::internal("user lookup failed"))?
        .is_some()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "username already exists",
        ));
    }

    let password_hash = hash_plain_password(&protection, &payload.password).await?;
    let user = db
        .create_user(
            &payload.username,
            &password_hash,
            payload.email.as_deref(),
            &payload.role,
        )
        .await
        .map_err(|_| ApiError::internal("create user failed"))?;
    validate_safe_user_id(user.id).map_err(|_| ApiError::internal("invalid user id"))?;

    Ok((StatusCode::CREATED, Json(UserSummary::from(user))))
}

pub async fn handle_get_user(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Result<Json<UserSummary>, ApiError> {
    require_self_or_admin(&current, id)?;
    let user = db
        .find_user_by_id(id)
        .await
        .map_err(|_| ApiError::internal("user lookup failed"))?
        .ok_or_else(not_found)?;
    validate_safe_user_id(user.id).map_err(|_| ApiError::internal("invalid user id"))?;
    Ok(Json(UserSummary::from(user)))
}

pub async fn handle_update_user(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Extension(protection): Extension<ApiProtectionState>,
    Path(id): Path<i64>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserSummary>, ApiError> {
    require_self_or_admin(&current, id)?;
    if current.role != "admin" && (payload.role.is_some() || payload.is_active.is_some()) {
        return Err(ApiError::forbidden(
            "only admin can update role or active state",
        ));
    }
    if let Some(role) = payload.role.as_ref() {
        validate_role(role)?;
    }

    let password_hash = match payload.password.as_ref() {
        Some(password) => Some(hash_plain_password(&protection, password).await?),
        None => None,
    };
    let should_increment_token_version = password_hash.is_some()
        || payload.force_logout.unwrap_or(false)
        || payload.is_active == Some(false);

    let user = db
        .update_user(
            id,
            UpdateUserFields {
                email: payload.email,
                role: if current.role == "admin" {
                    payload.role
                } else {
                    None
                },
                is_active: if current.role == "admin" {
                    payload.is_active
                } else {
                    None
                },
                password_hash,
                increment_token_version: should_increment_token_version,
            },
        )
        .await
        .map_err(|_| ApiError::internal("update user failed"))?;
    validate_safe_user_id(user.id).map_err(|_| ApiError::internal("invalid user id"))?;

    if should_increment_token_version {
        invalidate_token_cache(id);
    }

    Ok(Json(UserSummary::from(user)))
}

pub async fn handle_delete_user(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    require_admin(&current)?;
    if current.id == id {
        return Err(ApiError::bad_request("admin cannot delete self"));
    }

    db.deactivate_user(id)
        .await
        .map_err(|_| ApiError::internal("delete user failed"))?;
    invalidate_token_cache(id);
    Ok(StatusCode::NO_CONTENT)
}

fn require_admin(current: &CurrentUser) -> Result<(), ApiError> {
    if current.role != "admin" {
        return Err(ApiError::forbidden("admin role required"));
    }
    Ok(())
}

fn require_self_or_admin(current: &CurrentUser, target_id: i64) -> Result<(), ApiError> {
    if current.role != "admin" && current.id != target_id {
        return Err(ApiError::forbidden("you can only access your own resource"));
    }
    Ok(())
}

fn validate_role(role: &str) -> Result<(), ApiError> {
    match role {
        "admin" | "user" | "viewer" => Ok(()),
        _ => Err(ApiError::bad_request("invalid role")),
    }
}

fn not_found() -> ApiError {
    ApiError::not_found("user")
}
