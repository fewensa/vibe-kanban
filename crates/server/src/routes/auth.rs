use axum::{
    Extension,
    Json,
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use tracing::error;
use deployment::Deployment;

use api_types::{
    AuthStatusResponse, ChangePasswordRequest, CreateUserRequest,
    LocalCurrentUserResponse, LoginRequest, SetupRequest, UpdateUserRequest,
    UserListResponse, UserResponse,
};
use services::services::local_auth::{AuthError, LocalAuthService};

use crate::{DeploymentImpl, middleware::AuthContext};

pub fn public_router() -> Router<DeploymentImpl> {
    Router::new()
        .route("/auth/local/status", get(auth_status))
        .route("/auth/local/setup", post(setup))
        .route("/auth/local/login", post(login))
}

pub fn protected_router() -> Router<DeploymentImpl> {
    Router::new()
        .route("/auth/local/logout", post(logout))
        .route("/auth/local/me", get(current_user))
        .route("/auth/local/change-password", post(change_password))
        .route("/auth/users", get(list_users).post(create_user))
        .route("/auth/users/{id}", get(get_user).patch(update_user).delete(delete_user))
}

async fn auth_status(
    State(deployment): State<DeploymentImpl>,
) -> Result<Json<AuthStatusResponse>, AppError> {
    let auth_service = LocalAuthService::new(deployment.db().pool.clone());
    let setup_required = auth_service.is_setup_required().await?;

    Ok(Json(AuthStatusResponse {
        setup_required,
        authenticated: false,
    }))
}

async fn setup(
    State(deployment): State<DeploymentImpl>,
    Json(req): Json<SetupRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let auth_service = LocalAuthService::new(deployment.db().pool.clone());

    let response = auth_service.setup_initial_user(req).await?;

    Ok(Json(json!({
        "user": response.user,
        "session_token": response.session_token,
        "expires_at": response.expires_at,
    })))
}

async fn login(
    State(deployment): State<DeploymentImpl>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let auth_service = LocalAuthService::new(deployment.db().pool.clone());

    let response = auth_service.login(&req.email, &req.password).await?;

    Ok(Json(json!({
        "user": response.user,
        "session_token": response.session_token,
        "expires_at": response.expires_at,
    })))
}

async fn logout(
    State(deployment): State<DeploymentImpl>,
    Extension(auth_ctx): Extension<AuthContext>,
) -> Result<StatusCode, AppError> {
    let auth_service = LocalAuthService::new(deployment.db().pool.clone());
    
    // Revoke the session using the token from auth context
    auth_service.logout(&auth_ctx.token).await?;

    Ok(StatusCode::OK)
}

async fn current_user(
    Extension(auth_ctx): Extension<AuthContext>,
) -> Result<Json<LocalCurrentUserResponse>, AppError> {
    Ok(Json(LocalCurrentUserResponse {
        user: auth_ctx.user,
    }))
}

async fn change_password(
    State(deployment): State<DeploymentImpl>,
    Extension(auth_ctx): Extension<AuthContext>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, AppError> {
    let auth_service = LocalAuthService::new(deployment.db().pool.clone());
    
    auth_service
        .change_password(&auth_ctx.user.id, &req.current_password, &req.new_password)
        .await?;

    Ok(StatusCode::OK)
}

async fn list_users(
    State(deployment): State<DeploymentImpl>,
    Extension(_auth_ctx): Extension<AuthContext>,
) -> Result<Json<UserListResponse>, AppError> {
    let auth_service = LocalAuthService::new(deployment.db().pool.clone());
    
    let users = auth_service.list_users().await?;

    Ok(Json(UserListResponse { users }))
}

async fn create_user(
    State(deployment): State<DeploymentImpl>,
    Extension(_auth_ctx): Extension<AuthContext>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    let auth_service = LocalAuthService::new(deployment.db().pool.clone());
    
    let user = auth_service
        .create_user(&req.email, &req.password, req.username)
        .await?;

    Ok((StatusCode::CREATED, Json(UserResponse { user })))
}

async fn get_user(
    State(deployment): State<DeploymentImpl>,
    Extension(_auth_ctx): Extension<AuthContext>,
    Path(user_id): Path<String>,
) -> Result<Json<UserResponse>, AppError> {
    let auth_service = LocalAuthService::new(deployment.db().pool.clone());
    
    let user = auth_service.get_user_by_id(&user_id).await.map_err(|_| {
        AppError(anyhow::anyhow!(AuthError::UserNotFound))
    })?;

    Ok(Json(UserResponse { user }))
}

async fn update_user(
    State(deployment): State<DeploymentImpl>,
    Extension(_auth_ctx): Extension<AuthContext>,
    Path(user_id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    let auth_service = LocalAuthService::new(deployment.db().pool.clone());
    
    let user = auth_service
        .update_user(&user_id, req.username)
        .await?;

    Ok(Json(UserResponse { user }))
}

async fn delete_user(
    State(deployment): State<DeploymentImpl>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(user_id): Path<String>,
) -> Result<StatusCode, AppError> {
    // Prevent user from deleting themselves
    if auth_ctx.user.id == user_id {
        return Err(AppError::from(AuthError::CannotDeleteSelf));
    }

    let auth_service = LocalAuthService::new(deployment.db().pool.clone());
    
    auth_service.delete_user(&user_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// Error handling
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self.0.downcast_ref::<AuthError>() {
            Some(AuthError::InvalidCredentials) => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            Some(AuthError::UserNotFound) => (StatusCode::NOT_FOUND, "User not found"),
            Some(AuthError::SessionNotFound) => (StatusCode::UNAUTHORIZED, "Session not found"),
            Some(AuthError::SessionExpired) => (StatusCode::UNAUTHORIZED, "Session expired"),
            Some(AuthError::SessionRevoked) => (StatusCode::UNAUTHORIZED, "Session revoked"),
            Some(AuthError::EmailExists) => (StatusCode::CONFLICT, "Email already exists"),
            Some(AuthError::CannotDeleteSelf) => (StatusCode::FORBIDDEN, "Cannot delete yourself"),
            Some(AuthError::SetupCompleted) => (StatusCode::CONFLICT, "Setup already completed"),
            Some(AuthError::Database(_)) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
            Some(AuthError::PasswordHash(_)) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
            None => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };

        error!("API error: {}", self.0);

        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
