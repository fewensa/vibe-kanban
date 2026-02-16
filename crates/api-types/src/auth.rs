use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LocalUser {
    pub id: String,
    pub email: String,
    pub username: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AuthSession {
    pub id: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct SetupRequest {
    pub email: String,
    pub password: String,
    pub username: Option<String>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct LoginResponse {
    pub user: LocalUser,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct AuthStatusResponse {
    pub setup_required: bool,
    pub authenticated: bool,
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct LocalCurrentUserResponse {
    pub user: LocalUser,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub username: Option<String>,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct UserListResponse {
    pub users: Vec<LocalUser>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct UserResponse {
    pub user: LocalUser,
}
