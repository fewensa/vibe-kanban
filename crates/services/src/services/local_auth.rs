use anyhow::Result;
use argon2::{
    Argon2,
    PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Duration, Utc};
use sqlx::{SqlitePool, Row};
use thiserror::Error;
use tracing::warn;

use api_types::{AuthSession, LocalUser, LoginResponse, SetupRequest};

const SESSION_DURATION_DAYS: i64 = 30;
const SESSION_INACTIVITY_DAYS: i64 = 7;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User not found")]
    UserNotFound,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Session expired")]
    SessionExpired,
    #[error("Session revoked")]
    SessionRevoked,
    #[error("Email already exists")]
    EmailExists,
    #[error("Cannot delete yourself")]
    CannotDeleteSelf,
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Password hashing error: {0}")]
    PasswordHash(String),
    #[error("Setup already completed")]
    SetupCompleted,
}

pub struct LocalAuthService {
    pool: SqlitePool,
}

impl LocalAuthService {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Check if initial setup is required (no users exist)
    pub async fn is_setup_required(&self) -> Result<bool, AuthError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(count == 0)
    }

    /// Create the initial admin user
    pub async fn setup_initial_user(&self, req: SetupRequest) -> Result<LoginResponse, AuthError> {
        if !self.is_setup_required().await? {
            return Err(AuthError::SetupCompleted);
        }

        let user_id = uuid::Uuid::new_v4().to_string();
        let password_hash = self.hash_password(&req.password)?;

        sqlx::query(
            "INSERT INTO users (id, email, password_hash, username) VALUES (?1, ?2, ?3, ?4)"
        )
        .bind(&user_id)
        .bind(&req.email)
        .bind(&password_hash)
        .bind(&req.username)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                AuthError::EmailExists
            } else {
                AuthError::Database(e)
            }
        })?;

        let user = self.get_user_by_id(&user_id).await?;
        let session = self.create_session(&user_id).await?;

        Ok(LoginResponse {
            user,
            session_token: session.token,
            expires_at: session.session.expires_at,
        })
    }

    /// Authenticate user and create session
    pub async fn login(&self, email: &str, password: &str) -> Result<LoginResponse, AuthError> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, username, created_at, updated_at FROM users WHERE email = ?1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        let row = row.ok_or(AuthError::InvalidCredentials)?;

        let id: String = row.try_get("id")?;
        let email: String = row.try_get("email")?;
        let password_hash: String = row.try_get("password_hash")?;
        let username: Option<String> = row.try_get("username")?;
        let created_at: String = row.try_get("created_at")?;
        let updated_at: String = row.try_get("updated_at")?;

        // Verify password
        self.verify_password(password, &password_hash)?;

        let user = LocalUser {
            id: id.clone(),
            email,
            username,
            created_at: DateTime::parse_from_rfc3339(&created_at)
                .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_at)
                .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
                .with_timezone(&Utc),
        };

        let session = self.create_session(&id).await?;

        Ok(LoginResponse {
            user,
            session_token: session.token,
            expires_at: session.session.expires_at,
        })
    }

    /// Validate session token and return user
    pub async fn validate_session(&self, token: &str) -> Result<(LocalUser, String), AuthError> {
        let token_hash = self.hash_token(token);

        let row = sqlx::query(
            "SELECT id, user_id, expires_at, last_used_at, revoked_at FROM auth_sessions WHERE token_hash = ?1"
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AuthError::SessionNotFound)?;

        let session_id: String = row.try_get("id")?;
        let user_id: String = row.try_get("user_id")?;
        let expires_at: String = row.try_get("expires_at")?;
        let last_used_at: String = row.try_get("last_used_at")?;
        let revoked_at: Option<String> = row.try_get("revoked_at")?;

        if revoked_at.is_some() {
            return Err(AuthError::SessionRevoked);
        }

        let expires_at_dt = DateTime::parse_from_rfc3339(&expires_at)
            .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
            .with_timezone(&Utc);

        if Utc::now() > expires_at_dt {
            return Err(AuthError::SessionExpired);
        }

        let last_used_at_dt = DateTime::parse_from_rfc3339(&last_used_at)
            .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
            .with_timezone(&Utc);

        let inactivity_duration = Utc::now() - last_used_at_dt;
        if inactivity_duration > Duration::days(SESSION_INACTIVITY_DAYS) {
            self.revoke_session(&session_id).await?;
            return Err(AuthError::SessionExpired);
        }

        // Touch session
        self.touch_session(&session_id).await?;

        let user = self.get_user_by_id(&user_id).await?;

        Ok((user, session_id))
    }

    /// Revoke a session (logout)
    pub async fn logout(&self, token: &str) -> Result<(), AuthError> {
        let token_hash = self.hash_token(token);

        let row = sqlx::query(
            "SELECT id FROM auth_sessions WHERE token_hash = ?1"
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AuthError::SessionNotFound)?;

        let session_id: String = row.try_get("id")?;

        self.revoke_session(&session_id).await?;

        Ok(())
    }

    /// Create a new session for a user
    async fn create_session(&self, user_id: &str) -> Result<SessionWithToken, AuthError> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let token = self.generate_token();
        let token_hash = self.hash_token(&token);
        let expires_at = Utc::now() + Duration::days(SESSION_DURATION_DAYS);

        sqlx::query(
            "INSERT INTO auth_sessions (id, user_id, token_hash, expires_at) VALUES (?1, ?2, ?3, ?4)"
        )
        .bind(&session_id)
        .bind(user_id)
        .bind(&token_hash)
        .bind(expires_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        let session = self.get_session_by_id(&session_id).await?;

        Ok(SessionWithToken { session, token })
    }

    async fn get_session_by_id(&self, id: &str) -> Result<AuthSession, AuthError> {
        let row = sqlx::query(
            "SELECT id, user_id, expires_at, last_used_at, created_at FROM auth_sessions WHERE id = ?1"
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(AuthSession {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            expires_at: DateTime::parse_from_rfc3339(&row.try_get::<String, _>("expires_at")?)
                .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
                .with_timezone(&Utc),
            last_used_at: DateTime::parse_from_rfc3339(&row.try_get::<String, _>("last_used_at")?)
                .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
                .with_timezone(&Utc),
            created_at: DateTime::parse_from_rfc3339(&row.try_get::<String, _>("created_at")?)
                .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
                .with_timezone(&Utc),
        })
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<LocalUser, AuthError> {
        let row = sqlx::query(
            "SELECT id, email, username, created_at, updated_at FROM users WHERE id = ?1"
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(LocalUser {
            id: row.try_get("id")?,
            email: row.try_get("email")?,
            username: row.try_get("username")?,
            created_at: DateTime::parse_from_rfc3339(&row.try_get::<String, _>("created_at")?)
                .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.try_get::<String, _>("updated_at")?)
                .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
                .with_timezone(&Utc),
        })
    }

    async fn touch_session(&self, id: &str) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE auth_sessions SET last_used_at = ?1 WHERE id = ?2"
        )
        .bind(Utc::now().to_rfc3339())
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn revoke_session(&self, id: &str) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE auth_sessions SET revoked_at = ?1 WHERE id = ?2"
        )
        .bind(Utc::now().to_rfc3339())
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| AuthError::PasswordHash(e.to_string()))
    }

    fn verify_password(&self, password: &str, hash: &str) -> Result<(), AuthError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::PasswordHash(e.to_string()))?;

        let argon2 = Argon2::default();

        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)
    }

    fn generate_token(&self) -> String {
        let mut rng = rand::thread_rng();
        let token_bytes: [u8; 32] = rand::Rng::r#gen(&mut rng);
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.encode(token_bytes)
    }

    fn hash_token(&self, token: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<(), AuthError> {
        let now = Utc::now();
        let inactivity_threshold = now - Duration::days(SESSION_INACTIVITY_DAYS);

        let result = sqlx::query(
            "UPDATE auth_sessions SET revoked_at = ?1 WHERE revoked_at IS NULL AND (expires_at < ?1 OR last_used_at < ?2)"
        )
        .bind(now.to_rfc3339())
        .bind(inactivity_threshold.to_rfc3339())
        .execute(&self.pool)
        .await?;

        let count = result.rows_affected();

        if count > 0 {
            warn!("Revoked {} expired/inactive sessions", count);
        }

        Ok(())
    }

    /// Change user password
    pub async fn change_password(
        &self,
        user_id: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        // Fetch current password hash
        let row = sqlx::query("SELECT password_hash FROM users WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let password_hash: String = row.try_get("password_hash")?;

        // Verify current password
        self.verify_password(current_password, &password_hash)?;

        // Hash new password
        let new_password_hash = self.hash_password(new_password)?;

        // Update password
        sqlx::query("UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&new_password_hash)
            .bind(Utc::now().to_rfc3339())
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Get all users (admin only)
    pub async fn list_users(&self) -> Result<Vec<LocalUser>, AuthError> {
        let rows = sqlx::query(
            "SELECT id, email, username, created_at, updated_at FROM users ORDER BY created_at ASC"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut users = Vec::new();
        for row in rows {
            users.push(LocalUser {
                id: row.try_get("id")?,
                email: row.try_get("email")?,
                username: row.try_get("username")?,
                created_at: DateTime::parse_from_rfc3339(&row.try_get::<String, _>("created_at")?)
                    .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
                    .with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&row.try_get::<String, _>("updated_at")?)
                    .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))?
                    .with_timezone(&Utc),
            });
        }

        Ok(users)
    }

    /// Create a new user (admin only)
    pub async fn create_user(
        &self,
        email: &str,
        password: &str,
        username: Option<String>,
    ) -> Result<LocalUser, AuthError> {
        let user_id = uuid::Uuid::new_v4().to_string();
        let password_hash = self.hash_password(password)?;

        sqlx::query(
            "INSERT INTO users (id, email, password_hash, username) VALUES (?1, ?2, ?3, ?4)"
        )
        .bind(&user_id)
        .bind(email)
        .bind(&password_hash)
        .bind(&username)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                AuthError::EmailExists
            } else {
                AuthError::Database(e)
            }
        })?;

        self.get_user_by_id(&user_id).await
    }

    /// Update user information (admin only)
    pub async fn update_user(
        &self,
        user_id: &str,
        username: Option<String>,
    ) -> Result<LocalUser, AuthError> {
        sqlx::query("UPDATE users SET username = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&username)
            .bind(Utc::now().to_rfc3339())
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        self.get_user_by_id(user_id).await
    }

    /// Delete a user (admin only)
    pub async fn delete_user(&self, user_id: &str) -> Result<(), AuthError> {
        // Check if user exists
        let _ = self.get_user_by_id(user_id).await?;

        // Revoke all user sessions
        sqlx::query("UPDATE auth_sessions SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL")
            .bind(Utc::now().to_rfc3339())
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        // Delete user
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

struct SessionWithToken {
    session: AuthSession,
    token: String,
}
