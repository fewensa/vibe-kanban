use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::warn;
use deployment::Deployment;

use api_types::LocalUser;
use services::services::local_auth::{AuthError, LocalAuthService};

use crate::DeploymentImpl;

#[derive(Clone)]
pub struct AuthContext {
    pub user: LocalUser,
    pub session_id: String,
    pub token: String,
}

pub async fn require_auth(
    State(deployment): State<DeploymentImpl>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    // Extract token from Authorization header or cookie
    let token = extract_token(&req);

    let token = match token {
        Some(t) => t,
        None => {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let auth_service = LocalAuthService::new(deployment.db().pool.clone());

    let (user, session_id) = match auth_service.validate_session(&token).await {
        Ok(result) => result,
        Err(e) => {
            match e {
                AuthError::SessionNotFound | AuthError::SessionExpired | AuthError::SessionRevoked => {
                    warn!("Authentication failed: {}", e);
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                AuthError::Database(db_err) => {
                    warn!("Database error during auth: {}", db_err);
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                _ => {
                    warn!("Unexpected auth error: {}", e);
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        }
    };

    // Inject auth context into request extensions
    req.extensions_mut().insert(AuthContext {
        user,
        session_id,
        token: token.clone(),
    });

    next.run(req).await
}

fn extract_token(req: &Request<Body>) -> Option<String> {
    // Try Authorization header first (Bearer token)
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // Try Cookie header
    if let Some(cookie_header) = req.headers().get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(value) = cookie.strip_prefix("vk_session=") {
                    return Some(value.to_string());
                }
            }
        }
    }

    None
}
