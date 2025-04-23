use crate::config::JWT_SECRET;
use crate::error::{AppError, Result};
use crate::models::{Claims, Role};
use crate::AppState;
use axum::{
    extract::{Extension, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::sync::Arc;

// Helper to extract token from headers
fn extract_token(headers: &HeaderMap) -> Result<&str> {
    let auth_header = headers
        .get("Authorization")
        .ok_or_else(|| AppError::AuthenticationError("No authorization header".to_string()))?
        .to_str()
        .map_err(|_| AppError::AuthenticationError("Invalid authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::AuthenticationError(
            "Invalid authorization format, expected 'Bearer <token>'".to_string(),
        ));
    }

    Ok(&auth_header[7..]) // Skip "Bearer " prefix
}

// Verify JWT token and validate its claims
pub fn verify_token(token: &str) -> Result<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| AppError::AuthenticationError(format!("Invalid token: {}", e)))?;

    Ok(token_data.claims)
}

// Authentication middleware that verifies token and adds Claims to request extensions
pub async fn authenticate(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let headers = request.headers().clone();
    
    // Extract and verify token
    match extract_token(&headers) {
        Ok(token) => {
            match verify_token(token) {
                Ok(claims) => {
                    // Add claims to request extensions for downstream handlers and middleware
                    request.extensions_mut().insert(claims);
                    next.run(request).await
                },
                Err(e) => e.into_response(),
            }
        },
        Err(e) => e.into_response(),
    }
}

// Middleware to verify that user has an admin role
// Uses the claims added by authenticate middleware
pub async fn require_admin(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    // Extract claims from request extensions
    let claims = request.extensions().get::<Claims>();
    
    match claims {
        Some(claims) => {
            // Check if user has admin role
            if claims.role != Role::Admin {
                return AppError::AuthorizationError(
                    "Admin privileges required".to_string(),
                ).into_response();
            }
            
            // User is admin, proceed with request
            next.run(request).await
        },
        None => {
            // Claims should have been added by authenticate middleware
            AppError::AuthenticationError(
                "Authentication required".to_string()
            ).into_response()
        }
    }
}