// C:/Users/vini/RustroverProjects/AuthServerJacks/src/error.rs
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Authorization failed: {0}")]
    AuthorizationError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    // Changed to take username directly
    #[error("User '{0}' already exists")]
    UserExistsError(String), // Contains the username

    #[error("Invalid input: {0}")]
    ValidationError(String),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("Internal server error: {0}")]
    InternalError(String), // For general internal issues

    // Added NotFound error variant
    #[error("Resource not found: {0}")]
    NotFoundError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self { // Borrow self here
            AppError::AuthenticationError(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::AuthorizationError(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            // Log internal errors for debugging, but return a generic message to the client
            AppError::DatabaseError(e) => {
                tracing::error!("Database Error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "An internal error occurred".to_string())
            },
            AppError::UserExistsError(_) => (StatusCode::CONFLICT, self.to_string()), // Use the generated message
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            // Treat JWT errors as Unauthorized, but log the specific reason
            AppError::JwtError(e) => {
                tracing::warn!("JWT Error: {:?}", e);
                (StatusCode::UNAUTHORIZED, "Invalid or expired token".to_string())
            },
            // Log internal errors, return generic message
            AppError::InternalError(msg) => {
                tracing::error!("Internal Server Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "An internal error occurred".to_string())
            },
            AppError::NotFoundError(msg) => (StatusCode::NOT_FOUND, msg.clone()),
        };

        // Log the error before returning the response
        // Avoid logging sensitive details from AuthenticationError/AuthorizationError if applicable
        if status.is_server_error() {
            // Use the original error for server-side logging, not just the generic message
            tracing::error!("Responding with {}: Error: {}", status, self);
        } else if status.is_client_error() {
            // Log client errors as warnings
            tracing::warn!("Responding with {}: {}", status, error_message);
        }

        (status, Json(json!({ "error": error_message }))).into_response()
    }
}

// Helper type for handlers returning Result<_, AppError>
pub type Result<T, E = AppError> = std::result::Result<T, E>;