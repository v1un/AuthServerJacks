// C:/Users/vini/RustroverProjects/AuthServerJacks/src/handlers/auth.rs
use crate::config::JWT_SECRET; // Still need JWT_SECRET static
use crate::db::get_user_by_username;
// DbPool type alias is not needed if using AppState
// use crate::db::DbPool;
use crate::error::AppError;
use crate::models::{Claims, LoginRequest, LoginResponse, Role};
// Import AppState and Result alias
use crate::{error::Result, AppState};
use axum::{extract::State, Json};
use bcrypt::verify;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};

// Generate a JWT token for a user
// Takes expiry_hours from config now
fn generate_token(username: &str, role: Role, expiry_hours: i64) -> Result<String> {
    let now = Utc::now();
    let expiration = now
        .checked_add_signed(Duration::hours(expiry_hours))
        // Use InternalError for unexpected issues like invalid duration
        .ok_or_else(|| AppError::InternalError("Failed to calculate token expiration".to_string()))?
        .timestamp() as usize;

    let iat = now.timestamp() as usize;

    let claims = Claims {
        sub: username.to_owned(), // Use to_owned() for String
        role, // Store Role enum directly
        exp: expiration,
        iat,
    };

    let header = Header::default(); // Default is HS256
    let encoding_key = EncodingKey::from_secret(JWT_SECRET.as_bytes());

    encode(&header, &claims, &encoding_key).map_err(AppError::JwtError)
}

// User login endpoint
pub async fn login(
    State(state): State<AppState>, // Use AppState
    Json(login_req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> { // Use Result alias
    tracing::info!("Login attempt for user: {}", login_req.username);

    // Get user from database using the pool from AppState
    let user = get_user_by_username(&state.db_pool, &login_req.username)
        .await?
        // Use a more specific error or keep generic for security
        .ok_or_else(|| {
            tracing::warn!("Login failed: User '{}' not found.", login_req.username);
            // Return generic error to avoid user enumeration
            AppError::AuthenticationError("Invalid username or password".to_string())
        })?;

    // Verify password hash
    // Run blocking bcrypt verify in a blocking task
    let password_hash = user.password_hash.clone();
    let password = login_req.password.clone();
    let password_matches = tokio::task::spawn_blocking(move || verify(&password, &password_hash))
        .await
        // Handle potential JoinError from spawn_blocking
        .map_err(|e| AppError::InternalError(format!("Password verification task failed: {}", e)))?
        // Handle potential bcrypt::Error
        .map_err(|e| {
            tracing::error!("Bcrypt verification error for user {}: {}", user.username, e);
            // Return internal error, don't expose bcrypt details
            AppError::InternalError("Password verification process failed".to_string())
        })?;


    if !password_matches {
        tracing::warn!("Login failed: Invalid password for user '{}'.", user.username);
        return Err(AppError::AuthenticationError("Invalid username or password".to_string()));
    }

    // Get JWT expiry from the config in AppState
    let expiry_hours = state.config.jwt_expiry_hours;

    // Generate token
    // Convert role string from DB back to Role enum
    let role = Role::from(user.role.as_str());
    let token = generate_token(&user.username, role, expiry_hours)?;

    tracing::info!("Login successful for user: {}", user.username);

    // Return login response
    Ok(Json(LoginResponse {
        token,
        username: user.username,
        role: role.into(), // Convert Role enum back to String for response
    }))
}