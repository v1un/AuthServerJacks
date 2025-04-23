use crate::config::JWT_SECRET;
// Use db functions for user operations
use crate::db::{
    create_user, delete_user_by_id, get_user_by_id, update_user_role, // DbPool not needed directly
};
use crate::error::AppError;
use crate::models::{
    AddUserRequest, Claims, LoginRequest, LoginResponse, Role, SuccessResponse, UpdateUserRequest,
    UserResponse,
};
// Import AppState and Result alias
use crate::{error::Result, AppState};
use axum::{
    extract::{Path, State},
    Json, Extension, // Import Extension if using claims from middleware
};
use bcrypt::{hash, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};

// Generate a JWT token specifically for admin login
// Note: This is separate from the user token generation. Consider if they can be merged.
fn generate_admin_token(username: &str, expiry_hours: i64) -> Result<String> {
    let now = Utc::now();
    let expiration = now
        .checked_add_signed(Duration::hours(expiry_hours))
        .ok_or_else(|| AppError::InternalError("Failed to calculate token expiration".to_string()))?
        .timestamp() as usize;

    let iat = now.timestamp() as usize;

    let claims = Claims {
        sub: username.to_owned(),
        role: Role::Admin, // Explicitly set role to Admin
        exp: expiration,
        iat,
    };

    let header = Header::default();
    let encoding_key = EncodingKey::from_secret(JWT_SECRET.as_bytes());

    encode(&header, &claims, &encoding_key).map_err(AppError::JwtError)
}

// Admin login endpoint
pub async fn login(
    State(state): State<AppState>, // Use AppState
    Json(login_req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    tracing::info!("Admin login attempt for user: {}", login_req.username);

    // Get admin creds from config via AppState
    let config = &state.config;

    // Verify admin credentials against config
    // NOTE: Comparing passwords directly like this is okay ONLY because
    // the admin password comes from config/env, not a hash in the DB.
    if login_req.username != config.admin_username || login_req.password != config.admin_password {
        tracing::warn!(
            "Admin login failed: Invalid credentials for user '{}'.",
            login_req.username
        );
        return Err(AppError::AuthenticationError(
            "Invalid admin username or password".to_string(),
        ));
    }

    // Generate admin token using expiry from config
    let token = generate_admin_token(&config.admin_username, config.jwt_expiry_hours)?;

    tracing::info!("Admin login successful for user: {}", config.admin_username);

    // Return login response
    Ok(Json(LoginResponse {
        token,
        username: config.admin_username.clone(),
        role: Role::Admin.into(), // Convert Role enum to String
    }))
}

// Add user endpoint (requires admin authentication via middleware)
pub async fn add_user(
    State(state): State<AppState>, // Use AppState
    Extension(admin_claims): Extension<Claims>, // Get claims to log which admin performed action
    Json(user_req): Json<AddUserRequest>,
) -> Result<Json<SuccessResponse>> {
    // Admin authorization is handled by middleware applied in main.rs

    // Validate input
    let username = user_req.username.trim();
    let password = user_req.password.trim();

    if username.is_empty() {
        return Err(AppError::ValidationError("Username cannot be empty".to_string()));
    }
    if password.is_empty() {
        return Err(AppError::ValidationError("Password cannot be empty".to_string()));
    }
    if password.len() < 8 {
        // Consider making password complexity requirements configurable
        return Err(AppError::ValidationError(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    tracing::info!("Admin '{}' attempting to add user: {}", admin_claims.sub, username);

    // Hash password - run in blocking task
    let password_to_hash = password.to_string();
    let password_hash = tokio::task::spawn_blocking(move || hash(&password_to_hash, DEFAULT_COST))
        .await
        // Handle potential JoinError from spawn_blocking
        .map_err(|e| AppError::InternalError(format!("Password hashing task failed: {}", e)))?
        // Handle potential bcrypt::Error
        .map_err(|e| {
            tracing::error!("Password hashing failed: {}", e);
            AppError::InternalError("Failed to hash password".to_string())
        })?;


    // Create user with default Role::User
    // let role_to_set = user_req.role.unwrap_or(Role::User); // If role was optional in request
    let role_to_set = Role::User;
    let user_id = create_user(&state.db_pool, username, &password_hash, role_to_set).await?;

    tracing::info!("Admin '{}' successfully added user '{}' with ID {}", admin_claims.sub, username, user_id);

    // Return success response
    Ok(Json(SuccessResponse {
        message: format!("User '{}' created successfully", username),
    }))
}

// List all users (admin only)
pub async fn list_users(
    State(state): State<AppState>, // Use AppState
    Extension(admin_claims): Extension<Claims>, // Get claims if needed
) -> Result<Json<Vec<UserResponse>>> {
    tracing::debug!("Admin '{}' listing all users.", admin_claims.sub);
    let users = get_all_users(&state.db_pool).await?;
    Ok(Json(users))
}

// Get user by ID (admin only)
pub async fn get_user(
    State(state): State<AppState>, // Use AppState
    Extension(admin_claims): Extension<Claims>, // Get claims if needed
    Path(user_id): Path<i64>,
) -> Result<Json<UserResponse>> {
    tracing::debug!("Admin '{}' getting user by ID: {}", admin_claims.sub, user_id);
    let user = get_user_by_id(&state.db_pool, user_id)
        .await?
        // Use NotFoundError or specific message
        .ok_or_else(|| AppError::NotFoundError(format!("User with ID {} not found", user_id)))?;

    Ok(Json(user))
}

// Update user role (admin only) - Implemented
pub async fn update_user(
    State(state): State<AppState>, // Use AppState
    Extension(admin_claims): Extension<Claims>, // Get claims if needed
    Path(user_id): Path<i64>,
    Json(update_req): Json<UpdateUserRequest>, // Contains the new Role
) -> Result<Json<SuccessResponse>> {
    tracing::info!("Admin '{}' attempting to update role for user ID: {}", admin_claims.sub, user_id);

    // Prevent admin from changing their own role? (Optional safeguard)
    // if admin_claims.sub == some_username_associated_with_user_id {
    //     return Err(AppError::ValidationError("Admin cannot change their own role".to_string()));
    // }

    // Update user role in the database
    let updated = update_user_role(&state.db_pool, user_id, update_req.role).await?;

    if updated {
        let role_str: String = update_req.role.into();
        tracing::info!("Admin '{}' successfully updated role for user ID {} to '{}'", admin_claims.sub, user_id, role_str);
        Ok(Json(SuccessResponse {
            message: format!("User ID {} role updated successfully to '{}'", user_id, role_str),
        }))
    } else {
        // This likely means the user ID didn't exist
        tracing::warn!("Admin '{}' failed to update role for user ID {}: User not found.", admin_claims.sub, user_id);
        Err(AppError::NotFoundError(format!(
            "User with ID {} not found, update failed",
            user_id
        )))
    }
}

// Delete user (admin only)
pub async fn delete_user(
    State(state): State<AppState>, // Use AppState
    Extension(admin_claims): Extension<Claims>, // Get claims if needed
    Path(user_id): Path<i64>,
) -> Result<Json<SuccessResponse>> {
    tracing::info!("Admin '{}' attempting to delete user ID: {}", admin_claims.sub, user_id);

    // Prevent admin from deleting themselves? (Optional safeguard)
    // let user_to_delete = get_user_by_id(&state.db_pool, user_id).await?;
    // if let Some(user) = user_to_delete {
    //     if user.username == admin_claims.sub {
    //          return Err(AppError::ValidationError("Admin cannot delete themselves".to_string()));
    //     }
    // }

    let deleted = delete_user_by_id(&state.db_pool, user_id).await?;

    if deleted {
        tracing::info!("Admin '{}' successfully deleted user ID: {}", admin_claims.sub, user_id);
        Ok(Json(SuccessResponse {
            message: format!("User with ID {} deleted successfully", user_id),
        }))
    } else {
        tracing::warn!("Admin '{}' failed to delete user ID {}: User not found.", admin_claims.sub, user_id);
        Err(AppError::NotFoundError(format!(
            "User with ID {} not found",
            user_id
        )))
    }
}