// C:/Users/vini/RustroverProjects/AuthServerJacks/src/models.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow; // Import FromRow

// User Role Enum
// Added Clone, Copy for easier use
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")] // Simplifies serialization/deserialization
pub enum Role {
    User,
    Admin,
}

impl From<Role> for String {
    fn from(role: Role) -> Self {
        match role {
            Role::User => "user".to_string(),
            Role::Admin => "admin".to_string(),
        }
    }
}

// Consider making this fallible (return Result<Role, Error>)
// if strict validation against unknown strings is needed.
impl From<&str> for Role {
    fn from(role: &str) -> Self {
        match role.to_lowercase().as_str() {
            "admin" => Role::Admin,
            _ => Role::User, // Defaults to User for any other string
        }
    }
}

// JWT Claims for authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (username)
    // Store Role enum directly for type safety, serde handles string conversion
    pub role: Role,
    pub exp: usize, // Expiration time (Unix timestamp)
    pub iat: usize, // Issued at (Unix timestamp)
}

// Database User model
// Use sqlx::FromRow for easier querying
// Use chrono::DateTime<Utc> for timestamps if DB supports it, otherwise TEXT is fine with sqlx
#[derive(Debug, Serialize, FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)] // Ensure password hash is never accidentally serialized
    pub password_hash: String,
    // Store role as String matching DB, but consider Role enum if possible with sqlx mapping
    pub role: String,
    // Using String for SQLite compatibility with sqlx default mapping
    // sqlx can map DateTime<Utc> to TEXT automatically
    pub created_at: String, // Keep as String if sqlx::query_as! expects it
    pub updated_at: Option<String>, // Keep as String if sqlx::query_as! expects it
}

// User response without sensitive information
#[derive(Debug, Serialize, FromRow)] // Also derive FromRow if you ever query directly into this
pub struct UserResponse {
    pub id: i64,
    pub username: String,
    pub role: String, // Keep as String to match User struct and DB
    pub created_at: String,
    pub updated_at: Option<String>,
}

// Implement From<User> for UserResponse for easy conversion
impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            username: user.username,
            role: user.role,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

// Login request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
    pub role: String, // Keep as String for consistency
}


// Add user request (Admin)
#[derive(Debug, Deserialize)]
pub struct AddUserRequest {
    pub username: String,
    pub password: String,
    // Optionally allow setting role during creation, defaulting to User
    // pub role: Option<Role>,
}

// Update user request (Admin)
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    // Use the Role enum for validation during deserialization
    pub role: Role,
}

// Generic success response
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub message: String,
}