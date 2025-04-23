// C:/Users/vini/RustroverProjects/AuthServerJacks/src/db.rs
use crate::error::AppError;
use crate::models::{Role, User, UserResponse};
use anyhow::Context as AnyhowContext; // Alias to avoid conflict with crate::error::Result
use chrono::{DateTime, Utc};
use sqlx::{migrate::MigrateDatabase, Pool, Sqlite, SqlitePool};

pub type DbPool = Pool<Sqlite>;

// Initialize database and run migrations
// Changed return type to Result<DbPool, AppError> for consistency
pub async fn init_db(database_url: &str) -> Result<DbPool, AppError> {
    // Create database if it doesn't exist
    if !Sqlite::database_exists(database_url).await.unwrap_or(false) {
        Sqlite::create_database(database_url)
            .await
            .context("Failed to create SQLite database")
            .map_err(|e| AppError::InternalError(format!("DB Creation Error: {}", e)))?; // Map anyhow::Error

        tracing::info!("Created database: {}", database_url);
    } else {
        tracing::info!("Database already exists: {}", database_url);
    }

    // Connect to database
    let pool = SqlitePool::connect(database_url)
        .await
        .context("Failed to connect to SQLite database")
        .map_err(|e| AppError::InternalError(format!("DB Connection Error: {}", e)))?; // Map anyhow::Error

    // Run migrations (simple table creation)
    // Using sqlx::migrate! macro is generally preferred for more complex migrations
    // Ensure TEXT types are used for DateTime with SQLite in simple queries
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'admin')), -- Added CHECK constraint
            created_at TEXT NOT NULL, -- Storing as ISO 8601 string (SQLite default for DATETIME)
            updated_at TEXT -- Storing as ISO 8601 string
        )
        "#,
    )
        .execute(&pool)
        .await
        .context("Failed to create users table")
        .map_err(|e| AppError::InternalError(format!("DB Migration Error: {}", e)))?; // Map anyhow::Error

    tracing::info!("Database schema initialized/verified");

    Ok(pool)
}

// Database operations for users
pub async fn create_user(
    pool: &DbPool,
    username: &str,
    password_hash: &str,
    role: Role,
) -> Result<i64, AppError> {
    // Check if user already exists
    if user_exists(pool, username).await? {
        // Use specific error type
        return Err(AppError::UserExistsError(username.to_string()));
    }

    // Insert new user
    let role_str: String = role.into();
    // Use DateTime<Utc> directly, sqlx handles the conversion to TEXT for SQLite
    let now: DateTime<Utc> = Utc::now();

    // Use query! macro for compile-time checks
    let result = sqlx::query!(
        r#"
        INSERT INTO users (username, password_hash, role, created_at)
        VALUES (?, ?, ?, ?)
        "#,
        username,
        password_hash,
        role_str, // Ensure role_str matches CHECK constraint ('user' or 'admin')
        now // Pass DateTime<Utc>, sqlx maps it to TEXT
    )
        .execute(pool)
        .await
        .map_err(AppError::DatabaseError)?; // Map sqlx::Error to AppError::DatabaseError

    Ok(result.last_insert_rowid())
}

// Check if a user exists
pub async fn user_exists(pool: &DbPool, username: &str) -> Result<bool, AppError> {
    // Use fetch_optional to handle potentially zero rows gracefully
    // Use query_scalar! for a single optional value
    let exists: Option<i32> = sqlx::query_scalar!(
        "SELECT 1 FROM users WHERE username = ? LIMIT 1",
        username
    )
        .fetch_optional(pool)
        .await
        .map_err(AppError::DatabaseError)?;

    // If exists is Some(1), the user exists. If None, they don't.
    Ok(exists.is_some())
}

// Get user by username
pub async fn get_user_by_username(pool: &DbPool, username: &str) -> Result<Option<User>, AppError> {
    // sqlx::query_as! maps columns to the User struct fields
    // Ensure the struct fields match the query columns exactly
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT id, username, password_hash, role, created_at, updated_at
        FROM users
        WHERE username = ?
        "#,
        username
    )
        .fetch_optional(pool)
        .await
        .map_err(AppError::DatabaseError)?;

    Ok(user)
}

// Get user by ID (returning UserResponse)
pub async fn get_user_by_id(pool: &DbPool, user_id: i64) -> Result<Option<UserResponse>, AppError> {
    // Query directly into UserResponse using query_as!
    // Note: This requires UserResponse to derive sqlx::FromRow and have matching field names/types
    let user_response = sqlx::query_as!(
        UserResponse,
        r#"
        SELECT id, username, role, created_at, updated_at -- Select only needed fields
        FROM users
        WHERE id = ?
        "#,
        user_id
    )
        .fetch_optional(pool)
        .await
        .map_err(AppError::DatabaseError)?;

    Ok(user_response)
}

// Get all users (for admin panel)
pub async fn get_all_users(pool: &DbPool) -> Result<Vec<UserResponse>, AppError> {
    // Query directly into UserResponse
    let users = sqlx::query_as!(
        UserResponse,
        r#"
        SELECT id, username, role, created_at, updated_at -- Select only needed fields
        FROM users
        ORDER BY id
        "#,
    )
        .fetch_all(pool)
        .await
        .map_err(AppError::DatabaseError)?;

    Ok(users)
}

// Delete user by ID
pub async fn delete_user_by_id(pool: &DbPool, user_id: i64) -> Result<bool, AppError> {
    let result = sqlx::query!(
        r#"
        DELETE FROM users
        WHERE id = ?
        "#,
        user_id
    )
        .execute(pool)
        .await
        .map_err(AppError::DatabaseError)?;

    Ok(result.rows_affected() > 0)
}

// Update user role
pub async fn update_user_role(pool: &DbPool, user_id: i64, role: Role) -> Result<bool, AppError> {
    let role_str: String = role.into();
    let now: DateTime<Utc> = Utc::now();

    let result = sqlx::query!(
        r#"
        UPDATE users
        SET role = ?, updated_at = ?
        WHERE id = ?
        "#,
        role_str, // Ensure this matches CHECK constraint ('user' or 'admin')
        now,      // Pass DateTime<Utc>, sqlx maps it to TEXT
        user_id
    )
        .execute(pool)
        .await
        .map_err(AppError::DatabaseError)?;

    Ok(result.rows_affected() > 0)
}